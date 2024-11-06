import eventlet
eventlet.monkey_patch()
import os, jwt, base64, json, redis, yaml, requests, logging
import random
import string
from datetime import datetime, timedelta, timezone
from flask import Flask, flash, make_response, jsonify, redirect, render_template, request, url_for, g
from flask_socketio import SocketIO, join_room, leave_room, emit, disconnect
from flask_cors import CORS
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_migrate import Migrate
from dotenv import load_dotenv
from urllib.parse import urlparse
from modules.signalwireml import SignalWireML
from modules.models import db, AIAgent, AIUser, AISignalWireParams, AIFeatures, AIFunctions, AIIncludes, AIConversation, AISWMLRequest, AIParams, AIFunctionArgs, AIPrompt, AIPronounce, AILanguage, AIHints, AIIncludes, AISWMLRequest, AIDebugLogs, AIContext, AISteps, AIHooks, SharedAgent, AITranslate, PasswordResetToken
from modules.swml_generator import generate_swml_response
from modules.utils import (
    generate_random_password, get_signalwire_param, 
    setup_default_agent_and_params, create_admin_user,
    get_swaig_includes, check_agent_access, get_signalwire_param_by_agent_id
)
import secrets
if os.environ.get('DEBUG', False):
    debug_pin = f"{random.randint(100, 999)}-{random.randint(100, 999)}-{random.randint(100, 999)}"
    os.environ['WERKZEUG_DEBUG_PIN'] = debug_pin
    print(f"Debugger PIN: {debug_pin}")

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

load_dotenv()

app = Flask(__name__)
app.debug = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['REDIS_URL'] = os.environ.get('REDIS_URL')
app.config['ACCESS_SECRET_KEY'] = os.environ.get('ACCESS_SECRET_KEY')
app.config['REFRESH_SECRET_KEY'] = os.environ.get('REFRESH_SECRET_KEY')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
app.config['DEBUG'] = os.getenv('DEBUG', False)

db.init_app(app)

CORS(app, resources={
    r"/*": {
        "origins": os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',')
    }
})

# Add API prefix constant
API_PREFIX = '/api/v1'

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

redis_client = redis.from_url(app.config['REDIS_URL'])

app.static_folder = os.path.abspath('static')

login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

auth = HTTPBasicAuth()

@app.context_processor
def inject_agent_id():
    if current_user.is_authenticated:
        first_agent = AIAgent.query.filter_by(user_id=current_user.id).first()
        if first_agent:
            return {'agent_id': first_agent.id}
    return {'agent_id': None}

@auth.verify_password
def verify_password(username, password):
    full_url = request.url
    parsed_url = urlparse(full_url)
    path_segments = parsed_url.path.split('/')
    agent_id = path_segments[-1]
    g.agent_id = agent_id
    http_username = get_signalwire_param_by_agent_id(agent_id, 'HTTP_USERNAME')
    http_password = get_signalwire_param_by_agent_id(agent_id, 'HTTP_PASSWORD')

    if username == http_username and password == http_password:
        return True
    return False

with app.app_context():
    pass

pubsub_threads = {}
active_clients = {}

def redis_listener(channel):
    pubsub = redis_client.pubsub()
    pubsub.subscribe(channel)
    if channel not in pubsub_threads:
        pubsub.subscribe(channel)

    while True:
        message = pubsub.get_message()
        if message and message['type'] == 'message':
            socketio.emit('response', {'data': message['data'].decode('utf-8'), 'channel': channel}, room=channel)
        if active_clients[channel] == 0:
            pubsub.unsubscribe(channel)
            break
        eventlet.sleep(0.1)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(AIUser, int(user_id))

@app.route('/')
@login_required
def dashboard():
    number_of_requests = AISWMLRequest.query.filter_by().count()
    number_of_conversations = AIConversation.query.filter_by().count()
    number_of_functions = AIFunctions.query.filter_by().count()
    number_of_agents = AIAgent.query.filter_by().count()

    return render_template('dashboard.html', user=current_user, number_of_requests=number_of_requests, number_of_conversations=number_of_conversations, number_of_functions=number_of_functions, number_of_agents=number_of_agents)

@app.route('/import_swml', methods=['POST'])
@login_required
def import_swml():
    data = request.get_json()

    version = data.get('version')
    sections = data.get('sections', {})
    main_section = sections.get('main', [])

    new_agent = AIAgent(
        user_id=current_user.id,
        name=f"Imported Agent {version}",
        number=None
    )
    db.session.add(new_agent)
    db.session.commit()

    for section in main_section:
        if 'ai' in section:
            ai_data = section['ai']
            process_ai_data(new_agent.id, ai_data)

    return jsonify({'message': 'SWML imported successfully', 'agent_id': new_agent.id}), 201

def process_ai_data(agent_id, ai_data):
    params = ai_data.get('params', {})
    for key, value in params.items():
        new_param = AIParams(
            agent_id=agent_id,
            name=key,
            value=value
        )
        db.session.add(new_param)

    swaig = ai_data.get('SWAIG', {})
    functions = swaig.get('functions', [])
    for function in functions:
        purpose = function.get('purpose') or function.get('description')
        new_function = AIFunctions(
            agent_id=agent_id,
            name=function.get('function'),
            purpose=purpose,
            active=True
        )
        db.session.add(new_function)
        db.session.commit()

        argument = function.get('argument') or function.get('parameters', {}).get('properties')
        if argument:
            for prop, details in argument.items():
                new_argument = AIFunctionArgs(
                    function_id=new_function.id,
                    agent_id=agent_id,
                    name=prop,
                    type=details.get('type'),
                    description=details.get('description'),
                    required=prop in function.get('parameters', {}).get('required', [])
                )
                db.session.add(new_argument)

        data_map = function.get('data_map', {})
        webhooks = data_map.get('webhooks', [])
        for webhook in webhooks:
            new_hook = AIHooks(
                agent_id=agent_id,
                data=webhook,
                hook_type=AIHooks.HookType.other
            )
            db.session.add(new_hook)

    includes = swaig.get('includes', [])
    for include in includes:
        new_include = AIIncludes(
            agent_id=agent_id,
            url=include.get('url'),
            functions=include.get('functions')
        )
        db.session.add(new_include)

    prompt = ai_data.get('prompt', {})
    new_prompt = AIPrompt(
        agent_id=agent_id,
        prompt_type='prompt',
        prompt_text=prompt.get('text'),
        top_p=prompt.get('top_p'),
        temperature=prompt.get('temperature')
    )
    db.session.add(new_prompt)

    languages = ai_data.get('languages', [])
    for language in languages:
        new_language = AILanguage(
            agent_id=agent_id,
            name=language.get('name'),
            code=language.get('code'),
            voice=language.get('voice')
        )
        db.session.add(new_language)
        db.session.commit()

        for filler in language.get('function_fillers', []):
            new_filler = AILanguageFiller(
                language_id=new_language.id,
                text=filler
            )
            db.session.add(new_filler)

    post_prompt = ai_data.get('post_prompt', {})
    new_post_prompt = AIPostPrompt(
        agent_id=agent_id,
        text=post_prompt.get('text'),
        top_p=post_prompt.get('top_p'),
        temperature=post_prompt.get('temperature')
    )
    db.session.add(new_post_prompt)

    hints = ai_data.get('hints', [])
    for hint in hints:
        new_hint = AIHints(
            agent_id=agent_id,
            hint=hint
        )
        db.session.add(new_hint)

    pronounce = ai_data.get('pronounce', [])
    for entry in pronounce:
        new_pronounce = AIPronounce(
            agent_id=agent_id,
            replace_this=entry.get('replace_this'),
            replace_with=entry.get('replace_with'),
            ignore_case=entry.get('ignore_case', False)
        )
        db.session.add(new_pronounce)

    db.session.commit()

@app.route('/dashboard/completed', methods=['GET'])
@login_required
def dashboard_completed():
    # Use utcnow() to ensure the time is in UTC
    end_time = (datetime.utcnow() + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
    start_time = end_time - timedelta(hours=23)

    hourly_counts = {start_time + timedelta(hours=i): 0 for i in range(24)}

    completed_conversations = db.session.query(
        db.func.date_trunc('hour', AIConversation.created).label('hour'),
        db.func.count(AIConversation.id).label('count')
    ).filter(
        AIConversation.created >= start_time,
        AIConversation.created < end_time,
    ).group_by('hour').order_by('hour').all()

    for hour, count in completed_conversations:
        if hour in hourly_counts:
            hourly_counts[hour] = count

    labels = [(start_time + timedelta(hours=i)).strftime('%H:00') for i in range(24)]
    counts = [hourly_counts[start_time + timedelta(hours=i)] for i in range(24)]

    return jsonify({'labels': labels, 'counts': counts}), 200

@app.route('/refresh', methods=['POST'])
@login_required
def refresh():
    refresh_token = request.json.get('refresh_token')
    if not refresh_token:
        new_access_token = jwt.encode({
            'user_id': current_user.id,
            'exp': datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=60)
        }, app.config['ACCESS_SECRET_KEY'], algorithm='HS256')

        new_refresh_token = jwt.encode({
            'user_id': current_user.id,
            'exp': datetime.now(timezone.utc) + timedelta(days=30)
        }, app.config['REFRESH_SECRET_KEY'], algorithm='HS256')

        response = jsonify({'access_token': new_access_token, 'refresh_token': new_refresh_token, 'expires_in': 3600})
        response.set_cookie('access_token', new_access_token, httponly=True, samesite='Strict')
        response.set_cookie('refresh_token', new_refresh_token, httponly=True, samesite='Strict')
        return response, 200

    try:
        data = jwt.decode(refresh_token, app.config['REFRESH_SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']

        new_access_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.now(timezone.utc) + timedelta(minutes=60)
        }, app.config['ACCESS_SECRET_KEY'], algorithm='HS256')

        new_refresh_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.now(timezone.utc) + timedelta(days=30)
        }, app.config['REFRESH_SECRET_KEY'], algorithm='HS256')

        response = jsonify({'access_token': new_access_token, 'refresh_token': new_refresh_token, 'expires_in': 3600})
        response.set_cookie('access_token', new_access_token, httponly=True, samesite='Strict')
        response.set_cookie('refresh_token', new_refresh_token, httponly=True, samesite='Strict')
        return response, 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token'}), 401
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    response = make_response(redirect(url_for('login')))
    response.set_cookie('selectedAgentId', '', expires=0)
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = AIUser.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            response = make_response(redirect(url_for('dashboard')))
            
            login_user(user)
            
            default_agent_name = "BotWorks"
            default_agent = AIAgent.query.filter_by(name=default_agent_name, user_id=user.id).first()
            if default_agent is None:
                new_agent = AIAgent(
                    name=default_agent_name,
                    user_id=user.id
                )
                db.session.add(new_agent)
                db.session.commit()
                agent_id = new_agent.id
            else:
                agent_id = default_agent.id

            if not request.cookies.get('selectedAgentId'):
                first_agent = AIAgent.query.filter_by(user_id=user.id).first()
                if first_agent:
                    agent_id = first_agent.id
                    response.set_cookie('selectedAgentId', str(agent_id), samesite='Strict')
            
            setup_default_agent_and_params(user_id=user.id)

            access_token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=60)
            }, app.config['ACCESS_SECRET_KEY'], algorithm='HS256')

            refresh_token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.now(timezone.utc) + timedelta(days=7)
            }, app.config['REFRESH_SECRET_KEY'], algorithm='HS256')
            
            response.set_cookie('access_token', access_token, httponly=True, samesite='Strict')
            response.set_cookie('refresh_token', refresh_token, httponly=True, samesite='Strict')

            return response

        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')

        existing_user = AIUser.query.filter((AIUser.username == username) | (AIUser.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                return jsonify({'error': 'Username already in use. Please choose a different username.'}), 409
            if existing_user.email == email:
                return jsonify({'error': 'Email already in use. Please choose a different email.'}), 409

        new_user = AIUser(
            username=username.lower(),
            password=generate_password_hash(data.get('password'), method='pbkdf2:sha256'),
            full_name=data.get('full_name'),
            email=email
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User account created successfully'}), 201

    return render_template('signup.html')

@app.route('/yaml/<int:agent_id>', methods=['POST', 'GET'])
@auth.login_required
def get_yaml(id, agent_id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        data = request.args.to_dict()

    response_data = generate_swml_response(agent_id, request_body=data)

    response = make_response(yaml.dump(response_data))
    response.headers['Content-Type'] = 'text/x-yaml'
    
    return response


@app.route('/swaig/<int:agent_id>', methods=['POST'])
@auth.login_required
def swaig(agent_id):
    data = request.get_json()
    hook_type_value = data.get('function', '').lower()

    if hook_type_value in ['hangup_hook', 'startup_hook', 'summarize_conversation']:
        hook_type = AIHooks.HookType(hook_type_value)
    else:
        hook_type = AIHooks.HookType.other

    new_hook = AIHooks(
        agent_id=agent_id,
        data=data,
        hook_type=hook_type
    )

    db.session.add(new_hook)
    db.session.commit()

    return jsonify({'response': 'Data received successfully'}), 201

@app.route('/status/<int:agent_id>', methods=['POST'])
@auth.login_required
def status(agent_id):
    data = request.get_json()
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    response = {'response': 'Status updated successfully'}

    new_swml_request = AISWMLRequest(
        agent_id=agent_id,
        request=jsonify(data).json,
        response=jsonify(response).json,
        ip_address=ip_address
    )
    
    db.session.add(new_swml_request)
    db.session.commit()
    
    return jsonify({'response': 'Status updated successfully'}), 200

@app.route('/swml/<int:agent_id>', methods=['POST', 'GET'])
@auth.login_required
def swml(agent_id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        data = request.args.to_dict()

    response_data = generate_swml_response(agent_id, request_body=data)

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    new_swml_request = AISWMLRequest(
        agent_id=agent_id,
        request=jsonify(data).json,
        response=jsonify(response_data).json,
        ip_address=ip_address
    )
    db.session.add(new_swml_request)
    db.session.commit()
    
    response = make_response(jsonify(response_data))
    response.headers['Content-Type'] = 'application/json'
    
    return response

@app.route('/postprompt/<int:agent_id>', methods=['POST'])
@auth.login_required
def postprompt(agent_id):
    data = request.get_json()
    new_conversation = AIConversation(
        agent_id=agent_id,
        data=data
    )
    db.session.add(new_conversation)
    db.session.commit()

    call_id = data.get('call_id')
    
    message = {
        "command": "conversation_ended",
        "call_info": {"call_id": f"{call_id}"},
        "conversation_add": {"content": f"call has ended"}
    }
    
    redis_client.publish(f"debug_channel_{agent_id}", json.dumps(message))
    return jsonify({'message': 'Conversation entry created successfully'}), 201

@app.route('/datasphere/search/<uuid:document_id>', methods=['POST'])
@login_required
def search_datasphere(document_id):
    data = request.get_json()
    query_string = data.get('query_string', '')

    if not query_string:
        return jsonify({'message': 'Query string is required'}), 400

    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')

    url = f'https://{space_name}/api/datasphere/documents/search'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    payload = {
        'document_id': str(document_id),
        'query_string': data.get('query_string', '')
    }
        
    if 'tags' in data:
        payload['tags'] = data['tags']
    if 'distance' in data:
        payload['distance'] = data['distance']
    if 'count' in data:
        payload['count'] = data['count']
    if 'language' in data:
        payload['language'] = data['language']
    if 'pos_to_expand' in data:
        payload['pos_to_expand'] = data['pos_to_expand']
    if 'max_synonyms' in data:
        payload['max_synonyms'] = data['max_synonyms']

    response = requests.post(url, headers=headers, json=payload, auth=(project_id, auth_token))

    if response.status_code == 200:
        return jsonify(response.json()), 200
    elif response.status_code == 401:
        return jsonify({'error': 'SignalWire credentials missing'}), 401
    else:
        return jsonify({'error': 'An error occurred while searching the document'}), response.status_code

@app.route('/datasphere', methods=['POST'])
@login_required
def create_datasphere():
    data = request.get_json()
    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')
    
    url = f'https://{space_name}/api/datasphere/documents'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.post(url, headers=headers, json=data, auth=(project_id, auth_token))
    
    if response.status_code == 201:
        return jsonify(response.json()), 201
    elif response.status_code == 401:
        return jsonify({'error': 'SignalWire credentials missing'}), 401
    else:
        return jsonify({'error': 'Failed to create datasphere'}), response.status_code

@app.route('/datasphere/documents/<uuid:datasphere_id>', methods=['PATCH'])
@login_required
def update_datasphere(datasphere_id):
    data = request.get_json()
    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')
    
    url = f'https://{space_name}/api/datasphere/documents/{datasphere_id}'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.patch(url, headers=headers, json=data, auth=(project_id, auth_token))
    
    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({'error': 'Failed to update datasphere'}), response.status_code

@app.route('/datasphere', methods=['GET'])
@login_required
def datasphere():
    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            space_name = get_signalwire_param('SPACE_NAME')
            project_id = get_signalwire_param('PROJECT_ID')
            auth_token = get_signalwire_param('AUTH_TOKEN')
            
            url = f'https://{space_name}/api/datasphere/documents'
            headers = {'Accept': 'application/json'}
            response = requests.get(url, headers=headers, auth=(project_id, auth_token))

            if response.status_code == 200:
                return jsonify(response.json()), 200
            elif response.status_code == 401:
                return jsonify({'error': 'SignalWire credentials missing'}), 401
        else:   
            return render_template('datasphere.html', user=current_user)

@app.route('/datasphere/documents/<uuid:datasphere_id>', methods=['DELETE'])
@login_required
def delete_datasphere(datasphere_id):
    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')
    
    url = f'https://{space_name}/api/datasphere/documents/{datasphere_id}'
    headers = {
        'Accept': 'application/json'
    }
    response = requests.delete(url, headers=headers, auth=(project_id, auth_token))
    
    if response.status_code == 204:
        return jsonify({'message': 'Datasphere document deleted successfully'}), 204
    else:
        return jsonify({'error': 'Failed to delete datasphere document'}), response.status_code

@app.route('/agents/<int:agent_id>/livedebug', methods=['GET'])
@login_required
def livedebug_page(agent_id):
    channel = f'debug_channel_{agent_id}'

    return render_template('livedebug.html', channel=channel)

@socketio.on('connect')
def on_connect():
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']

        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        emit('status', {'message': 'Authentication successful'}, namespace='/')

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('join')
def on_join(data):
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']
        channel = data['channel']
        agent_id = int(channel.split('_')[-1])

        agent = AIAgent.query.filter_by(id=agent_id, user_id=user_id).first()
        if not agent:
            emit('error', {'message': 'Agent not found or access denied'}, namespace='/')
            disconnect()
            return

        user = db.session.get(AIUser, user_id)

        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        channel = data['channel']
        join_room(channel)

        if channel not in active_clients:
            active_clients[channel] = 0
        active_clients[channel] += 1

        if channel not in pubsub_threads:
            pubsub_threads[channel] = eventlet.spawn(redis_listener, channel)

        emit('status', {'message': f'Joined debug channel for {agent.name}'}, room=channel)

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('leave')
def on_leave(data):
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']

        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        channel = data['channel']
        leave_room(channel)

        if channel in active_clients:
            active_clients[channel] -= 1

            if active_clients[channel] == 0:
                del pubsub_threads[channel]
                emit('status', {'message': f'No more clients in {channel}. Channel listener stopping.'}, room=channel)

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('disconnect')
def on_disconnect():
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']

        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        for channel in list(active_clients.keys()):
            if channel in active_clients:
                active_clients[channel] -= 1

                if active_clients[channel] == 0:
                    pubsub_threads[channel].kill()
                    del pubsub_threads[channel]
                    del active_clients[channel]

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('send_message')
def handle_message(data):
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']

        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        if 'data' in data:
            parsed_data = json.loads(data['data'])
        else:
            emit('error', {'message': 'Invalid data format'}, namespace='/')
            return

        command = parsed_data.get('command', {})
        channel = parsed_data.get('channel', {} )
        call_id = parsed_data.get('call_info', {}).get('call_id')
        content = parsed_data.get('conversation_add', {}).get('content')
        role = parsed_data.get('conversation_add', {}).get('role')

        if not call_id or not content or not channel:
            emit('error', {'message': 'Invalid data format'}, namespace='/')
            return

        agent_id = int(channel.rsplit('_', 1)[-1])     

        space_name = get_signalwire_param('SPACE_NAME')
        auth_token = get_signalwire_param('AUTH_TOKEN')
        project_id = get_signalwire_param('PROJECT_ID')

        encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
        url = f"https://{space_name}/api/calling/calls"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {encoded_credentials}"
        }

        payload = {}

        if command == 'hangup':
            payload = {
                "id": call_id,
                "command": "calling.end",
                "params": {
                    "reason": "hangup",
                }
            }
        else:
            payload = {
                "id": call_id,
                "command": "calling.ai_message",
                "params": {
                    "role": role,
                    "message_text": f"{content}"
                }
            }
        
        response = requests.put(url, headers=headers, data=json.dumps(payload))

        if response.status_code != 200:
            emit('error', {'message': f'Failed to send command: {response.text}'}, namespace='/')
        else:
            emit('status', {'message': 'Command sent successfully'}, namespace='/')

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()
    except json.JSONDecodeError:
        emit('error', {'message': 'Invalid JSON format'}, namespace='/')
        disconnect()
    except Exception as e:
        emit('error', {'message': f'An unexpected error occurred: {str(e)}'}, namespace='/')

@app.route('/debugwebhook/<int:agent_id>', methods=['POST'])
@auth.login_required
def create_debuglog(agent_id):
    data = json.loads(request.get_data().decode('utf-8'))
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    channel_name = f'debug_channel_{agent_id}'

    redis_client.publish(channel_name, json.dumps(data).encode('utf-8'))

    new_log = AIDebugLogs(
        agent_id=agent_id,
        data=data,
        ip_address=ip_address
    )
    db.session.add(new_log)
    db.session.commit()

    return jsonify({'message': 'Debug log created successfully'}), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/debuglogs', methods=['GET', 'DELETE'])
@login_required
def get_debuglogs(agent_id):
    if request.method == 'GET':
        logs = AIDebugLogs.query.filter_by(agent_id=agent_id).all()
        logs_data = [{'id': log.id, 'created': log.created, 'data': log.data, 'ip_address': log.ip_address} for log in logs]
        return jsonify(logs_data), 200

    elif request.method == 'DELETE':
        AIDebugLogs.query.filter_by(agent_id=agent_id).delete()
        db.session.commit()
        return jsonify({'message': 'All debug logs for the agent deleted successfully'}), 200

@app.route(f'/agents/<int:agent_id>/debuglogs', methods=['GET'])
@login_required
def debuglogs_page(agent_id):
    return render_template('debuglog.html', user=current_user, agent_id=agent_id)

@app.route('/translate', methods=['GET'])
@login_required
def translate():
    if request.headers.get('Accept') == 'application/json':
        return jsonify([]), 200
    else:
        return render_template('translate.html', user=current_user)

@app.route('/transcribe', methods=['GET'])
@login_required
def transcribe():
    if request.headers.get('Accept') == 'application/json':
        return jsonify([]), 200
    else:
        return render_template('transcribe.html', user=current_user)

@app.route('/phone_numbers', methods=['GET'])
@login_required
def list_phone_numbers():
    if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
        space_name = get_signalwire_param('SPACE_NAME')
        project_id = get_signalwire_param('PROJECT_ID')
        auth_token = get_signalwire_param('AUTH_TOKEN')
        print(f"space_name: {space_name}, project_id: {project_id}, auth_token: {auth_token}")
        encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
        url = f'https://{space_name}/api/relay/rest/phone_numbers'
        authorization = f'Basic {encoded_credentials}'

        headers = {
            'Authorization': authorization,
            'Accept': 'application/json'
        }
        params = {}

        starts_with = request.args.get('starts_with')
        contains = request.args.get('contains')
        ends_with = request.args.get('ends_with')

        if starts_with:
            params['starts_with'] = starts_with
        elif contains:
            params['contains'] = contains
        elif ends_with:
            params['ends_with'] = ends_with

        max_results = request.args.get('max_results', 50, type=int)
        params['max_results'] = min(max_results, 100)

        region = request.args.get('region')
        city = request.args.get('city')

        if region:
            params['region'] = region
        if city:
            params['city'] = city

        params = {}
        filter_name = request.args.get('filter_name')
        filter_number = request.args.get('filter_number')
        if filter_name:
            params['filter_name'] = filter_name
        if filter_number:
            params['filter_number'] = filter_number

        response = requests.get(url, headers=headers, params=params)
        print(f"Response: {response}")
        if response.status_code == 200:
            return jsonify(response.json()), 200
        elif response.status_code == 401:
            return jsonify({'error': 'SignalWire credentials missing'}), 401
        else:
            return jsonify({'error': 'Failed to retrieve phone numbers'}), response.status_code

    else:
        return render_template('phone_numbers.html', user=current_user)
    
@app.route('/phone_numbers/search', methods=['GET'])
@login_required
def search_phone_numbers():
    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')

    encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
    url = f'https://{space_name}/api/relay/rest/phone_numbers/search'
    authorization = f'Basic {encoded_credentials}'

    headers = {
        'Authorization': authorization,
        'Accept': 'application/json'
    }

    params = {}
    if request.args.get('areacode'):
        params['areacode'] = request.args.get('areacode')
    if request.args.get('number_type'):
        params['number_type'] = request.args.get('number_type', 'local')
    if request.args.get('starts_with'):
        params['starts_with'] = request.args.get('starts_with')
    if request.args.get('contains'):
        params['contains'] = request.args.get('contains')
    if request.args.get('ends_with'):
        params['ends_with'] = request.args.get('ends_with')
    if request.args.get('max_results'):
        params['max_results'] = request.args.get('max_results', 50)
    if request.args.get('region'):
        params['region'] = request.args.get('region')
    if request.args.get('city'):
        params['city'] = request.args.get('city')

    response = requests.get(url, headers=headers, params=params, timeout=30)

    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({'error': 'Failed to search available phone numbers'}), response.status_code
    
@app.route('/phone_numbers', methods=['POST'])
@login_required
def purchase_phone_number():
    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')

    encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
    url = f'https://{space_name}/api/relay/rest/phone_numbers'
    authorization = f'Basic {encoded_credentials}'

    data = request.get_json()
    phone_number = data.get('number')

    if not phone_number:
        return jsonify({'error': 'Phone number is required'}), 400

    headers = {
        'Authorization': authorization,
        'Content-Type': 'application/json'
    }

    payload = {
        'number': phone_number
    }

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({'error': 'Failed to purchase phone number'}), response.status_code

@app.route('/phone_numbers/<uuid:phone_number_id>', methods=['PUT'])
@login_required
def update_phone_number(phone_number_id):
    data = request.get_json()
    phone_number = data.get('phone_number')
    agent_id = data.get('agent_id')

    auth_pass = get_signalwire_param('HTTP_PASSWORD')
    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')
    auth_user = get_signalwire_param('HTTP_USERNAME')
    swml_url = f"https://{auth_user}:{auth_pass}@{request.host}/swml/{agent_id}"  
    
    encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
    url = f'https://{space_name}/api/relay/rest/phone_numbers/{phone_number_id}'
    authorization = f'Basic {encoded_credentials}'

    agent_name = AIAgent.query.filter_by(id=agent_id).first().name

    AIAgent.query.filter_by(id=agent_id).update({'number': phone_number})
    db.session.commit()

    data = {
        "name": agent_name,
        "call_handler": "relay_script",
        "call_receive_mode": "voice",
        "call_request_method": "POST",
        "call_relay_script_url": swml_url
    }

    headers = {
        'Authorization': authorization,
        'Content-Type': 'application/json'
    }

    response = requests.put(url, headers=headers, json=data)

    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({'error': 'Failed to update phone number'}), response.status_code
    
@app.route('/phone_numbers/<uuid:phone_number_id>', methods=['DELETE'])
@login_required
def release_phone_number(phone_number_id):
    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')

    encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
    url = f'https://{space_name}/api/relay/rest/phone_numbers/{phone_number_id}'
    authorization = f'Basic {encoded_credentials}'

    headers = {
        'Authorization': authorization,
        'Accept': 'application/json'
    }

    response = requests.delete(url, headers=headers)
    print(f"Response: {response}")
    if response.status_code == 204:
        return jsonify({'message': 'Phone number released successfully'}), 204
    else:
        return jsonify({'error': 'Failed to release phone number'}), response.status_code

@app.route('/phone/authenticate', methods=['GET'])
@login_required
def phone_authenticate():


    identifier = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    space_name = get_signalwire_param('SPACE_NAME')
    project_id = get_signalwire_param('PROJECT_ID')
    auth_token = get_signalwire_param('AUTH_TOKEN')

    url = f"https://{space_name}/api/relay/rest/jwt"
    auth = (project_id, auth_token)
    headers = {"Content-Type": "application/json"}
    data = {
        "expires_in": 3600,
        "resource": identifier
    }
    encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
    authorization = f'Basic {encoded_credentials}'

    headers = {
        'Authorization': authorization,
        'Accept': 'application/json'
    }
    
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 200:
        response_json = response.json()
        jwt_token = response_json.get('jwt_token')
        refresh_token = response_json.get('refresh_token')

        resp = jsonify({
            'message': 'Authenticated successfully',
            'jwt_token': jwt_token,
            'refresh_token': refresh_token,
            'identifier': identifier,
            'project_id': project_id,
            'expires_in': 3600
        })
        resp.set_cookie('resource_id', identifier)
        return resp, 200
    else:
        return jsonify({'error': 'Authentication failed'}), response.status_code

@app.route('/phone', methods=['GET'])
@login_required
def phone():
    return render_template('phone.html', user=current_user)

@app.route('/users', methods=['GET'])
@login_required
def get_users():
    users = AIUser.query.filter(AIUser.id != current_user.id).all()
    users_data = [{'id': user.id, 'username': user.username, 'full_name': user.full_name} for user in users]
    return jsonify(users_data), 200

@app.route('/translators', methods=['GET'])
@login_required
def get_translators():
    if request.headers.get('Accept') == 'application/json': 
        translators = AITranslate.query.all()
        return jsonify([{
            'id': translator.id,
            'from_language': translator.from_language,
            'to_language': translator.to_language,
            'from_filter': translator.from_filter,  # Ensure this field is included
            'to_filter': translator.to_filter,      # Ensure this field is included
            'from_voice': translator.from_voice,
            'to_voice': translator.to_voice,
            'caller_id_number': translator.caller_id_number
        } for translator in translators])
    else:
        return render_template('translate.html', user=current_user)

@app.route('/translators', methods=['POST'])
@login_required
@check_agent_access
def add_translator():
    try:
        data = request.get_json()
        new_translator = AITranslate(
            user_id=current_user.id,
            from_language=data['from_language'],
            to_language=data['to_language'],
            from_filter=data.get('from_filter'),
            to_filter=data.get('to_filter'),
            from_voice=data.get('from_voice'),
            to_voice=data.get('to_voice'),
            caller_id_number=data.get('caller_id_number')
        )
        db.session.add(new_translator)
        db.session.commit()

        return jsonify(new_translator.to_dict()), 201
    except Exception as e:
        app.logger.error(f"Error adding translator: {e}")
        return jsonify({'error': 'Failed to add translator'}), 500

@app.route('/translators/<int:id>', methods=['GET'])
@login_required
def get_translator(id):
    translator = AITranslate.query.get_or_404(current_user.id, id)
    return jsonify({
        'id': translator.id,
        'from_language': translator.from_language,
        'to_language': translator.to_language,
        'from_filter': translator.from_filter,
        'to_filter': translator.to_filter,
        'from_voice': translator.from_voice,
        'to_voice': translator.to_voice,
        'caller_id_number': translator.caller_id_number
    }), 200

@app.route('/translators/<int:id>', methods=['PUT'])
@login_required
def update_translator(id):
    translator = AITranslate.query.get_or_404(current_user.id, id)
    data = request.get_json()
    translator.from_language = data['from_language']
    translator.to_language = data['to_language']
    translator.from_filter = data.get('from_filter')
    translator.to_filter = data.get('to_filter')
    translator.from_voice = data.get('from_voice')
    translator.to_voice = data.get('to_voice')
    translator.caller_id_number = data.get('caller_id_number')
    db.session.commit()
    return jsonify(translator.to_dict())

@app.route('/translators/<int:id>', methods=['DELETE'])
@login_required
def delete_translator(id):
    translator = AITranslate.query.get_or_404(current_user.id, id)
    db.session.delete(translator)
    db.session.commit()
    return jsonify({'message': 'Translator deleted successfully'})

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

def send_password_reset_email(email, reset_url):
    MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY')
    MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN')
    FROM_EMAIL = os.environ.get('MAILGUN_FROM_EMAIL')
    FROM_NAME = os.environ.get('MAILGUN_FROM_NAME')
    
    return requests.post(
        f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
        auth=("api", MAILGUN_API_KEY),
        data={
            "from": f"{FROM_NAME} <{FROM_EMAIL}>",
            "to": email,
            "subject": "Password Reset Request",
            "text": f"To reset your password, please click the following link: {reset_url}\n\n"
                   f"This link will expire in 15 minutes.\n\n"
                   f"If you did not request this password reset, please ignore this email."
        }
    )

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = AIUser.query.filter_by(email=email).first()
        
        if user:
            # Generate token and save to database
            token = secrets.token_urlsafe(32)
            reset_token = PasswordResetToken(user_id=user.id, token=token)
            db.session.add(reset_token)
            db.session.commit()
            
            # Generate reset URL
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send email
            try:
                response = send_password_reset_email(email, reset_url)
                if response.status_code == 200:
                    flash('Password reset instructions have been sent to your email.', 'success')
                else:
                    flash('Failed to send reset email. Please try again later.', 'error')
            except Exception as e:
                app.logger.error(f"Failed to send reset email: {str(e)}")
                flash('Failed to send reset email. Please try again later.', 'error')
                
        else:
            # To prevent email enumeration, show the same message even if email doesn't exist
            flash('Password reset instructions have been sent to your email if it exists in our system.', 'success')
            
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Find the token in database
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or not reset_token.is_valid():
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')
        
        # Update user's password
        user = AIUser.query.get(reset_token.user_id)
        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Mark token as used
        reset_token.used = True
        
        db.session.commit()
        
        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html')

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/share/<int:user_id>', methods=['DELETE'])
@login_required
def revoke_share(agent_id, user_id):
    shared_access = SharedAgent.query.filter_by(user_id=current_user.id, agent_id=agent_id, shared_with_user_id=user_id).all()
    for sa in shared_access:
        db.session.delete(sa)
    db.session.commit()
    return jsonify({'message': 'Share revoked successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/share', methods=['GET'])
@login_required
def get_shared_users(agent_id):
    shared_access_list = SharedAgent.query.filter_by(user_id=current_user.id, agent_id=agent_id).all()
    shared_users_data = []

    for sa in shared_access_list:
        user = AIUser.query.get(sa.shared_with_user_id)
        if user:
            shared_users_data.append({
                'id': sa.shared_with_user_id,
                'permissions': sa.permissions,
                'username': user.username,
                'full_name': user.full_name
            })

    return jsonify(shared_users_data), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/share', methods=['POST'])
@login_required
def share_agent(agent_id):
    data = request.get_json()
    shared_with_user_id = data.get('user_id')
    permissions = data.get('permissions', 'view')

    agent = AIAgent.query.filter_by(id=agent_id, user_id=current_user.id).first_or_404()

    shared_access = SharedAgent(user_id=current_user.id, agent_id=agent_id, shared_with_user_id=shared_with_user_id, permissions=permissions)
    db.session.add(shared_access)
    db.session.commit()

    return jsonify({'message': 'Agent shared successfully'}), 201


@app.route('/agents/<int:agent_id>', methods=['GET'])
@login_required
def agent_page(agent_id):
    return render_template('agents.html', user=current_user, agent_id=agent_id)

# API routes for agents
@app.route(f'{API_PREFIX}/agents', methods=['GET'])
@login_required
def list_agents():
    owned_agents = AIAgent.query.filter_by(user_id=current_user.id).all()
    shared_agent_ids = db.session.query(SharedAgent.agent_id).filter_by(shared_with_user_id=current_user.id).all()
    shared_agents = AIAgent.query.filter(AIAgent.id.in_([id for id, in shared_agent_ids])).all()
    
    all_agents = owned_agents + shared_agents
    agents_data = [{
        'id': agent.id,
        'name': agent.name,
        'number': agent.number,
        'created': agent.created
    } for agent in all_agents]
    
    return jsonify(agents_data), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>', methods=['GET'])
@login_required
def get_agent(agent_id):
    agent = AIAgent.query.get_or_404(agent_id)
    return jsonify({
        'id': agent.id,
        'name': agent.name,
        'number': agent.number,
        'created': agent.created
    }), 200
    
@app.route(f'{API_PREFIX}/agents', methods=['GET'])
@login_required
def get_all_agents():
    agents = AIAgent.query.all()
    agents_data = [{
        'id': agent.id,
        'name': agent.name,
        'number': agent.number,
        'created': agent.created
    } for agent in agents]
    
    return jsonify(agents_data), 200

@app.route(f'{API_PREFIX}/agents', methods=['POST'])
@login_required
def create_agent():
    data = request.get_json()
    name = data.get('name')
    number = data.get('number')

    if not name:
        return jsonify({'error': 'Name is required'}), 400

    new_agent = AIAgent(name=name, number=number, user_id=current_user.id)
    db.session.add(new_agent)
    db.session.commit()

    return jsonify({
        'message': 'Agent created successfully',
        'id': new_agent.id
    }), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>', methods=['PUT'])
@login_required
def update_agent(agent_id):
    agent = AIAgent.query.get_or_404(agent_id)
    data = request.get_json()
    
    agent.name = data.get('name', agent.name)
    agent.number = data.get('number', agent.number)
    
    db.session.commit()
    return jsonify({'message': 'Agent updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>', methods=['DELETE'])
@login_required
def delete_agent(agent_id):
    agent = AIAgent.query.get_or_404(agent_id)

    if agent.name == "BotWorks":
        return jsonify({'message': 'Cannot delete the default agent "BotWorks".'}), 403

    db.session.delete(agent)
    db.session.commit()
    return jsonify({'message': 'Agent deleted successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/clone', methods=['POST'])
@login_required
def clone_agent(agent_id):
    original_agent = AIAgent.query.get_or_404(agent_id)
    random_bits = generate_random_password(4)

    new_agent = AIAgent(
        user_id=current_user.id,
        name=f"{original_agent.name} Copy {random_bits}",
        number=original_agent.number
    )
    db.session.add(new_agent)
    db.session.commit()

    def clone_relationships(original, new, relationship_name):
        related_items = getattr(original, relationship_name)
        for item in related_items:
            new_item = item.__class__(**{col.name: getattr(item, col.name) 
                                       for col in item.__table__.columns if col.name != 'id'})
            new_item.agent_id = new.id
            new_item.user_id = current_user.id
            db.session.add(new_item)

    relationships = [
        'ai_functions', 'ai_function_argument', 
        'ai_hints', 'ai_pronounce', 'ai_prompt', 'ai_language', 
        'ai_params', 'ai_features', 'ai_includes', 'ai_contexts', 'ai_steps'
    ]

    for relationship in relationships:
        clone_relationships(original_agent, new_agent, relationship)

    db.session.commit()

    return jsonify({
        'message': 'Agent cloned successfully',
        'new_agent_id': new_agent.id
    }), 201

@app.route('/agents/<int:agent_id>/hints', methods=['GET'])
@login_required
def hints_page(agent_id):
    if request.headers.get('Accept') == 'application/json':
        hints = AIHints.query.filter_by(agent_id=agent_id).all()
        return jsonify([{
            'id': hint.id,
            'hint': hint.hint,
            'created': hint.created
        } for hint in hints]), 200
    return render_template('hints.html', user=current_user, agent_id=agent_id)

# API routes for hints
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/hints', methods=['GET'])
@login_required
def list_hints(agent_id):
    hints = AIHints.query.filter_by(agent_id=agent_id).all()
    return jsonify([{
        'id': hint.id,
        'hint': hint.hint,
        'created': hint.created
    } for hint in hints]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/hints/<int:hint_id>', methods=['GET'])
@login_required
def get_hint(agent_id, hint_id):
    hint = AIHints.query.filter_by(id=hint_id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': hint.id,
        'hint': hint.hint,
        'created': hint.created
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/hints', methods=['POST'])
@login_required
def create_hint(agent_id):
    data = request.get_json()
    new_hint = AIHints(
        hint=data['hint'],
        agent_id=agent_id
    )
    db.session.add(new_hint)
    db.session.commit()
    return jsonify({'message': 'Hint created successfully', 'id': new_hint.id}), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/hints/<int:hint_id>', methods=['PUT'])
@login_required
def update_hint(agent_id, hint_id):
    hint = AIHints.query.filter_by(id=hint_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    hint.hint = data['hint']
    db.session.commit()
    return jsonify({'message': 'Hint updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/hints/<int:hint_id>', methods=['DELETE'])
@login_required
def delete_hint(agent_id, hint_id):
    hint = AIHints.query.filter_by(id=hint_id, agent_id=agent_id).first_or_404()
    db.session.delete(hint)
    db.session.commit()
    return jsonify({'message': 'Hint deleted successfully'}), 200

@app.route('/agents/<int:agent_id>/pronounce', methods=['GET'])
@login_required
def pronounce_page(agent_id):
    return render_template('pronounce.html', user=current_user, agent_id=agent_id)

# API routes for pronounce
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/pronounce', methods=['GET'])
@login_required
def list_pronounce(agent_id):
    pronounces = AIPronounce.query.filter_by(agent_id=agent_id).all()
    return jsonify([{
        'id': p.id,
        'replace_this': p.replace_this,
        'replace_with': p.replace_with,
        'ignore_case': p.ignore_case,
        'created': p.created
    } for p in pronounces]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/pronounce/<int:pronounce_id>', methods=['GET'])
@login_required
def get_pronounce(agent_id, pronounce_id):
    pronounce = AIPronounce.query.filter_by(id=pronounce_id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': pronounce.id,
        'replace_this': pronounce.replace_this,
        'replace_with': pronounce.replace_with,
        'ignore_case': pronounce.ignore_case,
        'created': pronounce.created
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/pronounce', methods=['POST'])
@login_required
def create_pronounce(agent_id):
    data = request.get_json()
    new_pronounce = AIPronounce(
        replace_this=data['replace_this'],
        replace_with=data['replace_with'],
        ignore_case=data.get('ignore_case', False),
        agent_id=agent_id
    )
    db.session.add(new_pronounce)
    db.session.commit()
    return jsonify({
        'message': 'Pronounce entry created successfully',
        'id': new_pronounce.id
    }), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/pronounce/<int:pronounce_id>', methods=['PUT'])
@login_required
def update_pronounce(agent_id, pronounce_id):
    pronounce = AIPronounce.query.filter_by(id=pronounce_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    
    pronounce.replace_this = data.get('replace_this', pronounce.replace_this)
    pronounce.replace_with = data.get('replace_with', pronounce.replace_with)
    pronounce.ignore_case = data.get('ignore_case', pronounce.ignore_case)
    
    db.session.commit()
    return jsonify({'message': 'Pronounce entry updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/pronounce/<int:pronounce_id>', methods=['DELETE'])
@login_required
def delete_pronounce(agent_id, pronounce_id):
    pronounce = AIPronounce.query.filter_by(id=pronounce_id, agent_id=agent_id).first_or_404()
    db.session.delete(pronounce)
    db.session.commit()
    return jsonify({'message': 'Pronounce entry deleted successfully'}), 200

# API routes for SignalWire parameters
@app.route(f'{API_PREFIX}/signalwire', methods=['GET'])
@login_required
def list_signalwire_params():
    params = AISignalWireParams.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': param.id,
        'name': param.name,
        'value': param.value,
        'created': param.created
    } for param in params]), 200

@app.route(f'{API_PREFIX}/signalwire/<int:param_id>', methods=['GET'])
@login_required
def get_signalwire_param_by_id(param_id):
    param = AISignalWireParams.query.filter_by(id=param_id, user_id=current_user.id).first_or_404()
    return jsonify({
        'id': param.id,
        'name': param.name,
        'value': param.value,
        'created': param.created
    }), 200

@app.route(f'{API_PREFIX}/signalwire', methods=['POST'])
@login_required
def create_signalwire_param():
    data = request.get_json()
    new_param = AISignalWireParams(
        name=data['name'],
        value=data['value'],
        user_id=current_user.id
    )
    db.session.add(new_param)
    db.session.commit()
    return jsonify({
        'message': 'SignalWire parameter created successfully',
        'id': new_param.id
    }), 201

@app.route(f'{API_PREFIX}/signalwire/<int:param_id>', methods=['PUT'])
@login_required
def update_signalwire_param(param_id):
    param = AISignalWireParams.query.filter_by(id=param_id, user_id=current_user.id).first_or_404()
    data = request.get_json()
    
    param.name = data.get('name', param.name)
    param.value = data.get('value', param.value)
    
    db.session.commit()
    return jsonify({'message': 'SignalWire parameter updated successfully'}), 200

@app.route(f'{API_PREFIX}/signalwire/<int:param_id>', methods=['DELETE'])
@login_required
def delete_signalwire_param(param_id):
    param = AISignalWireParams.query.filter_by(id=param_id, user_id=current_user.id).first_or_404()
    db.session.delete(param)
    db.session.commit()
    return jsonify({'message': 'SignalWire parameter deleted successfully'}), 200

@app.route('/signalwire', methods=['GET'])
@login_required
def signalwire_page():
    if request.headers.get('Accept') == 'application/json':
        params = AISignalWireParams.query.filter_by(user_id=current_user.id).all()
        return jsonify([{
            'id': param.id,
            'name': param.name,
            'value': param.value,
            'created': param.created
        } for param in params]), 200
    return render_template('signalwire.html', user=current_user)

@app.route('/agents/<int:agent_id>/prompt', methods=['GET'])
@login_required
def prompt_page(agent_id):
    return render_template('prompt.html', user=current_user, agent_id=agent_id)

# API routes for prompts
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/prompt', methods=['GET'])
@login_required
def list_prompts(agent_id):
    prompts = AIPrompt.query.filter_by(agent_id=agent_id).all()
    return jsonify([{
        'id': prompt.id,
        'agent_id': prompt.agent_id,
        'prompt_type': prompt.prompt_type,
        'prompt_text': prompt.prompt_text,
        'top_p': prompt.top_p,
        'temperature': prompt.temperature,
        'max_tokens': prompt.max_tokens,
        'confidence': prompt.confidence,
        'frequency_penalty': prompt.frequency_penalty,
        'presence_penalty': prompt.presence_penalty,
        'created': prompt.created
    } for prompt in prompts]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/prompt/<int:prompt_id>', methods=['GET'])
@login_required
def get_prompt(agent_id, prompt_id):
    prompt = AIPrompt.query.filter_by(id=prompt_id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': prompt.id,
        'prompt_type': prompt.prompt_type,
        'prompt_text': prompt.prompt_text,
        'top_p': prompt.top_p,
        'temperature': prompt.temperature,
        'max_tokens': prompt.max_tokens,
        'confidence': prompt.confidence,
        'frequency_penalty': prompt.frequency_penalty,
        'presence_penalty': prompt.presence_penalty,
        'created': prompt.created
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/prompt', methods=['POST'])
@login_required
def create_prompt(agent_id):
    data = request.get_json()
    
    float_fields = ['top_p', 'temperature', 'confidence', 'frequency_penalty', 'presence_penalty']
    for field in float_fields:
        if field in data and data[field] == '':
            data[field] = None

    if 'prompt_text' in data:
        data['prompt_text'] = data['prompt_text'].encode('ascii', 'ignore').decode('ascii')

    if 'max_tokens' in data and data['max_tokens'] == '':
        data['max_tokens'] = None

    new_prompt = AIPrompt(
        agent_id=agent_id,
        prompt_type=data['prompt_type'],
        prompt_text=data['prompt_text'],
        top_p=data['top_p'],
        temperature=data['temperature'],
        max_tokens=data['max_tokens'],
        confidence=data['confidence'],
        frequency_penalty=data['frequency_penalty'],
        presence_penalty=data['presence_penalty']
    )
    
    db.session.add(new_prompt)
    db.session.commit()
    
    return jsonify({
        'message': 'Prompt created successfully',
        'id': new_prompt.id
    }), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/prompt/<int:prompt_id>', methods=['PUT'])
@login_required
def update_prompt(agent_id, prompt_id):
    prompt = AIPrompt.query.filter_by(id=prompt_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    
    # Convert empty strings to None for float fields
    float_fields = ['top_p', 'temperature', 'confidence', 'frequency_penalty', 'presence_penalty']
    for field in float_fields:
        if field in data:
            prompt.__setattr__(field, None if data[field] == '' else data[field])
            
    # Convert empty string to None for integer field
    if 'max_tokens' in data:
        prompt.max_tokens = None if data['max_tokens'] == '' else data['max_tokens']
    
    # Update other fields
    if 'prompt_type' in data:
        prompt.prompt_type = data['prompt_type']
    if 'prompt_text' in data:
        prompt.prompt_text = data['prompt_text']
    
    db.session.commit()
    return jsonify({'message': 'Prompt updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/prompt/<int:prompt_id>', methods=['PATCH'])
@login_required
def patch_prompt(agent_id, prompt_id):
    prompt = AIPrompt.query.filter_by(id=prompt_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    
    # Convert empty strings to None for float fields
    float_fields = ['top_p', 'temperature', 'confidence', 'frequency_penalty', 'presence_penalty']
    for field in float_fields:
        if field in data:
            value = None if data[field] == '' else data[field]
            if value is not None:
                setattr(prompt, field, value)
    
    # Convert empty string to None for integer field
    if 'max_tokens' in data:
        value = None if data['max_tokens'] == '' else data['max_tokens']
        if value is not None:
            prompt.max_tokens = value
    
    # Update other fields if present
    if 'prompt_type' in data:
        prompt.prompt_type = data['prompt_type']
    if 'prompt_text' in data:
        prompt.prompt_text = data['prompt_text']
    
    db.session.commit()
    return jsonify({'message': 'Prompt updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/prompt/<int:prompt_id>', methods=['DELETE'])
@login_required
def delete_prompt_api(agent_id, prompt_id):
    prompt = AIPrompt.query.filter_by(id=prompt_id, agent_id=agent_id).first_or_404()
    db.session.delete(prompt)
    db.session.commit()
    return jsonify({'message': 'Prompt deleted successfully'}), 200

@app.route('/agents/<int:agent_id>/context', methods=['GET'])
@login_required
def context_page(agent_id):
    return render_template('contexts.html', user=current_user, agent_id=agent_id)

# API routes for contexts
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context', methods=['GET'])
@login_required
def list_contexts(agent_id):
    contexts = AIContext.query.filter_by(agent_id=agent_id).all()
    return jsonify([context.to_dict() for context in contexts]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>', methods=['GET'])
@login_required
def get_context(agent_id, context_id):
    context = AIContext.query.filter_by(id=context_id, agent_id=agent_id).first_or_404()
    return jsonify(context.to_dict()), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context', methods=['POST'])
@login_required
def create_context(agent_id):
    data = request.get_json()
    new_context = AIContext(
        agent_id=agent_id,
        context_name=data['context_name']
    )
    db.session.add(new_context)
    db.session.commit()
    return jsonify({
        'message': 'Context created successfully',
        'id': new_context.id,
        'context': new_context.to_dict()
    }), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>', methods=['PUT'])
@login_required
def update_context(agent_id, context_id):
    context = AIContext.query.filter_by(id=context_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    
    context.context_name = data['context_name']
    
    db.session.commit()
    return jsonify({
        'message': 'Context updated successfully',
        'context': context.to_dict()
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>', methods=['PATCH'])
@login_required
def patch_context_api(agent_id, context_id):
    context = AIContext.query.filter_by(id=context_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    
    if 'context_name' in data:
        context.context_name = data['context_name']
    
    db.session.commit()
    return jsonify({
        'message': 'Context updated successfully',
        'context': context.to_dict()
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>', methods=['DELETE'])
@login_required
def delete_context(agent_id, context_id):
    context = AIContext.query.filter_by(id=context_id, agent_id=agent_id).first_or_404()
    db.session.delete(context)
    db.session.commit()
    return jsonify({'message': 'Context deleted successfully'}), 200

# API routes for steps within contexts
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>/steps', methods=['GET'])
@login_required
def list_context_steps(agent_id, context_id):
    steps = db.session.query(AISteps, AIContext).join(AIContext, AISteps.context_id == AIContext.id).filter(
        AISteps.context_id == context_id, AISteps.agent_id == agent_id).all()
    return jsonify([{'step': step.to_dict(), 'user_id': context.agent_id} for step, context in steps]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>/steps', methods=['POST'])
@login_required
def create_context_step(agent_id, context_id):
    data = request.get_json()
    new_step = AISteps(
        agent_id=agent_id,
        context_id=context_id,
        name=data['name'],
        text=data['text'],
        step_criteria=data.get('step_criteria'),
        valid_steps=data.get('valid_steps', []),
        valid_contexts=data.get('valid_contexts', []),
        end=data.get('end', False),
        functions=data.get('functions', []),
        skip_user_turn=data.get('skip_user_turn', False)
    )
    db.session.add(new_step)
    db.session.commit()
    return jsonify({
        'message': 'Step created successfully',
        'id': new_step.id,
        'step': new_step.to_dict()
    }), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>/steps/<int:step_id>', methods=['GET'])
@login_required
def get_context_step(agent_id, context_id, step_id):
    step = AISteps.query.filter_by(id=step_id, context_id=context_id, agent_id=agent_id).first_or_404()
    return jsonify(step.to_dict()), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>/steps/<int:step_id>', methods=['PUT'])
@login_required
def update_context_step(agent_id, context_id, step_id):
    step = AISteps.query.join(AIContext).join(AIAgent).filter(
        AISteps.id == step_id,
        AIContext.id == context_id,
        AIAgent.id == agent_id
    ).first_or_404()
    
    data = request.get_json()
    
    if 'name' in data:
        step.name = data['name']
    if 'text' in data:
        step.text = data['text']
    if 'step_criteria' in data:
        step.step_criteria = data.get('step_criteria')
    if 'valid_steps' in data:
        step.valid_steps = data.get('valid_steps', [])
    if 'valid_contexts' in data:
        step.valid_contexts = data.get('valid_contexts', [])
    if 'end' in data:
        step.end = data.get('end', False)
    if 'functions' in data:
        step.functions = data.get('functions', [])
    if 'skip_user_turn' in data:
        step.skip_user_turn = data.get('skip_user_turn', False)
    
    db.session.commit()
    return jsonify({
        'message': 'Step updated successfully',
        'step': step.to_dict()
    }), 200
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>/steps/<int:step_id>', methods=['PATCH'])
@login_required
def patch_context_step(agent_id, context_id, step_id):
    step = AISteps.query.filter_by(id=step_id, context_id=context_id).first_or_404()
    data = request.get_json()
    
    if 'name' in data:
        step.name = data['name']
    if 'text' in data:
        step.text = data['text']
    if 'step_criteria' in data:
        step.step_criteria = data['step_criteria']
    if 'valid_steps' in data:
        step.valid_steps = data['valid_steps']
    if 'valid_contexts' in data:
        step.valid_contexts = data['valid_contexts']
    if 'end' in data:
        step.end = data['end']
    if 'functions' in data:
        step.functions = data['functions']
    if 'skip_user_turn' in data:
        step.skip_user_turn = data['skip_user_turn']
    
    db.session.commit()
    return jsonify({
        'message': 'Step updated successfully',
        'step': step.to_dict()
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/context/<int:context_id>/steps/<int:step_id>', methods=['DELETE'])
@login_required
def delete_context_step(agent_id, context_id, step_id):
    step = AISteps.query.filter_by(id=step_id, context_id=context_id).first_or_404()
    db.session.delete(step)
    db.session.commit()
    return jsonify({'message': 'Step deleted successfully'}), 200

@app.route('/agents/<int:agent_id>/language', methods=['GET'])
@login_required
def language_page(agent_id):
    return render_template('language.html', user=current_user, agent_id=agent_id)

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/language/<int:id>', methods=['PATCH'])
@login_required
def patch_language(agent_id, id):
    language_entry = AILanguage.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        language_entry.name = data.get('name', language_entry.name)
        language_entry.code = data.get('code', language_entry.code)
        language_entry.voice = data.get('voice', language_entry.voice)
        language_entry.speech_fillers = data.get('speech_fillers', language_entry.speech_fillers)
        language_entry.function_fillers = data.get('function_fillers', language_entry.function_fillers)
        language_entry.language_order = data.get('language_order', language_entry.language_order)

        db.session.commit()
        return jsonify({'message': 'Language entry updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error updating language entry', 'error': str(e)}), 500

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/language/<int:id>', methods=['PUT'])
@login_required
def update_language(agent_id, id):
    data = request.get_json()
    language_entry = AILanguage.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    
    language_entry.name = data.get('name', language_entry.name)
    language_entry.code = data.get('code', language_entry.code)
    language_entry.voice = data.get('voice', language_entry.voice)
    language_entry.speech_fillers = data.get('speech_fillers', language_entry.speech_fillers)
    language_entry.function_fillers = data.get('function_fillers', language_entry.function_fillers)
    language_entry.language_order = data.get('language_order', language_entry.language_order)
    
    db.session.commit()
    return jsonify({'message': 'Language entry updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/language/<int:id>', methods=['GET'])
@login_required
def get_language_by_id(agent_id, id):
    language_entry = AILanguage.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': language_entry.id,
        'name': language_entry.name,
        'code': language_entry.code,
        'voice': language_entry.voice,
        'speech_fillers': language_entry.speech_fillers,
        'function_fillers': language_entry.function_fillers,
        'language_order': language_entry.language_order
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/language/<int:id>', methods=['DELETE'])
@login_required
def delete_language(agent_id, id):
    language_entry = AILanguage.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    db.session.delete(language_entry)
    db.session.commit()
    return jsonify({'message': 'Language entry deleted successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/language', methods=['GET'])
@login_required
def get_languages(agent_id):
    if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
        languages = AILanguage.query.filter_by(agent_id=agent_id).order_by(AILanguage.language_order.asc()).all()
        language_list = [{
            'id': l.id,
            'name': l.name,
            'code': l.code,
            'voice': l.voice,
            'speech_fillers': l.speech_fillers,
            'function_fillers': l.function_fillers,
            'language_order': l.language_order
        } for l in languages]
        return jsonify(language_list), 200
    else:
        return render_template('language.html', user=current_user)

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/language', methods=['POST'])
@login_required
def create_language(agent_id):
    data = request.get_json()
    new_language = AILanguage(
        name=data['name'],
        code=data['code'],
        voice=data['voice'],
        speech_fillers=data['speech_fillers'],
        function_fillers=data['function_fillers'],
        language_order=data.get('language_order', 0),
        agent_id=agent_id
    )
    db.session.add(new_language)
    db.session.commit()
    return jsonify({'message': 'Language entry created successfully'}), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/language', methods=['PUT'])
@login_required
def update_language_entry(agent_id):
    data = request.get_json()
    language_entry = AILanguage.query.filter_by(id=data['id'], agent_id=agent_id).first_or_404()
    
    language_entry.name = data.get('name', language_entry.name)
    language_entry.code = data.get('code', language_entry.code)
    language_entry.voice = data.get('voice', language_entry.voice)
    language_entry.speech_fillers = data.get('speech_fillers', language_entry.speech_fillers)
    language_entry.function_fillers = data.get('function_fillers', language_entry.function_fillers)
    language_entry.language_order = data.get('language_order', language_entry.language_order)
    
    db.session.commit()
    return jsonify({'message': 'Language entry updated successfully'}), 200

@app.route('/agents/<int:agent_id>/conversation', methods=['GET'])
@login_required
def conversation_page(agent_id):
    return render_template('conversation.html', user=current_user, agent_id=agent_id)

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/conversation/<int:id>', methods=['GET'])
@login_required
def get_or_delete_conversation(agent_id, id):
    conversation = AIConversation.query.filter_by(id=id, agent_id=agent_id).first_or_404()

    next_conversation = AIConversation.query.filter(
        AIConversation.id > id,
        AIConversation.agent_id == agent_id
        ).order_by(AIConversation.id.asc()).first()
        
    prev_conversation = AIConversation.query.filter(
            AIConversation.id < id,
            AIConversation.agent_id == agent_id
        ).order_by(AIConversation.id.desc()).first()

    return jsonify({
        'id': conversation.id,
        'created': conversation.created,
        'data': conversation.data,
        'next': next_conversation.id if next_conversation else None,
        'prev': prev_conversation.id if prev_conversation else None
    }), 200


@app.route(f'{API_PREFIX}/agents/<int:agent_id>/conversation/<int:id>', methods=['DELETE'])
@login_required
def delete_conversation(agent_id, id):
    conversation = AIConversation.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    db.session.delete(conversation)
    db.session.commit()
    return jsonify({'message': 'Conversation deleted successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/conversation', methods=['GET', 'POST'])
@login_required
def conversation(agent_id):
    if request.method == 'GET':
        conversations = AIConversation.query.filter_by(agent_id=agent_id).all()
        conversation_list = [{
            'id': conv.id,
            'created': conv.created.isoformat(),
            'data': conv.data
        } for conv in conversations]
        return jsonify(conversation_list), 200
    elif request.method == 'POST':
        data = request.get_json()
        new_conversation = Conversation(
            title=data['title'],
            content=data['content'],
            agent_id=agent_id
        )
        db.session.add(new_conversation)
        db.session.commit()
        return jsonify({'message': 'Conversation created successfully'}), 201

@app.route('/agents/<int:agent_id>/parameters', methods=['GET'])
@login_required
def parameters_page(agent_id):
    return render_template('parameters.html', user=current_user, agent_id=agent_id)

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/parameters/<int:id>', methods=['PATCH'])
@login_required
def patch_parameter(agent_id, id):
    parameter = AIParams.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        parameter.name = data.get('name', parameter.name)
        parameter.value = data.get('value', parameter.value)

        db.session.commit()
        return jsonify({'message': 'Parameter updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error updating parameter', 'error': str(e)}), 500

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/parameters/<int:id>', methods=['PUT'])
@login_required
def update_parameter(agent_id, id):
    data = request.get_json()
    parameter = AIParams.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    
    parameter.name = data.get('name', parameter.name)
    parameter.value = data.get('value', parameter.value)
    
    db.session.commit()
    return jsonify({'message': 'Parameter updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/parameters/<int:id>', methods=['GET'])
@login_required
def get_parameter_by_id(agent_id, id):
    parameter = AIParams.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': parameter.id,
        'name': parameter.name,
        'value': parameter.value
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/parameters/<int:id>', methods=['DELETE'])
@login_required
def delete_parameter(agent_id, id):
    parameter = AIParams.query.filter_by(id=id, agent_id=agent_id).first_or_404()
    db.session.delete(parameter)
    db.session.commit()
    return jsonify({'message': 'Parameter deleted successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/parameters', methods=['GET'])
@login_required
def get_parameters(agent_id):
    parameters = AIParams.query.filter_by(agent_id=agent_id).all()
    parameter_list = [{
        'id': p.id,
        'name': p.name,
        'value': p.value
    } for p in parameters]
    return jsonify(parameter_list), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/parameters', methods=['POST'])
@login_required
def create_parameter(agent_id):
    data = request.get_json()
    new_parameter = AIParams(
        name=data['name'],
        value=data['value'],
        agent_id=agent_id
    )
    db.session.add(new_parameter)
    db.session.commit()
    return jsonify({'message': 'Parameter created successfully'}), 201

# API route for listing hooks
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/hooks', methods=['GET'])
@login_required
def list_hooks(agent_id):
    hooks = AIHooks.query.filter_by(agent_id=agent_id).all()
    hooks_list = [{
        'id': hook.id,
        'agent_id': hook.agent_id,
        'created': hook.created,
        'updated': hook.updated,
        'data': hook.data,
        'hook_type': hook.hook_type.name
    } for hook in hooks]
    return jsonify(hooks_list), 200

# API route for deleting all hooks
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/hooks', methods=['DELETE'])
@login_required
def delete_all_hooks(agent_id):
    hooks = AIHooks.query.filter_by(agent_id=agent_id).all()
    for hook in hooks:
        db.session.delete(hook)
    db.session.commit()
    return jsonify({'message': 'All hooks deleted successfully'}), 200

# Separate route for rendering hooks page
@app.route('/agents/<int:agent_id>/hooks', methods=['GET'])
@login_required
def hooks_page(agent_id):
    return render_template('hooks.html', user=current_user, agent_id=agent_id)

# API routes for SWML Requests
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/swmlrequests', methods=['GET'])
@login_required
def list_swmlrequests(agent_id):
    swml_requests = AISWMLRequest.query.filter_by(agent_id=agent_id).all()
    return jsonify([{
        'id': request.id,
        'name': request.name,
        'description': request.description,
        'created': request.created
    } for request in swml_requests]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/swmlrequests', methods=['DELETE'])
@login_required
def delete_swmlrequest(agent_id):
    swml_requests = AISWMLRequest.query.filter_by(agent_id=agent_id).all()
    for request in swml_requests:
        db.session.delete(request)
    db.session.commit()
    return jsonify({'message': 'SWML Requests deleted successfully'}), 200

# Route for rendering the SWML Requests page
@app.route('/agents/<int:agent_id>/swmlrequests', methods=['GET'])
@login_required
def swmlrequests_page(agent_id):
    return render_template('swmlrequests.html', user=current_user, agent_id=agent_id)

# API routes for AI Features
@app.route(f'{API_PREFIX}/agents/<int:agent_id>/features', methods=['GET'])
@login_required
def list_aifeatures(agent_id):
    features = AIFeatures.query.filter_by(agent_id=agent_id).all()
    return jsonify([{
        'id': feature.id,
        'name': feature.name,
        'value': feature.value,
        'enabled': feature.enabled,
        'data': feature.data,
        'created': feature.created
    } for feature in features]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/features/<int:feature_id>', methods=['GET'])
@login_required
def get_aifeature(agent_id, feature_id):
    feature = AIFeatures.query.filter_by(id=feature_id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': feature.id,
        'name': feature.name,
        'value': feature.value,
        'enabled': feature.enabled,
        'data': feature.data,
        'created': feature.created
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/features', methods=['POST'])
@login_required
def create_aifeature(agent_id):
    data = request.get_json()
    new_feature = AIFeatures(
        name=data['name'],
        value=data['value'],
        enabled=data['enabled'],
        data=data.get('data'),
        agent_id=agent_id
    )
    db.session.add(new_feature)
    db.session.commit()
    return jsonify({'message': 'Feature added successfully', 'id': new_feature.id}), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/features/<int:feature_id>', methods=['PUT'])
@login_required
def update_aifeature(agent_id, feature_id):
    feature = AIFeatures.query.filter_by(id=feature_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    
    feature.name = data.get('name', feature.name)
    feature.value = data.get('value', feature.value)
    feature.enabled = data.get('enabled', feature.enabled)
    feature.data = data.get('data', feature.data)
    
    db.session.commit()
    return jsonify({'message': 'Feature updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/features/<int:feature_id>', methods=['DELETE'])
@login_required
def delete_aifeature(agent_id, feature_id):
    feature = AIFeatures.query.filter_by(id=feature_id, agent_id=agent_id).first_or_404()
    db.session.delete(feature)
    db.session.commit()
    return jsonify({'message': 'Feature deleted successfully'}), 200

# Route for rendering the AI Features page
@app.route('/agents/<int:agent_id>/features', methods=['GET'])
@login_required
def aifeatures_page(agent_id):
    return render_template('features.html', user=current_user, agent_id=agent_id)

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions', methods=['GET'])
@login_required
def list_functions(agent_id):
    functions = AIFunctions.query.filter_by(agent_id=agent_id).all()
    functions_data = [{
        'id': function.id,
        'name': function.name,
        'purpose': function.purpose,
        'active': function.active
    } for function in functions]
    return jsonify(functions_data), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/<int:function_id>', methods=['GET'])
@login_required
def get_function(agent_id, function_id):
    function = AIFunctions.query.filter_by(id=function_id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': function.id,
        'name': function.name,
        'purpose': function.purpose,
        'web_hook_url': function.web_hook_url,
        'wait_file': function.wait_file,
        'wait_file_loops': function.wait_file_loops,
        'fillers': function.fillers,
        'meta_data': function.meta_data,
        'meta_data_token': function.meta_data_token,
        'active': function.active
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/names', methods=['GET'])
@login_required
def get_function_names(agent_id):
    functions = AIFunctions.query.filter_by(agent_id=agent_id).all()
    function_names = [function.name for function in functions]

    return jsonify(function_names), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions', methods=['POST'])
@login_required
def create_function(agent_id):
    data = request.get_json()
    new_function = AIFunctions(
        agent_id=agent_id,
        name=data['name'],
        purpose=data['purpose'],
        web_hook_url=data.get('web_hook_url'),
        wait_file=data.get('wait_file'),
        wait_file_loops=data.get('wait_file_loops', 1),
        fillers=data.get('fillers'),
        meta_data=data.get('meta_data', {}),
        meta_data_token=data.get('meta_data_token'),
        active=data.get('active', True)
    )
    db.session.add(new_function)
    db.session.commit()
    return jsonify({'message': 'Function entry created successfully'}), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/<int:function_id>', methods=['PATCH'])
@login_required
def update_function(agent_id, function_id):
    function = AIFunctions.query.filter_by(id=function_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    function.purpose = data.get('purpose', function.purpose)
    function.web_hook_url = data.get('web_hook_url', function.web_hook_url)
    function.wait_file = data.get('wait_file', function.wait_file)
    function.wait_file_loops = data.get('wait_file_loops', function.wait_file_loops)
    function.fillers = data.get('fillers', function.fillers)
    function.meta_data = data.get('meta_data', function.meta_data)
    function.meta_data_token = data.get('meta_data_token', function.meta_data_token)
    function.active = data.get('active', function.active)
    db.session.commit()
    return jsonify({'message': 'Function updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/<int:function_id>', methods=['DELETE'])
@login_required
def delete_function(agent_id, function_id):
    function = AIFunctions.query.filter_by(id=function_id, agent_id=agent_id).first_or_404()
    db.session.delete(function)
    db.session.commit()
    return jsonify({'message': 'Function entry deleted successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/<int:function_id>/args', methods=['GET'])
@login_required
def list_function_args(agent_id, function_id):
    args = AIFunctionArgs.query.filter_by(function_id=function_id).all()
    args_data = [{
        'id': arg.id,
        'name': arg.name,
        'type': arg.type,
        'description': arg.description,
        'required': arg.required,
        'enum': arg.enum,
        'default': arg.default
    } for arg in args]
    return jsonify(args_data), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/<int:function_id>/args', methods=['POST'])
@login_required
def create_function_arg(agent_id, function_id):
    print(f"Creating argument for function {function_id}, agent_id: {agent_id}")
    data = request.get_json()
    new_arg = AIFunctionArgs(
        function_id=function_id,
        agent_id=agent_id,
        name=data['name'],
        type=data['type'],
        description=data.get('description'),
        required=data.get('required', False),
        enum=data.get('enum'),
        default=data.get('default')
    )
    db.session.add(new_arg)
    db.session.commit()
    return jsonify({'message': 'Argument created successfully'}), 201

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/<int:function_id>/args/<int:arg_id>', methods=['PATCH'])
@login_required
def update_function_arg(agent_id, function_id, arg_id):
    arg = AIFunctionArgs.query.filter_by(id=arg_id, function_id=function_id).first_or_404()
    data = request.get_json()
    arg.name = data.get('name', arg.name)
    arg.type = data.get('type', arg.type)
    arg.description = data.get('description', arg.description)
    arg.required = data.get('required', arg.required)
    arg.enum = data.get('enum', arg.enum)
    arg.default = data.get('default', arg.default)
    db.session.commit()
    return jsonify({'message': 'Argument updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/functions/<int:function_id>/args/<int:arg_id>', methods=['DELETE'])
@login_required
def delete_function_arg(agent_id, function_id, arg_id):
    arg = AIFunctionArgs.query.filter_by(agent_id=agent_id, id=arg_id, function_id=function_id).first_or_404()
    db.session.delete(arg)
    db.session.commit()
    return jsonify({'message': 'Argument deleted successfully'}), 200

@app.route('/agents/<int:agent_id>/functions', methods=['GET'])
@login_required
def functions_page(agent_id):
    return render_template('functions.html', user=current_user, agent_id=agent_id)


@app.route(f'{API_PREFIX}/agents/<int:agent_id>/includes', methods=['POST'])
@login_required
def create_or_update_include(agent_id):
    data = request.get_json()
    url = data.get('url').strip()
    functions = data.get('functions', [])
    get_swaig = data.get('get_remote_swaig', False)
    print(f"Creating or updating include for URL: {url}, functions: {functions}, get_swaig: {get_swaig}")

    if get_swaig:
        if not url:
            return jsonify({'error': 'URL parameter is required'}), 400
        print(f"Getting includes for URL: {url}")
        swaig_response = get_swaig_includes(url)
        print(f"SWAIG response: {swaig_response}")
        return jsonify(swaig_response), 200
    else:
        include_entry = AIIncludes.query.filter_by(url=url, agent_id=agent_id).first()

        if include_entry:
            include_entry.functions = functions
        else:
            include_entry = AIIncludes(url=url, functions=functions, agent_id=agent_id)
        db.session.add(include_entry)

    db.session.commit()
    return jsonify({'message': 'Include entry saved successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/includes', methods=['GET'])
@login_required
def get_includes_agent(agent_id):
    includes_entries = AIIncludes.query.filter_by(agent_id=agent_id).all()
    return jsonify([{
        'id': entry.id,
        'url': entry.url,
        'functions': entry.functions
    } for entry in includes_entries]), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/includes/<int:include_id>', methods=['GET'])
@login_required
def get_include_agent(agent_id, include_id):
    include_entry = AIIncludes.query.filter_by(id=include_id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': include_entry.id,
        'url': include_entry.url,
        'functions': include_entry.functions
    }), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/includes/<int:include_id>', methods=['PUT'])
@login_required
def update_include(agent_id, include_id):
    include_entry = AIIncludes.query.filter_by(id=include_id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    include_entry.url = data.get('url', include_entry.url)
    include_entry.functions = data.get('functions', include_entry.functions)
    db.session.commit()
    return jsonify({'message': 'Include updated successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/includes/<int:include_id>', methods=['DELETE'])
@login_required
def delete_include(agent_id, include_id):
    include_entry = AIIncludes.query.filter_by(id=include_id, agent_id=agent_id).first_or_404()
    db.session.delete(include_entry)
    db.session.commit()
    return jsonify({'message': 'Include deleted successfully'}), 200

@app.route(f'{API_PREFIX}/agents/<int:agent_id>/includes', methods=['POST'])
@login_required
def get_includes_post(agent_id):
    if request.headers.get('Accept') == 'application/json':
        url = request.get_json().get('url')
        if not url:
            return jsonify({'error': 'URL parameter is required'}), 400
        print(f"Getting includes for URL: {url}")
        swaig_response = get_swaig_includes(url)
        return jsonify(swaig_response), 200
    else:
        return jsonify({'error': 'Accept header must be application/json'}), 400

@app.route('/agents/<int:agent_id>/includes', methods=['GET'])
@login_required
def includes_page(agent_id):
    return render_template('includes.html', user=current_user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    socketio.run(app, host='0.0.0.0', port=5000, debug=app.config['DEBUG'])