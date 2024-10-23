import eventlet
eventlet.monkey_patch()
import os, jwt, base64, json, redis, yaml, requests, logging
from datetime import datetime, timedelta
from flask import Flask, flash, make_response, jsonify, redirect, render_template, request, url_for, g
from flask_socketio import SocketIO, join_room, leave_room, emit, disconnect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from urllib.parse import urlparse
from modules.signalwireml import SignalWireML
from modules.models import db, AIAgent, AIUser, AISignalWireParams, AIFeatures, AIFunctions, AIIncludes, AIConversation, AISWMLRequest, AIParams, AIFunctionArgs, AIPrompt, AIPronounce, AILanguage, AIHints, AIIncludes, AISWMLRequest, AIDebugLogs
from modules.swml_generator import generate_swml_response
from modules.utils import (
    generate_random_password, get_signal_wire_param, 
    extract_agent_id, setup_default_agent_and_params, create_admin_user,
    get_swaig_includes
)

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

load_dotenv()

app = Flask(__name__)
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['REDIS_URL'] = os.environ.get('REDIS_URL')
app.config['ACCESS_SECRET_KEY'] = os.environ.get('ACCESS_SECRET_KEY')
app.config['REFRESH_SECRET_KEY'] = os.environ.get('REFRESH_SECRET_KEY')
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024

db.init_app(app)

CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

redis_client = redis.from_url(app.config['REDIS_URL'])

app.static_folder = os.path.abspath('static')

login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    full_url = request.url
    parsed_url = urlparse(full_url)
    path_segments = parsed_url.path.split('/')
    agent_id = path_segments[-1]
    g.agent_id = agent_id
    user = AIUser.query.filter_by(username=username).first()
    if user:
        http_password = get_signal_wire_param(user.id, agent_id, 'HTTP_PASSWORD')
        if user.username == username and http_password == password:
            return user
    return None

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
    agent_id = request.cookies.get('selectedAgentId')
    if not agent_id:
        first_agent = AIAgent.query.filter_by(user_id=current_user.id).first()
        agent_id = first_agent.id if first_agent else None
    auth_user = current_user.username
    auth_pass = get_signal_wire_param(current_user.id, agent_id, 'HTTP_PASSWORD')

    swml_url = f"https://{auth_user}:{auth_pass}@{request.host}/swml/{current_user.id}/{agent_id}"
    yaml_url = f"https://{auth_user}:{auth_pass}@{request.host}/yaml/{current_user.id}/{agent_id}"
    debugwebhook_url = f"https://{auth_user}:{auth_pass}@{request.host}/debugwebhook/{current_user.id}/{agent_id}"

    number_of_requests = AISWMLRequest.query.filter_by(user_id=current_user.id, agent_id=agent_id).count()
    number_of_conversations = AIConversation.query.filter_by(user_id=current_user.id, agent_id=agent_id).count()

    return render_template('dashboard.html', user=current_user, swml_url=swml_url, yaml_url=yaml_url, debugwebhook_url=debugwebhook_url, number_of_requests=number_of_requests, number_of_conversations=number_of_conversations)

@app.route('/swmlrequests/<int:agent_id>', methods=['DELETE'])
@login_required
def delete_swmlrequests(agent_id):
    AISWMLRequest.query.filter_by(user_id=current_user.id, agent_id=agent_id).delete()
    db.session.commit()
    return jsonify({'message': 'All SWML requests for the agent deleted successfully'}), 200

@app.route('/swmlrequests', methods=['GET'])
@login_required
def swmlrequests():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.headers.get('Accept') == 'application/json':
        swml_requests = AISWMLRequest.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()

        swml_requests_data = [{
            'id': req.id,
            'created': req.created,
            'request': req.request,
            'response': req.response,
            'ip_address': req.ip_address
        } for req in swml_requests]
        return jsonify(swml_requests_data), 200

    else:
        return render_template('swmlrequests.html', user=current_user)

@app.route('/dashboard/completed', methods=['GET'])
@login_required
def dashboard_completed():
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    hourly_counts = {start_time + timedelta(hours=i): 0 for i in range(24)}

    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    completed_conversations = db.session.query(
        db.func.date_trunc('hour', AIConversation.created).label('hour'),
        db.func.count(AIConversation.id).label('count')
    ).filter(
        AIConversation.created >= start_time,
        AIConversation.created <= end_time,
        AIConversation.user_id == current_user.id,
        AIConversation.agent_id == selected_agent_id
    ).group_by('hour').order_by('hour').all()

    for hour, count in completed_conversations:
        hourly_counts[hour] = count

    labels = [hour.strftime('%H:00') for hour in hourly_counts.keys()]
    counts = [count for count in hourly_counts.values()]

    return jsonify({'labels': labels, 'counts': counts}), 200

@app.route('/functions', methods=['GET', 'POST'])
@login_required
def functions():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            functions = AIFunctions.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
            function_list = [{
                'id': f.id,
                'name': f.name,
                'purpose': f.purpose,
                'active': f.active,
                'web_hook_url': f.web_hook_url,
                'wait_file': f.wait_file,
                'wait_file_loops': f.wait_file_loops,
                'fillers': f.fillers,
                'meta_data': f.meta_data,
                'meta_data_token': f.meta_data_token,
                'created': f.created.isoformat()
            } for f in functions]
            return jsonify(function_list), 200
        else:
            return render_template('functions.html', user=current_user)
    elif request.method == 'POST':
        try:
            data = request.get_json()
            new_function = AIFunctions(
                name=data['name'],
                purpose=data['purpose'],
                user_id=current_user.id,
                agent_id=selected_agent_id,
                web_hook_url=data.get('web_hook_url'),
                wait_file=data.get('wait_file'),
                wait_file_loops=data.get('wait_file_loops', 0) or 0,
                fillers=data.get('fillers'),
                meta_data=data.get('meta_data'),
                meta_data_token=data.get('meta_data_token'),
                active=data.get('active', True)
            )
            db.session.add(new_function)
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            if 'Key (user_id, agent_id, name)' in str(e.orig):
                return jsonify({'message': 'Function name must be unique for the user and agent'}), 200
            else:
                return jsonify({'message': 'An error occurred while creating the function'}), 500
        
        try:
            # Save the arguments associated with the function
            arguments = data.get('arguments', [])
            for arg in arguments:
                new_argument = AIFunctionArgs(
                    function_id=new_function.id,
                    user_id=current_user.id,  # Ensure user_id is set
                    agent_id=selected_agent_id,  # Ensure agent_id is set
                    name=arg['name'],
                    type=arg['type'],
                    description=arg['description'],
                    required=arg['required'],
                    enum=arg.get('enum'),
                    default=arg.get('default')
                )
                db.session.add(new_argument)
            
            db.session.commit()
            return jsonify({'message': 'Function entry created successfully'}), 200
        except IntegrityError as e:
            db.session.rollback()
            if 'Key (user_id, function_id, name)' in str(e.orig):
                db.session.delete(new_function)
                db.session.commit()
                return jsonify({'message': 'Arguments must be unique'}), 200
            else:
                return jsonify({'message': 'An error occurred while adding arguments'}), 500

@app.route('/functions/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_function(id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    function_entry = AIFunctions.query.filter_by(id=id, agent_id=selected_agent_id).first_or_404()
    
    if function_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'GET':
        return jsonify({
            'id': function_entry.id,
            'name': function_entry.name,
            'purpose': function_entry.purpose,
            'active': function_entry.active,
            'web_hook_url': function_entry.web_hook_url,
            'wait_file': function_entry.wait_file,
            'wait_file_loops': function_entry.wait_file_loops,
            'fillers': function_entry.fillers,
            'meta_data': function_entry.meta_data,
            'meta_data_token': function_entry.meta_data_token
        }), 200

    elif request.method == 'PUT':
        data = request.get_json()
        function_entry.name = data.get('name', function_entry.name)
        function_entry.purpose = data.get('purpose', function_entry.purpose)
        function_entry.active = data.get('active', function_entry.active)
        function_entry.web_hook_url = data.get('web_hook_url', function_entry.web_hook_url)
        function_entry.wait_file = data.get('wait_file', function_entry.wait_file)
        function_entry.wait_file_loops = data.get('wait_file_loops', function_entry.wait_file_loops) or 0
        function_entry.fillers = data.get('fillers', function_entry.fillers)
        function_entry.meta_data = data.get('meta_data', function_entry.meta_data)
        function_entry.meta_data_token = data.get('meta_data_token', function_entry.meta_data_token)
        db.session.commit()
        return jsonify({'message': 'Function entry updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(function_entry)
        db.session.commit()
        return jsonify({'message': 'Function entry deleted successfully'}), 200

@app.route('/functions/<int:function_id>/args', methods=['POST'])
@login_required
def add_function_arg(function_id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    function_entry = AIFunctions.query.filter_by(id=function_id, agent_id=selected_agent_id).first_or_404()
    
    if function_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    new_arg = AIFunctionArgs(
        function_id=function_id,
        user_id=current_user.id,
        agent_id=selected_agent_id,
        name=data['name'],
        type=data['type'],
        required=data.get('required', False),
        enum=data.get('enum'),
        default=data.get('default')
    )
    db.session.add(new_arg)
    db.session.commit()
    return jsonify({'message': 'Function argument added successfully'}), 201

@app.route('/functions/<int:function_id>/args', methods=['GET'])
@login_required
def get_function_args(function_id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    function_entry = AIFunctions.query.filter_by(id=function_id, agent_id=selected_agent_id).first_or_404()
    
    if function_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403
    
    args = AIFunctionArgs.query.filter_by(function_id=function_id, agent_id=selected_agent_id).order_by(AIFunctionArgs.name.asc()).all()

    return jsonify([{
        'id': arg.id,
        'name': arg.name,
        'type': arg.type,
        'description': arg.description,
        'required': arg.required,
        'enum': arg.enum,
        'default': arg.default
    } for arg in args]), 200

@app.route('/functions/<int:function_id>/args/<int:arg_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_function_arg(function_id, arg_id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    function_entry = AIFunctions.query.filter_by(id=function_id, agent_id=selected_agent_id).first_or_404()
    arg_entry = AIFunctionArgs.query.filter_by(id=arg_id, agent_id=selected_agent_id).first_or_404()
    
    if function_entry.user_id != current_user.id or arg_entry.function_id != function_id:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'PUT':
        data = request.get_json()
        arg_entry.name = data.get('name', arg_entry.name)
        arg_entry.type = data.get('type', arg_entry.type)
        arg_entry.description = data.get('description', arg_entry.description)
        arg_entry.required = data.get('required', arg_entry.required)
        arg_entry.active = data.get('active', arg_entry.active)
        arg_entry.enum = data.get('enum', arg_entry.enum)
        arg_entry.default = data.get('default', arg_entry.default)
        db.session.commit()
        return jsonify({'message': 'Function argument updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(arg_entry)
        db.session.commit()
        return jsonify({'message': 'Function argument deleted successfully'}), 200

@app.route('/conversation/view/<int:id>', methods=['GET'])
@login_required
def view_conversation(id):
    conversation = AIConversation.query.get_or_404(id)
    
    if conversation.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    return render_template('conversation.html', id=id, user=current_user)

@app.route('/conversations')
@login_required
def conversations():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            conversations = AIConversation.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
            conversation_list = [{
                'id': conv.id,
                'created': conv.created.isoformat(),
                'data': conv.data
            } for conv in conversations]
            return jsonify(conversation_list), 200
        else:
            return render_template('conversations.html', user=current_user)

@app.route('/conversations/<int:id>', methods=['GET', 'DELETE'])
@login_required
def get_or_delete_conversation(id):
    conversation = AIConversation.query.get_or_404(id)
    
    if conversation.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'GET':
        next_conversation = AIConversation.query.filter(AIConversation.user_id == current_user.id, AIConversation.id > id).order_by(AIConversation.id.asc()).first()
        prev_conversation = AIConversation.query.filter(AIConversation.user_id == current_user.id, AIConversation.id < id).order_by(AIConversation.id.desc()).first()

        return jsonify({
            'id': conversation.id,
            'created': conversation.created,
            'data': conversation.data,
            'next': next_conversation.id if next_conversation else None,
            'prev': prev_conversation.id if prev_conversation else None
        }), 200
    elif request.method == 'DELETE':
        if conversation.user_id == current_user.id:
            db.session.delete(conversation)
            db.session.commit()
            return jsonify({'message': 'Conversation deleted successfully'}), 200
        else:
            return jsonify({'message': 'Permission denied'}), 403

@app.route('/hints', methods=['GET', 'POST'])
@login_required
def hints():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            hints = AIHints.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
            return jsonify([{
                'id': hint.id,
                'hint': hint.hint,
                'created': hint.created
            } for hint in hints]), 200
        else:
            return render_template('hints.html', user=current_user)
    elif request.method == 'POST':
        data = request.get_json()
        new_hint = AIHints(
            hint=data['hint'],
            user_id=current_user.id,
            agent_id=selected_agent_id
        )
        db.session.add(new_hint)
        db.session.commit()
        return jsonify({'message': 'Hint entry created successfully'}), 201

@app.route('/hints/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def hint(id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    hint_entry = AIHints.query.filter_by(id=id, agent_id=selected_agent_id).first_or_404()
    
    if hint_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'GET':
        return jsonify({
            'id': hint_entry.id,
            'hint': hint_entry.hint
        }), 200
    elif request.method == 'PUT':
        data = request.get_json()
        hint_entry.hint = data.get('hint', hint_entry.hint)
        db.session.commit()
        return jsonify({'message': 'Hint entry updated successfully'}), 200
    elif request.method == 'DELETE':
        db.session.delete(hint_entry)
        db.session.commit()
        return jsonify({'message': 'Hint entry deleted successfully'}), 200

@app.route('/signalwire/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_signalwire(id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    signalwire_entry = AISignalWireParams.query.filter_by(id=id, agent_id=selected_agent_id).first_or_404()
    
    if signalwire_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'GET':
        return jsonify({
            'id': signalwire_entry.id,
            'name': signalwire_entry.name,
            'value': signalwire_entry.value
        }), 200

    elif request.method == 'PUT':
        data = request.get_json()
        signalwire_entry.value = data.get('value', signalwire_entry.value)
        db.session.commit()
        return jsonify({'message': 'SignalWire entry updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(signalwire_entry)
        db.session.commit()
        return jsonify({'message': 'SignalWire entry deleted successfully'}), 200

@app.route('/signalwire', methods=['GET', 'POST'])
@login_required
def signalwire():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            params = AISignalWireParams.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
            return jsonify([{
                'id': param.id,
                'name': param.name,
                'value': param.value,
                'created': param.created
            } for param in params]), 200
        else:
            return render_template('signalwire.html', user=current_user)
    elif request.method == 'POST':
        data = request.get_json()
        new_params = AISignalWireParams(
            name=data['name'],
            value=data['value'],
            user_id=current_user.id,
            agent_id=selected_agent_id
        )
        db.session.add(new_params)
        db.session.commit()
        return jsonify({'message': 'SignalWire entry created successfully'}), 201

@app.route('/params/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_params(id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    params_entry = AIParams.query.filter_by(id=id, agent_id=selected_agent_id).first_or_404()
    
    if params_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'GET':
        return jsonify({
            'id': params_entry.id,
            'name': params_entry.name,
            'value': params_entry.value
        }), 200

    elif request.method == 'PUT':
        data = request.get_json()
        params_entry.value = data.get('value', params_entry.value)
        db.session.commit()
        return jsonify({'message': 'Params entry updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(params_entry)
        db.session.commit()
        return jsonify({'message': 'Params entry deleted successfully'}), 200

@app.route('/params', methods=['GET', 'POST'])
@login_required
def params():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            params = AIParams.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
            return jsonify([{
                'id': param.id,
                'name': param.name,
                'value': param.value,
                'created': param.created
            } for param in params]), 200
        else:
            return render_template('parameters.html', user=current_user)
    elif request.method == 'POST':
        data = request.get_json()
        new_params = AIParams(
            name=data['name'],
            value=data['value'],
            user_id=current_user.id,
            agent_id=selected_agent_id
        )
        db.session.add(new_params)
        db.session.commit()
        return jsonify({'message': 'Params entry created successfully'}), 201

@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.json.get('refresh_token')
    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing'}), 400

    try:
        data = jwt.decode(refresh_token, app.config['REFRESH_SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']

        new_access_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(minutes=60)
        }, app.config['ACCESS_SECRET_KEY'], algorithm='HS256')

        return jsonify({'access_token': new_access_token, 'expires_in': 3600}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token'}), 401
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = AIUser.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
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
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('selectedAgentId', str(agent_id), samesite='Strict')
                return response
            
            setup_default_agent_and_params(user_id=user.id)

            access_token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(minutes=60)
            }, app.config['ACCESS_SECRET_KEY'], algorithm='HS256')

            refresh_token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(days=7)
            }, app.config['REFRESH_SECRET_KEY'], algorithm='HS256')
            
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('access_token', access_token, samesite='Strict')
            response.set_cookie('refresh_token', refresh_token, samesite='Strict')
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
            username=username,
            password=generate_password_hash(data.get('password'), method='pbkdf2:sha256'),
            full_name=data.get('full_name'),
            email=email
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User account created successfully'}), 201

    return render_template('signup.html')

@app.route('/yaml/<int:id>/<int:agent_id>', methods=['POST', 'GET'])
@auth.login_required
def get_yaml(id, agent_id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        data = request.args.to_dict()

    response_data = generate_swml_response(id, agent_id, request_body=data)

    response = make_response(yaml.dump(response_data))
    response.headers['Content-Type'] = 'text/x-yaml'
    
    return response

@app.route('/swml/<int:user_id>/<int:agent_id>', methods=['POST', 'GET'])
@auth.login_required
@extract_agent_id
def swml(user_id, agent_id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        data = request.args.to_dict()

    response_data = generate_swml_response(user_id, agent_id, request_body=data)

    response = make_response(jsonify(response_data))
    response.headers['Content-Type'] = 'application/json'
    
    return response

@app.route('/postprompt/<int:id>/<int:agent_id>', methods=['POST'])
@auth.login_required
def postprompt(id, agent_id):
    data = request.get_json()
    new_conversation = AIConversation(
        user_id=id,
        agent_id=agent_id,
        data=data
    )
    db.session.add(new_conversation)
    db.session.commit()
    return jsonify({'message': 'Conversation entry created successfully'}), 201

@app.route('/pronounce/<int:id>', methods=['PUT'])
@login_required
def update_pronounce(id):
    data = request.get_json()
    pronounce_entry = AIPronounce.query.get_or_404(id)
    
    pronounce_entry.replace_this = data.get('replace_this', pronounce_entry.replace_this)
    pronounce_entry.replace_with = data.get('replace_with', pronounce_entry.replace_with)
    pronounce_entry.ignore_case = data.get('ignore_case', pronounce_entry.ignore_case)
    
    db.session.commit()
    return jsonify({'message': 'Pronounce entry updated successfully'}), 200

@app.route('/pronounce', methods=['GET', 'POST'])
@login_required
def pronounce():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            pronounces = AIPronounce.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
            pronounce_list = [{
                'id': p.id,
                'replace_this': p.replace_this,
                'replace_with': p.replace_with,
                'ignore_case': p.ignore_case
            } for p in pronounces]
            return jsonify(pronounce_list), 200
        else:
            return render_template('pronounce.html', user=current_user)
    elif request.method == 'POST':
        data = request.get_json()
        new_pronounce = AIPronounce(
            replace_this=data['replace_this'],
            replace_with=data['replace_with'],
            ignore_case=data.get('ignore_case', False),
            user_id=current_user.id,
            agent_id=selected_agent_id
        )
        db.session.add(new_pronounce)
        db.session.commit()
        return jsonify({'message': 'Pronounce entry created successfully'}), 201

@app.route('/pronounce/<int:id>', methods=['DELETE'])
@login_required
def delete_pronounce(id):
    pronounce_entry = AIPronounce.query.get_or_404(id)
    db.session.delete(pronounce_entry)
    db.session.commit()
    return jsonify({'message': 'Pronounce entry deleted successfully'}), 200

@app.route('/prompt', methods=['GET', 'POST'])
@login_required
def prompt():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.headers.get('Accept') == 'application/json':
            prompt_entries = AIPrompt.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
            response_data = [
                {
                    'id': prompt_entry.id,
                    'prompt_type': prompt_entry.prompt_type,
                    'prompt_text': prompt_entry.prompt_text,
                    'top_p': prompt_entry.top_p,
                    'temperature': prompt_entry.temperature,
                    'max_tokens': prompt_entry.max_tokens,
                    'confidence': prompt_entry.confidence,
                    'frequency_penalty': prompt_entry.frequency_penalty,
                    'presence_penalty': prompt_entry.presence_penalty
                } for prompt_entry in prompt_entries
            ]
            return jsonify(response_data), 200
        else:
            return render_template('prompt.html', user=current_user)
    
    elif request.method == 'POST':
        data = request.json
        user_id = current_user.id
        
        float_keys = ['top_p', 'temperature', 'confidence', 'frequency_penalty', 'presence_penalty']
        integer_keys = ['max_tokens']
        
        for key in float_keys + integer_keys:
            if key in data and data[key] == '':
                data[key] = None
        
        existing_prompt = AIPrompt.query.filter_by(user_id=user_id, agent_id=selected_agent_id, prompt_type=data['prompt_type']).first()
        
        if existing_prompt:
            existing_prompt.prompt_text = data['prompt_text']
            existing_prompt.top_p = data['top_p']
            existing_prompt.temperature = data['temperature']
            existing_prompt.max_tokens = data['max_tokens']
            existing_prompt.confidence = data['confidence']
            existing_prompt.frequency_penalty = data['frequency_penalty']
            existing_prompt.presence_penalty = data['presence_penalty']
            db.session.commit()
            return jsonify({'message': 'Prompt updated successfully'}), 200
        else:
            new_prompt = AIPrompt(
                user_id=user_id,
                agent_id=selected_agent_id,
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
            return jsonify({'message': 'Prompt created successfully'}), 201

@app.route('/prompt/<int:id>', methods=['DELETE'])
@login_required
def delete_prompt(id):
    prompt_entry = AIPrompt.query.get_or_404(id)
    
    if prompt_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    db.session.delete(prompt_entry)
    db.session.commit()
    return jsonify({'message': 'Prompt deleted successfully'}), 200

@app.route('/prompt/<int:id>', methods=['PUT'])
@login_required
def update_prompt(id):
    prompt_entry = AIPrompt.query.get_or_404(id)
    
    if prompt_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    prompt_entry.prompt_type = data.get('prompt_type', prompt_entry.prompt_type)
    prompt_entry.prompt_text = data.get('prompt_text', prompt_entry.prompt_text)
    prompt_entry.top_p = data.get('top_p', prompt_entry.top_p)
    prompt_entry.temperature = data.get('temperature', prompt_entry.temperature)
    prompt_entry.max_tokens = data.get('max_tokens', prompt_entry.max_tokens)
    prompt_entry.confidence = data.get('confidence', prompt_entry.confidence)
    prompt_entry.frequency_penalty = data.get('frequency_penalty', prompt_entry.frequency_penalty)
    prompt_entry.presence_penalty = data.get('presence_penalty', prompt_entry.presence_penalty)
    
    db.session.commit()
    return jsonify({'message': 'Prompt updated successfully'}), 200

@app.route('/language/<int:id>', methods=['PUT'])
@login_required
def update_language(id):
    data = request.get_json()
    language_entry = AILanguage.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    
    language_entry.name = data.get('name', language_entry.name)
    language_entry.code = data.get('code', language_entry.code)
    language_entry.voice = data.get('voice', language_entry.voice)
    language_entry.speech_fillers = data.get('speech_fillers', language_entry.speech_fillers)
    language_entry.function_fillers = data.get('function_fillers', language_entry.function_fillers)
    language_entry.language_order = data.get('language_order', language_entry.language_order)
    
    db.session.commit()
    return jsonify({'message': 'Language entry updated successfully'}), 200

@app.route('/language/<int:id>', methods=['GET'])
@login_required
def get_language_by_id(id):
    language_entry = AILanguage.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    return jsonify({
        'id': language_entry.id,
        'name': language_entry.name,
        'code': language_entry.code,
        'voice': language_entry.voice,
        'speech_fillers': language_entry.speech_fillers,
        'function_fillers': language_entry.function_fillers,
        'language_order': language_entry.language_order
    }), 200

@app.route('/language/<int:id>', methods=['DELETE'])
@login_required
def delete_language(id):
    language_entry = AILanguage.query.get_or_404(id)
    db.session.delete(language_entry)
    db.session.commit()
    return jsonify({'message': 'Language entry deleted successfully'}), 200

@app.route('/language', methods=['GET', 'POST', 'PUT'])
@login_required
def language():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            languages = AILanguage.query.filter_by(user_id=current_user.id, agent_id=selected_agent_id).all()
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
    elif request.method == 'POST':
        data = request.get_json()
        new_language = AILanguage(
            name=data['name'],
            code=data['code'],
            voice=data['voice'],
            speech_fillers=data['speech_fillers'],
            function_fillers=data['function_fillers'],
            language_order=data.get('language_order', 0),
            user_id=current_user.id,
            agent_id=selected_agent_id
        )
        db.session.add(new_language)
        db.session.commit()
        return jsonify({'message': 'Language entry created successfully'}), 201
    elif request.method == 'PUT':
        data = request.get_json()
        language_entry = AILanguage.query.filter_by(id=data['id'], user_id=current_user.id, agent_id=selected_agent_id).first_or_404()
        
        language_entry.name = data.get('name', language_entry.name)
        language_entry.code = data.get('code', language_entry.code)
        language_entry.voice = data.get('voice', language_entry.voice)
        language_entry.speech_fillers = data.get('speech_fillers', language_entry.speech_fillers)
        language_entry.function_fillers = data.get('function_fillers', language_entry.function_fillers)
        language_entry.language_order = data.get('language_order', language_entry.language_order)
        
        db.session.commit()
        return jsonify({'message': 'Language entry updated successfully'}), 200
    else:
        return render_template('language.html', user=current_user)

@app.route('/datasphere/search/<uuid:document_id>', methods=['POST'])
@login_required
def search_datasphere(document_id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    data = request.get_json()
    query_string = data.get('query_string', '')

    if not query_string:
        return jsonify({'message': 'Query string is required'}), 400

    space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')

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

@app.route('/datasphere/documents/<uuid:datasphere_id>', methods=['PATCH'])
@login_required
def update_datasphere(datasphere_id):
    selected_agent_id = request.cookies.get('selectedAgentId')  
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    data = request.get_json()
    space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')
    
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
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
            project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
            auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')
            
            url = f'https://{space_name}/api/datasphere/documents'
            headers = {'Accept': 'application/json'}
            response = requests.get(url, headers=headers, auth=(project_id, auth_token))

            if response.status_code == 200:
                return jsonify(response.json()), 200
            elif response.status_code == 401:
                return jsonify({'error': 'SignalWire credentials missing'}), 401
        else:   
            return render_template('datasphere.html', user=current_user)

@app.route('/datasphere', methods=['POST'])
@login_required
def create_datasphere():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    data = request.get_json()
    space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')
    
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

@app.route('/datasphere/documents/<uuid:datasphere_id>', methods=['DELETE'])
@login_required
def delete_datasphere(datasphere_id):
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')
    
    url = f'https://{space_name}/api/datasphere/documents/{datasphere_id}'
    headers = {
        'Accept': 'application/json'
    }
    response = requests.delete(url, headers=headers, auth=(project_id, auth_token))
    
    if response.status_code == 204:
        return jsonify({'message': 'Datasphere document deleted successfully'}), 204
    else:
        return jsonify({'error': 'Failed to delete datasphere document'}), response.status_code

@app.route('/agents/clone/<int:agent_id>', methods=['POST'])
@login_required
def clone_agent(agent_id):
    original_agent = AIAgent.query.get_or_404(agent_id)

    if original_agent.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    random_bits = generate_random_password(4)

    new_agent = AIAgent(
        user_id=original_agent.user_id,
        name=f"{original_agent.name} Copy {random_bits}",
        number=original_agent.number
    )
    db.session.add(new_agent)
    db.session.commit()

    def clone_relationships(original, new, relationship_name):
        related_items = getattr(original, relationship_name)
        for item in related_items:
            if not hasattr(item, 'function_id') or not hasattr(item, 'name'):
                continue

            existing_item = item.__class__.query.filter_by(
                user_id=item.user_id,
                function_id=item.function_id,
                name=item.name
            ).first()

            if existing_item:
                continue

            new_item = item.__class__(**{col.name: getattr(item, col.name) for col in item.__table__.columns if col.name != 'id'})
            new_item.agent_id = new.id
            db.session.add(new_item)

    relationships = [
        'ai_signalwire_params', 'ai_functions', 'ai_function_argument', 'ai_hints', 'ai_pronounce', 'ai_prompt', 'ai_language', 'ai_params', 'ai_features'
    ]

    for relationship in relationships:
        clone_relationships(original_agent, new_agent, relationship)

    db.session.commit()

    return jsonify({'message': 'Agent cloned successfully', 'new_agent_id': new_agent.id}), 201

@app.route('/agents', methods=['GET', 'POST'])
@login_required
def agents():
    if request.method == 'GET':
        if request.headers.get('Accept') == 'application/json':
            agents = AIAgent.query.filter_by(user_id=current_user.id).all()
            agents_data = [{'id': agent.id, 'name': agent.name, 'number': agent.number, 'created': agent.created} for agent in agents]
            return jsonify(agents_data), 200
        else:
            return render_template('agents.html', user=current_user)

    elif request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        number = data.get('number')

        if not name:
            return jsonify({'error': 'Name is required'}), 400

        new_agent = AIAgent(name=name, number=number, user_id=current_user.id)
        db.session.add(new_agent)
        db.session.commit()

        default_params = [
            {'name': 'HTTP_PASSWORD', 'value': generate_random_password()},
            {'name': 'SPACE_NAME', 'value': 'subdomain.signalwire.com'},
            {'name': 'AUTH_TOKEN', 'value': 'PTb4d1.....'},
            {'name': 'PROJECT_ID', 'value': '5f1c4418-.....'}
        ]

        for param in default_params:
            new_param = AISignalWireParams(
                user_id=current_user.id,
                agent_id=new_agent.id,
                name=param['name'],
                value=param['value']
            )
            db.session.add(new_param)

        db.session.commit()

        return jsonify({'message': 'Agent created successfully'}), 201
    
@app.route('/agents/<int:id>', methods=['GET'])
@login_required
def get_agent(id):
    agent = AIAgent.query.get_or_404(id)

    if agent.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    agent_data = {
        'id': agent.id,
        'name': agent.name,
        'number': agent.number,
        'created': agent.created
    }

    return jsonify(agent_data), 200

@app.route('/agents/<int:id>', methods=['DELETE'])
@login_required
def delete_agent(id):
    agent = AIAgent.query.get_or_404(id)

    if agent.name == "BotWorks":
        return jsonify({'message': 'Cannot delete the default agent "BotWorks".'}), 403

    if agent.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    db.session.delete(agent)
    db.session.commit()

    return jsonify({'message': 'Agent deleted successfully'}), 200

@app.route('/agents/<int:id>', methods=['PUT'])
@login_required
def update_agent(id):
    agent = AIAgent.query.get_or_404(id)

    if agent.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    agent.name = data.get('name', agent.name)
    agent.number = data.get('number', agent.number)
    db.session.commit()

    return jsonify({'message': 'Agent updated successfully'}), 200

@app.route('/livedebug', methods=['GET'])
@login_required
def livedebug():
    selected_agent_id = request.cookies.get('selectedAgentId')
    user_id = current_user.id

    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    agent = AIAgent.query.filter_by(id=selected_agent_id, user_id=current_user.id).first_or_404()

    channel = f'debug_channel_{user_id}_{selected_agent_id}'

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

        message = data['message']
        channel = data['channel']
        redis_client.publish(channel, message)

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@app.route('/debugwebhook/<int:user_id>/<int:agent_id>', methods=['POST'])
@auth.login_required
def create_debuglog(user_id, agent_id):
    data = json.loads(request.get_data().decode('utf-8'))
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    channel_name = f'debug_channel_{user_id}_{agent_id}'

    redis_client.publish(channel_name, json.dumps(data).encode('utf-8'))

    new_log = AIDebugLogs(
        user_id=user_id,
        agent_id=agent_id,
        data=data,
        ip_address=ip_address
    )
    db.session.add(new_log)
    db.session.commit()

    return jsonify({'message': 'Debug log created successfully'}), 201

@app.route('/debuglogs/<int:agent_id>', methods=['GET', 'DELETE'])
@login_required
def get_debuglogs(agent_id):
    if request.method == 'GET':
        logs = AIDebugLogs.query.filter_by(user_id=current_user.id, agent_id=agent_id).all()
        logs_data = [{'id': log.id, 'created': log.created, 'data': log.data, 'ip_address': log.ip_address} for log in logs]
        return jsonify(logs_data), 200

    elif request.method == 'DELETE':
        AIDebugLogs.query.filter_by(user_id=current_user.id, agent_id=agent_id).delete()
        db.session.commit()
        return jsonify({'message': 'All debug logs for the agent deleted successfully'}), 200

@app.route('/debuglogs', methods=['GET'])
@login_required
def debuglogs():
    return render_template('debuglog.html', user=current_user)

@app.route('/aifeatures/<int:agent_id>/<int:feature_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_aifeature(agent_id, feature_id):
    feature = AIFeatures.query.filter_by(id=feature_id, agent_id=agent_id, user_id=current_user.id).first_or_404()

    if request.method == 'GET':
        return jsonify({
            'id': feature.id,
            'name': feature.name,
            'value': feature.value,
            'enabled': feature.enabled,
            'created': feature.created
        }), 200

    elif request.method == 'PUT':
        data = request.get_json()
        feature.name = data.get('name', feature.name)
        feature.value = data.get('value', feature.value)
        feature.enabled = data.get('enabled', feature.enabled)
        db.session.commit()
        return jsonify({'message': 'Feature updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(feature)
        db.session.commit()
        return jsonify({'message': 'Feature deleted successfully'}), 200

@app.route('/aifeatures/<int:agent_id>', methods=['POST'])
@login_required
def add_aifeature(agent_id):
    data = request.get_json()
    new_feature = AIFeatures(
        name=data['name'],
        value=data['value'],
        enabled=data['enabled'],
        user_id=current_user.id,
        agent_id=agent_id
    )
    db.session.add(new_feature)
    db.session.commit()

    return jsonify({'message': 'Feature added successfully'}), 201

@app.route('/aifeatures', methods=['GET'])
@login_required
def aifeatures():
    return render_template('features.html', user=current_user)

@app.route('/aifeatures/<int:agent_id>', methods=['GET'])
@login_required
def aifeatures_agent(agent_id):
    if request.headers.get('Accept') == 'application/json':
        features = AIFeatures.query.filter_by(user_id=current_user.id, agent_id=agent_id).all()
        features_data = [{
            'id': feature.id,
            'name': feature.name,
            'agent_id': feature.agent_id,
            'value': feature.value,
            'enabled': feature.enabled,
            'created': feature.created
        } for feature in features]
        return jsonify(features_data), 200
    
@app.route('/phone_numbers', methods=['GET'])
@login_required
def list_phone_numbers():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
        space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
        project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
        auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')

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
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')

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

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({'error': 'Failed to search available phone numbers'}), response.status_code
    
@app.route('/phone_numbers', methods=['POST'])
@login_required
def purchase_phone_number():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')

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
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    data = request.get_json()
    phone_number = data.get('phone_number')
    agent_id = data.get('agent_id')

    auth_pass = get_signal_wire_param(current_user.id, agent_id, 'HTTP_PASSWORD')
    space_name = get_signal_wire_param(current_user.id, agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, agent_id, 'AUTH_TOKEN')
    auth_user = current_user.username
    swml_url = f"https://{auth_user}:{auth_pass}@{request.host}/swml/{current_user.id}/{agent_id}"  
    
    encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
    url = f'https://{space_name}/api/relay/rest/phone_numbers/{phone_number_id}'
    authorization = f'Basic {encoded_credentials}'

    agent_name = AIAgent.query.filter_by(id=selected_agent_id, user_id=current_user.id).first().name

    AIAgent.query.filter_by(id=selected_agent_id, user_id=current_user.id).update({'number': phone_number})
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
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    space_name = get_signal_wire_param(current_user.id, selected_agent_id, 'SPACE_NAME')
    project_id = get_signal_wire_param(current_user.id, selected_agent_id, 'PROJECT_ID')
    auth_token = get_signal_wire_param(current_user.id, selected_agent_id, 'AUTH_TOKEN')

    encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
    url = f'https://{space_name}/api/relay/rest/phone_numbers/{phone_number_id}'
    authorization = f'Basic {encoded_credentials}'

    headers = {
        'Authorization': authorization,
        'Accept': 'application/json'
    }

    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        return jsonify({'message': 'Phone number released successfully'}), 204
    else:
        return jsonify({'error': 'Failed to release phone number'}), response.status_code

@app.route('/includes/<int:agent_id>', methods=['POST'])
@login_required
def create_or_update_include(agent_id):
    data = request.get_json()
    url = data.get('url')
    functions = data.get('functions', [])

    include_entry = AIIncludes.query.filter_by(user_id=current_user.id, url=url, agent_id=agent_id).first()

    if include_entry:
        include_entry.functions = functions
    else:
        include_entry = AIIncludes(user_id=current_user.id, url=url, functions=functions, agent_id=agent_id)
        db.session.add(include_entry)

    db.session.commit()
    return jsonify({'message': 'Include entry saved successfully'}), 200

@app.route('/includes/<int:agent_id>', methods=['GET'])
@login_required
def get_includes_agent(agent_id):
    includes_entries = AIIncludes.query.filter_by(user_id=current_user.id, agent_id=agent_id).all()
    return jsonify([{
        'id': entry.id,
        'url': entry.url,
        'functions': entry.functions
    } for entry in includes_entries]), 200

@app.route('/includes/<int:agent_id>/<int:include_id>', methods=['GET'])
@login_required
def get_include_agent(agent_id, include_id):
    include_entry = AIIncludes.query.filter_by(id=include_id, user_id=current_user.id, agent_id=agent_id).first_or_404()
    return jsonify({
        'id': include_entry.id,
        'url': include_entry.url,
        'functions': include_entry.functions
    }), 200

@app.route('/includes/<int:agent_id>/<int:include_id>', methods=['PUT'])
@login_required
def update_include(agent_id, include_id):
    include_entry = AIIncludes.query.filter_by(id=include_id, user_id=current_user.id, agent_id=agent_id).first_or_404()
    data = request.get_json()
    include_entry.url = data.get('url', include_entry.url)
    include_entry.functions = data.get('functions', include_entry.functions)
    db.session.commit()
    return jsonify({'message': 'Include updated successfully'}), 200

@app.route('/includes/<int:agent_id>/<int:include_id>', methods=['DELETE'])
@login_required
def delete_include(agent_id, include_id):
    include_entry = AIIncludes.query.filter_by(id=include_id, user_id=current_user.id, agent_id=agent_id).first_or_404()
    db.session.delete(include_entry)
    db.session.commit()
    return jsonify({'message': 'Include deleted successfully'}), 200

@app.route('/includes', methods=['POST'])
@login_required
def get_includes_post():
    if request.headers.get('Accept') == 'application/json':
        url = request.get_json().get('url')
        if not url:
            return jsonify({'error': 'URL parameter is required'}), 400
        swaig_response = get_swaig_includes(url)
        return jsonify(swaig_response), 200
    else:
        return jsonify({'error': 'Accept header must be application/json'}), 400

@app.route('/includes', methods=['GET'])
@login_required
def includes():
    return render_template('includes.html', user=current_user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    socketio.run(app, host='0.0.0.0', port=5000, debug=os.getenv('DEBUG'))