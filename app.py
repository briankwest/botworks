import os  # Standard library import
from datetime import datetime

from dotenv import load_dotenv

from flask import Flask, flash, make_response, jsonify, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, login_required,
                         logout_user, current_user)
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.middleware.proxy_fix import ProxyFix

from modules.signalwireml import SignalWireML

def get_signal_wire_param(user_id, param_name):
    param = AISignalWireParams.query.filter_by(user_id=user_id, name=param_name).first()
    return param.value if param else None

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    user = AIUser.query.filter_by(username=username).first()
    if user:
        http_password = get_signal_wire_param(user.id, 'HTTP_PASSWORD')
        if user.username == username and http_password == password:
            return user
    return None

app = Flask(__name__)

# Apply ProxyFix middleware
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

load_dotenv()

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Explicitly set the static folder path (optional)
app.static_folder = os.path.abspath('static')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

# AISignalWireParams model definition
class AISignalWireParams(db.Model):
    __tablename__ = 'ai_signalwire_params'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_signalwire_params', lazy=True))

    def __repr__(self):
        return f'<AISignalWireParams {self.name}: {self.value}>'

# AISWMLRequest model definition
class AISWMLRequest(db.Model):
    __tablename__ = 'ai_swml_requests'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    request = db.Column(db.JSON, nullable=False)
    response = db.Column(db.JSON, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # Added ip_address field

    user = db.relationship('AIUser', backref=db.backref('ai_swml_requests', lazy=True))

    def __repr__(self):
        return f'<AISWMLRequest {self.id}>'

class AIFunctions(db.Model):
    __tablename__ = 'ai_functions'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.Text, nullable=True)
    purpose = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)

    user = db.relationship('AIUser', backref=db.backref('ai_functions', lazy=True))
    ai_function_args = db.relationship(
        'AIFunctionArgs', 
        back_populates='function', 
        cascade='all, delete-orphan', 
        lazy=True,
        overlaps="ai_function_argument, parent_function"
    )

    def __repr__(self):
        return f'<AIFunctions {self.name}>'

class AIFunctionArgs(db.Model):
    __tablename__ = 'ai_function_argument'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    function_id = db.Column(db.Integer, db.ForeignKey('ai_functions.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.Text, nullable=False)
    type = db.Column(db.Text, nullable=False, default='string')
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    required = db.Column(db.Boolean, nullable=False, default=False)
    enum = db.Column(db.Text, nullable=True)  # Add this line

    function = db.relationship(
        'AIFunctions', 
        back_populates='ai_function_args', 
        overlaps="parent_function"
    )
    user = db.relationship('AIUser', backref=db.backref('ai_function_argument', lazy=True))

    __table_args__ = (db.UniqueConstraint('user_id', 'function_id', 'name'),)

    def __repr__(self):
        return f'<AIFunctionArgs {self.name}>'

# AIHints model definition
class AIHints(db.Model):
    __tablename__ = 'ai_hints'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    hint = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_hints', lazy=True))

    def __repr__(self):
        return f'<AIHints {self.hint}>'

# AIPronounce model definition
class AIPronounce(db.Model):
    __tablename__ = 'ai_pronounce'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ignore_case = db.Column(db.Boolean, nullable=False, default=False)
    replace_this = db.Column(db.Text, nullable=False)
    replace_with = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_pronounce', lazy=True))

    def __repr__(self):
        return f'<AIPronounce {self.replace_this} -> {self.replace_with}>'

# AIPrompt model definition
class AIPrompt(db.Model):
    __tablename__ = 'ai_prompt'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    prompt = db.Column(db.Text, nullable=True)
    prompt_top_p = db.Column(db.Float, nullable=True)  # Changed to Float
    prompt_temperature = db.Column(db.Float, nullable=True)  # Changed to Float
    prompt_max_tokens = db.Column(db.Integer, nullable=True)  # Allowed to be empty or null
    prompt_confidence = db.Column(db.Float, nullable=True)  # Changed to Float
    prompt_frequency_penalty = db.Column(db.Float, nullable=True)  # Changed to Float
    prompt_presence_penalty = db.Column(db.Float, nullable=True)  # Changed to Float

    post_prompt = db.Column(db.Text, nullable=True)
    post_prompt_top_p = db.Column(db.Float, nullable=True)  # Changed to Float
    post_prompt_temperature = db.Column(db.Float, nullable=True)  # Changed to Float
    post_prompt_max_tokens = db.Column(db.Integer, nullable=True)  # Allowed to be empty or null
    post_prompt_confidence = db.Column(db.Float, nullable=True)  # Changed to Float
    post_prompt_frequency_penalty = db.Column(db.Float, nullable=True)  # Changed to Float
    post_prompt_presence_penalty = db.Column(db.Float, nullable=True)  # Changed to Float
    
    outbound_prompt = db.Column(db.Text, nullable=True)
    outbound_prompt_top_p = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_prompt_temperature = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_prompt_max_tokens = db.Column(db.Integer, nullable=True)  # Allowed to be empty or null
    outbound_prompt_confidence = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_prompt_frequency_penalty = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_prompt_presence_penalty = db.Column(db.Float, nullable=True)  # Changed to Float

    outbound_post_prompt = db.Column(db.Text, nullable=True)
    outbound_post_prompt_top_p = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_post_prompt_temperature = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_post_prompt_max_tokens = db.Column(db.Integer, nullable=True)  # Allowed to be empty or null
    outbound_post_prompt_confidence = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_post_prompt_frequency_penalty = db.Column(db.Float, nullable=True)  # Changed to Float
    outbound_post_prompt_presence_penalty = db.Column(db.Float, nullable=True)  # Changed to Float
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_prompt', lazy=True))

    __table_args__ = (db.UniqueConstraint('user_id'),)

    def __repr__(self):
        return f'<AIPrompt {self.prompt}>'

# AILanguage model definition
class AILanguage(db.Model):
    __tablename__ = 'ai_language'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    code = db.Column(db.Text, nullable=True)
    name = db.Column(db.Text, nullable=True)
    voice = db.Column(db.Text, nullable=True)
    speech_fillers = db.Column(db.Text, nullable=True)
    function_fillers = db.Column(db.Text, nullable=True)
    language_order = db.Column(db.Integer, nullable=False, default=0)

    user = db.relationship('AIUser', backref=db.backref('ai_language', lazy=True))

    def __repr__(self):
        return f'<AILanguage {self.name}>'

# AIConversation model definition
class AIConversation(db.Model):
    __tablename__ = 'ai_conversation'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data = db.Column(db.JSON, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_conversation', lazy=True))

    def __repr__(self):
        return f'<AIConversation {self.id}>'

class AIParams(db.Model):
    __tablename__ = 'ai_params'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_params', lazy=True))

    def __repr__(self):
        return f'<AIParams {self.name}: {self.value}>'

# AIUser model definition
class AIUser(UserMixin, db.Model):
    __tablename__ = 'ai_users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<AIUser {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(AIUser, int(user_id))

# Create all tables in the database and admin user if not exists
def create_admin_user():
    admin_username = os.environ.get('ADMIN_USERNAME')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    admin_email = os.environ.get('ADMIN_EMAIL')
    full_name = os.environ.get('ADMIN_FULL_NAME')
    
    # Check if admin user already exists
    admin_user = AIUser.query.filter_by(username=admin_username).first()
    if admin_user is None:
        try:
            hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
            admin_user = AIUser(
                user_id=1,
                full_name=full_name,
                username=admin_username,
                password=hashed_password,
                email=admin_email
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully.")
        except IntegrityError:
            db.session.rollback()
            print("Integrity error while creating admin user.")
    else:
        print("Admin user already exists.")

# Dashboard route
@app.route('/')
@login_required
def dashboard():
    auth_user = current_user.username
    auth_pass = get_signal_wire_param(current_user.id, 'HTTP_PASSWORD')

    swml_url = f"https://{auth_user}:{auth_pass}@{request.host}/swml/{current_user.id}"
    yaml_url = f"https://{auth_user}:{auth_pass}@{request.host}/yaml/{current_user.id}"
    debugwebhook_url = f"https://{auth_user}:{auth_pass}@{request.host}/debugwebhook/{current_user.id}"

    return render_template('dashboard.html', user=current_user, swml_url=swml_url, yaml_url=yaml_url, debugwebhook_url=debugwebhook_url)

# SWML Requests route
@app.route('/swmlrequests', methods=['GET'])
@login_required
def swmlrequests():
    print(request.headers.get('Accept'))
    if request.headers.get('Accept') == 'application/json':
         # Fetch all SWML requests for the current user
        swml_requests = AISWMLRequest.query.filter_by(user_id=current_user.id).all()

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
    from datetime import datetime, timedelta

    # Calculate the time range for the past 24 hours
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    # Initialize a dictionary to store the counts for each hour (default 0)
    hourly_counts = {start_time + timedelta(hours=i): 0 for i in range(24)}

    # Query to get the count of completed conversations grouped by hour
    completed_conversations = db.session.query(
        db.func.date_trunc('hour', AIConversation.created).label('hour'),
        db.func.count(AIConversation.id).label('count')
    ).filter(
        AIConversation.created >= start_time,
        AIConversation.created <= end_time,
        AIConversation.user_id == current_user.id
    ).group_by('hour').order_by('hour').all()

    # Update the dictionary with actual counts
    for hour, count in completed_conversations:
        hourly_counts[hour] = count

    # Prepare the data for the chart (ensure all 24 hours are represented)
    labels = [hour.strftime('%H:00') for hour in hourly_counts.keys()]
    counts = [count for count in hourly_counts.values()]

    return jsonify({'labels': labels, 'counts': counts}), 200

# SWAIG Functions route
@app.route('/functions', methods=['GET', 'POST'])
@login_required
def functions():
    if request.method == 'POST':
        data = request.get_json()
        new_function = AIFunctions(
            name=data['name'],
            purpose=data['purpose'],
            user_id=current_user.id
        )
        db.session.add(new_function)
        db.session.commit()
        return jsonify({'message': 'Function entry created successfully'}), 201
    else:
        return render_template('functions.html', user=current_user)

# Manage SWAIG Functions route
@app.route('/functions/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_function(id):
    function_entry = AIFunctions.query.get_or_404(id)
    
    if function_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'GET':
        return jsonify({
            'id': function_entry.id,
            'name': function_entry.name,
            'purpose': function_entry.purpose,
            'active': function_entry.active
        }), 200

    elif request.method == 'PUT':
        data = request.get_json()
        function_entry.name = data.get('name', function_entry.name)
        function_entry.purpose = data.get('purpose', function_entry.purpose)
        function_entry.active = data.get('active', function_entry.active)
        db.session.commit()
        return jsonify({'message': 'Function entry updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(function_entry)
        db.session.commit()
        return jsonify({'message': 'Function entry deleted successfully'}), 200

@app.route('/get_functions')
@login_required
def get_functions():
    functions = AIFunctions.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': func.id,
        'name': func.name,
        'purpose': func.purpose,
        'created': func.created.isoformat()
    } for func in functions])

# Add SWAIG Function Arguments route
@app.route('/functions/<int:function_id>/args', methods=['POST'])
@login_required
def add_function_arg(function_id):
    function_entry = AIFunctions.query.get_or_404(function_id)
    
    if function_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    new_arg = AIFunctionArgs(
        function_id=function_id,
        user_id=current_user.id,
        name=data['name'],
        type=data['type'],
        description=data.get('description'),
        required=data.get('required', False),
        enum=data.get('enum')
    )
    db.session.add(new_arg)
    db.session.commit()
    return jsonify({'message': 'Function argument added successfully'}), 201

@app.route('/functions/<int:function_id>/args/<int:arg_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_function_arg(function_id, arg_id):
    function_entry = AIFunctions.query.get_or_404(function_id)
    arg_entry = AIFunctionArgs.query.get_or_404(arg_id)
    
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
        db.session.commit()
        return jsonify({'message': 'Function argument updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(arg_entry)
        db.session.commit()
        return jsonify({'message': 'Function argument deleted successfully'}), 200

# View Conversation route
@app.route('/conversation/view/<int:id>', methods=['GET'])
@login_required
def view_conversation(id):
    conversation = AIConversation.query.get_or_404(id)
    
    if conversation.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    return render_template('conversation.html', id=id, user=current_user)

# Conversations route
@app.route('/conversations')
@login_required
def conversations():
    return render_template('conversations.html', user=current_user)

# Get Conversations route
@app.route('/get_conversations', methods=['GET'])
@login_required
def get_conversations():
    conversations = AIConversation.query.filter_by(user_id=current_user.id).all()
    data = [{
        'id': conversation.id,
        'created': conversation.created.strftime('%Y-%m-%d %H:%M:%S'),
        'data': conversation.data
    } for conversation in conversations]
    
    return jsonify({
        'data': data
    }), 200

# Get or Delete Conversation route
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
    if request.method == 'POST':
        data = request.get_json()
        new_hint = AIHints(
            hint=data['hint'],
            user_id=current_user.id
        )
        db.session.add(new_hint)
        db.session.commit()
        return jsonify({'message': 'Hint entry created successfully'}), 201
    else:
        return render_template('hints.html', user=current_user)

# Manage Hints route
@app.route('/hints/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def hint(id):
    hint_entry = AIHints.query.get_or_404(id)
    
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

# Get Hints route
@app.route('/get_hints', methods=['GET'])
@login_required
def get_hints():
    hints = AIHints.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': hint.id,
        'hint': hint.hint,
        'created': hint.created
    } for hint in hints]), 200

# Manage SignalWire Parameters route
@app.route('/signalwire/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_signalwire(id):
    signalwire_entry = AISignalWireParams.query.get_or_404(id)
    
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

# SignalWire Parameters route
@app.route('/signalwire', methods=['GET', 'POST'])
@login_required
def signalwire():
    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            params = AISignalWireParams.query.filter_by(user_id=current_user.id).all()
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
            user_id=current_user.id
        )
        db.session.add(new_params)
        db.session.commit()
        return jsonify({'message': 'SignalWire entry created successfully'}), 201

# Manage Parameters route
@app.route('/params/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_params(id):
    params_entry = AIParams.query.get_or_404(id)
    
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

# Parameters route
@app.route('/params', methods=['GET', 'POST'])
@login_required
def params():
    if request.method == 'GET':
        if request.accept_mimetypes['application/json'] and request.accept_mimetypes.best == 'application/json':
            params = AIParams.query.filter_by(user_id=current_user.id).all()
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
            user_id=current_user.id
        )
        db.session.add(new_params)
        db.session.commit()
        return jsonify({'message': 'Params entry created successfully'}), 201
    
# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = AIUser.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            import random
            import string

            # Generate a random alphanumeric string for HTTP_PASSWORD
            def generate_random_password(length=16):
                characters = string.ascii_letters + string.digits
                return ''.join(random.choice(characters) for i in range(length))

            # Check if HTTP_PASSWORD exists for the user, if not, create it
            http_password = get_signal_wire_param(user.id, 'HTTP_PASSWORD')
            if not http_password:
                random_password = generate_random_password()
                # Check and add HTTP_PASSWORD if it doesn't exist
                if not get_signal_wire_param(user.id, 'HTTP_PASSWORD'):
                    new_param = AISignalWireParams(
                        user_id=user.id,
                        name='HTTP_PASSWORD',
                        value=random_password
                    )
                    db.session.add(new_param)

            # Check and add SPACE_NAME if it doesn't exist
            if not get_signal_wire_param(user.id, 'SPACE_NAME'):
                    new_param = AISignalWireParams(
                        user_id=user.id,
                        name='SPACE_NAME',
                        value='subdomain.signalwire.com'  # Add appropriate default value if needed
                    )
                    db.session.add(new_param)

            # Check and add AUTH_TOKEN if it doesn't exist
            if not get_signal_wire_param(user.id, 'AUTH_TOKEN'):
                new_param = AISignalWireParams(
                    user_id=user.id,
                    name='AUTH_TOKEN',
                    value='PTb4d1.....'  # Add appropriate default value if needed
                )
                db.session.add(new_param)

            # Check and add PROJECT_ID if it doesn't exist
            if not get_signal_wire_param(user.id, 'PROJECT_ID'):
                new_param = AISignalWireParams(
                    user_id=user.id,
                    name='PROJECT_ID',
                    value='5f1c4418-.....'  # Add appropriate default value if needed
                )
                db.session.add(new_param)

                db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

# Generate SWML Response route
def generate_swml_response(user_id, request_body):
    swml = SignalWireML(version="1.0.0")
    
    prompt = AIPrompt.query.filter_by(user_id=user_id).first()
    if not prompt:
        return jsonify({'error': 'Prompt not found'}), 404

    # Set up the initial prompt
    aiprompt_data = {
        "temperature": prompt.prompt_temperature if prompt.prompt_temperature is not None else 0.5,
        "top_p": prompt.prompt_top_p if prompt.prompt_top_p is not None else 0.5,
        "text": prompt.prompt
    }
    if prompt.prompt_max_tokens is not None:
        aiprompt_data["max_tokens"] = prompt.prompt_max_tokens
    if prompt.prompt_confidence is not None:
        aiprompt_data["confidence"] = prompt.prompt_confidence
    if prompt.prompt_frequency_penalty is not None:
        aiprompt_data["frequency_penalty"] = prompt.prompt_frequency_penalty
    if prompt.prompt_presence_penalty is not None:
        aiprompt_data["presence_penalty"] = prompt.prompt_presence_penalty

    swml.set_aiprompt(aiprompt_data)

    # Set up the post prompt
    aipost_prompt_data = {
        "temperature": prompt.post_prompt_temperature if prompt.post_prompt_temperature is not None else 0.5,
        "top_p": prompt.post_prompt_top_p if prompt.post_prompt_top_p is not None else 0.5,
        "text": prompt.post_prompt
    }
    if prompt.post_prompt_max_tokens is not None:
        aipost_prompt_data["max_tokens"] = prompt.post_prompt_max_tokens
    if prompt.post_prompt_confidence is not None:
        aipost_prompt_data["confidence"] = prompt.post_prompt_confidence
    if prompt.post_prompt_frequency_penalty is not None:
        aipost_prompt_data["frequency_penalty"] = prompt.post_prompt_frequency_penalty
    if prompt.post_prompt_presence_penalty is not None:
        aipost_prompt_data["presence_penalty"] = prompt.post_prompt_presence_penalty

    swml.set_aipost_prompt(aipost_prompt_data)

    # Add hints
    hints = AIHints.query.filter_by(user_id=user_id).all()
    swml.add_aihints([hint.hint for hint in hints])
    
    # Add parameters
    ai_params = AIParams.query.filter_by(user_id=user_id).all()
    params_dict = {param.name: param.value for param in ai_params}
    swml.set_aiparams(params_dict)
    
    # Add languages
    languages = AILanguage.query.filter_by(user_id=user_id).order_by(AILanguage.language_order.asc()).all()
    for language in languages:
        language_data = {
            "language": language.name,
            "voice": language.voice,
            "name": language.name,
            "code": language.code
        }
        if language.speech_fillers:
            language_data["speech_fillers"] = language.speech_fillers
        if language.function_fillers:
            language_data["function_fillers"] = language.function_fillers

        swml.add_ailanguage(language_data)

    # Add pronounces
    pronounces = AIPronounce.query.filter_by(user_id=user_id).all()
    for pronounce in pronounces:
        swml.add_aipronounce({
            "replace_this": pronounce.replace_this,
            "replace_with": pronounce.replace_with,
            "ignore_case": pronounce.ignore_case
        })

    # Add functions
    functions = AIFunctions.query.filter_by(user_id=user_id).all()
    for function in functions:
        function_data = {
            "name": function.name,
            "purpose": function.purpose,
            "arguments": []
        }
        function_args = AIFunctionArgs.query.filter_by(function_id=function.id).all()
        required_args = []
        for arg in function_args:
            function_data["arguments"].append({
                "name": arg.name,
                "type": arg.type,
                "description": arg.description,
            })
            if arg.enum and arg.type == 'array':
                function_data["arguments"][-1]["enum"] = arg.enum.split(',')
            
            if arg.required:
                required_args.append(arg.name)
        function_payload = {
            "name": function.name,
            "purpose": function.purpose,
            "arguments": function_data["arguments"],
            "required": required_args,
        
        }
        if not function.active:
            function_payload["active"] = function.active
        swml.add_aiswaigfunction(function_payload)
    
    # Set URLs with authentication if available
    auth_user = AIUser.query.filter_by(id=user_id).first().username
    auth_pass = get_signal_wire_param(user_id, 'HTTP_PASSWORD')
    
    post_prompt_url = f"https://{request.host}/postprompt/{user_id}"
    if auth_user and auth_pass:
        post_prompt_url = f"https://{auth_user}:{auth_pass}@{request.host}/postprompt/{user_id}"
    swml.set_aipost_prompt_url({"post_prompt_url": post_prompt_url})

    web_hook_url = f"https://{request.host}/swaig/{user_id}"
    if auth_user and auth_pass:
        web_hook_url = f"https://{auth_user}:{auth_pass}@{request.host}/swaig/{user_id}"
    swml.add_aiswaigdefaults({"web_hook_url": web_hook_url})

    debug_webhook_url = f"https://{request.host}/debughook/{user_id}"
    if auth_user and auth_pass:
        debug_webhook_url = f"https://{auth_user}:{auth_pass}@{request.host}/debugwebhook/{user_id}"
    swml.add_aiparams({"debug_webhook_url": debug_webhook_url})

    # Add application
    swml.add_aiapplication("main")

    # Render the SWML response (this is what you will store in the response column)
    swml_response = swml.render()

    # Get the IP address of the client
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Log the SWML request (as a JSONB object) and the response in the AISWMLRequest table
    new_swml_request = AISWMLRequest(
        user_id=user_id,
        request=jsonify(request_body).json,    # Log the incoming request JSON data as JSONB
        response=jsonify(swml_response).json,   # Log the SWML response data as JSONB
        ip_address=ip_address
    )
    db.session.add(new_swml_request)
    db.session.commit()

    return swml_response

# Signup route
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')

        # Check if the username or email already exists
        existing_user = AIUser.query.filter((AIUser.username == username) | (AIUser.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                return jsonify({'error': 'Username already in use. Please choose a different username.'}), 409
            if existing_user.email == email:
                return jsonify({'error': 'Email already in use. Please choose a different email.'}), 409

        # Assuming AIUser is a model for user accounts
        new_user = AIUser(
            username=username,
            password=generate_password_hash(data.get('password'), method='pbkdf2:sha256'),  # Hash the password
            full_name=data.get('full_name'),
            email=email
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User account created successfully'}), 201

    # Serve the signup.html page for non-JSON requests
    return render_template('signup.html')

# Get YAML route
@app.route('/yaml/<int:id>', methods=['POST', 'GET'])
@auth.login_required
def get_yaml(id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        # For GET requests, you could handle query parameters or defaults
        data = request.args.to_dict()  # Get query parameters

    # Generate response in YAML format
    response_data = generate_swml_response(id, request_body=data)
    # Import the yaml module
    import yaml
    # Create the response with the correct Content-Type
    response = make_response(yaml.dump(response_data))
    response.headers['Content-Type'] = 'text/x-yaml'
    
    return response

# Generate SWML Response route
@app.route('/swml/<int:id>', methods=['POST', 'GET'])
@auth.login_required
def swml(id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        # For GET requests, you could handle query parameters or defaults
        data = request.args.to_dict()  # Get query parameters

    # Generate response in JSON format
    response_data = generate_swml_response(id, request_body=data)
    
    # Create the response with the correct Content-Type
    response = make_response(jsonify(response_data))
    response.headers['Content-Type'] = 'application/json'
    
    return response

# Post Prompt route
@app.route('/postprompt/<int:id>', methods=['POST'])
@auth.login_required
def postprompt(id):
    data = request.get_json()
    new_conversation = AIConversation(
        user_id=id,
        data=data
    )
    db.session.add(new_conversation)
    db.session.commit()
    return jsonify({'message': 'Conversation entry created successfully'}), 201

# Update Pronounce route
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

# Pronounce route
@app.route('/pronounce', methods=['GET', 'POST'])
@login_required
def pronounce():
    if request.method == 'POST':
        data = request.get_json()
        new_pronounce = AIPronounce(
            replace_this=data['replace_this'],
            replace_with=data['replace_with'],
            ignore_case=data.get('ignore_case', False),
            user_id=current_user.id
        )
        db.session.add(new_pronounce)
        db.session.commit()
        return jsonify({'message': 'Pronounce entry created successfully'}), 201
    else:
        return render_template('pronounce.html', user=current_user)

# Delete Pronounce route
@app.route('/pronounce/<int:id>', methods=['DELETE'])
@login_required
def delete_pronounce(id):
    pronounce_entry = AIPronounce.query.get_or_404(id)
    db.session.delete(pronounce_entry)
    db.session.commit()
    return jsonify({'message': 'Pronounce entry deleted successfully'}), 200

# Get Pronounce route
@app.route('/get_pronounce', methods=['GET'])
@login_required
def get_pronounce():
    pronounces = AIPronounce.query.filter_by(user_id=current_user.id).all()
    pronounce_list = [{
        'id': p.id,
        'replace_this': p.replace_this,
        'replace_with': p.replace_with,
        'ignore_case': p.ignore_case
    } for p in pronounces]
    return jsonify(pronounce_list)

@app.route('/prompt', methods=['GET', 'POST'])
@login_required
def prompt():
    if request.method == 'GET':
        if request.headers.get('Accept') == 'application/json':
            prompt_entry = AIPrompt.query.filter_by(user_id=current_user.id).first()
            if prompt_entry:
                prompt_fields = [
                    'prompt', 'prompt_top_p', 'prompt_temperature', 'prompt_max_tokens', 'prompt_confidence',
                    'prompt_frequency_penalty', 'prompt_presence_penalty', 'post_prompt', 'post_prompt_top_p',
                    'post_prompt_temperature', 'post_prompt_max_tokens', 'post_prompt_confidence',
                    'post_prompt_frequency_penalty', 'post_prompt_presence_penalty', 'outbound_prompt',
                    'outbound_prompt_top_p', 'outbound_prompt_temperature', 'outbound_prompt_max_tokens',
                    'outbound_prompt_frequency_penalty', 'outbound_prompt_presence_penalty', 'outbound_prompt_confidence',
                    'outbound_post_prompt', 'outbound_post_prompt_top_p', 'outbound_post_prompt_temperature',
                    'outbound_post_prompt_max_tokens', 'outbound_post_prompt_frequency_penalty',
                    'outbound_post_prompt_presence_penalty', 'outbound_post_prompt_confidence'
                ]

                response_data = {field: getattr(prompt_entry, field) for field in prompt_fields}

                return jsonify(response_data), 200
            else:
                fields = [
                    'prompt', 'prompt_top_p', 'prompt_temperature', 'prompt_max_tokens', 'prompt_confidence',
                    'prompt_frequency_penalty', 'prompt_presence_penalty', 'post_prompt', 'post_prompt_top_p',
                    'post_prompt_temperature', 'post_prompt_max_tokens', 'post_prompt_confidence',
                    'post_prompt_frequency_penalty', 'post_prompt_presence_penalty', 'outbound_prompt',
                    'outbound_prompt_top_p', 'outbound_prompt_temperature', 'outbound_prompt_max_tokens',
                    'outbound_prompt_frequency_penalty', 'outbound_prompt_presence_penalty', 'outbound_prompt_confidence',
                    'outbound_post_prompt', 'outbound_post_prompt_top_p', 'outbound_post_prompt_temperature',
                    'outbound_post_prompt_max_tokens', 'outbound_post_prompt_frequency_penalty',
                    'outbound_post_prompt_presence_penalty', 'outbound_post_prompt_confidence'
                ]
                response_data = {field: None for field in fields}
                return jsonify(response_data), 200
        else:
            return render_template('prompt.html', user=current_user)
    elif request.method == 'POST':
        data = request.json
        user_id = current_user.id
        
        # Convert empty strings to None for Float and Integer fields
        float_keys = [
            'prompt_top_p', 'prompt_temperature', 'prompt_confidence', 
            'prompt_frequency_penalty', 'prompt_presence_penalty',
            'post_prompt_top_p', 'post_prompt_temperature', 'post_prompt_confidence',
            'post_prompt_frequency_penalty', 'post_prompt_presence_penalty',
            'outbound_prompt_top_p', 'outbound_prompt_temperature', 'outbound_prompt_confidence',
            'outbound_prompt_frequency_penalty', 'outbound_prompt_presence_penalty',
            'outbound_post_prompt_top_p', 'outbound_post_prompt_temperature', 'outbound_post_prompt_confidence',
            'outbound_post_prompt_frequency_penalty', 'outbound_post_prompt_presence_penalty'
        ]
        
        integer_keys = [
            'prompt_max_tokens', 'post_prompt_max_tokens', 'outbound_prompt_max_tokens', 'outbound_post_prompt_max_tokens'
        ]
        
        for key in float_keys + integer_keys:
            if key in data and data[key] == '':
                data[key] = None
        
        prompt_entry = AIPrompt.query.filter_by(user_id=user_id).first()
        
        if prompt_entry:
            # Update existing entry
            for key, value in data.items():
                setattr(prompt_entry, key, value)
        else:
            # Create new entry
            prompt_entry = AIPrompt(
                user_id=user_id,
                prompt=data['prompt'],
                post_prompt=data['post_prompt'],
                outbound_prompt=data['outbound_prompt'],
                outbound_post_prompt=data['outbound_post_prompt']
            )
            db.session.add(prompt_entry)
        
        db.session.commit()
        return jsonify({'message': 'Prompt saved successfully'}), 200

# Update Language route
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

# Get Language by ID route
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

# Delete Language route
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
    if request.method == 'POST':
        data = request.get_json()
        new_language = AILanguage(
            name=data['name'],
            code=data['code'],
            voice=data['voice'],
            speech_fillers=data['speech_fillers'],
            function_fillers=data['function_fillers'],
            language_order=data.get('language_order', 0),
            user_id=current_user.id
        )
        db.session.add(new_language)
        db.session.commit()
        return jsonify({'message': 'Language entry created successfully'}), 201
    elif request.method == 'PUT':
        data = request.get_json()
        language_entry = AILanguage.query.filter_by(id=data['id'], user_id=current_user.id).first_or_404()
        
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

# Get Language route
@app.route('/get_language', methods=['GET'])
@login_required
def get_language():
    languages = AILanguage.query.filter_by(user_id=current_user.id).all()
    language_list = [{
        'id': l.id,
        'name': l.name,
        'code': l.code,
        'voice': l.voice,
        'speech_fillers': l.speech_fillers,
        'function_fillers': l.function_fillers,
        'language_order': l.language_order
    } for l in languages]
    return jsonify(language_list)

# Get Function Arguments route
@app.route('/functions/<int:function_id>/args', methods=['GET'])
@login_required
def get_function_args(function_id):
    function_entry = AIFunctions.query.get_or_404(function_id)
    
    if function_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    args = AIFunctionArgs.query.filter_by(function_id=function_id).all()
    return jsonify([{
        'id': arg.id,
        'name': arg.name,
        'type': arg.type,
        'description': arg.description,
        'required': arg.required,
        'enum': arg.enum
    } for arg in args]), 200

# Update Function Arguments route
@app.route('/functions/<int:function_id>/args/<int:arg_id>', methods=['PUT'])
@login_required
def update_function_arg(function_id, arg_id):
    function_entry = AIFunctions.query.get_or_404(function_id)
    arg_entry = AIFunctionArgs.query.get_or_404(arg_id)
    
    if function_entry.user_id != current_user.id or arg_entry.function_id != function_id:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    arg_entry.name = data.get('name', arg_entry.name)
    arg_entry.type = data.get('type', arg_entry.type)
    arg_entry.description = data.get('description', arg_entry.description)
    arg_entry.required = data.get('required', arg_entry.required)
    arg_entry.enum = data.get('enum', arg_entry.enum)
    db.session.commit()
    return jsonify({'message': 'Function argument updated successfully'}), 200



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(host='0.0.0.0', port=5000, debug=True)