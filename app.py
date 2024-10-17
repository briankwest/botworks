import os, string, random
from datetime import datetime
import requests
from dotenv import load_dotenv

from flask import Flask, flash, make_response, jsonify, redirect, render_template, request, url_for, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, login_required, logout_user, current_user)
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.middleware.proxy_fix import ProxyFix

from modules.signalwireml import SignalWireML

def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def get_signal_wire_param(user_id, agent_id, param_name):
    param = AISignalWireParams.query.filter_by(user_id=user_id, agent_id=agent_id, name=param_name).first()
    return param.value if param else None

auth = HTTPBasicAuth()

# Custom decorator to extract agent_id and set it in the global context
def extract_agent_id(f):
    def decorated_function(*args, **kwargs):
        g.agent_id = kwargs.get('agent_id')
        return f(*args, **kwargs)
    return decorated_function

@auth.verify_password
def verify_password(username, password):
    # Extract the full URL from the request
    full_url = request.url
    
    # Parse the URL to extract the agent_id
    from urllib.parse import urlparse
    parsed_url = urlparse(full_url)
    path_segments = parsed_url.path.split('/')
    
    # Extract the agent_id, assuming it's the last segment
    agent_id = path_segments[-1]
    
    # Set the agent_id in the global context
    g.agent_id = agent_id

    # Proceed with the existing logic
    user = AIUser.query.filter_by(username=username).first()
    if user:
        http_password = get_signal_wire_param(user.id, agent_id, 'HTTP_PASSWORD')
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

# AIAgent model definition
class AIAgent(db.Model):
    __tablename__ = 'ai_agents'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    number = db.Column(db.String(50), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_agents', lazy=True))
    
    # Add cascade delete to all related models with unique backref names
    ai_debug_logs = db.relationship('AIDebugLogs', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_signalwire_params = db.relationship('AISignalWireParams', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_swml_requests = db.relationship('AISWMLRequest', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_functions = db.relationship('AIFunctions', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_function_argument = db.relationship('AIFunctionArgs', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_hints = db.relationship('AIHints', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_pronounce = db.relationship('AIPronounce', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_prompt = db.relationship('AIPrompt', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_language = db.relationship('AILanguage', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_conversation = db.relationship('AIConversation', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_params = db.relationship('AIParams', back_populates='agent', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f'<AIAgent {self.name}>'

# AIDebugLogs model definition
class AIDebugLogs(db.Model):
    __tablename__ = 'ai_debug_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference
    data = db.Column(db.JSON, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    user = db.relationship('AIUser', backref=db.backref('ai_debug_logs', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_debug_logs')

    def __repr__(self):
        return f'<AIDebugLogs {self.id}>'

# AISignalWireParams model definition
class AISignalWireParams(db.Model):
    __tablename__ = 'ai_signalwire_params'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_signalwire_params', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_signalwire_params')

    def __repr__(self):
        return f'<AISignalWireParams {self.name}: {self.value}>'

# AISWMLRequest model definition
class AISWMLRequest(db.Model):
    __tablename__ = 'ai_swml_requests'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference
    request = db.Column(db.JSON, nullable=False)
    response = db.Column(db.JSON, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    user = db.relationship('AIUser', backref=db.backref('ai_swml_requests', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_swml_requests')

    def __repr__(self):
        return f'<AISWMLRequest {self.id}>'

# AIFunctions model definition
class AIFunctions(db.Model):
    __tablename__ = 'ai_functions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference
    name = db.Column(db.Text, nullable=True)
    purpose = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)

    user = db.relationship('AIUser', backref=db.backref('ai_functions', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_functions')
    ai_function_args = db.relationship(
        'AIFunctionArgs', 
        back_populates='function', 
        cascade='all, delete-orphan', 
        lazy=True
    )

    def __repr__(self):
        return f'<AIFunctions {self.name}>'

# AIFunctionArgs model definition
class AIFunctionArgs(db.Model):
    __tablename__ = 'ai_function_argument'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    function_id = db.Column(db.Integer, db.ForeignKey('ai_functions.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference
    name = db.Column(db.Text, nullable=False)
    type = db.Column(db.Text, nullable=False, default='string')
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    required = db.Column(db.Boolean, nullable=False, default=False)
    enum = db.Column(db.Text, nullable=True)

    function = db.relationship(
        'AIFunctions', 
        back_populates='ai_function_args'
    )
    user = db.relationship('AIUser', backref=db.backref('ai_function_argument', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_function_argument')

    __table_args__ = (db.UniqueConstraint('user_id', 'function_id', 'name'),)

    def __repr__(self):
        return f'<AIFunctionArgs {self.name}>'

# AIHints model definition
class AIHints(db.Model):
    __tablename__ = 'ai_hints'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    hint = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference

    user = db.relationship('AIUser', backref=db.backref('ai_hints', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_hints')

    def __repr__(self):
        return f'<AIHints {self.hint}>'

# AIPronounce model definition
class AIPronounce(db.Model):
    __tablename__ = 'ai_pronounce'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ignore_case = db.Column(db.Boolean, nullable=False, default=False)
    replace_this = db.Column(db.Text, nullable=False)
    replace_with = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference

    user = db.relationship('AIUser', backref=db.backref('ai_pronounce', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_pronounce')

    def __repr__(self):
        return f'<AIPronounce {self.replace_this} -> {self.replace_with}>'

# AIPrompt model definition
class AIPrompt(db.Model):
    __tablename__ = 'ai_prompt'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    prompt_type = db.Column(db.Enum('prompt', 'post_prompt', 'outbound_prompt', 'outbound_post_prompt', name='prompt_type_enum'), nullable=False)
    prompt_text = db.Column(db.Text, nullable=True)
    top_p = db.Column(db.Float, nullable=True)
    temperature = db.Column(db.Float, nullable=True)
    max_tokens = db.Column(db.Integer, nullable=True)
    confidence = db.Column(db.Float, nullable=True)
    frequency_penalty = db.Column(db.Float, nullable=True)
    presence_penalty = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference

    user = db.relationship('AIUser', backref=db.backref('ai_prompt', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_prompt')

    #__table_args__ = (db.UniqueConstraint('user_id', 'prompt_type'),)

    def __repr__(self):
        return f'<AIPrompt {self.prompt_type}: {self.prompt_text}>'

# AILanguage model definition
class AILanguage(db.Model):
    __tablename__ = 'ai_language'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference
    code = db.Column(db.Text, nullable=True)
    name = db.Column(db.Text, nullable=True)
    voice = db.Column(db.Text, nullable=True)
    speech_fillers = db.Column(db.Text, nullable=True)
    function_fillers = db.Column(db.Text, nullable=True)
    language_order = db.Column(db.Integer, nullable=False, default=0)

    user = db.relationship('AIUser', backref=db.backref('ai_language', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_language')

    def __repr__(self):
        return f'<AILanguage {self.name}>'

# AIConversation model definition
class AIConversation(db.Model):
    __tablename__ = 'ai_conversation'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data = db.Column(db.JSON, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference

    user = db.relationship('AIUser', backref=db.backref('ai_conversation', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_conversation')

    def __repr__(self):
        return f'<AIConversation {self.id}>'

# AIParams model definition
class AIParams(db.Model):
    __tablename__ = 'ai_params'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)  # New reference
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_params', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_params')

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

# Login manager user loader
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
    agent_id = request.cookies.get('selectedAgentId')
    if not agent_id:
        # Fix: Ensure the query is fetching the first agent for the current user
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

# SWML Requests route
@app.route('/swmlrequests', methods=['GET'])
@login_required
def swmlrequests():
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    if request.headers.get('Accept') == 'application/json':
        # Fetch all SWML requests for the current user and selected agent
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

# Delete SWML Request route
@app.route('/swmlrequests/<int:request_id>', methods=['DELETE'])
@login_required
def delete_swmlrequest(request_id):
    swml_request = AISWMLRequest.query.get_or_404(request_id)
    
    if swml_request.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    db.session.delete(swml_request)
    db.session.commit()
    return jsonify({'message': 'SWML request deleted successfully'}), 200

# Dashboard Completed route
@app.route('/dashboard/completed', methods=['GET'])
@login_required
def dashboard_completed():
    from datetime import datetime, timedelta

    # Calculate the time range for the past 24 hours
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    # Initialize a dictionary to store the counts for each hour (default 0)
    hourly_counts = {start_time + timedelta(hours=i): 0 for i in range(24)}

    # Get the selected agent ID from cookies
    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    # Query to get the count of completed conversations grouped by hour
    completed_conversations = db.session.query(
        db.func.date_trunc('hour', AIConversation.created).label('hour'),
        db.func.count(AIConversation.id).label('count')
    ).filter(
        AIConversation.created >= start_time,
        AIConversation.created <= end_time,
        AIConversation.user_id == current_user.id,
        AIConversation.agent_id == selected_agent_id  # Filter by agent_id
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
                'created': f.created.isoformat()
            } for f in functions]
            return jsonify(function_list), 200
        else:
            return render_template('functions.html', user=current_user)
    elif request.method == 'POST':
        data = request.get_json()
        new_function = AIFunctions(
            name=data['name'],
            purpose=data['purpose'],
            user_id=current_user.id,
            agent_id=selected_agent_id
        )
        db.session.add(new_function)
        db.session.commit()
        return jsonify({'message': 'Function entry created successfully'}), 201

# Manage SWAIG Functions route
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

# Add SWAIG Function Arguments route
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
        description=data.get('description'),
        required=data.get('required', False),
        enum=data.get('enum')
    )
    db.session.add(new_arg)
    db.session.commit()
    return jsonify({'message': 'Function argument added successfully'}), 201

# Get Function Arguments route
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
        'enum': arg.enum
    } for arg in args]), 200

# Manage Function Arguments route
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

# Manage Hints route
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

# Manage Hints route
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


# Manage SignalWire Parameters route
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

# SignalWire Parameters route
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
            agent_id=selected_agent_id  # Use the selected agent_id from cookies
        )
        db.session.add(new_params)
        db.session.commit()
        return jsonify({'message': 'SignalWire entry created successfully'}), 201

# Manage Parameters route
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

# Parameters route
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

            # Create default agent "BotWorks" if it doesn't exist
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
                print("Default agent 'BotWorks' created successfully.")
            else:
                agent_id = default_agent.id
                print("Default agent 'BotWorks' already exists.")

            # Set the selectedAgentId cookie if not set
            if not request.cookies.get('selectedAgentId'):
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('selectedAgentId', str(agent_id))
                return response

            # Check if HTTP_PASSWORD exists for the user, if not, create it
            http_password = get_signal_wire_param(user.id, agent_id, 'HTTP_PASSWORD')
            if not http_password:
                random_password = generate_random_password()
                # Check and add HTTP_PASSWORD if it doesn't exist
                if not get_signal_wire_param(user.id, agent_id, 'HTTP_PASSWORD'):
                    new_param = AISignalWireParams(
                        user_id=user.id,
                        agent_id=agent_id,  # Use the new agent_id
                        name='HTTP_PASSWORD',
                        value=random_password
                    )
                    db.session.add(new_param)

            # Check and add SPACE_NAME if it doesn't exist
            if not get_signal_wire_param(user.id, agent_id, 'SPACE_NAME'):
                    new_param = AISignalWireParams(
                        user_id=user.id,
                        agent_id=agent_id,  # Use the new agent_id
                        name='SPACE_NAME',
                        value='subdomain.signalwire.com'  # Add appropriate default value if needed
                    )
                    db.session.add(new_param)

            # Check and add AUTH_TOKEN if it doesn't exist
            if not get_signal_wire_param(user.id, agent_id, 'AUTH_TOKEN'):
                new_param = AISignalWireParams(
                    user_id=user.id,
                    agent_id=agent_id,  # Use the new agent_id
                    name='AUTH_TOKEN',
                    value='PTb4d1.....'  # Add appropriate default value if needed
                )
                db.session.add(new_param)

            # Check and add PROJECT_ID if it doesn't exist
            if not get_signal_wire_param(user.id, agent_id, 'PROJECT_ID'):
                new_param = AISignalWireParams(
                    user_id=user.id,
                    agent_id=agent_id,  # Use the new agent_id
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
def generate_swml_response(user_id, agent_id, request_body):
    request_body = request_body or {}
    swml = SignalWireML(version="1.0.0")
    
    # Determine if the request is outbound
    outbound = request_body.get('outbound', False)
    
    # Select the appropriate prompt based on the outbound flag
    if outbound:
        prompt = AIPrompt.query.filter_by(user_id=user_id, agent_id=agent_id, prompt_type='outbound_prompt').first()
        post_prompt = AIPrompt.query.filter_by(user_id=user_id, agent_id=agent_id, prompt_type='outbound_post_prompt').first()
    else:
        prompt = AIPrompt.query.filter_by(user_id=user_id, agent_id=agent_id, prompt_type='prompt').first()
        post_prompt = AIPrompt.query.filter_by(user_id=user_id, agent_id=agent_id, prompt_type='post_prompt').first()

    if not prompt:
        return jsonify({'error': 'Prompt not found'}), 404

    # Set up the initial prompt
    aiprompt_data = {
        "temperature": prompt.temperature if prompt.temperature is not None else 0.5,
        "top_p": prompt.top_p if prompt.top_p is not None else 0.5,
        "text": prompt.prompt_text
    }
    if prompt.frequency_penalty is not None and prompt.frequency_penalty != 0.0:
        aiprompt_data["frequency_penalty"] = prompt.frequency_penalty
    if prompt.presence_penalty is not None and prompt.presence_penalty != 0.0:
        aiprompt_data["presence_penalty"] = prompt.presence_penalty
    if prompt.max_tokens is not None and prompt.max_tokens != 0:
        aiprompt_data["max_tokens"] = prompt.max_tokens
    if prompt.confidence is not None and prompt.confidence != 0.0:
        aiprompt_data["confidence"] = prompt.confidence
   
    swml.set_aiprompt(aiprompt_data)
    
    # Add post_prompt if available
    if post_prompt:
        post_prompt_data = {
            "temperature": post_prompt.temperature if post_prompt.temperature is not None else 0.5,
            "top_p": post_prompt.top_p if post_prompt.top_p is not None else 0.5,
            "text": post_prompt.prompt_text
        }
        if post_prompt.frequency_penalty is not None and post_prompt.frequency_penalty != 0.0:
            post_prompt_data["frequency_penalty"] = post_prompt.frequency_penalty
        if post_prompt.presence_penalty is not None and post_prompt.presence_penalty != 0.0:
            post_prompt_data["presence_penalty"] = post_prompt.presence_penalty
        if post_prompt.max_tokens is not None:
            post_prompt_data["max_tokens"] = post_prompt.max_tokens
        if post_prompt.confidence is not None and post_prompt.confidence != 0.0:
            post_prompt_data["confidence"] = post_prompt.confidence

        swml.set_aipost_prompt(post_prompt_data)
    
    # Add hints
    hints = AIHints.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    swml.add_aihints([hint.hint for hint in hints])
    
    # Add parameters
    ai_params = AIParams.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    params_dict = {param.name: param.value for param in ai_params}
    swml.set_aiparams(params_dict)
    
    # Add languages
    languages = AILanguage.query.filter_by(user_id=user_id, agent_id=agent_id).order_by(AILanguage.language_order.asc()).all()
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
    pronounces = AIPronounce.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    for pronounce in pronounces:
        swml.add_aipronounce({
            "replace_this": pronounce.replace_this,
            "replace_with": pronounce.replace_with,
            "ignore_case": pronounce.ignore_case
        })

    # Add functions
    functions = AIFunctions.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    for function in functions:
        function_data = {
            "function": function.name,
            "purpose": function.purpose,
            "argument": {
                "properties": {}
            }
        }
        function_args = AIFunctionArgs.query.filter_by(function_id=function.id, agent_id=agent_id).all()
        for arg in function_args:
            function_data["argument"]["properties"][arg.name] = {
                "type": arg.type,
                "description": arg.description
            }
            if arg.enum and arg.type == 'array':
                function_data["argument"]["properties"][arg.name]["enum"] = arg.enum.split(',')

        function_data["argument"]["type"] = "object"

        function_payload = {
            "name": function.name,
            "purpose": function.purpose,
            "arguments": function_data["argument"],
            "required": [arg.name for arg in function_args if arg.required]
        }
        if not function.active:
            function_payload["active"] = function.active
        swml.add_aiswaigfunction(function_payload)
    
    # Set URLs with authentication if available
    auth_user = AIUser.query.filter_by(id=user_id, agent_id=agent_id).first().username
    auth_pass = get_signal_wire_param(user_id, agent_id, 'HTTP_PASSWORD')
    
    post_prompt_url = f"https://{request.host}/postprompt/{user_id}/{agent_id}"
    if auth_user and auth_pass:
        post_prompt_url = f"https://{auth_user}:{auth_pass}@{request.host}/postprompt/{user_id}/{agent_id}"
    swml.set_aipost_prompt_url({"post_prompt_url": post_prompt_url})

    web_hook_url = f"https://{request.host}/swaig/{user_id}/{agent_id}"
    if auth_user and auth_pass:
        web_hook_url = f"https://{auth_user}:{auth_pass}@{request.host}/swaig/{user_id}/{agent_id}"
    swml.add_aiswaigdefaults({"web_hook_url": web_hook_url})

    debug_webhook_url = f"https://{request.host}/debughook/{user_id}"
    if auth_user and auth_pass:
        debug_webhook_url = f"https://{auth_user}:{auth_pass}@{request.host}/debugwebhook/{user_id}/{agent_id}"
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
        agent_id=agent_id,  # Include agent_id in the request log
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
@app.route('/yaml/<int:id>/<int:agent_id>', methods=['POST', 'GET'])
@auth.login_required
def get_yaml(id, agent_id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        # For GET requests, you could handle query parameters or defaults
        data = request.args.to_dict()  # Get query parameters

    # Generate response in YAML format
    response_data = generate_swml_response(id, agent_id, request_body=data)
    # Import the yaml module
    import yaml
    # Create the response with the correct Content-Type
    response = make_response(yaml.dump(response_data))
    response.headers['Content-Type'] = 'text/x-yaml'
    
    return response

# Generate SWML Response route
@app.route('/swml/<int:user_id>/<int:agent_id>', methods=['POST', 'GET'])
@auth.login_required
@extract_agent_id
def swml(user_id, agent_id):
    if request.method == 'POST':
        data = request.get_json()
    else:
        data = request.args.to_dict()  # Get query parameters

    # Generate response in JSON format
    response_data = generate_swml_response(user_id, agent_id, request_body=data)
    
    # Create the response with the correct Content-Type
    response = make_response(jsonify(response_data))
    response.headers['Content-Type'] = 'application/json'
    
    return response

# Post Prompt route
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

# Delete Pronounce route
@app.route('/pronounce/<int:id>', methods=['DELETE'])
@login_required
def delete_pronounce(id):
    pronounce_entry = AIPronounce.query.get_or_404(id)
    db.session.delete(pronounce_entry)
    db.session.commit()
    return jsonify({'message': 'Pronounce entry deleted successfully'}), 200

# Manage Prompt route
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
                agent_id=selected_agent_id,  # Ensure agent_id is set
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

# Delete Prompt route
@app.route('/prompt/<int:id>', methods=['DELETE'])
@login_required
def delete_prompt(id):
    prompt_entry = AIPrompt.query.get_or_404(id)
    
    if prompt_entry.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    db.session.delete(prompt_entry)
    db.session.commit()
    return jsonify({'message': 'Prompt deleted successfully'}), 200


# Update Prompt route
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

# Manage Language route
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

# Update Datasphere route to use selected agent ID
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
            print(response)
            if response.status_code == 200:
                return jsonify(response.json()), 200
        else:   
            return render_template('datasphere.html', user=current_user)

# Create Datasphere route to use selected agent ID
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
    else:
        return jsonify({'error': 'Failed to create datasphere'}), response.status_code

# Delete Datasphere route to use selected agent ID
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

# Manage Agents route
@app.route('/agents', methods=['GET', 'POST'])
@login_required
def agents():
    if request.method == 'GET':
        if request.headers.get('Accept') == 'application/json':
            # Serve JSON data
            agents = AIAgent.query.filter_by(user_id=current_user.id).all()
            agents_data = [{'id': agent.id, 'name': agent.name, 'number': agent.number, 'created': agent.created} for agent in agents]
            return jsonify(agents_data), 200
        else:
            # Render HTML
            return render_template('agents.html', user=current_user)

    elif request.method == 'POST':
        # Create a new agent
        data = request.get_json()
        name = data.get('name')
        number = data.get('number')

        if not name:
            return jsonify({'error': 'Name is required'}), 400

        new_agent = AIAgent(name=name, number=number, user_id=current_user.id)
        db.session.add(new_agent)
        db.session.commit()

        # Set default SignalWire parameters for the new agent
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

# Delete Agents route
@app.route('/agents/<int:id>', methods=['DELETE'])
@login_required
def delete_agent(id):
    agent = AIAgent.query.get_or_404(id)

    # Prevent deletion of the "BotWorks" agent
    if agent.name == "BotWorks":
        return jsonify({'message': 'Cannot delete the default agent "BotWorks".'}), 403

    if agent.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    db.session.delete(agent)
    db.session.commit()

    return jsonify({'message': 'Agent deleted successfully'}), 200

# Update Agents route
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

# Create Debug Webhook route
@app.route('/debugwebhook/<int:user_id>/<int:agent_id>', methods=['POST'])
@auth.login_required
def create_debuglog(user_id, agent_id):
    data = request.get_json()
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    new_log = AIDebugLogs(
        user_id=user_id,
        agent_id=agent_id,
        data=data,
        ip_address=ip_address
    )
    db.session.add(new_log)
    db.session.commit()

    return jsonify({'message': 'Debug log created successfully'}), 201

@app.route('/debuglogs/<int:agent_id>', methods=['GET'])
@login_required
def get_debuglogs(agent_id):
    logs = AIDebugLogs.query.filter_by(user_id=current_user.id, agent_id=agent_id).all()
    logs_data = [{'id': log.id, 'created': log.created, 'data': log.data, 'ip_address': log.ip_address} for log in logs]
    return jsonify(logs_data), 200

@app.route('/debuglogs', methods=['GET'])
@login_required
def debuglogs():
    return render_template('debuglog.html', user=current_user)

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(host='0.0.0.0', port=5000, debug=True)