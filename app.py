

"""
This Flask application serves as a backend for managing AI agents and their interactions
with users. 

The application uses SQLAlchemy for database interactions and Flask-Login for user session management.
It also supports JSON and HTML responses for various routes, allowing for both API and web-based interactions.
"""
# Monkey patching for eventlet to make IO non-blocking
import eventlet
eventlet.monkey_patch()
# Importing required libraries
import os
import jwt
import base64
import string
import random
import json
import redis
import yaml
import requests
import logging
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
from flask_migrate import Migrate
from dotenv import load_dotenv
from urllib.parse import urlparse
from modules.signalwireml import SignalWireML

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('werkzeug').setLevel(logging.WARNING)



def get_feature(agent_id, feature_name):
        # Extract the full URL from the request
    full_url = request.url
    
    # Parse the URL to extract the agent_id
    parsed_url = urlparse(full_url)
    path_segments = parsed_url.path.split('/')
    
    # Extract the agent_id, assuming it's the last segment
    agent_id = path_segments[-1]
    user_id = path_segments[-2]
  
    feature = AIFeatures.query.filter_by(agent_id=agent_id, name=feature_name, user_id=user_id).first()
    return feature

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

# Apply CORS to the entire app
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")  # Allow all origins

# Apply ProxyFix middleware
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

load_dotenv()

# Configuration
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['REDIS_URL'] = os.environ.get('REDIS_URL')
app.config['ACCESS_SECRET_KEY'] = os.environ.get('ACCESS_SECRET_KEY')
app.config['REFRESH_SECRET_KEY'] = os.environ.get('REFRESH_SECRET_KEY')

# Initialize the Redis client
redis_client = redis.from_url(app.config['REDIS_URL'])

# Explicitly set the static folder path (optional)
app.static_folder = os.path.abspath('static')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

with app.app_context():
    # Perform operations that require the app context here
    # e.g., db operations, accessing current_user, etc.
    pass

# Dictionary to keep track of Redis pubsub threads and subscribers for each room
pubsub_threads = {}
active_clients = {}

def redis_listener(channel):
    """Subscribe to a Redis channel once and emit messages to WebSocket clients."""
    pubsub = redis_client.pubsub()
    print(f"Subscribing to channel: {channel}")
    print(f"Pubsub: {pubsub}")
    print(f"Channel: {channel}")
    pubsub.subscribe(channel)
    if channel not in pubsub_threads:
        pubsub.subscribe(channel)

    while True:
        message = pubsub.get_message()
        if message and message['type'] == 'message':
            # Emit the message to clients in the WebSocket room (same as Redis channel)
            socketio.emit('response', {'data': message['data'].decode('utf-8'), 'channel': channel}, room=channel)
        # If no clients are left in the channel, stop the listener
        if active_clients[channel] == 0:
            pubsub.unsubscribe(channel)
            break  # Exit the loop, ending the thread

        # Sleep briefly to prevent high CPU usage
        eventlet.sleep(0.1)

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
    ai_features = db.relationship('AIFeatures', back_populates='agent', cascade='all, delete-orphan', lazy=True)

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
    webhook_url = db.Column(db.String(255), nullable=True)  # New field

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

# AIFeatures model definition
class AIFeatures(db.Model):
    __tablename__ = 'ai_features'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_features', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_features')

    def __repr__(self):
        return f'<AIFeatures {self.name}: {self.value}, Enabled: {self.enabled}>'

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

def setup_default_agent_and_params(user_id):
    """Set up a default agent and necessary parameters for a user."""
    # Create default agent "BotWorks" if it doesn't exist
    default_agent_name = "BotWorks"
    default_agent = AIAgent.query.filter_by(name=default_agent_name, user_id=user_id).first()
    if default_agent is None:
        new_agent = AIAgent(
            name=default_agent_name,
            user_id=user_id
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
        response.set_cookie('selectedAgentId', str(agent_id), samesite='Strict')
        return response

    # Check and add necessary parameters if they don't exist
    params_to_check = {
        'HTTP_PASSWORD': generate_random_password(),
        'SPACE_NAME': 'subdomain.signalwire.com',
        'AUTH_TOKEN': 'PTb4d1.....',
        'PROJECT_ID': '5f1c4418-.....'
    }

    for param_name, default_value in params_to_check.items():
        if not get_signal_wire_param(user_id, agent_id, param_name):
            new_param = AISignalWireParams(
                user_id=user_id,
                agent_id=agent_id,
                name=param_name,
                value=default_value
            )
            db.session.add(new_param)

    db.session.commit()

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
            agent_id=selected_agent_id,
            webhook_url=data.get('webhook_url')  # Include webhook_url
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
            'active': function_entry.active,
            'webhook_url': function_entry.webhook_url  # Include webhook_url
        }), 200

    elif request.method == 'PUT':
        data = request.get_json()
        function_entry.name = data.get('name', function_entry.name)
        function_entry.purpose = data.get('purpose', function_entry.purpose)
        function_entry.active = data.get('active', function_entry.active)
        function_entry.webhook_url = data.get('webhook_url', function_entry.webhook_url)  # Update webhook_url
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
    
@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.json.get('refresh_token')
    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing'}), 400

    try:
        # Decode the refresh token
        data = jwt.decode(refresh_token, app.config['REFRESH_SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']

        # Generate a new access token
        new_access_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(minutes=60)  # Token expires in 15 minutes
        }, app.config['ACCESS_SECRET_KEY'], algorithm='HS256')

        return jsonify({'access_token': new_access_token, 'expires_in': 3600}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token'}), 401
    
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
        prompt = AIPrompt(
            user_id=user_id,
            agent_id=agent_id,
            prompt_type='outbound_prompt' if outbound else 'prompt',
            prompt_text="You are a helpful assistant.",
            top_p=0.5,
            temperature=0.5
        )
        db.session.add(prompt)
        db.session.commit()

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
    
    # Add parameters
    ai_params = AIParams.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    params_dict = {param.name: param.value for param in ai_params}
    swml.set_aiparams(params_dict)

    # Set URLs with authentication if available
    auth_user = AIUser.query.filter_by(id=user_id).first().username
    auth_pass = get_signal_wire_param(user_id, agent_id, 'HTTP_PASSWORD')
    
    post_prompt_url = f"https://{request.host}/postprompt/{user_id}/{agent_id}"
    if auth_user and auth_pass:
        post_prompt_url = f"https://{auth_user}:{auth_pass}@{request.host}/postprompt/{user_id}/{agent_id}"
        swml.set_aipost_prompt_url({"post_prompt_url": post_prompt_url})

    web_hook_url = f"https://{request.host}/swaig/{user_id}/{agent_id}"
    if auth_user and auth_pass:
        web_hook_url = f"https://{auth_user}:{auth_pass}@{request.host}/swaig/{user_id}/{agent_id}"
        swml.add_aiswaigdefaults({"web_hook_url": web_hook_url})

    debug_webhook_url = f"https://{request.host}/debugwebhook/{user_id}/{agent_id}"
    if auth_user and auth_pass:
        debug_webhook_url = f"https://{auth_user}:{auth_pass}@{request.host}/debugwebhook/{user_id}/{agent_id}"
        swml.add_aiparams({"debug_webhook_url": debug_webhook_url})

    # Add hints
    hints = AIHints.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    swml.add_aihints([hint.hint for hint in hints])
            
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
            **({"webhook_url": function.webhook_url} if function.webhook_url else {}),
            "required": [arg.name for arg in function_args if arg.required]
        }
        if not function.active:
            function_payload["active"] = function.active
        swml.add_aiswaigfunction(function_payload)

    # Check if the ENABLE_MESSAGE feature is enabled for the agent
    enable_message_feature = get_feature(agent_id, 'ENABLE_MESSAGE')

    if enable_message_feature and enable_message_feature.enabled:
        # Create a new SignalWireML instance
        msg = SignalWireML(version="1.0.0")

        # Add the application with the send_sms function
        msg.add_application("main", "send_sms", {
            "to_number": '${args.to}',
            "from_number": enable_message_feature.value,
            "body": '${args.message}'
        })

        # Check if ENABLE_MESSAGE_INACTIVE is set
        enable_message_inactive = get_feature(agent_id, 'ENABLE_MESSAGE_INACTIVE')

        swml.add_aiswaigfunction({
            "function": "send_message",
            **({"active": False} if enable_message_inactive and enable_message_inactive.enabled else {}),
            "purpose": "use to send text a message to the user",
            "argument": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "the message to send via text message to the user"
                    },
                    "to": {
                        "type": "string",
                        "description": "The user's number in e.164 format"
                    }
                },
                "required": ["message", "to"]
            },
            "data_map": {
                    "expressions": [{
                        "string": '${args.message}',
                        "pattern": ".*",
                        "output": {
                            "response": "Message sent.",
                            "action": [{"SWML": msg.render()}]
                        }
                }]
            }
        })
    
    # Check if the ENABLE_TRANSFER feature is enabled for the agent
    enable_transfer_feature = get_feature(agent_id, 'ENABLE_TRANSFER')

    if enable_transfer_feature and enable_transfer_feature.enabled:
        # Create a new SignalWireML instance for transfer
        transfer = SignalWireML(version="1.0.0")

        # Add the application with the connect function
        transfer.add_application("main", "connect", {
            "to": '${meta_data.table.${lc:args.target}}',
            "from": 'assistant'  # Replace 'assistant' with the appropriate variable
        })

        # Parse the TRANSFER_TABLE configuration
        transfer_table = get_feature(agent_id, 'TRANSFER_TABLE')
        transfer_hash = {}
        for pair in transfer_table.value.split('|'):
            key, value = pair.split(':', 1)
            transfer_hash[key] = value

        enable_transfer_inactive = get_feature(agent_id, 'ENABLE_TRANSFER_INACTIVE')

        # Add the transfer function to SWML
        swml.add_aiswaigfunction({
            "function": "transfer",
            **({"active": False} if enable_transfer_inactive and enable_transfer_inactive.enabled else {}),
            "purpose": "use to transfer to a target",
            "meta_data": {
                "table": transfer_hash
            },
            "argument": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "the target to transfer to"
                    }
                },
                "required": ["target"]
            },
            "data_map": {
                "expressions": [
                    {
                        "string": '${meta_data.table.${lc:args.target}}',
                        "pattern": '\\w+',
                        "output": {
                            "response": "Tell the user you are going to transfer the call to whoever they asked for. Do not change languages from the one you are currently using. Do not hangup.",
                            "action": [{"SWML": transfer.render(), "transfer": 'true'}]
                        }
                    },
                    {
                        "string": '${args.target}',
                        "pattern": '.*',
                        "output": {
                            "response": "I'm sorry, I was unable to transfer your call to ${input.args.target}."
                        }
                    }
                ]
            }
        })
    
    # Retrieve API_NINJAS_KEY using get_feature
    api_ninjas_key_feature = get_feature(agent_id, 'API_NINJAS_KEY')
    api_ninjas_key = api_ninjas_key_feature.value if api_ninjas_key_feature and api_ninjas_key_feature.enabled else None

    if api_ninjas_key:
        # Add weather function if enabled
        enable_weather_feature = get_feature(agent_id, 'ENABLE_WEATHER')
        if enable_weather_feature and enable_weather_feature.enabled:
            swml.add_aiswaigfunction({
                "function": "get_weather",
                "purpose": "latest weather information for any city",
                "argument": {
                    "type": "object",
                    "properties": {
                        "city": {
                            "type": "string",
                            "description": "City name."
                        },
                        "state": {
                            "type": "string",
                            "description": "US state for United States cities only. Optional"
                        }
                    }
                },
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/weather?city=${{enc:args.city}}&state=${{enc:args.state}}',
                        "method": "GET",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'Be sure to say the temperature in Fahrenheit. The weather in ${input.args.city} ${temp}C, Humidity: ${humidity}%, High: ${max_temp}C, Low: ${min_temp}C Wind Direction: ${wind_degrees} (say cardinal direction), Clouds: ${cloud_pct}%, Feels Like: ${feels_like}C.'
                        }
                    }]
                }
            })

        # Add jokes function if enabled
        enable_jokes_feature = get_feature(agent_id, 'ENABLE_JOKES')
        if enable_jokes_feature and enable_jokes_feature.enabled:
            dj = SignalWireML(version="1.0.0")
            dj.add_application("main", "set", {"dad_joke": '${array[0].joke}'})

            swml.add_aiswaigfunction({
                "function": "get_joke",
                "purpose": "tell a joke",
                "argument": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "must either be 'jokes' or 'dadjokes'"
                        }
                    }
                },
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/${{args.type}}',
                        "method": "GET",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'Tell the user: ${array[0].joke}',
                            "action": [{"SWML": dj.render()}]
                        }
                    }]
                }
            })

        # Add trivia function if enabled
        enable_trivia_feature = get_feature(agent_id, 'ENABLE_TRIVIA')
        if enable_trivia_feature and enable_trivia_feature.enabled:
            swml.add_aiswaigfunction({
                "function": "get_trivia",
                "purpose": "get a trivia question",
                "argument": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Valid options are artliterature, language, sciencenature, general, fooddrink, peopleplaces, geography, historyholidays, entertainment, toysgames, music, mathematics, religionmythology, sportsleisure. Pick a category at random if not asked for a specific category."
                        }
                    }                },
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/trivia?category=${{args.category}}',
                        "method": "GET",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'category ${array[0].category} questions: ${array[0].question} answer: ${array[0].answer}, be sure to give the user time to answer before saying the answer.'
                        }
                    }]
                }
            })

    # Check if the ENABLE_DATASPHERE feature is enabled for the agent
    enable_datasphere_feature = get_feature(agent_id, 'ENABLE_DATASPHERE')
    if enable_datasphere_feature and enable_datasphere_feature.enabled:
        # Retrieve the document ID from the feature's value
        document_id = enable_datasphere_feature.value

        # Retrieve SIGNALWIRE details
        space_name = get_signal_wire_param(user_id, agent_id, 'SPACE_NAME')
        project_id = get_signal_wire_param(user_id, agent_id, 'PROJECT_ID')
        auth_token = get_signal_wire_param(user_id, agent_id, 'AUTH_TOKEN')

        # Construct the URL and authorization header
        encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
        url = f"https://{space_name}/api/datasphere/documents/search"
        authorization = f"Basic {encoded_credentials}"

        # Add the get_vector_data function
        swml.add_aiswaigfunction({
            "function": "get_vector_data",
            "data_map": {
                "webhooks": [
                    {
                        "method": "POST",
                        "url": url,
                        "headers": {
                            "Content-Type": "application/json",
                            "Authorization": authorization
                        },
                        "params": {
                            "query_string": "${args.user_question}",
                            "document_id": document_id,
                            "count": 1
                        },
                        "output": {
                            "response": 'Use this information to answer the user\'s query, only provide answers from this information and do not make up anything: ${chunks[0].text} and ${chunks[0].document_id}'
                        }
                    }
                ]
            },
            "purpose": "The question the user will ask",
            "argument": {
                "properties": {
                    "user_question": {
                        "type": "string",
                        "description": "The question the user will ask."
                    }
                },
                "type": "object"
            }
        })

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
    elif response.status_code == 401:  # Unauthorized
        return jsonify({'error': 'SignalWire credentials missing'}), 401
    else:
        return jsonify({'error': 'An error occurred while searching the document'}), response.status_code

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

            if response.status_code == 200:
                return jsonify(response.json()), 200
            elif response.status_code == 401:  # Unauthorized
                return jsonify({'error': 'SignalWire credentials missing'}), 401
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
    elif response.status_code == 401:  # Unauthorized
        return jsonify({'error': 'SignalWire credentials missing'}), 401
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

# Clone Agents route
@app.route('/agents/clone/<int:agent_id>', methods=['POST'])
@login_required
def clone_agent(agent_id):
    # Retrieve the original agent
    original_agent = AIAgent.query.get_or_404(agent_id)

    # Check if the current user owns the agent
    if original_agent.user_id != current_user.id:
        return jsonify({'message': 'Permission denied'}), 403

    random_bits = generate_random_password(4)

    # Create a new agent with the same details
    new_agent = AIAgent(
        user_id=original_agent.user_id,
        name=f"{original_agent.name} Copy {random_bits}",
        number=original_agent.number
    )
    db.session.add(new_agent)
    db.session.commit()

    # Clone related data models
    def clone_relationships(original, new, relationship_name):
        related_items = getattr(original, relationship_name)
        for item in related_items:
            new_item = item.__class__(**{col.name: getattr(item, col.name) for col in item.__table__.columns if col.name != 'id'})
            new_item.agent_id = new.id
            db.session.add(new_item)

    # List of relationships to clone
    relationships = [
        'ai_signalwire_params', 'ai_functions', 'ai_function_argument', 'ai_hints', 'ai_pronounce', 'ai_prompt', 'ai_language', 'ai_params', 'ai_features'
    ]

    for relationship in relationships:
        clone_relationships(original_agent, new_agent, relationship)

    db.session.commit()

    return jsonify({'message': 'Agent cloned successfully', 'new_agent_id': new_agent.id}), 201


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
    
# Get Agent route
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

#live debug route
@app.route('/livedebug', methods=['GET'])
@login_required
def livedebug():
    selected_agent_id = request.cookies.get('selectedAgentId')
    user_id = current_user.id

    if not selected_agent_id:
        return jsonify({'message': 'Agent ID not found in cookies'}), 400

    # Check if the current user owns the agent
    agent = AIAgent.query.filter_by(id=selected_agent_id, user_id=current_user.id).first_or_404()

    channel = f'debug_channel_{user_id}_{selected_agent_id}'

    # Render the live debug template and pass the user_id and agent_id
    return render_template('livedebug.html', channel=channel)

# WebSocket connection and authentication
@socketio.on('connect')
def on_connect():
    """Handle client connection and authenticate using JWT from cookies."""
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        # Decode the access token
        data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']

        # Verify the user exists
        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        # Authentication successful
        emit('status', {'message': 'Authentication successful'}, namespace='/')

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('join')
def on_join(data):
    """Handle client joining a specific channel with authentication."""
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        # Decode the access token
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']

        user = db.session.get(AIUser, user_id)

        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        # Authentication successful, proceed to join the channel
        channel = data['channel']
        join_room(channel)  # Join the WebSocket room

        # Track number of active clients per channel
        if channel not in active_clients:
            print(f"Client joined channel {channel}")
            active_clients[channel] = 0
        active_clients[channel] += 1

        # If no listener exists for this channel, create one
        if channel not in pubsub_threads:
            print(f"Creating listener for channel {channel}")
            pubsub_threads[channel] = eventlet.spawn(redis_listener, channel)

        emit('status', {'message': f'Joined channel {channel}'}, room=channel)

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('leave')
def on_leave(data):
    """Handle client leaving a specific channel with authentication."""
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        # Decode the access token
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']

        # Verify the user exists
        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        # Authentication successful, proceed to leave the channel
        channel = data['channel']
        leave_room(channel)  # Leave the WebSocket room

        # Decrease the count of active clients in the channel
        if channel in active_clients:
            print(f"Client left channel {channel}")
            active_clients[channel] -= 1

            # If no clients are left, allow the Redis listener to terminate
            if active_clients[channel] == 0:
                print(f"No clients remain in channel {channel}, stopping listener.")
                del pubsub_threads[channel]  # Remove the thread from tracking
                emit('status', {'message': f'No more clients in {channel}. Channel listener stopping.'}, room=channel)

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('disconnect')
def on_disconnect():
    """Handle client disconnection with authentication."""
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        # Decode the access token
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']

        # Verify the user exists
        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        # Authentication successful, proceed with disconnection
        for channel in list(active_clients.keys()):
            if channel in active_clients:
                active_clients[channel] -= 1
                print(f"Client disconnected from channel {channel}")

                # If no clients are left, allow the Redis listener to terminate
                if active_clients[channel] == 0:
                    pubsub_threads[channel].kill()  # Terminate the listener thread
                    del pubsub_threads[channel]  # Remove the thread from the dictionary
                    del active_clients[channel]  # Remove the channel from active clients
                    print(f"Listener for channel {channel} terminated")

    except jwt.ExpiredSignatureError:
        emit('error', {'message': 'Access token expired'}, namespace='/')
        disconnect()
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Invalid access token'}, namespace='/')
        disconnect()

@socketio.on('send_message')
def handle_message(data):
    """Handle message sent by client to a specific channel with authentication."""
    access_token = request.cookies.get('access_token')
    if not access_token:
        emit('error', {'message': 'Access token is missing'}, namespace='/')
        disconnect()
        return

    try:
        # Decode the access token
        token_data = jwt.decode(access_token, app.config['ACCESS_SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']

        # Verify the user exists
        user = db.session.get(AIUser, user_id)
        if not user:
            emit('error', {'message': 'User not found'}, namespace='/')
            disconnect()
            return

        # Authentication successful, proceed to handle the message
        message = data['message']
        channel = data['channel']
        redis_client.publish(channel, message)
        # Dump the pubsub_threads and active_clients for debugging
        print("Current pubsub_threads:", pubsub_threads)
        print("Current active_clients:", active_clients)  # Publish the message to the corresponding Redis channel

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
    
    # Create a dynamic channel name
    channel_name = f'debug_channel_{user_id}_{agent_id}'

    # Publish the data to the dynamic Redis channel
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

# Debug Logs route for specific agent
@app.route('/debuglogs/<int:agent_id>', methods=['GET', 'DELETE'])
@login_required
def get_debuglogs(agent_id):
    if request.method == 'GET':
        logs = AIDebugLogs.query.filter_by(user_id=current_user.id, agent_id=agent_id).all()
        logs_data = [{'id': log.id, 'created': log.created, 'data': log.data, 'ip_address': log.ip_address} for log in logs]
        return jsonify(logs_data), 200

    elif request.method == 'DELETE':
        # Delete all logs for the specified agent
        AIDebugLogs.query.filter_by(user_id=current_user.id, agent_id=agent_id).delete()
        db.session.commit()
        return jsonify({'message': 'All debug logs for the agent deleted successfully'}), 200

# Debug Logs route
@app.route('/debuglogs', methods=['GET'])
@login_required
def debuglogs():
    return render_template('debuglog.html', user=current_user)

# Manage AI Feature route
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


# AI Features route
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

# AI Features route
@app.route('/aifeatures', methods=['GET'])
@login_required
def aifeatures():
    return render_template('features.html', user=current_user)

# AI Features route
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

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    socketio.run(app, host='0.0.0.0', port=5000, debug=os.getenv('DEBUG'))