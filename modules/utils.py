import string
import base64
import random
import requests
import os
from urllib.parse import urlparse
from flask import g, request, make_response, jsonify
from flask_login import current_user
from werkzeug.security import generate_password_hash
from modules.db import db
from modules.models import AIFeatures, AIUser, AISignalWireParams, AIAgent, SharedAccess
from functools import wraps

def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def get_feature(agent_id, feature_name):
    full_url = request.url
    parsed_url = urlparse(full_url)
    path_segments = parsed_url.path.split('/')
    agent_id = path_segments[-1]

    feature = AIFeatures.query.filter_by(agent_id=agent_id, name=feature_name).first()
    return feature


def get_signalwire_param_by_agent_id(agent_id, param_name):
    user_id = db.session.query(AIAgent.user_id).filter(AIAgent.id == agent_id).scalar()

    if not user_id:
        return None 

    param = AISignalWireParams.query.filter_by(user_id=user_id, name=param_name).first()
    return param.value if param else None

def get_signalwire_param(param_name):
    param = AISignalWireParams.query.filter_by(user_id=current_user.id, name=param_name).first()
    return param.value if param else None

def extract_agent_id(f):
    def decorated_function(*args, **kwargs):
        g.agent_id = kwargs.get('agent_id')
        return f(*args, **kwargs)
    return decorated_function

def setup_default_agent_and_params(user_id):
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

    params_to_check = {
        'HTTP_PASSWORD': os.environ.get('HTTP_PASSWORD', generate_random_password()),
        'HTTP_USERNAME': os.environ.get('HTTP_USERNAME', generate_random_password()),
        'SPACE_NAME': os.environ.get('SPACE_NAME', 'subdomain.signalwire.com'),
        'AUTH_TOKEN': os.environ.get('AUTH_TOKEN', 'PTb4d1.....'),
        'PROJECT_ID': os.environ.get('PROJECT_ID', '5f1c4418-.....')
    }

    for param_name, default_value in params_to_check.items():
        if not get_signalwire_param(param_name):
            new_param = AISignalWireParams(
                user_id=user_id,
                name=param_name,
                value=default_value
            )
            db.session.add(new_param)

    db.session.commit()

def create_admin_user():
    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    full_name = os.environ.get('ADMIN_FULL_NAME', 'Admin User')

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
        except Exception as e:
            db.session.rollback() 
            print(f"Error while creating admin user: {str(e)}")
    else:
        print("Admin user already exists.")

def get_swaig_includes(url):
    parsed_url = urlparse(url)
    username = parsed_url.username
    password = parsed_url.password

    headers = {
        'Accept': 'application/json'
    }
    if username and password:
        headers['Authorization'] = f'Basic {base64.b64encode(f"{username}:{password}".encode()).decode()}'

    payload = {
        "functions": [],
        "action": "get_signature",
        "version": "2.0",
        "content_type": "text/swaig"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()  # Raises an HTTPError for bad responses

        # Check if the response is JSON
        if response.headers.get('Content-Type') == 'application/json':
            return response.json()
        else:
            print("Response is not JSON.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def user_has_access_to_agent(agent_id):
    owns_agent = AIAgent.query.filter_by(id=agent_id, user_id=current_user.id).first()
    has_shared_access = SharedAccess.query.filter_by(agent_id=agent_id, shared_with_user_id=current_user.id).first()
    return owns_agent or has_shared_access

def get_or_set_selected_agent_id():
    if not current_user or not hasattr(current_user, 'id'):
        raise ValueError("User is not authenticated or current_user is not set.")

    selected_agent_id = request.cookies.get('selectedAgentId')
    if not selected_agent_id:
        first_agent = AIAgent.query.filter_by(user_id=current_user.id).first()
        if first_agent:
            selected_agent_id = first_agent.id
            response = make_response()
            response.set_cookie('selectedAgentId', str(selected_agent_id), samesite='Strict')
            return selected_agent_id, response
        else:
            return None, jsonify({'message': 'No agents found for the user'}), 400
    return selected_agent_id, None

def check_agent_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        selected_agent_id, response = get_or_set_selected_agent_id()
        if not selected_agent_id:
            return response

        if not user_has_access_to_agent(selected_agent_id):
            return jsonify({'message': 'Permission denied'}), 403

        return f(selected_agent_id, *args, **kwargs)
    return decorated_function
