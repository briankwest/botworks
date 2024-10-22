import string, base64
import random
import requests
import os
from urllib.parse import urlparse
from flask import g, request
from werkzeug.security import generate_password_hash
from modules.db import db
from modules.models import AIFeatures, AIUser, AISignalWireParams, AIAgent

def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def get_feature(agent_id, feature_name):
    full_url = request.url
    parsed_url = urlparse(full_url)
    path_segments = parsed_url.path.split('/')
    agent_id = path_segments[-1]
    user_id = path_segments[-2]
    feature = AIFeatures.query.filter_by(agent_id=agent_id, name=feature_name, user_id=user_id).first()
    return feature

def get_signal_wire_param(user_id, agent_id, param_name):
    param = AISignalWireParams.query.filter_by(user_id=user_id, agent_id=agent_id, name=param_name).first()
    return param.value if param else None

def extract_agent_id(f):
    def decorated_function(*args, **kwargs):
        g.agent_id = kwargs.get('agent_id')
        return f(*args, **kwargs)
    return decorated_function

def setup_default_agent_and_params(user_id):
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

def create_admin_user():
    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    full_name = os.environ.get('ADMIN_FULL_NAME', 'Admin User')

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
        except Exception as e:
            db.session.rollback() 
            print(f"Error while creating admin user: {str(e)}")
    else:
        print("Admin user already exists.")

# Get SWAIG includes function
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
    response = requests.post(url, json=payload, headers=headers)
    print(response.json())  
    return response.json()
