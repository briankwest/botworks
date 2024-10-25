from modules.db import db
from flask_login import UserMixin
from datetime import datetime

class AIAgent(db.Model):
    __tablename__ = 'ai_agents'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    number = db.Column(db.String(50), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_agents', lazy=True))
    
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
    ai_context_list = db.relationship('AIContext', backref='agent', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<AIAgent {self.name}>'

class AIDebugLogs(db.Model):
    __tablename__ = 'ai_debug_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    user = db.relationship('AIUser', backref=db.backref('ai_debug_logs', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_debug_logs')

    def __repr__(self):
        return f'<AIDebugLogs {self.id}>'

class AISignalWireParams(db.Model):
    __tablename__ = 'ai_signalwire_params'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_signalwire_params', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_signalwire_params')

    def __repr__(self):
        return f'<AISignalWireParams {self.name}: {self.value}>'

class AISWMLRequest(db.Model):
    __tablename__ = 'ai_swml_requests'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    request = db.Column(db.JSON, nullable=False)
    response = db.Column(db.JSON, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    user = db.relationship('AIUser', backref=db.backref('ai_swml_requests', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_swml_requests')

    def __repr__(self):
        return f'<AISWMLRequest {self.id}>'

class AIFunctions(db.Model):
    __tablename__ = 'ai_functions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.Text, nullable=True)
    purpose = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    web_hook_url = db.Column(db.String(255), nullable=True)
    wait_file = db.Column(db.String(255), nullable=True)
    wait_file_loops = db.Column(db.Integer, nullable=True, default=-1)
    fillers = db.Column(db.Text, nullable=True)
    meta_data = db.Column(db.JSON, nullable=True)
    meta_data_token = db.Column(db.String(255), nullable=True)

    user = db.relationship('AIUser', backref=db.backref('ai_functions', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_functions')
    
    __table_args__ = (db.UniqueConstraint('user_id', 'agent_id', 'name'),)
    
    ai_function_args = db.relationship(
        'AIFunctionArgs', 
        back_populates='function', 
        cascade='all, delete-orphan', 
        lazy=True
    )

    def __repr__(self):
        return f'<AIFunctions {self.name}>'

class AIFunctionArgs(db.Model):
    __tablename__ = 'ai_function_argument'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    function_id = db.Column(db.Integer, db.ForeignKey('ai_functions.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.Text, nullable=False)
    type = db.Column(db.Text, nullable=False, default='string')
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    required = db.Column(db.Boolean, nullable=False, default=False)
    enum = db.Column(db.Text, nullable=True)
    default = db.Column(db.Text, nullable=True)

    function = db.relationship(
        'AIFunctions', 
        back_populates='ai_function_args'
    )
    user = db.relationship('AIUser', backref=db.backref('ai_function_argument', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_function_argument')

    __table_args__ = (db.UniqueConstraint('user_id', 'function_id', 'name'),)

    def __repr__(self):
        return f'<AIFunctionArgs {self.name}>'

class AIHints(db.Model):
    __tablename__ = 'ai_hints'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    hint = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_hints', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_hints')

    def __repr__(self):
        return f'<AIHints {self.hint}>'

class AIPronounce(db.Model):
    __tablename__ = 'ai_pronounce'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ignore_case = db.Column(db.Boolean, nullable=False, default=False)
    replace_this = db.Column(db.Text, nullable=False)
    replace_with = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_pronounce', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_pronounce')

    def __repr__(self):
        return f'<AIPronounce {self.replace_this} -> {self.replace_with}>'

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
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_prompt', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_prompt')

    def __repr__(self):
        return f'<AIPrompt {self.prompt_type}: {self.prompt_text}>'

class AILanguage(db.Model):
    __tablename__ = 'ai_language'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
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

class AIConversation(db.Model):
    __tablename__ = 'ai_conversation'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data = db.Column(db.JSON, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('AIUser', backref=db.backref('ai_conversation', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_conversation')

    def __repr__(self):
        return f'<AIConversation {self.id}>'

class AIParams(db.Model):
    __tablename__ = 'ai_params'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('AIUser', backref=db.backref('ai_params', lazy=True))
    agent = db.relationship('AIAgent', back_populates='ai_params')

    def __repr__(self):
        return f'<AIParams {self.name}: {self.value}>'

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
    
class AIIncludes(db.Model):
    __tablename__ = 'ai_includes'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    functions = db.Column(db.JSON, nullable=True)

    user = db.relationship('AIUser', backref=db.backref('ai_includes', lazy=True))
    agent = db.relationship('AIAgent', backref=db.backref('ai_includes', lazy=True))

    def __repr__(self):
        return f'<AIIncludes {self.url}>'
    
class AIContext(db.Model):
    __tablename__ = 'ai_contexts'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    context_name = db.Column(db.String(100), nullable=False)

    # Change the backref name here to avoid conflict
    ai_steps = db.relationship('AISteps', backref='ai_context', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'context_name': self.context_name
        }

class AISteps(db.Model):
    __tablename__ = 'ai_steps'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    context_id = db.Column(db.Integer, db.ForeignKey('ai_contexts.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    step_criteria = db.Column(db.Text, nullable=True)
    valid_steps = db.Column(db.ARRAY(db.String), nullable=True)
    valid_contexts = db.Column(db.ARRAY(db.String), nullable=True)
    end = db.Column(db.Boolean, nullable=False, default=False)
    functions = db.Column(db.ARRAY(db.String), nullable=True)
    skip_user_turn = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f'<AISteps {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'context_id': self.context_id,
            'name': self.name,
            'text': self.text,
            'step_criteria': self.step_criteria,
            'valid_steps': self.valid_steps,
            'valid_contexts': self.valid_contexts,
            'end': self.end,
            'functions': self.functions,
            'skip_user_turn': self.skip_user_turn
        }