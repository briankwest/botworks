from modules.db import db
from flask_login import UserMixin
from datetime import datetime, timedelta
import enum

class AIAgent(db.Model):
    __tablename__ = 'ai_agents'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    number = db.Column(db.String(50), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('AIUser', backref=db.backref('ai_agents', lazy=True))
    
    ai_debug_logs = db.relationship('AIDebugLogs', back_populates='agent', cascade='all, delete-orphan', lazy=True)

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
    ai_contexts = db.relationship('AIContext', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    ai_steps = db.relationship('AISteps', back_populates='agent', cascade='all, delete-orphan', lazy=True)
    shared_agent = db.relationship('SharedAgent', back_populates='agent', cascade='all, delete-orphan', lazy='dynamic')

    def __repr__(self):
        return f'<AIAgent {self.name}>'

class AIDebugLogs(db.Model):
    __tablename__ = 'ai_debug_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_debug_logs')

    def __repr__(self):
        return f'<AIDebugLogs {self.id}>'

class AISignalWireParams(db.Model):
    __tablename__ = 'ai_signalwire_params'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False, unique=False)
    value = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<AISignalWireParams {self.name}: {self.value}>'

class AISWMLRequest(db.Model):
    __tablename__ = 'ai_swml_requests'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    request = db.Column(db.JSON, nullable=False)
    response = db.Column(db.JSON, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    agent = db.relationship('AIAgent', back_populates='ai_swml_requests')

    def __repr__(self):
        return f'<AISWMLRequest {self.id}>'

class AIFunctions(db.Model):
    __tablename__ = 'ai_functions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    web_hook_url = db.Column(db.String(255), nullable=True)
    wait_file = db.Column(db.String(255), nullable=True)
    wait_file_loops = db.Column(db.Integer, nullable=True, default=-1)
    fillers = db.Column(db.Text, nullable=True)
    meta_data = db.Column(db.JSON, nullable=True)
    meta_data_token = db.Column(db.String(255), nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_functions')
    
    __table_args__ = (db.UniqueConstraint('agent_id', 'name'),)
    
    ai_function_args = db.relationship('AIFunctionArgs', back_populates='function', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f'<AIFunctions {self.name}>'

class AIFunctionArgs(db.Model):
    __tablename__ = 'ai_function_argument'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    function_id = db.Column(db.Integer, db.ForeignKey('ai_functions.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.Text, nullable=False)
    type = db.Column(db.Text, nullable=False, default='string')
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    required = db.Column(db.Boolean, nullable=False, default=False)
    enum = db.Column(db.Text, nullable=True)
    default = db.Column(db.Text, nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    function = db.relationship('AIFunctions', back_populates='ai_function_args')
    agent = db.relationship('AIAgent', back_populates='ai_function_argument')

    __table_args__ = (db.UniqueConstraint('function_id', 'name'),)

    def __repr__(self):
        return f'<AIFunctionArgs {self.name}>'

class AIHints(db.Model):
    __tablename__ = 'ai_hints'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    hint = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_hints')

    def __repr__(self):
        return f'<AIHints {self.hint}>'

class AIPronounce(db.Model):
    __tablename__ = 'ai_pronounce'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ignore_case = db.Column(db.Boolean, nullable=False, default=False)
    replace_this = db.Column(db.Text, nullable=False)
    replace_with = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_pronounce')

    def __repr__(self):
        return f'<AIPronounce {self.replace_this} -> {self.replace_with}>'

class AIPrompt(db.Model):
    __tablename__ = 'ai_prompt'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    prompt_type = db.Column(db.Enum('prompt', 'post_prompt', 'outbound_prompt', 'outbound_post_prompt', name='prompt_type_enum'), nullable=False)
    prompt_text = db.Column(db.Text, nullable=True)
    top_p = db.Column(db.Float, nullable=True)
    temperature = db.Column(db.Float, nullable=True)
    max_tokens = db.Column(db.Integer, nullable=True)
    confidence = db.Column(db.Float, nullable=True)
    frequency_penalty = db.Column(db.Float, nullable=True)
    presence_penalty = db.Column(db.Float, nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_prompt')

    def __repr__(self):
        return f'<AIPrompt {self.prompt_type}: {self.prompt_text}>'

class AILanguage(db.Model):
    __tablename__ = 'ai_language'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    code = db.Column(db.Text, nullable=True)
    name = db.Column(db.Text, nullable=True)
    voice = db.Column(db.Text, nullable=True)
    speech_fillers = db.Column(db.Text, nullable=True)
    function_fillers = db.Column(db.Text, nullable=True)
    language_order = db.Column(db.Integer, nullable=False, default=0)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_language')

    def __repr__(self):
        return f'<AILanguage {self.name}>'

class AIConversation(db.Model):
    __tablename__ = 'ai_conversation'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    data = db.Column(db.JSON, nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_conversation')

    def __repr__(self):
        return f'<AIConversation {self.id}>'

class AIParams(db.Model):
    __tablename__ = 'ai_params'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String, nullable=False)
    value = db.Column(db.String, nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_params')

    def __repr__(self):
        return f'<AIParams {self.name}: {self.value}>'

class AIFeatures(db.Model):
    __tablename__ = 'ai_features'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=True)
    data = db.Column(db.JSON, nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    shared_agent = db.relationship(
        'SharedAgent',
        back_populates='user',
        cascade='all, delete-orphan',
        lazy='dynamic',
        primaryjoin="AIUser.id == SharedAgent.shared_with_user_id"
    )
    ai_translates = db.relationship(
        'AITranslate',
        back_populates='user',
        cascade='all, delete-orphan',
        lazy='dynamic',
        primaryjoin="AIUser.id == AITranslate.user_id"
    )

    def __repr__(self):
        return f'<AIUser {self.username}>'

class AIIncludes(db.Model):
    __tablename__ = 'ai_includes'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    functions = db.Column(db.JSON, nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', backref=db.backref('ai_includes', cascade='all, delete-orphan', lazy=True))

    def __repr__(self):
        return f'<AIIncludes {self.url}>'

class AIContext(db.Model):
    __tablename__ = 'ai_contexts'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    context_name = db.Column(db.String(100), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = db.relationship('AIAgent', back_populates='ai_contexts')
    ai_steps = db.relationship('AISteps', back_populates='context', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'context_name': self.context_name
        }

class AISteps(db.Model):
    __tablename__ = 'ai_steps'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    context_id = db.Column(db.Integer, db.ForeignKey('ai_contexts.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    step_criteria = db.Column(db.Text, nullable=True)
    valid_steps = db.Column(db.ARRAY(db.String), nullable=True)
    valid_contexts = db.Column(db.ARRAY(db.String), nullable=True)
    end = db.Column(db.Boolean, nullable=False, default=False)
    functions = db.Column(db.ARRAY(db.String), nullable=True)
    skip_user_turn = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    agent = db.relationship('AIAgent', back_populates='ai_steps')   
    context = db.relationship('AIContext', back_populates='ai_steps')
    
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
        
class AIHooks(db.Model):
    __tablename__ = 'ai_hooks'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    data = db.Column(db.JSON, nullable=False)
    
    class HookType(enum.Enum):
        hangup_hook = "hangup_hook"
        startup_hook = "startup_hook"
        summarize_conversation = "summarize_conversation"
        other = "other"
    
    hook_type = db.Column(db.Enum(HookType), nullable=False)

    agent = db.relationship('AIAgent', backref=db.backref('ai_hooks', lazy=True))

    def __repr__(self):
        return f'<AIHooks {self.hook_type}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'agent_id': self.agent_id,
            'created': self.created,
            'updated': self.updated,
            'data': self.data,
            'hook_type': self.hook_type.value
        }

class SharedAgent(db.Model):
    __tablename__ = 'shared_agent'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agents.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    permissions = db.Column(db.String(50), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('AIUser', back_populates='shared_agent', foreign_keys=[user_id])
    agent = db.relationship('AIAgent', back_populates='shared_agent')
    
class SharedConversations(db.Model):
    __tablename__ = 'shared_conversations'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), nullable=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('ai_conversation.id', ondelete='CASCADE'), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    conversation = db.relationship('AIConversation', backref=db.backref('shared_conversations', lazy=True))

    def __repr__(self):
        return f'<SharedConversations {self.id}>'
    

class AITranslate(db.Model):
    __tablename__ = 'ai_translate'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id', ondelete='CASCADE'), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    from_language = db.Column(db.String(50), nullable=False)
    to_language = db.Column(db.String(50), nullable=False)
    from_filter = db.Column(db.String(255), nullable=True)
    to_filter = db.Column(db.String(255), nullable=True)
    from_voice = db.Column(db.String(50), nullable=True)
    to_voice = db.Column(db.String(50), nullable=True)
    caller_id_number = db.Column(db.String(50), nullable=True)

    user = db.relationship('AIUser', back_populates='ai_translates')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'from_language': self.from_language,
            'to_language': self.to_language,
            # other fields...
        }

    def __repr__(self):
        return f'<AITranslate {self.from_language} to {self.to_language}>'

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('ai_users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    expires = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    def __init__(self, user_id, token):
        self.user_id = user_id
        self.token = token
        self.created = datetime.utcnow()
        self.expires = self.created + timedelta(minutes=15)
        self.used = False

    def is_expired(self):
        return datetime.utcnow() > self.expires

    def is_valid(self):
        return not self.used and not self.is_expired()

