from modules.db import db
from flask_login import UserMixin
from datetime import datetime

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
