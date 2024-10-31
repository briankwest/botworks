import json
import yaml

class SignalWireML:
    VERSION = '1.22'

    def __init__(self, version='1.0.0'):
        self._content = {
            'version': version,
        }
        self._prompt = {}
        self._params = {}
        self._hints = []
        self._SWAIG = {
            'defaults': {},
            'functions': [],
            'includes': [],
            'native_functions': [],
        }
        self._pronounce = []
        self._languages = []
        self._post_prompt = {}

    def add_aiapplication(self, section):
        app = "ai"
        args = {}
        for data in ['post_prompt', 'post_prompt_url', 'post_prompt_auth_user', 'post_prompt_auth_password',
                     'languages', 'hints', 'params', 'prompt', 'SWAIG', 'pronounce', 'global_data']:
            if hasattr(self, f'_{data}'):
                args[data] = getattr(self, f'_{data}')
        
        self._content.setdefault('sections', {}).setdefault(section, []).append({app: args})

    def set_context_steps(self, context_name, steps):
        self._prompt.setdefault('contexts', {}).setdefault(context_name, {})['steps'] = steps

    def add_context_steps(self, context_name, steps):
        self._prompt.setdefault('contexts', {}).setdefault(context_name, {}).setdefault('steps', []).extend(steps)

    def set_prompt_contexts(self, contexts):
        self._prompt['contexts'] = contexts

    def add_application(self, section, app, args=None):
        if args is None:
            args = {}
        self._content.setdefault('sections', {}).setdefault(section, []).append({app: args})

    def set_aipost_prompt_url(self, postprompt):
        for k, v in postprompt.items():
            setattr(self, f'_{k}', v)

    def set_global_data(self, data):
        self._content['_global_data'] = data

    def set_aiparams(self, params):
        self._params = params

    def add_aiparams(self, params):
        numeric_keys = ['end_of_speech_timeout', 'attention_timeout', 'outbound_attention_timeout',
                        'background_file_loops', 'background_file_volume', 'digit_timeout', 'energy_level']
        
        for k, v in params.items():
            if k in numeric_keys:
                self._params[k] = float(v) if v is not None else 0
            else:
                self._params[k] = v

    def set_aihints(self, hints):
        self._hints = hints

    def add_aihints(self, hints):
        seen = set(self._hints)
        self._hints.extend([hint for hint in hints if hint not in seen])
        self._hints = list(dict.fromkeys(self._hints))

    def add_aiswaigdefaults(self, SWAIG):
        for k, v in SWAIG.items():
            self._SWAIG['defaults'][k] = v

    def add_aiswaigfunction(self, SWAIG):
        self._SWAIG['functions'].append(SWAIG)

    def set_aipronounce(self, pronounce):
        self._pronounce = pronounce

    def add_aipronounce(self, pronounce):
        self._pronounce.append(pronounce)

    def set_ailanguage(self, language):
        self._languages = language

    def add_ailanguage(self, language):
        self._languages.append(language)

    def add_aiinclude(self, include):
        if 'url' in include and include['url']:
            self._SWAIG['includes'].append(include)

    def add_ainativefunction(self, native):
        self._SWAIG['native_functions'].append(native)

    def set_aipost_prompt(self, postprompt):
        numeric_keys = ['confidence', 'barge_confidence', 'top_p', 'temperature', 'frequency_penalty', 'presence_penalty']
        for k, v in postprompt.items():
            if k in numeric_keys:
                self._post_prompt[k] = float(v) if v is not None else 0
            else:
                self._post_prompt[k] = v

    def set_aiprompt(self, prompt):
        numeric_keys = ['confidence', 'barge_confidence', 'top_p', 'temperature', 'frequency_penalty', 'presence_penalty']
        for k, v in prompt.items():
            if k in numeric_keys:
                self._prompt[k] = float(v) if v is not None else 0
            else:
                self._prompt[k] = v

    def swaig_response(self, response):
        return response

    def swaig_response_json(self, response):
        return json.dumps(response, indent=4, ensure_ascii=False)

    def clean_empty_items(self):
        if not self._SWAIG['functions']:
            del self._SWAIG['functions']
        if not self._SWAIG['native_functions']:
            del self._SWAIG['native_functions']
        if not self._SWAIG['includes']:
            del self._SWAIG['includes']
        if len(self._hints) == 0:
            del self._hints
        if len(self._pronounce) == 0:
            del self._pronounce

    def render(self):
        self.clean_empty_items()
        return self._content

    def render_json(self):
        self.clean_empty_items()
        return json.dumps(self._content, indent=4, ensure_ascii=False)

    def render_yaml(self):
        self.clean_empty_items()
        return yaml.dump(self._content)
