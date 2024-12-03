import json, base64
from flask import request
from modules.models import (
    AIPrompt, AIParams, AIHints, AILanguage, AIPronounce, 
    AIFunctions, AIFunctionArgs, AIIncludes, AISteps, AIContext
)
from modules.utils import get_feature, get_signalwire_param_by_agent_id
from modules.signalwireml import SignalWireML
from modules.db import db

def generate_swml_response(agent_id, request_body):
    request_body = request_body or {}
    swml = SignalWireML(version="1.0.0")
    
    outbound = request_body.get('outbound', False)
    
    enable_record_feature = get_feature(agent_id, 'ENABLE_RECORD')
    if enable_record_feature:
        swml.add_application("main", "answer")
        swml.add_application("main", "record_call", {
            "stereo": True,
            "format": enable_record_feature
        })  
    
    if outbound:
        prompt = AIPrompt.query.filter_by(agent_id=agent_id, prompt_type='outbound_prompt').first()
        post_prompt = AIPrompt.query.filter_by(agent_id=agent_id, prompt_type='outbound_post_prompt').first()
    else:
        prompt = AIPrompt.query.filter_by(agent_id=agent_id, prompt_type='prompt').first()
        post_prompt = AIPrompt.query.filter_by(agent_id=agent_id, prompt_type='post_prompt').first()

    if not prompt:
        prompt = AIPrompt(
            agent_id=agent_id,
            prompt_type='outbound_prompt' if outbound else 'prompt',
            prompt_text="You are a helpful assistant.",
            top_p=0.5,
            temperature=0.5
        )
        db.session.add(prompt)
        db.session.commit()

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
        if post_prompt.max_tokens is not None and post_prompt.max_tokens != 0:
            post_prompt_data["max_tokens"] = post_prompt.max_tokens
        if post_prompt.confidence is not None and post_prompt.confidence != 0.0:
            post_prompt_data["confidence"] = post_prompt.confidence

        swml.set_aipost_prompt(post_prompt_data)
    
    ai_params = AIParams.query.filter_by(agent_id=agent_id).all()
    params_dict = {param.name: param.value for param in ai_params}
    swml.set_aiparams(params_dict)

    auth_user = get_signalwire_param_by_agent_id(agent_id, 'HTTP_USERNAME')
    auth_pass = get_signalwire_param_by_agent_id(agent_id, 'HTTP_PASSWORD')
    
    post_prompt_url = f"https://{request.host}/postprompt/{agent_id}"
    if auth_user and auth_pass:
        post_prompt_url = f"https://{auth_user}:{auth_pass}@{request.host}/postprompt/{agent_id}"
        swml.set_aipost_prompt_url({"post_prompt_url": post_prompt_url})

    web_hook_url = f"https://{request.host}/onboard/swaig/{agent_id}"
    if auth_user and auth_pass:
        web_hook_url = f"https://{auth_user}:{auth_pass}@{request.host}/onboard/swaig/{agent_id}"
        swml.add_aiswaigdefaults({"web_hook_url": web_hook_url})

    debug_webhook_url = f"https://{request.host}/debugwebhook/{agent_id}"
    if auth_user and auth_pass:
        debug_webhook_url = f"https://{auth_user}:{auth_pass}@{request.host}/debugwebhook/{agent_id}"
        swml.add_aiparams({"debug_webhook_url": debug_webhook_url})

    if outbound:
        swml.add_aiparams({"wait_for_user": "true"})

    hints = AIHints.query.filter_by(agent_id=agent_id).all()
    swml.add_aihints([hint.hint for hint in hints])
            
    languages = AILanguage.query.filter_by(agent_id=agent_id).order_by(AILanguage.language_order.asc()).all()
    for language in languages:
        language_data = {
            "language": language.name,
            "voice": language.voice,
            "name": language.name,
            "code": language.code
        }
        if language.speech_fillers:
            language_data["speech_fillers"] = [language.speech_fillers]
        if language.function_fillers:
            language_data["function_fillers"] = [language.function_fillers]

        swml.add_ailanguage(language_data)

    pronounces = AIPronounce.query.filter_by(agent_id=agent_id).all()
    for pronounce in pronounces:
        swml.add_aipronounce({
            "replace_this": pronounce.replace_this,
            "replace_with": pronounce.replace_with,
            "ignore_case": pronounce.ignore_case
        })

    functions = AIFunctions.query.filter_by(agent_id=agent_id).all()
    for function in functions:
        function_data = {
            "function": function.name,
            "description": function.description,
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
        if function.web_hook_url:
            function_data["web_hook_url"] = function.web_hook_url
        if function.wait_file:
            function_data["wait_file"] = function.wait_file
        if function.wait_file_loops:
            function_data["wait_file_loops"] = function.wait_file_loops
        if function.fillers:
            function_data["fillers"] = function.fillers
        if function.meta_data:
            function_data["meta_data"] = function.meta_data
        if function.meta_data_token:
            function_data["meta_data_token"] = function.meta_data_token
        print("Debug: ", function_data)
        function_args = AIFunctionArgs.query.filter_by(function_id=function.id, agent_id=agent_id).all()
        for arg in function_args:
            function_data["parameters"]["properties"][arg.name] = {
                "type": arg.type,
                "description": arg.description,
                "type": arg.type if arg.type in ['integer', 'number', 'boolean', 'string', 'array', 'object'] else 'string',
                **({"default": (int(arg.default) if arg.type == 'integer' else 
                               float(arg.default) if arg.type == 'number' else 
                               bool(arg.default) if arg.type == 'boolean' else 
                               arg.default) 
                    } if arg.default else {})
            }
            if arg.enum and arg.type == 'array':
                function_data["parameters"]["properties"][arg.name]["enum"] = arg.enum.split(',')

        function_payload = {
            "function": function.name,
            "description": function.description,
            **function_data,
            "required": [arg.name for arg in function_args if arg.required]
        }
        if not function.active:
            function_payload["active"] = function.active

        swml.add_aiswaigfunction(function_payload)

    enable_message_feature = get_feature(agent_id, 'ENABLE_MESSAGE')

    if enable_message_feature:
        msg = SignalWireML(version="1.0.0")

        msg.add_application("main", "send_sms", {
            "to_number": '%{args.to}',
            "from_number": enable_message_feature,
            "body": '%{args.message}'
        })

        enable_message_inactive = get_feature(agent_id, 'ENABLE_MESSAGE_INACTIVE')

        swml.add_aiswaigfunction({
            "function": "send_message",
            **({"active": False} if enable_message_inactive else {}),
            "description": "use to send text a message to the user",
            "parameters": {
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
                        "string": '%{args.message}',
                        "pattern": ".*",
                        "output": {
                            "response": "Message sent.",
                            "action": [{"SWML": msg.render()}]
                        }
                }]
            }
        })

    ai_includes = AIIncludes.query.filter_by(agent_id=agent_id).all()
    for ai_include in ai_includes:
        function_dict = {
            "url": ai_include.url,
            "functions": json.loads(ai_include.functions)
        }
        if function_dict["functions"] and function_dict["url"]:
            swml.add_aiinclude(function_dict)
    
    
    context_steps = (
        db.session.query(AISteps, AIContext)
        .join(AIContext, AISteps.context_id == AIContext.id)
        .filter(AIContext.agent_id == agent_id)
        .all()
    )
    context_step_groups = {}
    for step, context in context_steps:
        try:
            valid_steps = []
            if step.valid_steps:
                valid_step_ids = json.loads(step.valid_steps) if isinstance(step.valid_steps, str) else step.valid_steps
                valid_steps = [s.name for s in AISteps.query.filter(AISteps.id.in_(valid_step_ids)).all()]

            valid_contexts = []
            if step.valid_contexts:
                valid_context_ids = json.loads(step.valid_contexts) if isinstance(step.valid_contexts, str) else step.valid_contexts
                valid_contexts = [c.context_name for c in AIContext.query.filter(AIContext.id.in_(valid_context_ids)).all()]

            functions = []
            if step.functions:
                function_ids = json.loads(step.functions) if isinstance(step.functions, str) else step.functions
                functions = [f.name for f in AIFunctions.query.filter(AIFunctions.id.in_(function_ids)).all()]

            step_dict = {
                'name': step.name,
                'step_criteria': step.step_criteria,
                'text': step.text,
                'skip_user_turn': step.skip_user_turn,
            }
            
            if step.end:
                step_dict['end'] = True
                if functions:
                    step_dict['functions'] = functions
            else:
                if functions:
                    step_dict['functions'] = functions
                if valid_steps:
                    step_dict['valid_steps'] = valid_steps
                if valid_contexts:
                    step_dict['valid_contexts'] = valid_contexts

            step_dict = {k: v for k, v in step_dict.items() if v is not None and v != ''}
            context_step_groups.setdefault(context.context_name, []).append(step_dict)
        except Exception as e:
            db.session.rollback()
            print(f"Error processing step {step.id}: {str(e)}")
            continue
    
    for context_name, steps in context_step_groups.items():
        swml.add_context_steps(context_name, steps)

    enable_transfer_feature = get_feature(agent_id, 'ENABLE_TRANSFER')


    if enable_transfer_feature:
        assistant_number = get_feature(agent_id, 'ASSISTANT_NUMBER')
        transfer = SignalWireML(version="1.0.0")

        transfer.add_application("main", "connect", {
            "to": '%{meta_data.table.%{lc:args.target}}',
            "from": assistant_number
        })

        transfer_table = get_feature(agent_id, 'TRANSFER_TABLE')
        transfer_hash = {}
        for pair in transfer_table.split('|'):
            key, value = pair.split(':', 1)
            transfer_hash[key] = value

        enable_transfer_inactive = get_feature(agent_id, 'ENABLE_TRANSFER_INACTIVE')

        swml.add_aiswaigfunction({
            "function": "transfer",
            **({"active": False} if enable_transfer_inactive else {}),
            "description": "use to transfer to a target",
            "meta_data": {
                "table": transfer_hash
            },
            "parameters": {
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
                        "string": '%{meta_data.table.%{lc:args.target}}',
                        "pattern": '\\w+',
                        "output": {
                            "response": "Tell the user you are going to transfer the call to whoever they asked for. Do not change languages from the one you are currently using. Do not hangup.", "post_process": 'true',
                            "action": [{"SWML": transfer.render(), "transfer": 'true'}]
                        }
                    },
                    {
                        "string": '%{args.target}',
                        "pattern": '.*',
                        "output": {
                            "response": "I'm sorry, I was unable to transfer your call to %{input.args.target}."
                        }
                    }
                ]
            }
        })
    
    api_ninjas_key = get_feature(agent_id, 'API_NINJAS_KEY')

    if api_ninjas_key:
        api_ninjas_weather_feature = get_feature(agent_id, 'API_NINJAS_WEATHER')
        if api_ninjas_weather_feature:
            swml.add_aiswaigfunction({
                "function": "get_weather",
                "description": "latest weather information for any city",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "city": {
                            "type": "string",
                            "description": "City name."
                        },
                        "state": {
                            "type": "string",
                            "description": "US state for United States cities only. Optional"
                        },
                        "country": {
                            "type": "string",
                            "description": "Country name. Optional"
                        },
                    },
                },
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/weather?city=%{{enc:args.city}}&state=%{{enc:args.state}}&country=%{{enc:args.country}}',
                        "method": "GET",
                        "error_keys": "error",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'You must say any temprature in Fahrenheit. The weather in %{input.args.city} %{temp}C, Humidity: %{humidity}%, High: %{max_temp}C, Low: %{min_temp}C Wind Direction: %{wind_degrees} (say cardinal direction), Clouds: %{cloud_pct}%, Feels Like: %{feels_like}C.'
                        }
                    }]
                }
            })

        api_ninjas_jokes_feature = get_feature(agent_id, 'API_NINJAS_JOKES')
        if api_ninjas_jokes_feature:
            dj = SignalWireML(version="1.0.0")
            dj.add_application("main", "set", {"dad_joke": '%{array[0].joke}'})

            swml.add_aiswaigfunction({
                "function": "get_joke",
                "description": "tell a joke",
                "parameters": {
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
                        "url": f'https://api.api-ninjas.com/v1/%{{args.type}}',
                        "method": "GET",
                        "error_keys": "error",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'Tell the user: %{array[0].joke}',
                            "action": [{"SWML": dj.render()}]
                        }
                    }]
                }
            })

        api_ninjas_trivia_feature = get_feature(agent_id, 'API_NINJAS_TRIVIA')
        if api_ninjas_trivia_feature:
            swml.add_aiswaigfunction({
                "function": "get_trivia",
                "description": "get a trivia question",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Valid options are artliterature, language, sciencenature, general, fooddrink, peopleplaces, geography, historyholidays, entertainment, toysgames, music, mathematics, religionmythology, sportsleisure. Pick a category at random if not asked for a specific category."
                        }
                    }                },
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/trivia?category=%{{args.category}}',
                        "method": "GET",
                        "error_keys": "error",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'category %{array[0].category} questions: %{array[0].question} answer: %{array[0].answer}, be sure to give the user time to answer before saying the answer.'
                        }
                    }]
                }
            })

        api_ninjas_facts_feature = get_feature(agent_id, 'API_NINJAS_FACTS')
        if api_ninjas_facts_feature:
            swml.add_aiswaigfunction({
                "function": "get_fact",
                "description": "provide a random interesting fact",
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/facts',
                        "method": "GET",
                        "error_keys": "error",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'Here is a fact for you: %{array[0].fact}'
                        }
                    }]
                }
            })

        api_ninjas_quotes_feature = get_feature(agent_id, 'API_NINJAS_QUOTES')
        if api_ninjas_quotes_feature:
            swml.add_aiswaigfunction({
                "function": "get_quote",
                "description": "provide a random quote",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": (
                                "Category of the quote. Optional. "
                                "Possible values include: age, alone, amazing, anger, architecture, art, attitude, "
                                "beauty, best, birthday, business, car, change, communications, computers, cool, courage, "
                                "dad, dating, death, design, dreams, education, environmental, equality, experience, "
                                "failure, faith, family, famous, fear, fitness, food, forgiveness, freedom, friendship, "
                                "funny, future, god, good, government, graduation, great, happiness, health, history, "
                                "home, hope, humor, imagination, inspirational, intelligence, jealousy, knowledge, "
                                "leadership, learning, legal, life, love, marriage, medical, men, mom, money, morning, "
                                "movies, success, motivational, music, nature, parenting, patience, peace, pet, poetry, "
                                "politics, power, relationship, religion, respect, science, smile, society, sports, "
                                "strength, success, technology, time, travel, trust, truth, war, wisdom, work."
                            )
                        }
                    }
                },
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/quotes?category=%{{args.category}}',
                        "method": "GET",
                        "error_keys": "error",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'Here is a quote for you: "%{array[0].quote}" - %{array[0].author}'
                        }
                    }]
                }
            })
            
        api_ninjas_cocktails_feature = get_feature(agent_id, 'API_NINJAS_COCKTAILS')
        if api_ninjas_cocktails_feature:
            swml.add_aiswaigfunction({
                "function": "get_cocktail",
                "description": "fetch cocktail recipes by name or ingredients",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name of the cocktail. Optional."
                        },
                        "ingredients": {
                            "type": "string",
                            "description": "Ingredients to search for in cocktails. Optional."
                        }
                    }
                },
                "data_map": {
                    "webhooks": [{
                        "url": f'https://api.api-ninjas.com/v1/cocktail?name=%{{enc:args.name}}&ingredients=%{{enc:args.ingredients}}',
                        "method": "GET",
                        "headers": {
                            "X-Api-Key": api_ninjas_key
                        },
                        "output": {
                            "response": 'Here is a cocktail recipe for you: %{array[0].name}. Ingredients: %{array[0].ingredients[0]}, %{array[0].ingredients[1]}, %{array[0].ingredients[2]}, %{array[0].ingredients[3]}, %{array[0].ingredients[4]}, %{array[0].ingredients[5]}, %{array[0].ingredients[6]}, %{array[0].ingredients[7]}, %{array[0].ingredients[8]}, %{array[0].ingredients[9]}, %{array[0].ingredients[10]}. Instructions: %{array[0].instructions}.'
                        }
                    }]
                }
            })

    enable_datasphere_feature = get_feature(agent_id, 'ENABLE_DATASPHERE')
    if enable_datasphere_feature:
        document_id = enable_datasphere_feature

        space_name = get_signalwire_param_by_agent_id(agent_id, 'SPACE_NAME')
        project_id = get_signalwire_param_by_agent_id(agent_id, 'PROJECT_ID')
        auth_token = get_signalwire_param_by_agent_id(agent_id, 'AUTH_TOKEN')

        encoded_credentials = base64.b64encode(f"{project_id}:{auth_token}".encode()).decode()
        url = f"https://{space_name}/api/datasphere/documents/search"
        authorization = f"Basic {encoded_credentials}"

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
                            "query_string": "%{args.user_question}",
                            "document_id": document_id,
                            "count": 1
                        },
                        "output": {
                            "response": 'Use this information to answer the user\'s query, only provide answers from this information and do not make up anything: %{chunks[0].text} and %{chunks[0].document_id}'
                        }
                    }
                ]
            },
            "description": "The question the user will ask",
            "parameters": {
                "properties": {
                    "user_question": {
                        "type": "string",
                        "description": "The question the user will ask."
                    }
                },
                "type": "object"
            }
        })

    swml.add_aiapplication("main")
    swml_response = swml.render()

    return swml_response







