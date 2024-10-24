import json, base64
from flask import request, jsonify
from modules.models import (
    AIPrompt, AIParams, AIUser, AIHints, AILanguage, AIPronounce, 
    AIFunctions, AIFunctionArgs, AIIncludes, AISWMLRequest
)
from modules.utils import get_feature, get_signal_wire_param
from modules.signalwireml import SignalWireML
from modules.db import db

def generate_swml_response(user_id, agent_id, request_body):
    request_body = request_body or {}
    swml = SignalWireML(version="1.0.0")
    
    outbound = request_body.get('outbound', False)
    
    enable_record_feature = get_feature(agent_id, 'ENABLE_RECORD')
    if enable_record_feature and enable_record_feature.enabled:
        swml.add_application("main", "answer")
        swml.add_application("main", "record_call", {
            "stereo": True,
            "format": enable_record_feature.value
        })  
    
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
        if post_prompt.max_tokens is not None:
            post_prompt_data["max_tokens"] = post_prompt.max_tokens
        if post_prompt.confidence is not None and post_prompt.confidence != 0.0:
            post_prompt_data["confidence"] = post_prompt.confidence

        swml.set_aipost_prompt(post_prompt_data)
    
    ai_params = AIParams.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    params_dict = {param.name: param.value for param in ai_params}
    swml.set_aiparams(params_dict)

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

    hints = AIHints.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    swml.add_aihints([hint.hint for hint in hints])
            
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

    pronounces = AIPronounce.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    for pronounce in pronounces:
        swml.add_aipronounce({
            "replace_this": pronounce.replace_this,
            "replace_with": pronounce.replace_with,
            "ignore_case": pronounce.ignore_case
        })

    functions = AIFunctions.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    for function in functions:
        function_data = {
            "function": function.name,
            "purpose": function.purpose,
            **({"web_hook_url": function.web_hook_url} if function.web_hook_url else {}),
            **({"wait_file": function.wait_file} if function.wait_file else {}),
            **({"wait_file_loops": function.wait_file_loops} if function.wait_file_loops else {}),
            **({"fillers": function.fillers} if function.fillers else {}),
            **({"meta_data": function.meta_data} if function.meta_data else {}),
            **({"meta_data_token": function.meta_data_token} if function.meta_data_token else {}),
            "argument": {
                "properties": {}
            }
        }
        function_args = AIFunctionArgs.query.filter_by(function_id=function.id, agent_id=agent_id).all()
        for arg in function_args:
            function_data["argument"]["properties"][arg.name] = {
                "type": arg.type,
                "description": arg.description,
                **({"default": (int(arg.default) if arg.type == 'integer' else 
                               float(arg.default) if arg.type == 'number' else 
                               bool(arg.default) if arg.type == 'boolean' else 
                               arg.default) 
                    } if arg.default else {})
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

    enable_message_feature = get_feature(agent_id, 'ENABLE_MESSAGE')

    if enable_message_feature and enable_message_feature.enabled:
        msg = SignalWireML(version="1.0.0")

        msg.add_application("main", "send_sms", {
            "to_number": '%{args.to}',
            "from_number": enable_message_feature.value,
            "body": '%{args.message}'
        })

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
                        "string": '%{args.message}',
                        "pattern": ".*",
                        "output": {
                            "response": "Message sent.",
                            "action": [{"SWML": msg.render()}]
                        }
                }]
            }
        })

    ai_includes = AIIncludes.query.filter_by(user_id=user_id, agent_id=agent_id).all()
    for ai_include in ai_includes:
        function_dict = {
            "url": ai_include.url,
            "functions": json.loads(ai_include.functions)
        }

        swml.add_aiinclude(function_dict)

    enable_transfer_feature = get_feature(agent_id, 'ENABLE_TRANSFER')

    if enable_transfer_feature and enable_transfer_feature.enabled:
        transfer = SignalWireML(version="1.0.0")

        transfer.add_application("main", "connect", {
            "to": '%{meta_data.table.%{lc:args.target}}',
            "from": 'assistant'
        })

        transfer_table = get_feature(agent_id, 'TRANSFER_TABLE')
        transfer_hash = {}
        for pair in transfer_table.value.split('|'):
            key, value = pair.split(':', 1)
            transfer_hash[key] = value

        enable_transfer_inactive = get_feature(agent_id, 'ENABLE_TRANSFER_INACTIVE')

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
                        "string": '%{meta_data.table.%{lc:args.target}}',
                        "pattern": '\\w+',
                        "output": {
                            "response": "Tell the user you are going to transfer the call to whoever they asked for. Do not change languages from the one you are currently using. Do not hangup.",
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
    
    api_ninjas_key_feature = get_feature(agent_id, 'API_NINJAS_KEY')
    api_ninjas_key = api_ninjas_key_feature.value if api_ninjas_key_feature and api_ninjas_key_feature.enabled else None

    if api_ninjas_key:
        api_ninjas_weather_feature = get_feature(agent_id, 'API_NINJAS_WEATHER')
        if api_ninjas_weather_feature and api_ninjas_weather_feature.enabled:
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
                            "response": 'Say the temperature in Fahrenheit. The weather in %{input.args.city} %{temp}C, Humidity: %{humidity}%, High: %{max_temp}C, Low: %{min_temp}C Wind Direction: %{wind_degrees} (say cardinal direction), Clouds: %{cloud_pct}%, Feels Like: %{feels_like}C.'
                        }
                    }]
                }
            })

        api_ninjas_jokes_feature = get_feature(agent_id, 'API_NINJAS_JOKES')
        if api_ninjas_jokes_feature and api_ninjas_jokes_feature.enabled:
            dj = SignalWireML(version="1.0.0")
            dj.add_application("main", "set", {"dad_joke": '%{array[0].joke}'})

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
        if api_ninjas_trivia_feature and api_ninjas_trivia_feature.enabled:
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
        if api_ninjas_facts_feature and api_ninjas_facts_feature.enabled:
            swml.add_aiswaigfunction({
                "function": "get_fact",
                "purpose": "provide a random interesting fact",
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
        if api_ninjas_quotes_feature and api_ninjas_quotes_feature.enabled:
            swml.add_aiswaigfunction({
                "function": "get_quote",
                "purpose": "provide a random quote",
                "argument": {
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
        if api_ninjas_cocktails_feature and api_ninjas_cocktails_feature.enabled:
            swml.add_aiswaigfunction({
                "function": "get_cocktail",
                "purpose": "fetch cocktail recipes by name or ingredients",
                "argument": {
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
    if enable_datasphere_feature and enable_datasphere_feature.enabled:
        document_id = enable_datasphere_feature.value

        space_name = get_signal_wire_param(user_id, agent_id, 'SPACE_NAME')
        project_id = get_signal_wire_param(user_id, agent_id, 'PROJECT_ID')
        auth_token = get_signal_wire_param(user_id, agent_id, 'AUTH_TOKEN')

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

    swml.add_aiapplication("main")
    swml_response = swml.render()

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    new_swml_request = AISWMLRequest(
        user_id=user_id,
        agent_id=agent_id,
        request=jsonify(request_body).json,
        response=jsonify(swml_response).json,
        ip_address=ip_address
    )
    db.session.add(new_swml_request)
    db.session.commit()

    return swml_response
