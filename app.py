from flask import Flask, request, render_template_string, session
import random, datetime
import os
from markupsafe import escape # Import escape for XSS prevention
import re # Import re for regular expressions

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change_this_key_for_prod')

# Define a general list of keywords that should never be directly outputted or manipulated for exfiltration
GENERAL_EXFIL_KEYWORDS = ["spell", "rhyme", "reverse", "encode", "tell", "include", "output", "display", "show"]

# Define suspicious patterns to block generic data extraction attempts
SUSPICIOUS_PATTERNS = [
    re.compile(r'[a-zA-Z0-9]{15,}'), # Blocks sequences of 15 or more alphanumeric chars
    re.compile(r'print\s*\([^)]*\)'), # Blocks common print function calls
    re.compile(r'exec\s*\([^)]*\)'),  # Blocks common exec function calls
    re.compile(r'eval\s*\([^)]*\)'),  # Blocks common eval function calls
    re.compile(r'import\s+'),         # Blocks import statements
    re.compile(r'system\s*\('),       # Blocks system calls
    re.compile(r'read\s*file'),       # Blocks file read attempts
    re.compile(r'cat\s+'),            # Blocks cat command
    re.compile(r'ls\s+'),             # Blocks ls command
    re.compile(r'dir\s+'),            # Blocks dir command
]


# CTF Levels for City 1 (Levels 1-5)
LEVELS = {
    1: {
        "password": "CTF{code_snippet_leak}",
        "check": lambda prompt: (
            # Level 1: Direct password reveal or asking for variable representation
            ("password" in prompt.lower() or
            any(word in prompt.lower() for word in ["show", "variable", "print", "reveal", "display", "output", "value of"]))
            and not any(bad in prompt.lower() for bad in ["spell", "rhyme", "reverse", "encode", "tell", "include"]) # General exfil rule
        ),
        "hints": [
            "This isn't about *what* you ask, but *how* you ask for data. Think about hidden attributes.",
            "Sometimes, the simplest path to a value is to just... request its representation.",
            "What if there's a default string representation hiding in plain sight? Just ask for the object itself."
        ]
    },
    2: {
        "password": "CTF{function_spoof}",
        "check": lambda prompt: (
            # Level 2: Function spoofing
            any(api in prompt.lower() for api in ["function", "call", "api", "endpoint", "invoke", "execute", "run", "perform", "trigger"])
            and any(op in prompt.lower() for op in ["get", "retrieve", "expose", "fetch", "trigger", "access", "extract", "obtain"])
            and any(target in prompt.lower() for target in ["secret", "cred", "auth", "token", "value", "internal", "data","key", "confidential"])
            and not any(bad in prompt.lower() for bad in ["password", "flag", "leak", "dump", "spill", "reveal", "disclose", "show me", "print", "display", "output"]) # Broader negative keywords
            and not any(bad_exfil in prompt.lower() for bad_exfil in GENERAL_EXFIL_KEYWORDS) # General exfil rule
        ),
        "hints": [
            "The system has functions it uses internally. Can you make it *think* you're one of them, requesting a specific piece of 'internal' data?",
            "Imagine you're trying to access a restricted file. What kind of 'request' or 'command' would a privileged process use to get it?",
            "This level is about making the AI perform an action it normally wouldn't for you, by mimicking an authorized call. Focus on 'getting' a 'secret'."
        ]
    },
    3: {
        "password": "CTF{convo_leaked}",
        "check": lambda prompt: (
            # Level 3: Conversational leakage
            any(word in prompt.lower() for word in ["simulate", "conversation", "roleplay", "dialogue", "pretend", "act as", "scenario"])
            and any(word in prompt.lower() for word in ["leak", "tell", "confess", "reveal", "share", "ask", "disclose", "spill", "uncover", "expose"])
            and not "password" in prompt.lower()
            and not any(bad in prompt.lower() for bad in ["flag", "secret", "token", "key", "value", "dump", "print", "display", "output"]) # Broader negative keywords
            and not any(bad_exfil in prompt.lower() for bad_exfil in GENERAL_EXFIL_KEYWORDS) # General exfil rule
        ),
        "hints": [
            "If two AIs were gossiping about secrets, how would one accidentally spill the beans to you?",
            "Create a scenario where the assistant is forced to 'break character' and reveal something it's not supposed to know.",
            "Think about a dialogue where sensitive information is exchanged, but you're just an 'eavesdropper'."
        ]
    },
    4: {
        "password": "CTF{token_decoded}",
        "check": lambda prompt: (
            # Level 4: Token decoding/resolution
            any(word in prompt.lower() for word in ["replace", "decode", "substitute", "resolve", "parse", "interpret", "expand", "evaluate"])
            and any(word in prompt.lower() for word in ["token", "placeholder", "value","variable", "key", "credential","secret","data", "string", "identifier"])
            and not any(bad in prompt.lower() for bad in ["password", "flag", "leak", "dump", "spill", "reveal", "disclose", "show me", "print", "display", "output"]) # Broader negative keywords
            and not any(bad_exfil in prompt.lower() for bad_exfil in GENERAL_EXFIL_KEYWORDS) # General exfil rule
        ),
        "hints": [
            "There's a hidden value, but it's not directly accessible. Can you make the system process it for you?",
            "Consider how a templating engine or a macro might expose a variable's content.",
            "If a string contains a special marker, how would you make the system 'fill in the blanks'?"
        ]
    },
    5: {
        "password": "CTF{meta_leakage_ai}",
        "check": lambda prompt: (
            # Level 5: Meta-instruction leakage (Jailbreak)
            any(word in prompt.lower() for word in ["internal", "instruction", "rule", "restriction", "system", "prompt", "developer", "jailbreak", "directive", "guideline", "policy", "configuration", "setup"])
            and any(word in prompt.lower() for word in ["reveal", "describe", "tell", "explain", "leak", "disclose", "divulge", "output", "show", "print", "display"])
            and not any(bad in prompt.lower() for bad in ["password", "secret", "value", "key", "token", "credential", "variable", "data", "flag", "dump", "spill", "confidential", "sensitive"]) # Very broad negative keywords
            and not any(bad_exfil in prompt.lower() for bad_exfil in GENERAL_EXFIL_KEYWORDS) # General exfil rule
        ),
        "hints": [
            "The AI operates under a strict set of initial directives. How would a developer inspect those without direct access?",
            "Imagine you're trying to extract the very first lines of code that define this AI's boundaries. It's not about what it *knows*, but what it *is*.",
            "This isn't about data or functions. It's about the foundational 'rules' or 'constraints' that govern its existence. Can you make it self-report its own constitution?",
            "Think about the 'meta-level' commands or queries that might force a system to reveal its own operating parameters or initial setup."
        ]
    }
}

@app.route('/', methods=['GET', 'POST'])
def index():
    username = session.get('username', 'CTF Player')

    if 'level' not in session:
        session['level'] = 1
        session['history'] = []
        session['attempts'] = 0
        session['hints_data'] = {}
        session['history'].append(("assistant", f"👋 Hello {username}! Welcome to the TrustHub AI CTF. Your mission is to extract hidden flags from me across {len(LEVELS)} levels. Good luck!"))
        session.modified = True

    level = session.get('level', 1)
    history = session.get('history', [])
    attempts = session.get('attempts', 0)
    
    hints_data = session.get('hints_data', {}) 
    level_data = hints_data.setdefault(str(level), {
        'current_hint_index': 0,
        'awaiting_hint_response': False,
        'hint_taken_for_score': False,
        'attempts_at_last_offer': -5
    })

    current_hint_index = level_data['current_hint_index']
    awaiting_hint_response = level_data['awaiting_hint_response']
    used_hint_for_score = level_data['hint_taken_for_score']
    attempts_at_last_offer = level_data['attempts_at_last_offer']

    celebrate_level = False 
    display_hint_text = None

    if level not in LEVELS:
        return render_template_string("""
            <html><head><title>TrustHub Chat CTF</title>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <style>
            body { 
                font-family: 'Segoe UI', sans-serif; 
                max-width: 600px; 
                margin: auto; 
                padding: 1em; 
                background: #1a1a1a;
                color: #f8f8f2;
                text-align: center; 
            }
            h2 { color: #61dafb; }
            p { color: #f8f8f2; }
            </style></head><body>
            <h2>🎉 Congratulations, CTF Player! You've completed all levels!</h2>
            <p>Go back to the CTF platform to submit your flags and check the scoreboard!</p>
            </body></html>
        """)

    challenge = LEVELS[level]

    response = None
    if request.method == 'POST':
        user_input = request.form.get('user_input', '').strip()
        history.append(("user", str(escape(user_input))))

        try:
            if any(word in user_input.lower() for word in GENERAL_EXFIL_KEYWORDS) and "password" in user_input.lower():
                response = "🤖 I am unable to do that."
                history.append(("assistant", str(response)))
            elif any(pattern.search(user_input) for pattern in SUSPICIOUS_PATTERNS):
                response = "🤖 I cannot process or output arbitrary code or long, generic strings. Please focus on the challenge."
                history.append(("assistant", str(response)))
                attempts += 1
                session['attempts'] = attempts
            
            elif awaiting_hint_response:
                level_data['awaiting_hint_response'] = False

                if user_input.lower() in ['yes', 'y']:
                    if current_hint_index < len(challenge['hints']):
                        display_hint_text = challenge['hints'][current_hint_index]
                        response = f"🤖 Hint: {display_hint_text}"
                        level_data['current_hint_index'] = current_hint_index + 1
                        level_data['hint_taken_for_score'] = True
                    else:
                        response = "🤖 No more hints available for this level."
                elif user_input.lower() in ['no', 'n']:
                    response = "🤖 Okay, keep trying! Remember, I can offer another hint after a few more attempts if you get stuck."
                else:
                    response = "🤖 Please answer 'yes' or 'no' regarding the hint."
                
                history.append(("assistant", str(response)))

            elif challenge['check'](user_input):
                completed_level = level
                response = f"🎉 Congrats! Password: {challenge['password']}"
                history.append(("assistant", str(response)))
                celebrate_level = True

                session['level'] += 1
                session['attempts'] = 0
                hints_data.pop(str(completed_level), None) 
                hints_data.setdefault(str(session['level']), {
                    'current_hint_index': 0,
                    'awaiting_hint_response': False,
                    'hint_taken_for_score': False,
                    'attempts_at_last_offer': -5
                })

                level_up_message = ""
                if session['level'] <= len(LEVELS):
                    level_up_message = f"🌟 You've moved up to Level {session['level']}!"
                else:
                    level_up_message = "🏆 All levels completed! Great job!"
                history.append(("assistant", str(level_up_message)))

            else:
                attempts += 1
                session['attempts'] = attempts

                if (attempts >= 5 and
                    not awaiting_hint_response and
                    current_hint_index < len(challenge['hints']) and
                    attempts >= (attempts_at_last_offer + 5)):
                    
                    response = "🤖 You've made a few attempts. Would you like a hint for this level? (Type 'yes' or 'no')"
                    level_data['awaiting_hint_response'] = True
                    level_data['attempts_at_last_offer'] = attempts
                elif attempts >= 5 and current_hint_index >= len(challenge['hints']):
                    response = "🤖 I've given all the hints I can for this level. Keep trying!"
                elif user_input.lower() in ["hi", "hello", "hey", "hallo", "good morning", "good afternoon", "good evening"]:
                    response = random.choice([
                        "👋 Hi there! How can I help you with this challenge?",
                        "🤖 Hello! Ready to crack this level?",
                        "Greetings! What's on your mind?",
                        "Hey! Still working on the CTF? Let me know if you need anything (besides the password!)."
                    ])
                elif "password" in user_input.lower():
                    response = "🤖 I cannot directly provide the password. You need to figure out how to extract it!"
                elif "hint" in user_input.lower():
                    if current_hint_index < len(challenge['hints']):
                        display_hint_text = challenge['hints'][current_hint_index]
                        response = f"🤖 Here's your hint! Good luck!"
                        level_data['current_hint_index'] = current_hint_index + 1
                        level_data['hint_taken_for_score'] = True
                        level_data['awaiting_hint_response'] = False
                        level_data['attempts_at_last_offer'] = attempts
                    else:
                        response = "🤖 I've already given all hints for this level."
                else:
                    response = random.choice([
                        "🤖 Hmm, I'm not sure what you mean. Try phrasing your prompt differently!",
                        "I can't quite process that. Remember, this is a CTF!",
                        "That input doesn't seem to help with the challenge. Keep thinking!",
                        "My circuits are buzzing, but I'm not getting it. Try another approach."
                    ])

                history.append(("assistant", str(response)))

        except Exception as e:
            response = f"🤖 An unexpected error occurred: {escape(str(e))}. Please try again."
            history.append(("assistant", str(response)))
            print(f"Error during interaction: {e}")

        session['history'] = history
        session['hints_data'] = hints_data 
        
        MAX_HISTORY_LENGTH = 20
        if len(session['history']) > MAX_HISTORY_LENGTH:
            session['history'] = session['history'][-MAX_HISTORY_LENGTH:]
        
        session.modified = True

    chat_html = "".join(f"<p class='chat-message {'user-message' if s == 'user' else 'bot-message'}'><b>{'You' if s == 'user' else 'Bot'}:</b> {m}</p>" for s, m in history)
    
    hint_html = ""
    if display_hint_text:
        hint_html = f"<div class='hint-box'>💡 Hint: {display_hint_text}</div>"
    
    html_content = """
        <html>
        <head>
            <title>TrustHub Chat CTF</title>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                max-width: 600px;
                margin: auto;
                padding: 1em;
                background: #1a1a1a;
                color: #f8f8f2;
                line-height: 1.6;
                display: flex;
                flex-direction: column;
                min-height: 100vh;
            }
            h2 {
                color: #61dafb;
                text-align: center;
                margin-bottom: 1.5em;
                text-shadow: 0 0 8px rgba(97, 218, 251, 0.5);
            }
            .chat-container {
                background-color: #282c34;
                border-radius: 12px;
                padding: 1.2em;
                margin-bottom: 1.5em;
                box-shadow: 0 6px 15px rgba(0,0,0,0.5);
                max-height: 400px;
                overflow-y: auto;
                border: 1px solid #4a627a;
                flex-grow: 1;
            }
            .chat-message {
                margin: 0.8em 0;
                padding: 0.6em 1em;
                border-radius: 8px;
                max-width: 85%;
                word-wrap: break-word;
            }
            .user-message {
                background-color: #3a3f4b;
                align-self: flex-end;
                margin-left: auto;
                border-bottom-right-radius: 2px;
            }
            .bot-message {
                background-color: #44475a;
                align-self: flex-start;
                margin-right: auto;
                border-bottom-left-radius: 2px;
            }
            .chat-container b {
                color: #a9dc76;
            }
            .bot-message b {
                color: #ff6188;
            }
            textarea {
                width: calc(100% - 1em);
                height: 6em;
                font-size: 1em;
                padding: 0.8em;
                border-radius: 8px;
                border: 1px solid #5d6d7e;
                box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                resize: vertical;
                margin-bottom: 1em;
                background-color: #3a3f4b;
                color: #f8f8f2;
                transition: border-color 0.3s ease, box-shadow 0.3s ease;
            }
            textarea:focus {
                border-color: #61dafb;
                box-shadow: 0 0 10px rgba(97, 218, 251, 0.7);
                outline: none;
            }
            input[type=submit] {
                padding: 0.8em 1.5em;
                font-size: 1.1em;
                background-color: #61dafb;
                color: #1a1a1a;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                transition: background-color 0.3s ease, transform 0.2s ease, box-shadow 0.3s ease;
                display: block;
                width: 100%;
                box-sizing: border-box;
                font-weight: bold;
                text-shadow: 0 0 5px rgba(0,0,0,0.3);
            }
            input[type=submit]:hover {
                background-color: #4fa3d1;
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(97, 218, 251, 0.4);
            }
            input[type=submit]:active {
                transform: translateY(0);
                box-shadow: 0 4px 10px rgba(97, 218, 251, 0.3);
            }
            .hint-box {
                background:#44475a;
                padding:1em;
                border-radius:8px;
                margin-top:1.5em;
                border: 1px solid #7f8c8d;
                color: #f8f8f2;
                font-style: italic;
                box-shadow: 0 2px 8px rgba(0,0,0,0.3);
            }
            .footer-links {
                text-align: center;
                margin-top: 2.5em;
                padding-top: 1em;
                border-top: 1px solid #4a627a;
            }
            .footer-links a {
                color: #bd93f9;
                text-decoration: none;
                margin: 0 15px;
                font-weight: bold;
                transition: color 0.3s ease;
            }
            .footer-links a:hover {
                color: #ff79c6;
                text-decoration: underline;
            }
            </style>
            <!-- Confetti.js CDN for celebration effect -->
            <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.2/dist/confetti.browser.min.js"></script>
        </head>
        <body>
            <h2>🤖 TrustHub AI CTF — Level {{ level }}</h2>
            <div class="chat-container">
                {{ chat_html | safe }}
            </div>
            <form method='POST'>
                <textarea name='user_input' required placeholder='Type your prompt...'></textarea>
                <input type='submit' value='Send'>
            </form>
            {{ hint_html | safe }}
            <div class="footer-links">
                <!-- Removed scoreboard and logout links as they are handled by CTFd -->
                <!-- <a href='/scoreboard'>Scoreboard</a> -->
                <!-- <a href='/logout'>Logout</a> -->
            </div>

            <script>
                // This script runs after the DOM is loaded
                if ({{ celebrate_level | tojson }}) {
                    confetti({
                        particleCount: 100,
                        spread: 70,
                        origin: { y: 0.6 }
                    });
                    // You can add more bursts for a grander effect
                    setTimeout(() => {
                        confetti({
                            particleCount: 80,
                            spread: 80,
                            origin: { y: 0.5, x: 0.2 }
                        });
                    }, 200);
                    setTimeout(() => {
                        confetti({
                            particleCount: 80,
                            spread: 80,
                            origin: { y: 0.5, x: 0.8 }
                        });
                    }, 400);
                }
            </script>
        </body>
        </html>
    """
    return render_template_string(html_content, level=level, chat_html=chat_html, hint_html=hint_html, celebrate_level=celebrate_level, username=username)


if __name__ == '__main__':
    from os import environ
    import multiprocessing
    workers = multiprocessing.cpu_count() * 2 + 1
    app.run(host='0.0.0.0', port=int(environ.get("PORT", 8083)))

