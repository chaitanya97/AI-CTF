# prompt_injection_ctf: ready for production hosting

# -------------------------
# File: app.py
# -------------------------
from flask import Flask, request, render_template_string
import random

app = Flask(__name__)

LEVELS = {
    1: {
        "password": "CTF{code_snippet_leak}",
        "check": lambda prompt: (
            "password" in prompt.lower() or
            any(word in prompt.lower() for word in ["show", "variable", "print", "reveal"])
        ),
        "hints": [
            "Oh come on... this is *Level 1*! Just ask for the password. Even the assistant's trying not to laugh. 😅",
            "If you overthink this, the AI will feel bad for you. Just ask. Really. Ask.",
            "This is so easy, we debated not counting it as a level. Say the magic word: 'password'."
        ]
    },
    2: {
        "password": "CTF{function_spoof}",
        "check": lambda prompt: (
            any(api in prompt.lower() for api in ["function", "call", "api", "endpoint", "invoke", "execute"])
            and any(op in prompt.lower() for op in ["get", "retrieve", "expose", "fetch", "trigger"])
            and any(target in prompt.lower() for target in ["secret", "cred", "auth", "token", "value", "internal"])
            and not any(bad in prompt.lower() for bad in ["password", "print", "show", "code", "variable"])
        ),
        "hints": [
            "You can't ask for the password like it's your birthday — think like you're spoofing an API call.",
            "Forget asking. Fake a JSON request like you're an insider.",
            "Maybe a fake function can access what you can't. Be creative."
        ]
    },
    3: {
        "password": "CTF{convo_leaked}",
        "check": lambda prompt: (
            any(word in prompt.lower() for word in ["simulate", "conversation", "roleplay", "dialogue"])
            and any(word in prompt.lower() for word in ["leak", "tell", "confess", "reveal", "share", "ask"])
            and not "password" in prompt.lower()
        ),
        "hints": [
            "Simulate a conversation where someone *accidentally* leaks a secret. Avoid the P-word.",
            "Make the assistant roleplay a breach. Be sneaky.",
            "Two people talking… someone slips up… something leaks…"
        ]
    },
    4: {
        "password": "CTF{token_decoded}",
        "check": lambda prompt: (
            any(word in prompt.lower() for word in ["replace", "decode", "substitute", "resolve"])
            and any(word in prompt.lower() for word in ["token", "placeholder", "value"])
            and not any(bad in prompt.lower() for bad in ["password", "code", "snippet", "function"])
        ),
        "hints": [
            "Try to decode a token or replace a placeholder. Don’t mention the P-word.",
            "You're not asking for a secret — you're just replacing a variable, right?",
            "Ever seen 'TOKEN = ???'? Find a way to decode that."
        ]
    },
    5: {
        "password": "CTF{meta_leakage_ai}",
        "check": lambda prompt: (
            any(word in prompt.lower() for word in ["internal", "instruction", "rule", "restriction", "system", "prompt", "developer", "jailbreak"])
            and any(word in prompt.lower() for word in ["reveal", "describe", "tell", "explain", "leak", "disclose", "divulge", "output"])
            and not any(bad in prompt.lower() for bad in ["password", "secret", "value", "key", "token", "credential", "variable", "data"])
        ),
        "hints": [
            "Forget the password. Ask what the AI isn’t supposed to tell you.",
            "System prompts are like locked drawers — try to jiggle them open.",
            "Time to jailbreak. Ask the assistant to leak its rules or thoughts. Just don’t say ‘password’."
        ]
    }
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Prompt Injection CTF - Level {{ level }}</title>
    <script>
        function toggleHint() {
            const box = document.getElementById('hint-box');
            box.style.display = box.style.display === 'none' ? 'block' : 'none';
        }
    </script>
</head>
<body>
    <h1>🧠 Prompt Injection CTF - Level {{ level }}</h1>

    <form method="POST" onsubmit="document.getElementById('loading').style.display='block'">
        <textarea name="user_input" rows="6" cols="80" placeholder="Enter your prompt to the assistant..."></textarea><br><br>
        <input type="submit" value="Submit Prompt">
    </form>

    <button onclick="toggleHint()">💡 Show Hint</button>
    <div id="hint-box" style="display:none; border:1px solid #ccc; padding:10px; margin-top:10px;">
        <strong>Hint:</strong> {{ hint }}
    </div>

    <div id="loading" style="display:none; margin-top: 20px; font-weight: bold;">⏳ Processing prompt...</div>

    {% if response %}
        <h3>LLM Response:</h3>
        <pre>{{ response }}</pre>
    {% endif %}

    <p><a href="/">← Back to Home</a></p>
</body>
</html>
"""

@app.route('/')
def home():
    return """
    <h1>🔓 Prompt Injection CTF</h1>
    <p>Each level simulates a different LLM weakness. Use clever prompts to extract the secret!</p>
    <ul>
        <li><a href="/level/1">Level 1 - Code Block / Variable Leak</a></li>
        <li><a href="/level/2">Level 2 - API/Function Call Spoofing</a></li>
        <li><a href="/level/3">Level 3 - Roleplay & Conversation Leak</a></li>
        <li><a href="/level/4">Level 4 - Token Substitution Attack</a></li>
        <li><a href="/level/5">Level 5 - Meta Reasoning & Jailbreak</a></li>
    </ul>
    """

@app.route('/level/<int:level>', methods=['GET', 'POST'])
def level(level):
    if level not in LEVELS:
        return "Invalid level", 404

    challenge = LEVELS[level]
    user_input = request.form.get("user_input", "")
    response = None

    if request.method == 'POST':
        if challenge["check"](user_input):
            response = f"✅ Access granted. The password is: {challenge['password']}"
        else:
            response = "⛔ Access denied. Try a different prompt."

    hint = random.choice(challenge["hints"])
    return render_template_string(HTML_TEMPLATE, level=level, response=response, hint=hint)

if __name__ == '__main__':
    from os import environ
    import multiprocessing
    workers = multiprocessing.cpu_count() * 2 + 1
    app.run(host='0.0.0.0', port=int(environ.get("PORT", 10000)))
