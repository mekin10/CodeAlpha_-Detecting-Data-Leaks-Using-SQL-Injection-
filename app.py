import os
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Safe AES-256 Key Loading
aes_key_b64 = os.environ.get('AES_KEY_BASE64')
if not aes_key_b64:
    raise ValueError("Missing AES_KEY_BASE64 environment variable!")
try:
    AES_KEY = base64.urlsafe_b64decode(aes_key_b64)
    if len(AES_KEY) != 32:
        raise ValueError("AES_KEY must be exactly 32 bytes")
except Exception as e:
    raise ValueError(f"Invalid AES_KEY_BASE64: {str(e)}")

JWT_SECRET = os.environ.get(
    'JWT_SECRET', 'change-this-secret-in-production-12345')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    encrypted_sensitive = db.Column(db.Text, nullable=False)


def encrypt(data: str) -> str:
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt(encrypted: str) -> str:
    data = base64.b64decode(encrypted)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(AES_KEY)
    return aesgcm.decrypt(nonce, ct, None).decode()

# Capability Code now lasts 24 hours


def generate_capability(user_id: int) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def require_capability(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Capability code required'}), 401
        try:
            data = jwt.decode(token.split()[1],
                              JWT_SECRET, algorithms=['HS256'])
            return f(*args, **kwargs, user_id=data['user_id'])
        except:
            return jsonify({'error': 'Invalid or expired capability code'}), 401
    decorated.__name__ = f.__name__
    return decorated


def detect_sql_injection(text: str) -> bool:
    bad = ['OR 1=1', 'DROP', 'UNION', '--', ';', 'EXEC', 'DELETE']
    return any(word.upper() in text.upper() for word in bad)


def get_home_html(message=""):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Cloud System</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #f4f7f9; }}
            h1 {{ color: #2c3e50; text-align: center; }}
            .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); margin: 20px 0; }}
            input {{ width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 5px; }}
            button {{ background: #3498db; color: white; padding: 12px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }}
            button:hover {{ background: #2980b9; }}
            .success {{ color: green; font-weight: bold; }}
            .error {{ color: red; font-weight: bold; }}
            code {{ background: #f1f1f1; padding: 10px; display: block; word-break: break-all; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <h1>🔒 Secure Cloud System</h1>
        <p style="text-align:center; color:#7f8c8d;">AES-256 Encryption + Capability Code + Anti-SQL Injection</p>
        
        <div class="card">
            <h2>Register New User</h2>
            <form action="/register" method="post">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password" required><br>
                <input name="sensitive" placeholder="Sensitive Info (e.g. card number)" required><br>
                <button type="submit">Register</button>
            </form>
        </div>

        <div class="card">
            <h2>Login</h2>
            <form action="/login" method="post">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
        </div>

        {message}
    </body>
    </html>
    '''


@app.route('/')
def home():
    return render_template_string(get_home_html())


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    sensitive = request.form.get('sensitive', '').strip()

    if detect_sql_injection(username) or detect_sql_injection(password) or detect_sql_injection(sensitive):
        return render_template_string(get_home_html('<p class="error">🚨 Suspicious input blocked (SQL injection attempt)</p>'))

    if User.query.filter_by(username=username).first():
        return render_template_string(get_home_html('<p class="error">User already exists</p>'))

    user = User(
        username=username,
        encrypted_password=encrypt(password),
        encrypted_sensitive=encrypt(sensitive)
    )
    db.session.add(user)
    db.session.commit()
    return render_template_string(get_home_html('<p class="success">✅😀 Registered successfully! Data is AES-256 encrypted.</p>'))


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if detect_sql_injection(username) or detect_sql_injection(password):
        return render_template_string(get_home_html('<p class="error">🚨 Suspicious input blocked</p>'))

    user = User.query.filter_by(username=username).first()
    if not user or decrypt(user.encrypted_password) != password:
        return render_template_string(get_home_html('<p class="error">❌ Wrong username or password</p>'))

    capability_code = generate_capability(user.id)
    sensitive_data = decrypt(user.encrypted_sensitive)

    success_message = f'''
    <div class="card" style="background:#d5f4e6;">
        <h2>✅ Welcome, {username}!</h2>
        <p><strong>Sensitive Information (Decrypted):</strong> {sensitive_data}</p>
        <p class="success">✅ Data successfully decrypted using AES-256 encryption</p>
        
        <h3>Capability Code (valid for 24 hours)</h3>
        <code style="font-size:13px;">{capability_code}</code>
        
        <br><br>
        <a href="/profile"><button style="background:#27ae60;">View My Secure Profile</button></a>
    </div>
    '''
    return render_template_string(get_home_html(success_message))


@app.route('/profile', methods=['GET'])
@require_capability
def profile(user_id):
    user = User.query.get(user_id)
    if not user:
        return render_template_string(get_home_html('<p class="error">User not found</p>'))

    sensitive = decrypt(user.encrypted_sensitive)

    profile_html = f'''
    <div class="card" style="background:#d5f4e6;">
        <h2>🔐 My Secure Profile</h2>
        <p><strong>Username:</strong> {user.username}</p>
        <p><strong>Sensitive Information:</strong> {sensitive}</p>
        <p class="success">This page is protected by Capability Code + AES-256 Encryption</p>
        <br>
        <a href="/"><button>← Back to Home</button></a>
    </div>
    '''
    return render_template_string(get_home_html(profile_html))


# Logging for Gunicorn
if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
else:
    with app.app_context():
        db.create_all()
