import logging
import os
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# === SECRETS (we will set these safely) ===
# Safe AES key loading
aes_key_b64 = os.environ.get('AES_KEY_BASE64')
if not aes_key_b64:
    raise ValueError("Missing AES_KEY_BASE64 environment variable!")
try:
    AES_KEY = base64.urlsafe_b64decode(aes_key_b64)
    if len(AES_KEY) != 32:
        raise ValueError("AES_KEY must be exactly 32 bytes after decoding")
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


def generate_capability(user_id: int) -> str:
    payload = {'user_id': user_id, 'exp': datetime.utcnow() +
               timedelta(minutes=60)}
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
            return jsonify({'error': 'Invalid capability code'}), 401
    decorated.__name__ = f.__name__
    return decorated


def detect_sql_injection(text: str) -> bool:
    bad = ['OR 1=1', 'DROP', 'UNION', '--', ';', 'EXEC', 'DELETE']
    return any(word.upper() in text.upper() for word in bad)


@app.route('/')
def home():
    html = '''
    <h1>🔒 My Secure Cloud System</h1>
    <p>Beginner friendly • AES-256 • Anti SQL Injection</p>
    
    <h2>1. Register</h2>
    <form action="/register" method="post">
        Username: <input name="username" required><br><br>
        Password: <input name="password" type="password" required><br><br>
        Sensitive Info (e.g. card number): <input name="sensitive" required><br><br>
        <button type="submit">Register</button>
    </form>

    <h2>2. Login</h2>
    <form action="/login" method="post">
        Username: <input name="username" required><br><br>
        Password: <input name="password" type="password" required><br><br>
        <button type="submit">Login</button>
    </form>
    '''
    return render_template_string(html)


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    sensitive = request.form.get('sensitive')

    if detect_sql_injection(username) or detect_sql_injection(password) or detect_sql_injection(sensitive):
        return jsonify({'error': '🚨 Suspicious input blocked (SQL injection attempt)'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'User already exists'}), 400

    user = User(
        username=username,
        encrypted_password=encrypt(password),
        encrypted_sensitive=encrypt(sensitive)
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': '✅ Registered! Everything is AES-256 encrypted.'})


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if detect_sql_injection(username) or detect_sql_injection(password):
        return jsonify({'error': '🚨 Suspicious input blocked'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or decrypt(user.encrypted_password) != password:
        return jsonify({'error': 'Wrong username or password'}), 401

    capability_code = generate_capability(user.id)
    return jsonify({
        'message': '✅ Login successful!',
        'capability_code': capability_code,
        'how_to_use': 'Copy this code. Use it as Bearer token in Authorization header for /profile'
    })


@app.route('/profile', methods=['GET'])
@require_capability
def profile(user_id):
    user = User.query.get(user_id)
    sensitive = decrypt(user.encrypted_sensitive)
    return jsonify({
        'username': user.username,
        'sensitive_info': sensitive,
        'note': 'This data was encrypted in the database!'
    })


# === ADD THIS LOGGING SETUP FOR GUNICORN (very important for Render) ===
if __name__ != '__main__':
    # When running under Gunicorn, use Gunicorn's logger
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

# === CREATE DB TABLES ON STARTUP ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
else:
    # For production (Gunicorn)
    with app.app_context():
        db.create_all()
