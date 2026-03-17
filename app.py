from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '9b0665fd484afd702ad7e207992023cd3610e576a21caa2b73bab14fddc873f2'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)
# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)

# Create tables
with app.app_context():
    db.create_all()

# Signup endpoint
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not data or 'username' not in data or 'password' not in data or 'email' not in data or 'phone' not in data:
        return jsonify({'message': 'All fields required'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password required'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    token = jwt.encode({
        'user': user.username,
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'access_token': token})

# Protected example route
@app.route('/profile', methods=['GET'])
def profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header or " " not in auth_header:
        return jsonify({'message': 'Token missing'}), 401

    token = auth_header.split(" ")[1]
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.filter_by(username=data['user']).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    return jsonify({'username': user.username, 'id': user.id})

@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or " " not in auth_header:
        return jsonify({'message': 'Token missing'}), 401

    token = auth_header.split(" ")[1]
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.filter_by(username=data['user']).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)