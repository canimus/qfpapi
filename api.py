from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from jwcrypto import jwt, jwk
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = jwk.JWK(generate='oct', size=256)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Retrieve only table colimns defined in models as a function
dict_filter = lambda x, y: dict( [(i, x[i]) for i in x if i in set(y) ])

db = SQLAlchemy(app)

class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        public_id = db.Column(db.String(50), unique=True)
        name = db.Column(db.String(50))
        password = db.Column(db.String(80))
        admin = db.Column(db.Boolean)

class Todo(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        text = db.Column(db.String(50))
        complete = db.Column(db.Boolean)


@app.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()
    if not users:
        return jsonify({'message' : 'No users found!'})

    users_data = list(map(lambda x: dict_filter(x.__dict__, x.__table__.columns.keys()), users))
    return jsonify(users_data)

@app.route('/user/<public_id>', methods=['GET'])
def get_one_user(public_id):
    user = User.query.filter_by(public_id = public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = dict_filter(user.__dict__, user.__table__.columns.keys())
    return jsonify(user_data)

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'New user created'})

@app.route('/user/<public_id>', methods=['PUT'])
def promote_user(public_id):
    user = User.query.filter_by(public_id = public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'User has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):
    user = User.query.filter_by(public_id = public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'User has been deleted.'})

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm: "Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm: "Login required!"'})

    if check_password_hash(user.password, auth.password):
        payload = dict()
        payload['public_id'] = user.public_id
        payload['exp'] = str(datetime.datetime.utcnow() + datetime.timedelta(minutes=30))
        token = jwt.JWT(header={"alg": "HS256"}, claims=payload)
        token.make_signed_token(app.config['SECRET_KEY'])
        #token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, )

        return jsonify({'token' : token.serialize()})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm: "Login required!"'})

if __name__ == '__main__':
        app.run(debug=True, host="0.0.0.0")
