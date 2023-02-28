from flask import Flask
from flask import request
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from flask_jwt_extended import \
    (
        JWTManager,
        jwt_required,
        create_access_token,
        get_jwt_identity,
        get_jwt_header,
        get_jwt
    )
from flask_bcrypt import Bcrypt


def create_app():
    app = Flask(__name__)
    return app


app = create_app()
bcrypt = Bcrypt(app)

# kör med flask run
# flask --debug run
if not 'WEBSITE_HOSTNAME' in os.environ:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./test.db'
    app.config.from_prefixed_env()

else:
    DATABASE_URI = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
        dbuser=os.environ['DBUSER'],
        dbpass=os.environ['DBPASS'],
        dbhost=os.environ['DBHOST'] + ".postgres.database.azure.com",
        dbname=os.environ['DBNAME'])

    app.config['JWT_SECRET_KEY'] = os.environ['DBSECRET']
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI


app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 12000


jwt = JWTManager(app)
db = SQLAlchemy(app)


read_by = db.Table('read_by',
                   db.Column('user_id', db.Integer, db.ForeignKey('User.id')),
                   db.Column('msg_id', db.Integer, db.ForeignKey('Message.id'))
                   )


class User(db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    read_message = db.relationship(
        "Message", secondary='read_by', back_populates="user_read_msg")
    name = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(200), unique=False, nullable=False)

    def __init__(self, name, password):
        self.name = name
        self.password = bcrypt.generate_password_hash(password).decode("utf-8")


class Message(db.Model):
    __tablename__ = "Message"
    id = db.Column(db.Integer, primary_key=True)
    msg = db.Column(db.String(250))
    user_read_msg = db.relationship(
        "User", secondary='read_by', back_populates="read_message")

    def to_dict(self):
        result = {}
        result['id'] = self.id
        result['message'] = self.msg
        idlist = [userid.id for userid in self.user_read_msg]
        result["read_by"] = idlist

        return result


class JWT_blocklist(db.Model):
    __tablename__ = "JWT_blocklist"
    id = db.Column(db.Integer, primary_key=True)
    revoked_token = db.Column("token", db.String(700), unique=True)


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    is_revoked = JWT_blocklist.query.filter_by(revoked_token=jti).first()
    if is_revoked is None:
        return False
    return True


@app.route('/user/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    revoked = JWT_blocklist(revoked_token=jti)
    db.session.add(revoked)
    db.session.commit()

    return jsonify({'message': 'logged out'}), 200


@app.route("/user", methods=['POST'])
def register():
    data = request.json
    name = data["name"]
    password = data["password"]
    user = User.query.filter_by(name=name).first()

    if user is None:
        user = User(name=name, password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created"}), 200

    return jsonify({"message": "Username taken"}), 400


@app.route("/user/login", methods=['POST'])
def login():
    data = request.json
    password = data["password"]
    name = data["name"]
    user = User.query.filter_by(name=name).first()
    if user is None:
        return jsonify({'message': 'Wrong password'}), 400

    elif not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Wrong password'}), 400

    token = create_access_token(identity=user.name, expires_delta=None)
    return jsonify(access_token=token), 200


@app.route("/", methods=['GET'])
@jwt_required()
def hello_world():
    return "Hello world"


@app.route("/messages", methods=['POST'])
@jwt_required()
def save_message():
    data = request.json
    msgIn = data["message"]
    msg = Message(msg=msgIn)
    db.session.add(msg)
    db.session.commit()
    return jsonify({"response": "message saved"}), 200


@app.route("/messages", methods=['GET'])
def get_all_msg():
    messages = Message.query.filter_by().all()
    temp_list = [msg.to_dict() for msg in messages]
    return jsonify(temp_list), 200


@app.route("/messages/<MessageID>", methods=['GET'])
def get_msg(MessageID):
    message = Message.query.filter_by(id=MessageID).first()
    if message is not None:
        return jsonify(message.to_dict()), 200
    return jsonify({'response': "Message not found"}), 404


@app.route("/messages/<MessageID>", methods=['DELETE'])
@jwt_required()
def del_msg(MessageID):
    message = Message.query.filter_by(id=MessageID).first()
    if message is not None:
        db.session.delete(message)
        db.session.commit()
        return jsonify({"response": "Message deleted"}), 200
    return jsonify({'response': "Message not found"}), 404


@app.route("/messages/<MessageID>/read/<UserID>", methods=["POST"])
@jwt_required()
def mark_as_read(MessageID, UserID):
    message = Message.query.filter_by(id=MessageID).first()
    if message is not None:
        user = User.query.filter_by(id=UserID).first()
        if user is None:
            user = User(id=UserID)
        message.user_read_msg.append(user)
        db.session.add(message)
        db.session.commit()
        return jsonify({"response": "Message read"}), 200

    return jsonify({'response': "Message not found"}), 404


@app.route("/messages/unread/<UserID>", methods=["GET"])
@jwt_required()
def show_unread(UserID):
    output = []

    user = User.query.filter_by(id=UserID).first()

    if user is None:
        return jsonify({"response": "User not found"}), 404
    read_msg = user.read_message
    all_msg = Message.query.filter_by().all()
    read_id = [id.id for id in read_msg]
    for message in all_msg:
        if message.id not in read_id:
            output.append(message.to_dict())
    return jsonify(output), 200


@app.route("/clearAll", methods=["DELETE"])
def del_all():

    meta = db.metadata
    for table in reversed(meta.sorted_tables):
        print("clear table %s" % table)
        db.session.execute(table.delete())
    db.session.commit()
    return "all deleted", 200


if __name__ == "__main__":
    app.debug = True
    db.init_app(app)
    app.run()
