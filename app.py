from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime

app = Flask(__name__)
app.config.from_object("config.Config")
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


@app.route("/register", methods=["POST"])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="pbkdf2:sha256")
    new_user = User(username=data["username"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "registered successfully"})


@app.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()
    if user and check_password_hash(user.password, data["password"]):
        token = jwt.encode(
            {
                "username": user.username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        return jsonify({"token": token})
    return make_response(
        "could not verify", 401, {"WWW-Authenticate": 'Basic realm="Login required!"'}
    )


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
