import os
import pdb

# from passlib.hash import pbkdf2_sha256
from werkzeug.security import check_password_hash, generate_password_hash

from flask import Flask, session, render_template, request
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
# engine = create_engine(
#     os.getenv(
#         "postgres://eahwehioiwzgix:6cbc5e10d3106a72b1d996237366052807c67bd2ad77fbe5d6041a144e607e3a@ec2-54-228-207-163.eu-west-1.compute.amazonaws.com:5432/d1nkcldcl1832o"
#     )
# )
db = scoped_session(sessionmaker(bind=engine))


@app.route("/")
def index():
    if session.get("logged_in"):
        return render_template("search.html", username=session["user_name"])
    else:
        return render_template("welcome.html")


@app.route("/register", methods=["POST", "GET"])
def register():

    if request.method == "POST":

        # Get form information.
        username = request.form.get("username")
        password = request.form.get("password")

        if (
            db.execute(
                "SELECT * FROM users WHERE username = :username", {"username": username}
            ).rowcount
            > 0
        ):
            return render_template("error.html", message="Username already exists.")
        else:
            # Hash user's password to store in DB
            hashedPassword = generate_password_hash(
                request.form.get("password"), method="pbkdf2:sha256", salt_length=8
            )
            db.execute(
                "INSERT INTO users (username, password) VALUES (:username, :password)",
                {"username": username, "password": hashedPassword},
            )
            db.commit()
            session["user_name"] = username
            session["logged_in"] = True
            return render_template("search.html")
    else:
        return render_template("register.html")


@app.route("/login", methods=["POST"])
def login():
    if request.method == "GET":
        return render_template("welcome.html")
    else:
        # Get form information.
        username = request.form.get("username")
        password = request.form.get("password")

        result = db.execute(
            "SELECT * FROM users WHERE username = :username", {"username": username}
        ).fetchone()

        if result == None or not check_password_hash(result[1], password):
            return render_template(
                "error.html", message="invalid username and/or password"
            )
        else:
            session["user_name"] = username
            session["logged_in"] = True
            return render_template("search.html")


@app.route("/logout")
def logout():
    session["user_name"] = None
    session['logged_in'] = False
    session.clear()
    return render_template("welcome.html")


# # key: yuxGnaukypsnFepTf3Yg
# # secret: 2x3OT4XuPJDFfEYeUWrH0w77BM2LMMrw3SQKKldg8Y
