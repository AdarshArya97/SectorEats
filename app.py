from flask import Flask,render_template
from flask_sqlalchemy import SQLAlchemy
import os

basedir=os.path.abspath(os.path.dirname(__file__))

app=Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

@app.route("/bestseller")
def bestseller():
    return render_template("bestseller.html")


db = SQLAlchemy(app)