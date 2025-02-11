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

@app.route("/about_us")
def about_us():
    return render_template("about_us.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


db = SQLAlchemy(app)

if __name__=="__main__":
    app.run(debug=True)
   