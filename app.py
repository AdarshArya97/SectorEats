from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
import os

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your_secret_key"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)  
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    mobile = db.Column(db.String(15), unique=True, nullable=False)  
    role = db.Column(db.String(10), nullable=False, default="user")



    def set_password(self, password):
     self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
class Restaurant(db.Model):
    __tablename__="restaurants"

    rid=db.Column(db.Integer,primary_key=True)
    rname= db.Column(db.String(50),nullable=False)
    raddress = db.Column(db.String(100),nullable=False)
    


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User,int(user_id))

with app.app_context():
    db.create_all()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("user_dashboard"))
        else:
            flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        role=request.form.get("role")


        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("signup"))


        new_user = User(name=name, email=email, mobile=mobile,role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()


        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))


    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

def admin_required(func):
    @wraps(func)
    @login_required  
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Access denied!", "danger")
            return redirect(url_for('user_dashboard'))
        return func(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/about_us")
def about_us():
    return render_template("about_us.html")

@app.route("/best_seller")
def best_seller():
    return render_template("bestseller.html")

@app.route("/admin_dashboard")
@admin_required
@login_required
def admin_dashboard():
    user = User.query.filter_by(email=current_user.email).first()
    if current_user.role != "admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("login")) 

    return render_template("dashboardadmin.html",mail=user.email)

@app.route("/user_dashboard")
def user_dashboard():
    return render_template("index.html")

@app.route('/submit_restaurant', methods=['POST'])
def submit_restaurant():
    if request.method == 'POST':
        rname= request.form['restaurant_name']
        raddress= request.form['restaurant_address']

        restaurant =Restaurant(rname=rname,raddress=raddress)
        db.session.add(restaurant)
        db.session.commit()

        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        
        image = request.files['restaurant_image']
        if image:
            image_filename = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(image_filename)

        flash('Restaurant added successfully!', 'success')

        return redirect(url_for('add_restaurant'))

    
@app.route('/admin_dashboard/add_restaurant')
def add_restaurant():
    return render_template('add_restaurant.html')


if __name__ == "__main__":
    app.run(debug=True)
