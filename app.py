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
    address= db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)  
    city = db.Column(db.String(15), nullable=False)  
    role = db.Column(db.String(10), nullable=False, default="user")

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
class Restaurant(db.Model):
    __tablename__="restaurants"

    rid=db.Column(db.Integer, primary_key=True)
    rname= db.Column(db.String(50),nullable=False)
    raddress = db.Column(db.String(100),nullable=False)
    image_filename = db.Column(db.String(200), nullable=True)

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
        address=request.form.get("address")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        role=request.form.get("role")
        city=request.form.get("city")

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("signup"))

        new_user = User(name=name, email=email, mobile=mobile,role=role,address=address,city=city)
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

@app.route('/delete_restaurant/<int:rid>', methods=['POST'])
@admin_required
@login_required
def delete_restaurant(rid):
    restaurant = Restaurant.query.get_or_404(rid)
    
    if restaurant.image_filename:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], restaurant.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)  # Delete file from storage

    db.session.delete(restaurant)
    db.session.commit()
    flash('Restaurant deleted successfully!', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/edit_restaurant/<int:rid>', methods=['GET'])
@admin_required
def edit_restaurant(rid):
    restaurant = Restaurant.query.get_or_404(rid)
    return render_template('add_restaurant.html', restaurant=restaurant)


@app.route("/user_dashboard")
@login_required
def user_dashboard():
    user_city = current_user.city  
    restaurants = Restaurant.query.filter(Restaurant.raddress.ilike(f"%{user_city}%")).all()  
    return render_template("user_dashboard.html", restaurants=restaurants)

@app.route('/submit_restaurant', methods=['POST'])
@admin_required
def submit_restaurant():
    rid = request.form.get('rid')  # Get restaurant ID (if updating)
    rname = request.form['restaurant_name']
    raddress = request.form['restaurant_address']
    
    image = request.files['restaurant_image']
    
    if rid:  # If restaurant ID exists, update existing record
        restaurant = Restaurant.query.get_or_404(rid)
        restaurant.rname = rname
        restaurant.raddress = raddress
        
        if image:  # If a new image is uploaded, replace the old one
            old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], restaurant.image_filename)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)
            
            image_filename = image.filename
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            restaurant.image_filename = image_filename
        
        flash('Restaurant updated successfully!', 'success')
    else:  # If no restaurant ID, add new restaurant
        image_filename = image.filename if image else None
        if image:
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        restaurant = Restaurant(rname=rname, raddress=raddress, image_filename=image_filename)
        db.session.add(restaurant)
        flash('Restaurant added successfully!', 'success')

    db.session.commit()
    return redirect(url_for('add_restaurant'))

@app.route('/admin_dashboard/add_restaurant')
@admin_required
@login_required
def add_restaurant():
    return render_template('add_restaurant.html')

@app.route('/admin_dashboard/orders')
@admin_required
@login_required
def orders_admin():
    return render_template("orders_admin.html")

if __name__ == "__main__":
    app.run(debug=True)
