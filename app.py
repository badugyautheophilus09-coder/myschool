from flask import Flask, flash, render_template, request, redirect, url_for, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_migrate import Migrate
import logging
import os
import bcrypt
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ----------------------------
# Configure Logging
# ----------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ----------------------------
# Flask App Setup
# ----------------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "mysecretkey")
app.config['SESSION_PERMANENT'] = False

# Fix for SameSite Partitioned cookies
original_set_cookie = Response.set_cookie
def set_cookie_without_partitioned(self, *args, **kwargs):
    if 'Partitioned' in (kwargs.get('samesite') or ''):
        kwargs['samesite'] = None
    original_set_cookie(self, *args, **kwargs)
Response.set_cookie = set_cookie_without_partitioned

# ----------------------------
# Database + Login Manager
# ----------------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------------
# Database Models
# ----------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def get_id(self):
        return str(self.id)


class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    class_level = db.Column(db.String(50), nullable=False)   # e.g. JHS1, Primary5
    course = db.Column(db.String(255), nullable=False)       # e.g. Maths, Science
    score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# ----------------------------
# User Loader
# ----------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------
# Error Handler
# ----------------------------
@app.errorhandler(500)
def handle_500(e):
    logger.error(f"Internal Server Error: {e}")
    return jsonify({"error": "Internal Server Error"}), 500

# ----------------------------
# Routes
# ----------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken", "error")
            return redirect(url_for('signup'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(email=email, full_name=full_name, username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("User created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "error")
            return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard
@app.route('/about')
@login_required
def about():
    return render_template('about.html', active_page='about')

@app.route('/help')
@login_required
def help():
    return render_template('help.html', active_page='help')

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html', active_page='contact')

@app.route('/home')
@login_required
def dashboard():
    return render_template('dashboard.html', active_page='home')

@app.route('/main')
@login_required
def main():
    return render_template('main.html')

@app.route('/dash')
@login_required
def dash():
    return render_template('dash.html')

# Forgot Password
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # TODO: Implement actual password reset logic (email service, token, etc.)
            flash("Password reset instructions have been sent to your email if it exists in our system.", "success")
        else:
            flash("If the email exists in our system, you will receive instructions to reset your password.", "info")
            
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ----------------------------
# Run App
# ----------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # makes sure tables exist
    app.run(debug=True)
