from flask import Flask, flash, render_template, request, redirect, url_for, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
import logging
import os
import bcrypt

# (Removed invalid JavaScript/TypeScript code)

# Configure Logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask App Setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'postgresql+psycopg2://postgres:Theo123@localhost:5432/school'
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "mysecretkey")
app.config['SESSION_PERMANENT'] = False

# Fix for "Partitioned" SameSite issue
original_set_cookie = Response.set_cookie
def set_cookie_without_partitioned(self, *args, **kwargs):
    if 'Partitioned' in (kwargs.get('samesite') or ''):
        kwargs['samesite'] = None
    original_set_cookie(self, *args, **kwargs)
Response.set_cookie = set_cookie_without_partitioned

# Initialize DB and LoginManager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
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

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Error Handler
@app.errorhandler(500)
def handle_500(e):
    logger.error(f"Internal Server Error: {e}")
    return jsonify({"error": "Internal Server Error"}), 500

# Root Redirect
@app.route('/')
def index():
    return redirect(url_for('login'))

# Signup Route
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

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "error")
            return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard
@app.route('/home')
@login_required
def dashboard():
    return render_template('dashboard.html')



@app.route('/main')
@login_required
def main():
    return render_template('main.html')

@app.route('/dash')
@login_required
def dash():
    return render_template('dash.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Run the App
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure DB tables exist
    app.run(debug=True)

from flask_migrate import Migrate
migrate = Migrate(app, db)

