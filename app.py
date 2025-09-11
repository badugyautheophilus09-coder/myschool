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
# Initialize extensions
# ----------------------------
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'login'

# ----------------------------
# Application Factory
# ----------------------------
def create_app():
    app = Flask(__name__)
    
    # Load configuration
    database_url = os.getenv('DATABASE_URL', 'sqlite:///school.db')
    
    # Configure PostgreSQL with SSL for production
    if database_url.startswith('postgres'):
        # Convert postgres:// to postgresql:// for SQLAlchemy
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql+psycopg2://', 1)
        
        # Configure SQLAlchemy engine options
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'connect_args': {
                'connect_timeout': 10,
                'keepalives': 1,
                'keepalives_idle': 30,
                'keepalives_interval': 10,
                'keepalives_count': 5,
                'sslmode': 'require'
            }
        }
            
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    
    # Ensure the database URI is set
    if not app.config['SQLALCHEMY_DATABASE_URI']:
        raise ValueError("No database URL set. Please set the DATABASE_URL environment variable.")
    
    # Log the database URL (without password for security)
    db_url = app.config['SQLALCHEMY_DATABASE_URI']
    if db_url:
        safe_url = db_url.split('@')[-1] if '@' in db_url else db_url
        app.logger.info(f'Using database: {safe_url}')
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    
    # Import and register blueprints here if you have any
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    # Fix for SameSite Partitioned cookies
    original_set_cookie = Response.set_cookie
    def set_cookie_without_partitioned(self, *args, **kwargs):
        if 'Partitioned' in (kwargs.get('samesite') or ''):
            kwargs['samesite'] = None
        return original_set_cookie(self, *args, **kwargs)
    Response.set_cookie = set_cookie_without_partitioned
    
    return app

# ----------------------------
# Create Flask Application
# ----------------------------
app = create_app()

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
    import traceback
    error_traceback = traceback.format_exc()
    logger.error(f"500 Error: {str(e)}\n{error_traceback}")
    
    # Log the database URL (without password)
    db_url = app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')
    if db_url and '@' in db_url:
        db_url = db_url.split('@')[-1]
    logger.error(f"Database URL: {db_url}")
    
    # Return a more detailed error in development, generic in production
    if app.config.get('FLASK_ENV') == 'development':
        return jsonify({
            "error": "Internal Server Error",
            "message": str(e),
            "traceback": error_traceback.split('\n')
        }), 500
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
