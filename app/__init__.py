# In app/__init__.py
# ****************************************************************
# WARNING: HARDCODED CONFIGURATION BELOW - INSECURE!
# Replace placeholder values and remove before deployment/commit.
# ****************************************************************

import os 
from flask import Flask
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from .models import db, SiteSetting , Admin

from werkzeug.middleware.proxy_fix import ProxyFix


limiter = Limiter(get_remote_address)
load_dotenv() 
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # --- AWS / S3 Hardcoded Configuration ---
    app.config['S3_BUCKET'] = os.environ.get('S3_BUCKET')
    app.config['S3_REGION'] = os.environ.get('S3_REGION')


    app.config['AWS_ACCESS_KEY_ID'] = os.environ.get('AWS_ACCESS_KEY_ID')
    app.config['AWS_SECRET_ACCESS_KEY'] = os.environ.get('AWS_SECRET_ACCESS_KEY')
    # --- End Hardcoded Configuration ---


    # --- Initialize Extensions ---
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'admin_login'

   

    @login_manager.user_loader
    def load_user(user_id):  
        return Admin.query.get(int(user_id))

    # --- Import Blueprints/Routes ---
    with app.app_context():
        from . import routes
        from . import models # Ensure models are imported for migrate

        admin_username = os.environ.get('ADMIN_USERNAME', 'admin') # Use env var or default
        admin_password = os.environ.get('PRIVATE_SECTION_PASSWORD', 'Nagwa22!') # Use env var or default
        existing_admin = Admin.query.filter_by(username=admin_username).first()
        if not existing_admin:
            admin = Admin(
                username=admin_username,
                password_hash=generate_password_hash(admin_password)
            )
            db.session.add(admin)
            db.session.commit()
            print(f"Default admin user '{admin_username}' created.")
        else:
            print(f"Admin user '{admin_username}' already exists.")


        # --- START: Initialize Private Section Password ---
        private_section_pw_key = "private_section_password"
        existing_section_pw = SiteSetting.query.filter_by(key=private_section_pw_key).first()

        if not existing_section_pw:
            default_section_pw = os.environ.get('PRIVATE_SECTION_PASSWORD')
            if default_section_pw:
                hashed_pw = generate_password_hash(default_section_pw)
                setting = SiteSetting(key=private_section_pw_key, value=hashed_pw)
                db.session.add(setting)
                db.session.commit()
                print("Default private section password initialized in database.")
            else:
                print("PRIVATE_SECTION_PASSWORD environment variable not set. Skipping default section password initialization.")
        else:
            print("Private section password setting already exists in database.")
        # --- END: Initialize Private Section Password ---

    return app