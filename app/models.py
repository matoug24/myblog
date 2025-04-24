# In app/models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class Admin(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)

class VisitorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), index=True) # Index for potential filtering
    visit_time = db.Column(db.DateTime, default=datetime.utcnow, index=True) # Index time
    
    # --- New Columns ---
    # Foreign Key to link to the BlogPost table
    blog_post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=True, index=True) # Allow null if logging non-post visits later? Index added.
    # Store the title at the time of visit for easy display (denormalized)
    blog_post_title = db.Column(db.String(150), nullable=True) 
    # Store User Agent string
    user_agent = db.Column(db.String(255), nullable=True) 
    # Store Referrer
    referrer = db.Column(db.String(255), nullable=True)

class BlogPost(db.Model):
    # ... (keep existing code)
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    body = db.Column(db.Text)
    date_posted = db.Column(db.Date)
    category = db.Column(db.String(20))  # 'personal' or 'professional'
    is_private = db.Column(db.Boolean, default=False)
    password = db.Column(db.Text, nullable=True)
    image_filenames = db.Column(db.Text, nullable=True) # Comma-separated list

class AboutSection(db.Model):
    # ... (keep existing code)
    id = db.Column(db.Integer, primary_key=True)
    section_type = db.Column(db.String(20))  # 'personal' or 'professional'
    content = db.Column(db.Text)
    image_filenames = db.Column(db.Text)

# --- NEW MODEL ---
class SiteSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key, default=None):
        """Helper to get a setting value"""
        setting = SiteSetting.query.filter_by(key=key).first()
        return setting.value if setting else default

    @staticmethod
    def set(key, value):
        """Helper to set or update a setting value"""
        setting = SiteSetting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = SiteSetting(key=key, value=value)
            db.session.add(setting)
        # db.session.commit() # Commit immediately or manage transactions externally

    @staticmethod
    def get_bool(key, default=False):
        """Helper to get a boolean setting"""
        value = SiteSetting.get(key)
        if value is None:
            return default
        return value.lower() in ['true', '1', 'yes', 'on']