from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from enum import Enum, auto

# Initialize SQLAlchemy
db = SQLAlchemy()

class UserRole(str, Enum):
    ADMIN = "admin"
    TEACHER = "teacher"
    STUDENT = "student"
    PARENT = "parent"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    student_id = db.Column(db.String(20), nullable=True)  # For students and parents
    language_preference = db.Column(db.String(10), default='en')  # Default to English
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.email}>'
