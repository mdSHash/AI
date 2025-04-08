from datetime import datetime
from user_management import db

class Broadcast(db.Model):
    __tablename__ = 'broadcasts'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    target_role = db.Column(db.String(20), default='all')  # 'all', 'student', 'parent', 'teacher'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Broadcast {self.id} - {self.sender_id}>'
