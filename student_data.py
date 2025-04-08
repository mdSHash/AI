from datetime import datetime
from user_management import db

class StudentScore(db.Model):
    __tablename__ = 'student_scores'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    exam_type = db.Column(db.String(50), nullable=False)  # e.g., quiz, midterm, final
    score = db.Column(db.Float, nullable=False)
    max_score = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Score {self.student_id} - {self.subject} - {self.exam_type}>'

class StudentEnrollment(db.Model):
    __tablename__ = 'student_enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), nullable=False)
    course_id = db.Column(db.String(20), nullable=False)
    enrollment_date = db.Column(db.Date, nullable=False)
    active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Enrollment {self.student_id} - {self.course_id}>'

class Course(db.Model):
    __tablename__ = 'courses'
    
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    def __repr__(self):
        return f'<Course {self.course_id} - {self.name}>'
