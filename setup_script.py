"""
This script creates initial data for the educational institute RAG system.
Run this after setting up the application to populate with sample data.
"""

import os
import sys
from datetime import datetime, timedelta
import random
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Add the current directory to path to import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our application modules
from app import app, db
from user_management import User, UserRole
from student_data import StudentScore, Course, StudentEnrollment
from broadcast import Broadcast

# Load environment variables
load_dotenv()

# Sample data
subjects = [
    "Mathematics", "Science", "English", "Arabic", "Social Studies", 
    "Computer Science", "Physics", "Chemistry", "Biology", "Islamic Studies"
]

exam_types = ["Quiz", "Midterm", "Final", "Project", "Homework"]

# Function to create sample data
def create_sample_data():
    with app.app_context():
        # Clear existing data
        db.drop_all()
        db.create_all()
        
        print("Creating users...")
        # Create admin user
        admin = User(
            email="admin@example.com",
            password=generate_password_hash("adminpass"),
            name="Admin User",
            role=UserRole.ADMIN,
            language_preference="en"
        )
        db.session.add(admin)
        
        # Create teacher users
        teachers = []
        for i in range(1, 6):
            teacher = User(
                email=f"teacher{i}@example.com",
                password=generate_password_hash("teacherpass"),
                name=f"Teacher {i}",
                role=UserRole.TEACHER,
                language_preference="en" if i % 2 == 0 else "ar"  # Alternate languages
            )
            db.session.add(teacher)
            teachers.append(teacher)
        
        # Create student users
        students = []
        for i in range(1, 51):  # 50 students
            language = "en" if i % 3 != 0 else "ar"  # 2/3 English, 1/3 Arabic
            student = User(
                email=f"student{i}@example.com",
                password=generate_password_hash("studentpass"),
                name=f"Student {i}",
                role=UserRole.STUDENT,
                student_id=f"S{1000+i}",
                language_preference=language
            )
            db.session.add(student)
            students.append(student)
        
        # Create parent users
        for i in range(1, 31):  # 30 parents
            language = "en" if i % 3 != 0 else "ar"
            parent = User(
                email=f"parent{i}@example.com",
                password=generate_password_hash("parentpass"),
                name=f"Parent {i}",
                role=UserRole.PARENT,
                student_id=f"S{1000+i}",  # Link to their child
                language_preference=language
            )
            db.session.add(parent)
        
        db.session.commit()
        print("Users created successfully.")
        
        print("Creating courses...")
        # Create courses
        courses = []
        for i, subject in enumerate(subjects):
            course = Course(
                course_id=f"C{2000+i}",
                name=subject,
                description=f"Course for {subject}",
                teacher_id=teachers[i % len(teachers)].id
            )
            db.session.add(course)
            courses.append(course)
        
        db.session.commit()
        print("Courses created successfully.")
        
        print("Creating enrollments...")
        # Create student enrollments
        for student in students:
            # Each student enrolls in 5-7 courses
            num_courses = random.randint(5, 7)
            selected_courses = random.sample(courses, num_courses)
            
            for course in selected_courses:
                enrollment = StudentEnrollment(
                    student_id=student.student_id,
                    course_id=course.course_id,
                    enrollment_date=datetime.now() - timedelta(days=random.randint(30, 90)),
                    active=True
                )
                db.session.add(enrollment)
        
        db.session.commit()
        print("Enrollments created successfully.")
        
        print("Creating scores...")
        # Create student scores
        today = datetime.now().date()
        
        for student in students:
            # Get the courses this student is enrolled in
            enrollments = StudentEnrollment.query.filter_by(student_id=student.student_id).all()
            
            for enrollment in enrollments:
                course = Course.query.filter_by(course_id=enrollment.course_id).first()
                
                # Create scores for different exam types
                for exam_type in exam_types:
                    # Not all students have all exam types
                    if random.random() > 0.2:  # 80% chance of having this exam
                        max_score = 100 if exam_type in ["Midterm", "Final"] else 50
                        score = round(random.uniform(60, 95), 1)  # Score between 60-95
                        
                        # Date in the past 0-90 days
                        exam_date = today - timedelta(days=random.randint(0, 90))
                        
                        student_score = StudentScore(
                            student_id=student.student_id,
                            subject=course.name,
                            exam_type=exam_type,
                            score=score,
                            max_score=max_score,
                            date=exam_date
                        )
                        db.session.add(student_score)
        
        db.session.commit()
        print("Scores created successfully.")
        
        print("Creating broadcasts...")
        # Create some broadcast messages
        broadcasts = [
            {
                "sender_id": admin.id,
                "message": "Welcome to the new academic year 2025-2026!",
                "target_role": "all"
            },
            {
                "sender_id": teachers[0].id,
                "message": "Midterm exams will begin next week. Please prepare accordingly.",
                "target_role": "student"
            },
            {
                "sender_id": admin.id,
                "message": "Parent-teacher meeting scheduled for April 15, 2025.",
                "target_role": "parent"
            },
            {
                "sender_id": teachers[1].id,
                "message": "مراجعة شاملة لمادة الرياضيات ستقام يوم الخميس القادم",  # Arabic: "Comprehensive math review will be held next Thursday"
                "target_role": "student"
            }
        ]
        
        for broadcast_data in broadcasts:
            broadcast = Broadcast(**broadcast_data)
            db.session.add(broadcast)
        
        db.session.commit()
        print("Broadcasts created successfully.")
        
        print("Sample data creation complete!")

if __name__ == "__main__":
    create_sample_data()
