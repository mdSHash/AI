import os
import logging
import tempfile
import traceback
import threading
import yaml
import uuid
import jwt
import pandas as pd
import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv

# Import custom modules
from document_processor import process_and_add_documents, vector_db, load_metadata, save_metadata
from language_utils import detect_language, translate_text_if_needed
from rag_engine import setup_retrieval_chain, WatsonxModelSingleton
from models import User, UserRole, db, Broadcast, QueryLog, StudentScore, Student, StudentEnrollment, ParentChildRelationship, AcademicWeek, Message, Course

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
INSTITUTE_NAME = os.getenv("INSTITUTE_NAME", "UAE Educational Institute")

# Load configurations
def load_config(config_path="config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

config = load_config()
ALLOWED_EXTENSIONS = set(config['allowed_file_extensions'])
file_metadata = {}

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///institute.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()

# Initialize retrieval chain and memory
retrieval_chain, conversation_memories = setup_retrieval_chain()

# Load documents metadata
load_metadata()

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            logger.error(f"Token error: {e}")
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Admin role required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        # Add debugging to see what's happening
        logger.info(f"User {current_user.id} has role: '{current_user.role}'")
        
        # Compare with string values instead of enum objects
        if current_user.role not in ["admin", "teacher"]:
            return jsonify({'message': 'Admin privilege required!'}), 403
        return f(current_user, *args, **kwargs)
    
    return decorated

# Routes
@app.route('/')
def index():
    return render_template('index.html', institute_name=INSTITUTE_NAME)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'User already exists!'}), 409
    
    # Validate student ID if role is student or parent
    student_id = data.get('student_id')
    if data['role'] in ['student', 'parent'] and not student_id:
        return jsonify({'message': 'Student ID is required for students and parents!'}), 400
    
    # Create new user
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    try:
        new_user = User(
            email=data['email'],
            password=hashed_password,
            name=data['name'],
            role=data['role'],
            student_id=student_id,
            language_preference=data.get('language_preference', 'en')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'message': 'User registered successfully!'}), 201
    
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({'message': 'Registration failed!'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    # Generate JWT token
    print("About to encode JWT...")

    token = jwt.encode({
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    print("JWT created:", token)

    
    # Initialize conversation memory for user if not exists
    user_id = str(user.id)
    if user_id not in conversation_memories:
        conversation_memories[user_id] = []
    
    return jsonify({
        'token': token,
        'user_id': user.id,
        'name': user.name,
        'email': user.email,
        'role': user.role,
        'language_preference': user.language_preference
    }), 200

@app.route('/students', methods=['GET'])
@token_required
def get_students(current_user):
    try:
        if current_user.role == UserRole.PARENT:
            # Get all children for this parent
            parent_child_relationships = ParentChildRelationship.query.filter_by(parent_id=current_user.id).all()
            student_ids = [rel.student_id for rel in parent_child_relationships]
            students = Student.query.filter(Student.id.in_(student_ids)).all()
        elif current_user.role == UserRole.TEACHER:
            # Get all students in courses taught by this teacher
            taught_courses = Course.query.filter_by(teacher_id=current_user.id).all()
            course_ids = [course.id for course in taught_courses]
            
            # Get enrollments for these courses
            enrollments = StudentEnrollment.query.filter(StudentEnrollment.course_id.in_(course_ids)).all()
            student_ids = list(set([enrollment.student_id for enrollment in enrollments]))
            students = Student.query.filter(Student.id.in_(student_ids)).all()
        elif current_user.role == UserRole.ADMIN:
            # Admins can see all students
            students = Student.query.all()
        else:
            return jsonify({"error": "Unauthorized access"}), 403
        
        result = []
        for student in students:
            result.append({
                "id": student.id,
                "student_id": student.student_id,
                "name": student.name,
                "grade": student.grade,
                "section": student.section
            })
        
        return jsonify({"students": result}), 200
    
    except Exception as e:
        logger.error(f"Error getting students: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/academic_weeks', methods=['GET'])
@token_required
def get_academic_weeks(current_user):
    try:
        # Everyone can see academic weeks
        academic_weeks = AcademicWeek.query.order_by(AcademicWeek.start_date).all()
        
        result = []
        for week in academic_weeks:
            result.append({
                "id": week.id,
                "week_number": week.week_number,
                "start_date": week.start_date.strftime("%Y-%m-%d"),
                "end_date": week.end_date.strftime("%Y-%m-%d"),
                "term": week.term,
                "academic_year": week.academic_year
            })
        
        return jsonify({"academic_weeks": result}), 200
    
    except Exception as e:
        logger.error(f"Error getting academic weeks: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/scores_by_week', methods=['GET'])
@token_required
def get_scores_by_week(current_user):
    try:
        student_id = request.args.get('student_id')
        week_id = request.args.get('week_id')
        
        # Validate access permissions
        if current_user.role == UserRole.PARENT:
            # Check if this student belongs to the parent
            relationship = ParentChildRelationship.query.filter_by(
                parent_id=current_user.id, 
                student_id=student_id
            ).first()
            
            if not relationship:
                return jsonify({"error": "You do not have access to this student's records"}), 403
        
        # Query scores for the student and week
        query = StudentScore.query.filter_by(student_id=student_id)
        
        if week_id:
            query = query.filter_by(academic_week_id=week_id)
        
        # Group scores by subject and exam type
        scores = query.order_by(StudentScore.subject, StudentScore.exam_type).all()
        
        # Organize scores by subject and exam type
        organized_scores = {}
        for score in scores:
            if score.subject not in organized_scores:
                organized_scores[score.subject] = {}
            
            if score.exam_type not in organized_scores[score.subject]:
                organized_scores[score.subject][score.exam_type] = []
            
            organized_scores[score.subject][score.exam_type].append({
                "id": score.id,
                "score": score.score,
                "max_score": score.max_score,
                "percentage": (score.score / score.max_score * 100) if score.max_score > 0 else 0,
                "date": score.date.strftime("%Y-%m-%d"),
                "week_id": score.academic_week_id
            })
        
        return jsonify({"scores": organized_scores}), 200
    
    except Exception as e:
        logger.error(f"Error getting scores by week: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/messages', methods=['GET'])
@token_required
def get_messages(current_user):
    try:
        # Get all messages received by the user
        messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
        
        result = []
        for message in messages:
            sender = User.query.get(message.sender_id)
            student = None
            if message.related_student_id:
                student = Student.query.get(message.related_student_id)
            
            result.append({
                "id": message.id,
                "subject": message.subject,
                "content": message.content,
                "sender_name": sender.name if sender else "Unknown",
                "sender_id": message.sender_id,
                "related_student_name": student.name if student else None,
                "related_student_id": message.related_student_id,
                "read": message.read,
                "ai_generated": message.ai_generated,
                "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        
        return jsonify({"messages": result}), 200
    
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/send_message', methods=['POST'])
@token_required
def send_message(current_user):
    try:
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        subject = data.get('subject')
        content = data.get('content')
        related_student_id = data.get('related_student_id')
        ai_generated = data.get('ai_generated', False)
        
        if not recipient_id or not content:
            return jsonify({"error": "Recipient and content are required"}), 400
        
        # Create the message
        message = Message(
            sender_id=current_user.id,
            recipient_id=recipient_id,
            subject=subject,
            content=content,
            related_student_id=related_student_id,
            ai_generated=ai_generated
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({"message": "Message sent successfully", "message_id": message.id}), 201
    
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/forward_to_teacher', methods=['POST'])
@token_required
def forward_to_teacher(current_user):
    try:
        data = request.get_json()
        query_id = data.get('query_id')
        student_id = data.get('student_id')
        
        if not query_id or not student_id:
            return jsonify({"error": "Query ID and student ID are required"}), 400
        
        # Get the query from the log
        query_log = QueryLog.query.get(query_id)
        if not query_log:
            return jsonify({"error": "Query not found"}), 404
        
        # Mark query as forwarded
        query_log.forwarded_to_teacher = True
        
        # Get student to find teacher(s)
        student = Student.query.get(student_id)
        if not student:
            return jsonify({"error": "Student not found"}), 404
        
        # Find all courses the student is enrolled in
        enrollments = StudentEnrollment.query.filter_by(student_id=student_id, active=True).all()
        
        # Find teachers for those courses
        teacher_ids = set()
        for enrollment in enrollments:
            course = Course.query.get(enrollment.course_id)
            if course and course.teacher_id:
                teacher_ids.add(course.teacher_id)
        
        if not teacher_ids:
            return jsonify({"error": "No teachers found for this student"}), 404
        
        # Send message to each teacher
        for teacher_id in teacher_ids:
            message = Message(
                sender_id=current_user.id,
                recipient_id=teacher_id,
                subject="Question from parent",
                content=f"Original Question: {query_log.query}\n\nBot Answer: {query_log.response}\n\nParent needs more information about this topic.",
                related_student_id=student_id,
                ai_generated=True
            )
            db.session.add(message)
        
        db.session.commit()
        
        return jsonify({"message": "Question forwarded to teachers successfully"}), 200
    
    except Exception as e:
        logger.error(f"Error forwarding to teacher: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/add_academic_week', methods=['POST'])
@token_required
@admin_required
def add_academic_week(current_user):
    try:
        data = request.get_json()
        
        new_week = AcademicWeek(
            week_number=data.get('week_number'),
            start_date=datetime.datetime.strptime(data.get('start_date'), "%Y-%m-%d").date(),
            end_date=datetime.datetime.strptime(data.get('end_date'), "%Y-%m-%d").date(),
            term=data.get('term'),
            academic_year=data.get('academic_year')
        )
        
        db.session.add(new_week)
        db.session.commit()
        
        return jsonify({"message": "Academic week added successfully", "week_id": new_week.id}), 201
    
    except Exception as e:
        logger.error(f"Error adding academic week: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/add_student', methods=['POST'])
@token_required
@admin_required
def add_student(current_user):
    try:
        data = request.get_json()
        
        # Check if student_id already exists
        if Student.query.filter_by(student_id=data.get('student_id')).first():
            return jsonify({"error": "Student ID already exists"}), 400
        
        new_student = Student(
            student_id=data.get('student_id'),
            name=data.get('name'),
            grade=data.get('grade'),
            section=data.get('section'),
            date_of_birth=datetime.datetime.strptime(data.get('date_of_birth'), "%Y-%m-%d").date() if data.get('date_of_birth') else None
        )
        
        db.session.add(new_student)
        db.session.commit()
        
        return jsonify({"message": "Student added successfully", "student_id": new_student.id}), 201
    
    except Exception as e:
        logger.error(f"Error adding student: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/link_parent_child', methods=['POST'])
@token_required
@admin_required
def link_parent_child(current_user):
    try:
        data = request.get_json()
        parent_id = data.get('parent_id')
        student_id = data.get('student_id')
        relationship_type = data.get('relationship_type', 'parent')
        
        # Check if parent and student exist
        parent = User.query.get(parent_id)
        student = Student.query.get(student_id)
        
        if not parent or not student:
            return jsonify({"error": "Parent or student not found"}), 404
        
        # Check if relationship already exists
        existing = ParentChildRelationship.query.filter_by(
            parent_id=parent_id,
            student_id=student_id
        ).first()
        
        if existing:
            return jsonify({"error": "Relationship already exists"}), 400
        
        # Create relationship
        relationship = ParentChildRelationship(
            parent_id=parent_id,
            student_id=student_id,
            relationship_type=relationship_type
        )
        
        db.session.add(relationship)
        db.session.commit()
        
        return jsonify({"message": "Parent-child relationship created successfully"}), 201
    
    except Exception as e:
        logger.error(f"Error linking parent and child: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/upload', methods=['POST'])
@token_required
@admin_required
def upload_document(current_user):
    try:
        file = request.files.get('file')
        metadata = request.form.get('metadata', '{}')
        import json
        metadata = json.loads(metadata)
        
        # Add uploader information to metadata
        metadata["uploader_id"] = current_user.id
        
        if file and allowed_file(file.filename):
            with tempfile.TemporaryDirectory() as temp_dir:
                filepath = os.path.join(temp_dir, file.filename)
                file.save(filepath)
                
                # Process the file based on its type
                if file.filename.endswith('.xlsx'):
                    # Handle Excel files (student data)
                    df = pd.read_excel(filepath)
                    process_student_data(df, metadata)
                    return jsonify({"message": "Student data processed successfully."}), 200
                else:
                    # Process as a document for RAG
                    process_and_add_documents([filepath], metadata)
                    return jsonify({"message": "Document uploaded and processed successfully."}), 200
        
        return jsonify({"error": "Unsupported file type."}), 400
    
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/delete', methods=['POST'])
@token_required
@admin_required
def delete_document(current_user):
    try:
        data = request.get_json()
        filename = data.get("filename")
        
        if not filename:
            return jsonify({"error": "No filename provided."}), 400
        
        # Find all entries in file_metadata that match the filename
        matching_entries = []
        for path, meta_obj in file_metadata.items():
            if meta_obj.get('filename') == filename:
                # Check permissions: admins can delete any file, teachers only their own
                uploader_id = meta_obj.get('uploader_id')
                if current_user.role == "admin" or current_user.id == uploader_id:
                    matching_entries.append(path)
                elif current_user.role == "teacher" and current_user.id != uploader_id:
                    return jsonify({"error": "You can only delete files you have uploaded."}), 403
        
        if not matching_entries:
            return jsonify({"error": "File not found in database."}), 404
        
        # Remove entries from file_metadata and delete from vector DB
        chunk_ids = set()
        for entry in matching_entries:
            meta_obj = file_metadata.pop(entry, {})
            chunk_ids.update(meta_obj.get('chunks', set()))
        
        if chunk_ids:
            vector_db.delete(ids=list(chunk_ids))
            vector_db.persist()
            save_metadata()
            logger.info(f"Deleted document: {filename}")
            return jsonify({"message": f"File {filename} removed successfully."}), 200
        
        return jsonify({"error": "File had no associated chunks."}), 400
    
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/list_files', methods=['GET'])
@token_required
def list_files(current_user):
    try:
        file_list = []
        
        for filepath, meta_obj in file_metadata.items():
            filename = meta_obj.get('filename', os.path.basename(filepath))
            uploader_id = meta_obj.get('uploader_id')
            
            # Determine if this file should be visible to the current user
            is_visible = False
            if current_user.role in ["admin", "teacher"]:
                # Admins can see all files, teachers can see their own uploads
                is_visible = (current_user.role == "admin") or (current_user.id == uploader_id)
            else:
                # Students and parents can only see public documents
                is_visible = meta_obj.get('public', True)
            
            if is_visible:
                file_info = {
                    "filename": filename,
                    "uploader_id": uploader_id,
                    # Add more fields as needed
                }
                file_list.append(file_info)
        
        return jsonify({"files": file_list}), 200
    
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/query', methods=['POST'])
@token_required
def query_chatbot(current_user):
    try:
        data = request.get_json()
        query = data.get("query", "")
        
        if not query:
            return jsonify({"error": "Empty query."}), 400
        
        # Detect query language
        query_lang = detect_language(query)
        user_lang = current_user.language_preference
        
        # Log the query
        log_query(current_user.id, query, query_lang)
        
        # Get user-specific context
        user_context = get_user_context(current_user)
        
        # Append user info and language to the query
        enhanced_query = f"{query} [User ID: {current_user.id}, Role: {current_user.role}, Language: {query_lang}]"
        
        # Add user's conversation memory
        user_id = str(current_user.id)
        memory_dicts = conversation_memories.get(user_id, [])
        
        # Convert memory format to tuples for the retrieval chain
        formatted_memory = []
        for i in range(0, len(memory_dicts), 2):
            if i+1 < len(memory_dicts):  # Make sure we have pairs
                user_msg = memory_dicts[i]['content']
                assistant_msg = memory_dicts[i+1]['content']
                formatted_memory.append((user_msg, assistant_msg))
        
        # Run the query through the retrieval chain with user context
        result = retrieval_chain({
            "question": enhanced_query,
            "chat_history": formatted_memory,  # List of tuples now
            "user_context": user_context
        })
        
        # Update conversation memory in the original format
        memory_dicts.append({"role": "user", "content": query})
        memory_dicts.append({"role": "assistant", "content": result['answer']})
        conversation_memories[user_id] = memory_dicts[-10:]  # Keep last 10 exchanges
        
        # Ensure response is in the same language as the query
        response = result['answer']
        
        # Suggested follow-up queries
        suggested_queries = generate_suggested_queries(query, response, current_user)
        
        return jsonify({
            "response": response,
            "suggested_queries": suggested_queries
        }), 200
    
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

@app.route('/clear_memory', methods=['POST'])
@token_required
def clear_memory(current_user):
    user_id = str(current_user.id)
    if user_id in conversation_memories:
        conversation_memories[user_id] = []
    
    return jsonify({"message": "Conversation memory cleared successfully."}), 200

@app.route('/get_scores', methods=['GET'])
@token_required
def get_scores(current_user):
    try:
        if current_user.role in [UserRole.STUDENT, UserRole.PARENT]:
            # Get student ID (either the student's own ID or parent's child ID)
            student_id = current_user.student_id
            
            # Query the scores from database
            scores = StudentScore.query.filter_by(student_id=student_id).all()
            
            result = []
            for score in scores:
                result.append({
                    "subject": score.subject,
                    "exam_type": score.exam_type,
                    "score": score.score,
                    "max_score": score.max_score,
                    "date": score.date.strftime("%Y-%m-%d")
                })
            
            return jsonify({"scores": result}), 200
        
        elif current_user.role in [UserRole.ADMIN, UserRole.TEACHER]:
            # Admins and teachers need to specify student_id
            student_id = request.args.get('student_id')
            if not student_id:
                return jsonify({"error": "Student ID required."}), 400
            
            # Query the scores from database
            scores = StudentScore.query.filter_by(student_id=student_id).all()
            
            result = []
            for score in scores:
                result.append({
                    "subject": score.subject,
                    "exam_type": score.exam_type,
                    "score": score.score,
                    "max_score": score.max_score,
                    "date": score.date.strftime("%Y-%m-%d")
                })
            
            return jsonify({"scores": result}), 200
        
        else:
            return jsonify({"error": "Unauthorized access."}), 403
    
    except Exception as e:
        logger.error(f"Error getting scores: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/broadcast', methods=['POST'])
@token_required
@admin_required
def send_broadcast(current_user):
    try:
        data = request.get_json()
        message = data.get('message')
        target_role = data.get('target_role', 'all')  # 'all', 'student', 'parent'
        
        if not message:
            return jsonify({"error": "Message is required."}), 400
        
        
        new_broadcast = Broadcast(
            sender_id=current_user.id,
            message=message,
            target_role=target_role
        )
        
        db.session.add(new_broadcast)
        db.session.commit()
        
        return jsonify({"message": "Broadcast sent successfully."}), 200
    
    except Exception as e:
        logger.error(f"Error sending broadcast: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/get_broadcasts', methods=['GET'])
@token_required
def get_broadcasts(current_user):
    try:
        
        # Get broadcasts targeted to user's role or 'all'
        broadcasts = Broadcast.query.filter(
            (Broadcast.target_role == current_user.role) | 
            (Broadcast.target_role == 'all')
        ).order_by(Broadcast.timestamp.desc()).limit(10).all()
        
        result = []
        for broadcast in broadcasts:
            sender = User.query.get(broadcast.sender_id)
            result.append({
                "id": broadcast.id,
                "message": broadcast.message,
                "sender": sender.name if sender else "Unknown",
                "timestamp": broadcast.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        
        return jsonify({"broadcasts": result}), 200
    
    except Exception as e:
        logger.error(f"Error getting broadcasts: {e}")
        return jsonify({"error": str(e)}), 500

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_student_data(df, metadata):
    try:
        # Expected columns: student_id, subject, exam_type, score, max_score, date, week_number (optional)
        for _, row in df.iterrows():
            student_id_value = row['student_id']
            date_value = pd.to_datetime(row['date']).date()
            
            # Find the student record
            student = Student.query.filter_by(student_id=student_id_value).first()
            if not student:
                logger.warning(f"Student with ID {student_id_value} not found, skipping record")
                continue
            
            # Find or create academic week based on the date
            academic_week = None
            if 'week_number' in row:
                # If week_number is provided, find matching academic week
                academic_week = AcademicWeek.query.filter_by(
                    week_number=row['week_number'],
                    academic_year=metadata.get('academic_year', '2024-2025')  # Default academic year
                ).first()
            
            if not academic_week:
                # Find week by date
                academic_week = AcademicWeek.query.filter(
                    AcademicWeek.start_date <= date_value,
                    AcademicWeek.end_date >= date_value
                ).first()
            
            # Create score record
            score = StudentScore(
                student_id=student.id,
                subject=row['subject'],
                exam_type=row['exam_type'],
                score=float(row['score']),
                max_score=float(row['max_score']),
                date=date_value,
                academic_week_id=academic_week.id if academic_week else None
            )
            db.session.add(score)
        
        db.session.commit()
        logger.info(f"Processed {len(df)} student records")
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing student data: {e}")
        raise

def log_query(user_id, query, language):
    
    try:
        new_log = QueryLog(
            user_id=user_id,
            query=query,
            language=language
        )
        
        db.session.add(new_log)
        db.session.commit()
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error logging query: {e}")

def get_user_context(user):
    """Get user-specific context for the query"""
    context = {
        "user_id": user.id,
        "role": user.role,
        "name": user.name
    }
    
    # Add student-specific context
    if user.role == UserRole.STUDENT:
        student = Student.query.filter_by(student_id=user.student_id).first()
        if student:
            # Get student's subjects
            scores = StudentScore.query.filter_by(student_id=student.id).all()
            subjects = list(set(score.subject for score in scores))
            
            context["student_id"] = student.id
            context["student_name"] = student.name
            context["grade"] = student.grade
            context["section"] = student.section
            context["subjects"] = subjects
    
    # For parents, add all children
    elif user.role == UserRole.PARENT:
        # Get all children for this parent
        parent_child_relationships = ParentChildRelationship.query.filter_by(parent_id=user.id).all()
        children = []
        
        for rel in parent_child_relationships:
            student = Student.query.get(rel.student_id)
            if student:
                # Get student subjects
                scores = StudentScore.query.filter_by(student_id=student.id).all()
                subjects = list(set(score.subject for score in scores))
                
                children.append({
                    "student_id": student.id,
                    "student_name": student.name,
                    "grade": student.grade,
                    "section": student.section,
                    "subjects": subjects,
                    "relationship": rel.relationship_type
                })
        
        context["children"] = children
    
    return context

def generate_suggested_queries(user_query, response, user):
    """Generate suggested follow-up queries based on user query and response"""
    suggested_queries = []
    
    # Basic suggestions for students/parents
    if user.role in [UserRole.STUDENT, UserRole.PARENT]:
        suggested_queries = [
            "What are my grades in Math?",
            "How am I performing compared to class average?",
            "When is the next exam?",
            "Show me my progress over time",
            "What subjects do I need to improve?"
        ]
        
        # Add Arabic suggestions
        arabic_suggestions = [
            "ما هي درجاتي في الرياضيات؟",
            "كيف أدائي مقارنة بمتوسط الفصل؟",
            "متى الامتحان القادم؟",
            "أظهر لي تقدمي بمرور الوقت",
            "ما هي المواد التي أحتاج إلى تحسينها؟"
        ]
        
        suggested_queries.extend(arabic_suggestions)
    
    # Suggestions for teachers/admins
    elif user.role in [UserRole.TEACHER, UserRole.ADMIN]:
        suggested_queries = [
            "Show me class performance in Science",
            "Which students need additional help?",
            "Summarize exam results for Grade 10",
            "What is the average score in English?",
            "How to upload new scores?"
        ]
        
        # Add Arabic suggestions
        arabic_suggestions = [
            "أظهر لي أداء الفصل في العلوم",
            "ما هي الطلاب الذين يحتاجون إلى مساعدة إضافية؟",
            "لخص نتائج الامتحانات للصف العاشر",
            "ما هو متوسط الدرجات في اللغة الإنجليزية؟",
            "كيفية تحميل درجات جديدة؟"
        ]
        
        suggested_queries.extend(arabic_suggestions)
    
    # Select 5 random suggestions from the list
    import random
    if len(suggested_queries) > 5:
        suggested_queries = random.sample(suggested_queries, 5)
    
    return suggested_queries

if __name__ == '__main__':
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, port=5000, threaded=True)
