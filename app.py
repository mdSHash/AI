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
from user_management import User, UserRole, db

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

@app.route('/upload', methods=['POST'])
@token_required
@admin_required
def upload_document(current_user):
    try:
        file = request.files.get('file')
        metadata = request.form.get('metadata', '{}')
        import json
        metadata = json.loads(metadata)
        
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
        matching_entries = [path for path in file_metadata.keys() 
                           if os.path.basename(path) == filename]
        
        if not matching_entries:
            return jsonify({"error": "File not found in database."}), 404
        
        # Remove entries from file_metadata and delete from vector DB
        chunk_ids = set()
        for entry in matching_entries:
            chunk_ids.update(file_metadata.pop(entry, set()))
        
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
        if current_user.role in [UserRole.ADMIN, UserRole.TEACHER]:
            # Admins and teachers can see all files
            file_list = list(set(os.path.basename(filepath) for filepath in file_metadata.keys()))
        else:
            # Students and parents can only see public documents
            file_list = []
            for filepath, meta in file_metadata.items():
                if meta.get('public', True):  # Default to public if not specified
                    file_list.append(os.path.basename(filepath))
            file_list = list(set(file_list))
        
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
            from student_data import StudentScore
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
            from student_data import StudentScore
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
        
        from broadcast import Broadcast
        
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
        from broadcast import Broadcast
        
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
    from student_data import StudentScore
    
    try:
        # Expected columns: student_id, subject, exam_type, score, max_score, date
        for _, row in df.iterrows():
            score = StudentScore(
                student_id=row['student_id'],
                subject=row['subject'],
                exam_type=row['exam_type'],
                score=float(row['score']),
                max_score=float(row['max_score']),
                date=pd.to_datetime(row['date']).date()
            )
            db.session.add(score)
        
        db.session.commit()
        logger.info(f"Processed {len(df)} student records")
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing student data: {e}")
        raise

def log_query(user_id, query, language):
    from query_log import QueryLog
    
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
    if user.role in [UserRole.STUDENT, UserRole.PARENT]:
        from student_data import StudentScore
        
        # Get student's subjects
        scores = StudentScore.query.filter_by(student_id=user.student_id).all()
        subjects = list(set(score.subject for score in scores))
        
        context["student_id"] = user.student_id
        context["subjects"] = subjects
    
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
