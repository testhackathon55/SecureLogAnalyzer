from flask import Flask, request, redirect, session, jsonify, render_template_string
from mapreduce import run_mapreduce
import psycopg2
import psycopg2.extras
import os
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from functools import wraps
from multiprocessing import cpu_count
from dotenv import load_dotenv

# Create Flask app FIRST
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'log', 'txt'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Database configuration
from dotenv import load_dotenv
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hash_value):
    return hash_password(password) == hash_value

def init_database():
    """Initialize database tables with correct schema and constraints"""
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to database")
        return
    
    cur = conn.cursor()
    
    # Create users table if it doesn't exist with proper constraints
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    
    # Create analytics table if it doesn't exist
    # Drop and recreate analytics table with correct schema
    try:
        cur.execute("DROP TABLE IF EXISTS analytics")
        conn.commit()
        cur.execute("""
            CREATE TABLE analytics (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                filename TEXT,
                file_size BIGINT,
                total_lines INTEGER,
                analysis_result JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        print("Analytics table ready")
    except Exception as e:
        print(f"Analytics table creation: {e}")
    
    # Create index for faster queries
    try:
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_analytics_user_id 
            ON analytics(user_id)
        """)
        conn.commit()
    except Exception as e:
        print(f"Index creation: {e}")
    
    cur.close()
    conn.close()
    print("Database initialized successfully!")

# Initialize database
init_database()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_analytics(user_id, filename, file_size, total_lines, analysis_result):
    """Save analysis results to analytics table"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO analytics (user_id, filename, file_size, total_lines, analysis_result)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, filename, file_size, total_lines, json.dumps(analysis_result)))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving analytics: {e}")
        return False

def get_user_analytics(user_id, limit=10):
    """Get user's analysis history"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, filename, file_size, total_lines, analysis_result, created_at
            FROM analytics
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (user_id, limit))
        results = cur.fetchall()
        cur.close()
        conn.close()
        return results
    except Exception as e:
        print(f"Error fetching analytics: {e}")
        return []

def generate_sample_logs():
    """Generate comprehensive sample logs for testing"""
    logs = []
    
    ips = ['192.168.1.1', '192.168.1.2', '10.0.0.1', '172.16.0.1', '203.0.113.5']
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    endpoints = ['/api/users', '/api/login', '/api/data', '/api/report', '/api/status', '/admin/dashboard']
    status_codes = [200, 201, 400, 401, 403, 404, 500, 502, 503]
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Firefox/89.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15',
    ]
    
    for i in range(100):
        ip = ips[i % len(ips)]
        method = methods[i % len(methods)]
        endpoint = endpoints[i % len(endpoints)]
        status = status_codes[i % len(status_codes)]
        size = (i + 1) * 100
        ua = user_agents[i % len(user_agents)]
        
        hour = (i % 24)
        minute = i % 60
        second = i % 60
        day = (i % 28) + 1
        
        log = f'{ip} - - [{day}/Jun/2026:{hour:02d}:{minute:02d}:{second:02d} +0000] "{method} {endpoint} HTTP/1.1" {status} {size} "{ua}" response_time={(i * 10) % 1000}'
        logs.append(log)
    
    return logs

# HTML Templates
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Login - Log Analyzer</title>
    <style>
        body { font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); width: 350px; }
        h2 { text-align: center; margin-bottom: 30px; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #5a67d8; }
        .error { color: red; text-align: center; margin-top: 10px; padding: 10px; background: #fee; border-radius: 5px; }
        .success { color: green; text-align: center; margin-top: 10px; padding: 10px; background: #efe; border-radius: 5px; }
        .link { text-align: center; margin-top: 20px; }
        a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Login</h2>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        {% if message %}
        <div class="success">{{ message }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="link">
            <a href="/register">Don't have an account? Register</a>
        </div>
    </div>
</body>
</html>
"""

REGISTER_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Register - Log Analyzer</title>
    <style>
        body { font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); width: 350px; }
        h2 { text-align: center; margin-bottom: 30px; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #5a67d8; }
        .error { color: red; text-align: center; margin-top: 10px; padding: 10px; background: #fee; border-radius: 5px; }
        .link { text-align: center; margin-top: 20px; }
        a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Register</h2>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username (min 3 chars)" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password (min 6 chars)" required>
            <button type="submit">Register</button>
        </form>
        <div class="link">
            <a href="/login">Already have an account? Login</a>
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Log Analyzer</title>
    <style>
        body { font-family: Arial; margin: 0; padding: 0; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }
        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; }
        .upload-area { border: 2px dashed #ddd; border-radius: 10px; padding: 40px; text-align: center; cursor: pointer; transition: all 0.3s; }
        .upload-area:hover { border-color: #667eea; background: #f9f9f9; }
        input[type="file"] { display: none; }
        button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-top: 10px; font-size: 14px; }
        button:hover { background: #5a67d8; }
        button:disabled { opacity: 0.6; cursor: not-allowed; }
        .results { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; margin-top: 20px; display: none; max-height: 500px; overflow-y: auto; }
        pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', monospace; font-size: 12px; }
        .logout { float: right; background: rgba(255,255,255,0.2); padding: 8px 15px; border-radius: 5px; color: white; text-decoration: none; }
        .logout:hover { background: rgba(255,255,255,0.3); }
        .nav { margin-top: 10px; }
        .nav a { color: white; text-decoration: none; margin: 0 10px; }
        .loading { display: none; text-align: center; margin-top: 20px; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .file-info { margin-top: 10px; padding: 10px; background: #e8f5e9; border-radius: 5px; display: none; }
    </style>
</head>
<body>
    <div class="header">
        <a href="/logout" class="logout">Logout</a>
        <h1>🔒 Secure Cloud Log Analyzer</h1>
        <div class="nav">
            <a href="/dashboard">Dashboard</a>
            <a href="/history">History</a>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <h2>Welcome, {{ username }}! 👋</h2>
            <p>Upload log files to analyze system errors and traffic patterns using parallel MapReduce processing.</p>
        </div>
        
        <div class="card">
            <h2>📁 Upload Log File</h2>
            <div class="upload-area" id="uploadArea">
                <p>📄 Click or drag & drop your log file here</p>
                <p style="font-size: 12px; color: #666;">Supported formats: .log, .txt</p>
                <input type="file" id="fileInput" accept=".log,.txt">
            </div>
            <div id="fileInfo" class="file-info"></div>
            <button id="uploadBtn" disabled>Upload & Analyze with MapReduce</button>
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Processing with MapReduce parallel engine using {{ cpu_cores }} cores...</p>
            </div>
            <div class="results" id="results">
                <h3>📊 MapReduce Analysis Results:</h3>
                <pre id="resultsPre"></pre>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 Analyze Sample Log</h2>
            <button id="analyzeBtn">Run Sample Analysis</button>
            <div class="loading" id="analyzeLoading">
                <div class="spinner"></div>
                <p>Analyzing with MapReduce...</p>
            </div>
            <div class="results" id="analyzeResults">
                <h3>📊 Sample Analysis Results:</h3>
                <pre id="analyzeResultsPre"></pre>
            </div>
        </div>
    </div>
    
    <script>
        let selectedFile = null;
        
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const uploadBtn = document.getElementById('uploadBtn');
        const fileInfo = document.getElementById('fileInfo');
        
        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => { 
            e.preventDefault(); 
            uploadArea.style.borderColor = '#667eea';
            uploadArea.style.background = '#f0f0ff';
        });
        uploadArea.addEventListener('dragleave', () => { 
            uploadArea.style.borderColor = '#ddd';
            uploadArea.style.background = 'white';
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            selectedFile = e.dataTransfer.files[0];
            uploadBtn.disabled = false;
            uploadArea.style.borderColor = '#4CAF50';
            uploadArea.style.background = '#e8f5e9';
            fileInfo.style.display = 'block';
            fileInfo.innerHTML = `<strong>Selected:</strong> ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)`;
        });
        
        fileInput.addEventListener('change', (e) => {
            selectedFile = e.target.files[0];
            uploadBtn.disabled = false;
            fileInfo.style.display = 'block';
            fileInfo.innerHTML = `<strong>Selected:</strong> ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)`;
        });
        
        uploadBtn.addEventListener('click', async () => {
            if (!selectedFile) return;
            
            const formData = new FormData();
            formData.append('file', selectedFile);
            
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            uploadBtn.disabled = true;
            
            try {
                const response = await fetch('/upload', { method: 'POST', body: formData });
                const result = await response.json();
                
                document.getElementById('loading').style.display = 'none';
                document.getElementById('results').style.display = 'block';
                
                if (response.ok) {
                    document.getElementById('resultsPre').textContent = JSON.stringify(result.data, null, 2);
                    selectedFile = null;
                    fileInfo.style.display = 'none';
                    fileInput.value = '';
                } else {
                    document.getElementById('resultsPre').textContent = '❌ Error: ' + result.error;
                }
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('results').style.display = 'block';
                document.getElementById('resultsPre').textContent = '❌ Error: ' + error.message;
            }
            uploadBtn.disabled = false;
        });
        
        document.getElementById('analyzeBtn').addEventListener('click', async () => {
            document.getElementById('analyzeLoading').style.display = 'block';
            document.getElementById('analyzeResults').style.display = 'none';
            
            try {
                const response = await fetch('/analyze');
                const result = await response.json();
                
                document.getElementById('analyzeLoading').style.display = 'none';
                document.getElementById('analyzeResults').style.display = 'block';
                
                if (response.ok) {
                    const formatted = JSON.stringify(result.data, null, 2);
                    document.getElementById('analyzeResultsPre').textContent = formatted;
                } else {
                    document.getElementById('analyzeResultsPre').textContent = '❌ Error: ' + result.error;
                }
            } catch (error) {
                document.getElementById('analyzeLoading').style.display = 'none';
                document.getElementById('analyzeResults').style.display = 'block';
                document.getElementById('analyzeResultsPre').textContent = '❌ Error: ' + error.message;
            }
        });
    </script>
</body>
</html>
"""

HISTORY_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Analysis History - Log Analyzer</title>
    <style>
        body { font-family: Arial; margin: 0; padding: 0; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }
        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; }
        .analytics-item { background: #f9f9f9; padding: 15px; margin-bottom: 15px; border-radius: 5px; border-left: 4px solid #667eea; }
        .analytics-filename { font-size: 18px; font-weight: bold; color: #667eea; }
        .analytics-details { margin-top: 10px; color: #666; }
        .analytics-date { font-size: 12px; color: #999; margin-top: 5px; }
        .view-btn { background: #667eea; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; margin-top: 10px; }
        .logout { float: right; background: rgba(255,255,255,0.2); padding: 8px 15px; border-radius: 5px; color: white; text-decoration: none; }
        .logout:hover { background: rgba(255,255,255,0.3); }
        .nav { margin-top: 10px; }
        .nav a { color: white; text-decoration: none; margin: 0 10px; }
        .no-data { text-align: center; padding: 40px; color: #999; }
        .modal { display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
        .modal-content { background-color: white; margin: 5% auto; padding: 20px; border-radius: 10px; width: 80%; max-width: 800px; max-height: 80%; overflow-y: auto; }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: black; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <div class="header">
        <a href="/logout" class="logout">Logout</a>
        <h1>🔒 Secure Cloud Log Analyzer</h1>
        <div class="nav">
            <a href="/dashboard">Dashboard</a>
            <a href="/history">History</a>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <h2>📊 Analysis History</h2>
            <div id="analyticsList"></div>
        </div>
    </div>
    
    <div id="resultModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h3>📊 Analysis Results</h3>
            <pre id="modalContent"></pre>
        </div>
    </div>
    
    <script>
        async function loadHistory() {
            try {
                const response = await fetch('/api/history');
                const data = await response.json();
                
                const container = document.getElementById('analyticsList');
                
                if (data.length === 0) {
                    container.innerHTML = '<div class="no-data">No analysis history found. Upload a file to get started!</div>';
                    return;
                }
                
                let html = '';
                for (const item of data) {
                    const date = new Date(item.created_at).toLocaleString();
                    const result = typeof item.analysis_result === 'string' ? JSON.parse(item.analysis_result) : item.analysis_result;
                    
                    html += `
                        <div class="analytics-item">
                            <div class="analytics-filename">📄 ${item.filename}</div>
                            <div class="analytics-details">
                                📏 File Size: ${(item.file_size / 1024).toFixed(2)} KB<br>
                                📝 Total Lines: ${item.total_lines}
                            </div>
                            <div class="analytics-date">🕒 ${date}</div>
                            <button class="view-btn" onclick='viewResult(${JSON.stringify(result)})'>View Results</button>
                        </div>
                    `;
                }
                container.innerHTML = html;
            } catch (error) {
                document.getElementById('analyticsList').innerHTML = '<div class="no-data">Error loading history</div>';
            }
        }
        
        var modal = document.getElementById('resultModal');
        var span = document.getElementsByClassName('close')[0];
        
        span.onclick = function() {
            modal.style.display = 'none';
        }
        
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
        
        function viewResult(result) {
            document.getElementById('modalContent').textContent = JSON.stringify(result, null, 2);
            modal.style.display = 'block';
        }
        
        loadHistory();
    </script>
</body>
</html>
"""

# ================ ROUTES ================

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_HTML)
    
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return render_template_string(LOGIN_HTML, error="Username and password required")
    
    conn = get_db_connection()
    if not conn:
        return render_template_string(LOGIN_HTML, error="Database connection error")
    
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if user and verify_password(password, user[2]):
        session.permanent = True
        session['user_id'] = user[0]
        session['username'] = user[1]
        return redirect('/dashboard')
    
    return render_template_string(LOGIN_HTML, error="Invalid credentials")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(REGISTER_HTML)
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not username or not email or not password:
        return render_template_string(REGISTER_HTML, error="All fields are required")
    
    if len(username) < 3:
        return render_template_string(REGISTER_HTML, error="Username must be at least 3 characters")
    
    if len(password) < 6:
        return render_template_string(REGISTER_HTML, error="Password must be at least 6 characters")
    
    if '@' not in email or '.' not in email:
        return render_template_string(REGISTER_HTML, error="Please enter a valid email address")
    
    conn = get_db_connection()
    if not conn:
        return render_template_string(REGISTER_HTML, error="Database connection error")
    
    cur = conn.cursor()
    
    try:
        # Check if username exists
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return render_template_string(REGISTER_HTML, error=f"Username '{username}' already exists")
        
        # Check if email exists
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return render_template_string(REGISTER_HTML, error=f"Email '{email}' already registered")
        
        # Create new user
        password_hash = hash_password(password)
        cur.execute("""
            INSERT INTO users (username, email, password_hash) 
            VALUES (%s, %s, %s)
        """, (username, email, password_hash))
        conn.commit()
        cur.close()
        conn.close()
        
        return render_template_string(LOGIN_HTML, message="✅ Registration successful! Please login.")
        
    except psycopg2.IntegrityError as e:
        conn.rollback()
        cur.close()
        conn.close()
        # Handle duplicate key errors
        if "duplicate key value violates unique constraint" in str(e):
            if "username" in str(e):
                return render_template_string(REGISTER_HTML, error=f"Username '{username}' already exists")
            elif "email" in str(e):
                return render_template_string(REGISTER_HTML, error=f"Email '{email}' already registered")
        return render_template_string(REGISTER_HTML, error=f"Registration failed: {str(e)}")
        
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        return render_template_string(REGISTER_HTML, error=f"Registration failed: {str(e)}")

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template_string(DASHBOARD_HTML, username=session.get('username', 'User'), cpu_cores=cpu_count())

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template_string(HISTORY_HTML)

@app.route('/api/history')
@login_required
def get_history():
    analytics = get_user_analytics(session['user_id'])
    return jsonify(analytics)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .log and .txt files allowed'}), 400
    
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_filename = f"{timestamp}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        
        # Use MapReduce for analysis
        result = run_mapreduce(lines)
        
        save_analytics(session['user_id'], filename, file_size, total_lines, result)
        
        os.remove(filepath)
        
        return jsonify({'success': True, 'data': result})
        
    except Exception as e:
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

@app.route('/analyze')
def analyze():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    file_path = "uploads/sample.log"
    
    if not os.path.exists(file_path):
        sample_logs = generate_sample_logs()
        os.makedirs("uploads", exist_ok=True)
        with open(file_path, "w") as f:
            f.write('\n'.join(sample_logs))
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        result = run_mapreduce(lines)
        return jsonify({'success': True, 'data': result})
        
    except Exception as e:
        return jsonify({'error': f'Error analyzing file: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 Secure Cloud Log Analyzer Started")
    print("="*60)
    print("📍 Access at: http://localhost:5000")
    print(f"💻 Using {cpu_count()} CPU cores for parallel processing")
    print("\n💡 Features:")
    print("   ✅ User Registration & Login")
    print("   ✅ File Upload with MapReduce Analysis")
    print("   ✅ Analytics Storage in Neon Database")
    print("   ✅ View Analysis History")
    print("   ✅ Sample Log Analysis")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)