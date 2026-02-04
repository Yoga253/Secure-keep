from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import db
import security
import os
import sqlite3
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.urandom(24) # Session key

# Email Configuration
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USERNAME = 'temp44260@gmail.com'
MAIL_PASSWORD = 'gavzzmdhhjzmrxyb'
MAIL_SENDER = 'temp44260@gmail.com'

# Initialize RSA Keys on startup
security.generate_rsa_keys()

# Initialize DB on startup (Ensure tables exist)
try:
    db.init_db()
except Exception as e:
    print(f"Startup DB init failed: {e}")

def send_otp(recipient_email, otp, username):
    """Sends OTP via email."""
    import ssl
    
    try:
        msg = MIMEMultipart()
        msg['From'] = MAIL_SENDER
        msg['To'] = recipient_email
        msg['Subject'] = 'SecureKeep - Your Login OTP'
        
        body = f"""Hello {username},

Your one-time password (OTP) for SecureKeep login is:

    {otp}

This code is valid for 5 minutes. Do not share this code with anyone.

If you did not request this code, please ignore this email.

- SecureKeep Security Team
"""
        msg.attach(MIMEText(body, 'plain'))
        
        context = ssl.create_default_context()
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        server.starttls(context=context)
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"[EMAIL] OTP sent to {recipient_email}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        # Fallback: show in console
        print(f"\n[FALLBACK] OTP for {username}: {otp}\n")
        return False

# --- Helper Functions ---

def log_event(action, details=None):
    """Logs security events to the database."""
    try:
        if 'user_id' in session:
            user_id = session['user_id']
            username = session['username']
        else:
            user_id = None
            username = "System/Anonymous"
            
        conn = db.get_db_connection()
        conn.execute('INSERT INTO logs (user_id, username, action, details) VALUES (?, ?, ?, ?)',
                     (user_id, username, action, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging Error: {e}")

def check_acl(role, resource, action):
    """
    Explicit Access Control Matrix Implementation.
    Returns True if allowed, False otherwise.
    """
    acl_matrix = {
        'ADMIN': {
            'notes': ['read', 'write', 'delete', 'read_all'],
            'users': ['read', 'create', 'update', 'delete'],
            'logs': ['read'],
            'acl': ['read']
        },
        'MANAGER': {
            'notes': [], # Manager cannot see notes
            'users': ['read'],
            'logs': ['read'],
            'acl': ['read']
        },
        'USER': {
            'notes': ['read', 'write', 'delete'], # Only own notes (enforced by logic)
            'users': [],
            'logs': [],
            'acl': ['read']
        }
    }
    
    allowed_actions = acl_matrix.get(role, {}).get(resource, [])
    return action in allowed_actions

# --- Decorators ---

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'ADMIN':
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email']
        password = request.form['password']
        
        hashed_pw = security.hash_password(password)
        
        conn = None
        try:
            conn = db.get_db_connection()
            # Check if any users exist to assign ADMIN role to the first one
            user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            
            # Logic to determine role (Demo compliant)
            print(f"DEBUG: Registering user '{username}', Count: {user_count}") # Debug log
            
            if user_count == 0:
                role = 'ADMIN'
            elif username.lower().startswith('mgr_'):
                role = 'MANAGER'
            else:
                role = 'USER'
            
            print(f"DEBUG: Assigned Role: {role}") # Debug log
            
            conn.execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                         (username, email, hashed_pw, role))
            conn.commit()
            
            log_event("REGISTER", f"New user registered: {username} as {role}")
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        except Exception as e:
            flash(f'An error occurred: {e}', 'error')
            print(f"Registration Error: {e}")
        finally:
            if conn:
                conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = db.get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and security.verify_password(password, user['password_hash']):
            # 1st Factor Success. Now 2nd Factor.
            otp = security.generate_otp()
            session['pre_auth_user_id'] = user['id']
            session['pre_auth_username'] = user['username']
            session['pre_auth_role'] = user['role']
            session['pre_auth_email'] = user['email']
            session['otp'] = otp
            
            # Send OTP via email
            email_sent = send_otp(user['email'], otp, username)
            if email_sent:
                flash('OTP sent to your email! Please check your inbox.', 'info')
            else:
                flash('OTP sent to console (email failed). Check server logs.', 'info')
            
            return redirect(url_for('otp_verify'))
        else:
            log_event("LOGIN_FAILED", f"Failed login attempt for {username}")
            flash('Invalid username or password.', 'error')
            
    return render_template('login.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp_verify():
    if 'pre_auth_user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == session.get('otp'):
            # MFA Success. Promote to full session.
            session['user_id'] = session['pre_auth_user_id']
            session['username'] = session['pre_auth_username']
            session['role'] = session['pre_auth_role']
            
            # Cleanup temp session vars
            session.pop('pre_auth_user_id', None)
            session.pop('pre_auth_username', None)
            session.pop('pre_auth_role', None)
            session.pop('pre_auth_email', None)
            session.pop('otp', None)
            
            log_event("LOGIN_SUCCESS", f"User {session['username']} logged in.")
            return redirect(url_for('dashboard'))
        else:
            log_event("MFA_FAILED", f"Invalid OTP for {session.get('pre_auth_username')}")
            flash('Invalid OTP.', 'error')
            
    return render_template('otp.html')

@app.route('/logout')
def logout():
    log_event("LOGOUT", "User logged out.")
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Role-Based Access Control logic
    # MANAGER cannot view notes
    if session['role'] == 'MANAGER':
        return render_template('dashboard.html', notes=[], user=session['username'], role=session['role'], message="Manager account restricted from viewing private notes.")

    conn = db.get_db_connection()
    user_id = session['user_id']
    
    # ACL: Users see their own notes.
    if check_acl(session['role'], 'notes', 'read'):
        notes_data = conn.execute('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    else:
        notes_data = [] # Should not happen given logic, but safe fallback
        
    conn.close()
    
    decrypted_notes = []
    for note in notes_data:
        # 1. Verify Integrity & Signature
        current_hash = security.generate_integrity_hash(note['encrypted_note'])
        is_valid = security.verify_signature(current_hash, note['signature'])
        
        status = "Verified" if is_valid else "TAMPERED"
        
        # 2. Decrypt
        try:
            aes_key = security.decrypt_key_rsa(note['encrypted_aes_key'])
            plaintext = security.decrypt_data_aes(note['encrypted_note'], aes_key)
        except Exception as e:
            plaintext = "[Decryption Failed]"
            
        decrypted_notes.append({
            'id': note['id'],
            'title': note['title'],
            'content': plaintext,
            'status': status,
            'created_at': note['created_at']
        })
        
    return render_template('dashboard.html', notes=decrypted_notes, user=session['username'], role=session['role'])

@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    if not check_acl(session['role'], 'notes', 'write'):
        abort(403)

    title = request.form['title']
    content = request.form['content']
    user_id = session['user_id']
    
    # 1. Encrypt Content (AES)
    encrypted_note_b64, aes_key = security.encrypt_data_aes(content)
    
    # 2. Encrypt AES Key (RSA)
    encrypted_key_b64 = security.encrypt_key_rsa(aes_key)
    
    # 3. Generate Integrity Hash of the Encrypted Note
    integrity_hash = security.generate_integrity_hash(encrypted_note_b64)
    
    # 4. Sign the Hash
    signature_b64 = security.sign_hash(integrity_hash)
    
    conn = db.get_db_connection()
    conn.execute('''
        INSERT INTO notes (user_id, title, encrypted_note, encrypted_aes_key, integrity_hash, signature)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, title, encrypted_note_b64, encrypted_key_b64, integrity_hash, signature_b64))
    conn.commit()
    conn.close()
    
    log_event("ADD_NOTE", f"User {session['username']} added a note.")
    return redirect(url_for('dashboard'))

@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    conn = db.get_db_connection()
    # ACL: Ensure user owns the note (and has write permission)
    note = conn.execute('SELECT * FROM notes WHERE id = ?', (note_id,)).fetchone()
    
    if not note or note['user_id'] != session['user_id']:
        conn.close()
        abort(403)
        
    if not check_acl(session['role'], 'notes', 'write'):
        conn.close()
        abort(403)

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # --- Re-Encryption Process ---
        # 1. Encrypt Content (AES)
        encrypted_note_b64, aes_key = security.encrypt_data_aes(content)
        
        # 2. Encrypt AES Key (RSA)
        encrypted_key_b64 = security.encrypt_key_rsa(aes_key)
        
        # 3. Generate Integrity Hash
        integrity_hash = security.generate_integrity_hash(encrypted_note_b64)
        
        # 4. Sign the Hash
        signature_b64 = security.sign_hash(integrity_hash)
        
        conn.execute('''
            UPDATE notes 
            SET title = ?, encrypted_note = ?, encrypted_aes_key = ?, integrity_hash = ?, signature = ?
            WHERE id = ?
        ''', (title, encrypted_note_b64, encrypted_key_b64, integrity_hash, signature_b64, note_id))
        conn.commit()
        conn.close()
        
        log_event("EDIT_NOTE", f"User {session['username']} edited note {note_id}")
        return redirect(url_for('dashboard'))
    
    # GET: Decrypt for display
    try:
        aes_key = security.decrypt_key_rsa(note['encrypted_aes_key'])
        plaintext = security.decrypt_data_aes(note['encrypted_note'], aes_key)
    except Exception as e:
        plaintext = "[Decryption Failed - content cannot be edited]"
        
    conn.close()
    return render_template('edit_note.html', note=note, content=plaintext)

@app.route('/delete_note/<int:note_id>')
@login_required
def delete_note(note_id):
    if not check_acl(session['role'], 'notes', 'delete'):
        abort(403)
        
    conn = db.get_db_connection()
    # ACL: Ensure user owns the note
    note = conn.execute('SELECT user_id FROM notes WHERE id = ?', (note_id,)).fetchone()
    if note and note['user_id'] == session['user_id']:
        conn.execute('DELETE FROM notes WHERE id = ?', (note_id,))
        conn.commit()
        log_event("DELETE_NOTE", f"User {session['username']} deleted note {note_id}")
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/logs')
@login_required
def view_logs():
    # ACL check using new Matrix
    if not check_acl(session['role'], 'logs', 'read'):
        abort(403)
        
    conn = db.get_db_connection()
    logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50').fetchall()
    conn.close()
    
    return render_template('logs.html', logs=logs)

@app.route('/acl')
def view_acl():
    # Publicly viewable or restricted? Requirements say 'explicitly define'. Let's make it viewable to auth users.
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # Validates that we have a Matrix
    return render_template('acl.html')

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    conn = db.get_db_connection()
    
    # ACL: Admin can read all users and notes
    all_users = conn.execute('SELECT id, username, email, role FROM users').fetchall()
    all_notes_raw = conn.execute('SELECT * FROM notes').fetchall()
    conn.close()
    
    all_notes = []
    for note in all_notes_raw:
        # Admin can view notes too (Requirement: Admin can read all notes)
        # Decrypt logic repeated
        try:
            aes_key = security.decrypt_key_rsa(note['encrypted_aes_key'])
            plaintext = security.decrypt_data_aes(note['encrypted_note'], aes_key)
        except:
            plaintext = "[Decryption Error]"
            
        all_notes.append({
            'id': note['id'],
            'user_id': note['user_id'],
            'title': note['title'],
            'content': plaintext
        })

    return render_template('admin.html', users=all_users, notes=all_notes)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
