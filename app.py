from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import db
import security
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24) # Session key

# Initialize RSA Keys on startup
security.generate_rsa_keys()

# Initialize DB on startup (Ensure tables exist)
try:
    db.init_db()
except Exception as e:
    print(f"Startup DB init failed: {e}")

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
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_pw = security.hash_password(password)
        
        conn = None
        try:
            conn = db.get_db_connection()
            # Check if any users exist to assign ADMIN role to the first one
            user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            role = 'ADMIN' if user_count == 0 else 'USER'
            
            conn.execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                         (username, email, hashed_pw, role))
            conn.commit()
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
            session['otp'] = otp
            
            # In a real app, send email/SMS. Here, console output as per requirements.
            print(f"\n[SECURITY] OTP for {username}: {otp}\n")
            flash('OTP sent to console. Please verify.', 'info')
            
            return redirect(url_for('otp_verify'))
        else:
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
            session.pop('otp', None)
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP.', 'error')
            
    return render_template('otp.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = db.get_db_connection()
    user_id = session['user_id']
    
    # ACL: Users see their own notes.
    notes_data = conn.execute('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
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
    
    return redirect(url_for('dashboard'))

@app.route('/delete_note/<int:note_id>')
@login_required
def delete_note(note_id):
    conn = db.get_db_connection()
    # ACL: Ensure user owns the note
    note = conn.execute('SELECT user_id FROM notes WHERE id = ?', (note_id,)).fetchone()
    if note and note['user_id'] == session['user_id']:
        conn.execute('DELETE FROM notes WHERE id = ?', (note_id,))
        conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

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
