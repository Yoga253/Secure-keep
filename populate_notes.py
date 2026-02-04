import sqlite3
import security
import db
import random

# Initialize DB (just in case)
db.init_db()

# Dummy Data
titles = [
    "Project Alpha Credentials",
    "Meeting Notes: Q1 Goals",
    "Server Config Backup",
    "Personal Journal: Monday",
    "Key Contact List",
    "Idea for new feature: Dark Mode",
    "Incident Report: 2024-05-12",
    "Recipe: Secret Sauce",
    "Gym Schedule",
    "Travel Itinerary: Paris"
]

contents = [
    "Username: admin, Password: ultra_secure_password_123",
    "Focus on increasing user retention by 20%. Launch marketing campaign in June.",
    "IP: 192.168.1.10, Port: 22, User: root, Key: /home/admin/.ssh/id_rsa",
    "Today was a productive day. I learned about AES encryption and RSA key exchange.",
    "John Doe: 555-0123, Jane Smith: 555-0199, Bob: 555-0000",
    "Implement a toggle switch in the navbar. Use local storage to persist preference.",
    "Server downtime observed at 03:00 AM due to maintenance. Restarted at 03:15 AM.",
    "Ingredients: 2 cups sunlight, 1 cup hard work, a pinch of luck.",
    "Monday: Chest, Tuesday: Back, Wednesday: Legs, Thursday: Shoulders, Friday: Arms.",
    "Flight AA123, Hotel: The Grand Budapest. Reservation #998877."
]

def populate_notes():
    conn = db.get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    
    if not users:
        print("No users found! Please register a user first.")
        return

    print(f"Found {len(users)} users. Generating notes...")

    for i in range(15): # Generate 15 notes
        user = random.choice(users)
        user_id = user['id']
        username = user['username']
        
        title = random.choice(titles)
        content = random.choice(contents)
        
        # --- Encryption Flow (Matches app.py) ---
        
        # 1. Encrypt Content (AES)
        encrypted_note_b64, aes_key = security.encrypt_data_aes(content)
        
        # 2. Encrypt AES Key (RSA)
        encrypted_key_b64 = security.encrypt_key_rsa(aes_key)
        
        # 3. Generate Integrity Hash
        integrity_hash = security.generate_integrity_hash(encrypted_note_b64)
        
        # 4. Sign the Hash
        signature_b64 = security.sign_hash(integrity_hash)
        
        try:
            conn.execute('''
                INSERT INTO notes (user_id, title, encrypted_note, encrypted_aes_key, integrity_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, title, encrypted_note_b64, encrypted_key_b64, integrity_hash, signature_b64))
            print(f"Added note '{title}' for user {username}")
        except Exception as e:
            print(f"Failed to add note: {e}")

    conn.commit()
    conn.close()
    print("\nDummy notes added successfully!")

if __name__ == '__main__':
    populate_notes()
