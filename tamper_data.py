import sqlite3
import base64
import os

DB_NAME = "secure_notes.db"
TARGET_NOTE_ID = 5 # As identified in previous step

def tamper_data():
    conn = sqlite3.connect(DB_NAME)
    
    print(f"--- Tampering with Note ID {TARGET_NOTE_ID} ---")
    
    # 1. Fetch original data
    note = conn.execute("SELECT title, encrypted_note FROM notes WHERE id = ?", (TARGET_NOTE_ID,)).fetchone()
    if not note:
        print("Note not found!")
        return

    print(f"Original Title: {note[0]}")
    print(f"Original Encrypted Data (First 20 chars): {note[1][:20]}...")
    
    # 2. Corrupt the encrypted data 
    # We will just append some garbage bytes to the base64 string
    # This simulates a hacker modifying the blob in the DB
    corrupted_data = note[1][:-5] + "AAAAA" 
    
    # 3. Update the DB WITHOUT updating the signature/hash
    conn.execute("UPDATE notes SET encrypted_note = ? WHERE id = ?", (corrupted_data, TARGET_NOTE_ID))
    conn.commit()
    
    print(f"Corrupted Data (First 20 chars): {corrupted_data[:20]}...")
    print("Database updated successfully.")
    print("Verify in the dashboard that the status is now 'TAMPERED'.")
    
    conn.close()

if __name__ == '__main__':
    tamper_data()
