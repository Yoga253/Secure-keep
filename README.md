# Secure Notes Management System

A secure, web-based notes application built with Flask and SQLite, demonstrating core cybersecurity concepts including Authentication, Authorization, Encryption, Hashing, and Encoding.

## 🚀 Setup & Run

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run Application:**
    ```bash
    python app.py
    ```

3.  **Access:**
    Open `http://127.0.0.1:5000` in your browser.
    
    *   **First User:** The first user registered will be automatically assigned the `ADMIN` role.
    *   **Subsequent Users:** Will be assigned the `USER` role.

## 🔒 Security Concepts Implemented

### 1. Authentication (NIST SP 800-63-2)
*   **Password Storage:** Passwords are hashed using `bcrypt` with a random salt. This prevents rainbow table attacks.
*   **Multi-Factor Authentication (MFA):**
    *   **Factor 1:** Something you know (Password).
    *   **Factor 2:** Something you have (OTP).
    *   The OTP is generated securely on the server using the `secrets` library and displayed in the server console (simulating an SMS/Email gateway).
*   **Session Management:** Sessions are secured with a cryptographically strong random key (`os.urandom`).

### 2. Authorization (Access Control)
*   **Role-Based Access Control (RBAC):**
    *   **USER:** Can only Create, Read, Update, Delete (CRUD) their *own* notes.
    *   **ADMIN:** Can view all users and read all notes (for auditing purposes) but strictly separated from standard user flow.
*   **Implementation:** Decorators (`@login_required`, `@admin_required`) enforce these rules on every request.

### 3. Encryption (Confidentiality)
*   **Symmetric Encryption (AES):**
    *   Each note is encrypted with a unique, randomly generated 256-bit AES key.
    *   Mode: CFB (Cipher Feedback) with a random IV (Initialization Vector).
    *   **Why:** AES is fast and suitable for encrypting large amounts of data (the note content).
*   **Asymmetric Encryption (RSA):**
    *   The unique AES key for each note is encrypted using the System's RSA Public Key.
    *   **Why:** This simulates a secure key exchange/storage mechanism where the master key (Private Key) is kept secure and only used for decryption.

### 4. Hashing & Integrity
*   **Integrity Check:** A SHA-256 hash is generated for the encrypted note content.
*   **Digital Signature:** The hash is signed using the System's RSA Private Key.
*   **Verification:** Upon retrieval, the system verifies the signature using the Public Key and recalculates the hash to ensure the data hasn't been tampered with in the database.

### 5. Encoding
*   **Base64:** All binary encrypted data (ciphertext, keys, signatures) is Base64 encoded before storage in the SQLite database to ensure safe handling of text fields.

## ⚠️ Security Levels & Risks

*   **Hashing vs. Encryption:** 
    *   **Passwords** are hashed (one-way) because the system never needs to know the original password, only verify it.
    *   **Notes** are encrypted (two-way) because the user needs to retrieve the original content.
*   **Key Compromise:**
    *   If the **RSA Private Key** is compromised, an attacker can decrypt the AES keys and subsequently all notes. This is the "Root of Trust".
    *   If a single **AES Key** is compromised, only that specific note is at risk.

## 🛡️ Possible Attacks & Mitigations

1.  **Brute Force Attack:**
    *   *Mitigation:* `bcrypt` is slow by design, making brute-forcing passwords computationally expensive.
2.  **SQL Injection:**
    *   *Mitigation:* Use of parameterized queries (`?` placeholders) in `db.py` ensures user input is never executed as code.
3.  **Man-in-the-middle (MITM):**
    *   *Mitigation:* In a real deployment, HTTPS (SSL/TLS) would encrypt the traffic between client and server. The current encryption protects data *at rest* (in the DB).
4.  **Replay Attack:**
    *   *Mitigation:* OTPs are valid only for the current session attempt (though in this simple demo, they don't have strict time windows, they are one-time use per login flow).
