# Contributing to Secure Notes App

Thank you for your interest in contributing to the Secure Notes App!

## Getting Started

1. **Fork the repository** and clone it locally
2. **Set up your environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Run the application**:
   ```bash
   python app.py
   ```

## Project Structure

- `app.py` - Main Flask application with routes and authentication
- `db.py` - Database initialization and models
- `security.py` - Encryption, hashing, and security utilities
- `templates/` - HTML templates
- `static/` - CSS stylesheets

## Guidelines

- Follow PEP 8 coding standards
- Write meaningful commit messages
- Test your changes before submitting

## Security

This project implements:
- AES encryption for notes
- SHA-256 hashing for integrity verification
- Role-based access control (ADMIN, USER, MANAGER)
- OTP-based two-factor authentication

---
*Last updated: February 2026*
