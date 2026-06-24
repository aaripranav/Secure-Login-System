🔐 Secure Login System (Python HTTP Server)

A lightweight but secure authentication system built using Python's
built-in HTTP server and SQLite, featuring password hashing, session
management, CSRF protection, and login security controls.

This project demonstrates how real-world authentication systems work
without external frameworks like Flask or Django.

------------------------------------------------------------------------

## 📚 Table of Contents

-   What This Project Teaches\
-   Features\
-   Security Architecture\
-   Installation & Run\
-   How It Works\
-   Database Schema\
-   Authentication Flow\
-   Security Design Choices\
-   Project Structure

------------------------------------------------------------------------

## 🎓 What This Project Teaches

### 🔐 Core Security Concepts

-   Password hashing with PBKDF2-SHA256\
-   Salting passwords to prevent rainbow table attacks\
-   Secure session management using HTTP cookies\
-   CSRF protection using per-session tokens\
-   SQL injection prevention using parameterized queries\
-   Account lockout after repeated failed login attempts

### 💻 Backend Engineering Skills

-   Building a web server using http.server\
-   Handling HTTP requests manually (GET/POST)\
-   Working with SQLite without an ORM\
-   Implementing authentication without frameworks\
-   Secure cookie handling\
-   Session lifecycle management

------------------------------------------------------------------------

## ✨ Features

### 🔑 Authentication System

-   User registration\
-   Secure login system\
-   Password hashing with PBKDF2-SHA256\
-   Unique salt per user

### 🛡️ Security Features

-   SQL injection protection (parameterized queries)\
-   CSRF token protection\
-   Session expiration (8 hours TTL)\
-   Secure session hashing\
-   HttpOnly cookies (recommended usage)

### 🚫 Attack Prevention

-   Login attempt tracking\
-   Account lockout after 5 failed attempts\
-   Temporary lockout (10 minutes)\
-   Session invalidation on logout

### 🍪 Session System

-   Server-side sessions stored in SQLite\
-   Session ID hashed before storage\
-   Expiry-based cleanup\
-   CSRF token per session

------------------------------------------------------------------------

## 🏗️ Security Architecture

Browser\
↓\
HTTP Request (login/register)\
↓\
Python HTTP Server (app.py)\
↓\
Validation Layer\
├── Username/email validation (regex)\
├── Password verification (PBKDF2)\
├── CSRF check\
↓\
Security Layer\
├── Lockout check\
├── Session creation\
├── Session hashing\
↓\
SQLite Database

------------------------------------------------------------------------

## 🚀 Installation & Run

Step 1: Run Server python app.py

Step 2: Open Browser http://127.0.0.1:8000

Optional: Persistent Database
\$env:DB_PATH="C:`\path`{=tex}`\secure`{=tex}\_login.sqlite3" python
app.py

------------------------------------------------------------------------

## 🧠 How It Works

### 🔐 Registration Flow

User submits form\
↓\
Input validation (regex checks)\
↓\
Password hashed (PBKDF2 + salt)\
↓\
Stored in SQLite database

### 🔑 Login Flow

User enters credentials\
↓\
User lookup in database\
↓\
Check if account is locked\
↓\
Verify password hash\
↓\
If valid: - Reset failed login counter\
- Create session ID\
- Hash session ID\
- Store CSRF token\
- Set cookie

### 🚪 Logout Flow

User clicks logout\
↓\
Session removed from database\
↓\
Cookie invalidated

------------------------------------------------------------------------

## 🗄️ Database Schema

Users Table: CREATE TABLE users ( id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE, email TEXT UNIQUE, password_hash TEXT, totp_secret
TEXT, created_at INTEGER, failed_logins INTEGER DEFAULT 0, locked_until
INTEGER );

Sessions Table: CREATE TABLE sessions ( id_hash TEXT PRIMARY KEY,
user_id INTEGER, csrf_token TEXT, expires_at INTEGER, created_at INTEGER
);

------------------------------------------------------------------------

## 🔐 Security Design Choices

### 1. Password Hashing (PBKDF2-SHA256)

hashlib.pbkdf2_hmac( "sha256", password, salt, 310000 )

### 2. Session Security

-   Session IDs are SHA-256 hashed before storage\
-   Sessions expire automatically (TTL system)

### 3. CSRF Protection

Each session includes: csrf_token = secrets.token_hex(32)

### 4. Account Lockout System

-   5 failed login attempts → lock account\
-   10-minute cooldown

### 5. Input Validation

USERNAME_RE = r"[^1]{3,30}$"
EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

------------------------------------------------------------------------

## 📁 Project Structure

Secure-Login-System/

├── app.py ├── static/ │ └── styles.css ├── templates/ │ ├── login.html
│ ├── register.html │ └── dashboard.html ├── database.sqlite3 └──
README.md

------------------------------------------------------------------------

## ⚠️ Important Notes

-   Uses Python built-in HTTP server (no Flask/Django)\
-   Educational purpose only\
-   Not production-ready without HTTPS\
-   No encryption layer (only hashing)

------------------------------------------------------------------------

## 🧪 Possible Improvements

-   Add Argon2 hashing\
-   Migrate to FastAPI\
-   Add 2FA (TOTP)\
-   Add JWT authentication\
-   Add HTTPS (TLS certificates)\
-   Add rate limiting\
-   Add React frontend

------------------------------------------------------------------------

## 🧠 Key Takeaways

  Concept             Purpose
  ------------------- -----------------------------
  PBKDF2 Hashing      Secure password storage
  Salt                Prevent hash attacks
  CSRF Token          Prevent request forgery
  Sessions            Track logged-in users
  Lockout System      Prevent brute-force attacks
  Parameterized SQL   Prevent SQL injection

------------------------------------------------------------------------

## 📝 License

Educational project --- free to use and modify.

[^1]: A-Za-z0-9\_.-
