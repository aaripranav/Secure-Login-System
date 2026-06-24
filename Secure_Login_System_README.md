# 🔐 Secure Login System

A secure login web application built with Python and SQLite, designed to
demonstrate real-world authentication concepts including password
hashing, session management, and protection against common web attacks.

Perfect for learning **web security fundamentals, authentication
systems, and backend development best practices**.

------------------------------------------------------------------------

## 📚 Table of Contents

1.  What You'll Learn
2.  Installation & Setup
3.  Features
4.  How It Works
5.  Security Model
6.  Usage Guide
7.  Architecture
8.  Project Structure

------------------------------------------------------------------------

## 🎓 What You'll Learn

### 🔐 Security Concepts

-   Password hashing (PBKDF2 / bcrypt / Argon2 concepts)
-   Why plain-text passwords are dangerous
-   Session-based authentication
-   SQL injection and parameterized queries
-   CSRF protection basics
-   Brute-force attack prevention (lockouts)

### 💻 Backend Development Skills

-   Python web server fundamentals
-   SQLite database integration
-   HTTP request/response handling
-   Cookie-based session management
-   Input validation and sanitization
-   Secure authentication flow design

------------------------------------------------------------------------

## 🚀 Installation & Setup

### Prerequisites

-   Python 3.8+

------------------------------------------------------------------------

### Step 1: Run the Application

``` powershell
& 'C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' app.py
```

------------------------------------------------------------------------

### Step 2: Open in Browser

http://127.0.0.1:8000

------------------------------------------------------------------------

### Optional: Persistent Database

``` powershell
$env:DB_PATH = "C:\path\to\secure_login.sqlite3"
& 'C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' app.py
```

------------------------------------------------------------------------

## ✨ Features

### 1. User Authentication System

-   Secure registration
-   Login with hashed passwords
-   No plain-text password storage

### 2. Password Security

-   PBKDF2-SHA256 hashing
-   Unique salt per user
-   High iteration count (310,000+)

### 3. SQL Injection Protection

-   Parameterized queries only
-   No raw SQL string concatenation

### 4. Input Validation

-   Username/email/password validation
-   Basic format enforcement

### 5. Session Management

-   Server-side sessions
-   HttpOnly cookies
-   SameSite protection

### 6. Logout System

-   Session invalidation
-   Cookie clearing

### 7. Security Enhancements

-   Login attempt lockout
-   CSRF protection
-   Brute-force mitigation

### 8. Optional 2FA

-   TOTP support
-   Authenticator app compatibility

------------------------------------------------------------------------

## 🔍 How It Works

User registers → password hashed → stored in DB\
User logs in → hash verified → session created → cookie issued

------------------------------------------------------------------------

## 🔐 Security Model

### Password Storage

-   Never store plain text
-   Always hash with salt

### SQL Injection Protection

``` python
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

### Session Security

-   Random session IDs
-   HttpOnly cookies
-   Server-side validation

------------------------------------------------------------------------

## 💻 Usage Guide

### Register

-   Go to /register
-   Create account

### Login

-   Enter credentials
-   Session created on success

### Dashboard

-   Protected route

### Logout

-   Session destroyed

------------------------------------------------------------------------

## 🏗️ Architecture

Browser → Python Server → Auth Layer → Database

------------------------------------------------------------------------

## 📁 Project Structure

Secure-Login-System/ - app.py - auth.py - database.py - security.py -
sessions.py - templates/ - static/ - utils/ - README.md

------------------------------------------------------------------------

## 🧠 Key Concepts

  Concept      Purpose
  ------------ -------------------------------
  Hashing      Secure password storage
  Salt         Prevent rainbow table attacks
  Sessions     User authentication
  CSRF         Request protection
  SQL Params   Injection prevention

------------------------------------------------------------------------

## 📝 License

Educational project
