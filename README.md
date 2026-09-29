# 🏥 Hospital Appointment System

A secure, full-stack **Hospital Appointment Management System** built with **Python Flask** and **Firebase**, featuring multi-role access control and a comprehensive cybersecurity layer including encryption, digital signatures, and two-factor authentication.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Features](#-features)
- [User Roles](#-user-roles)
- [Security Architecture](#-security-architecture)
- [API Endpoints](#-api-endpoints)
- [Setup & Installation](#-setup--installation)
- [Running the App](#-running-the-app)
- [Cybersecurity Topics Implemented](#-cybersecurity-topics-implemented)

---

## 📌 Overview

This system allows **patients** to register and book appointments with doctors, **doctors** to manage their appointments, and **admins** to oversee the entire system. Every piece of sensitive data (appointments) is **encrypted at rest** using a hybrid AES + RSA encryption scheme, and all appointment records are **digitally signed** to ensure authenticity and integrity.

---

## 🧱 Tech Stack

| Layer        | Technology                          |
|--------------|-------------------------------------|
| Backend      | Python 3, Flask                     |
| Database     | Firebase Firestore (NoSQL)          |
| Auth         | Firebase Authentication             |
| Frontend     | HTML5, CSS3, JavaScript (Jinja2)    |
| Cryptography | `cryptography` library (Python)     |
| Hashing      | `hashlib` (PBKDF2-HMAC-SHA256)      |

---

## 📁 Project Structure

```
Project/
│
├── app.py                  # Main Flask application (routes & logic)
├── Security_utils.py       # Password hashing, digital signatures, integrity checks
├── crypto_utils.py         # AES-256 encryption & RSA key wrapping
│
├── private_key.pem         # RSA private key (used for signing & decryption)
├── public_key.pem          # RSA public key (used for verification & encryption)
├── serviceAccountKey.json  # Firebase admin SDK credentials
│
├── templates/              # Jinja2 HTML templates
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── otp.html
│   ├── patient.html
│   ├── doctor.html
│   ├── admin.html
│   ├── book_appointment.html
│   └── appoinment.html
│
├── static/                 # CSS & JS assets
│   ├── home.css
│   ├── login.css
│   ├── register.css
│   ├── otp.css
│   ├── patient.css
│   ├── doctor.css
│   ├── admin.css
│   ├── book_appointment.css
│   └── book_appointment.js
│
├── appointments.json       # Local fallback data
├── patients.json           # Local fallback data
└── README.md
```

---

## ✨ Features

- 🔐 **Secure Registration & Login** with Firebase Authentication
- 🔑 **Two-Factor Authentication (2FA)** via OTP (5-minute expiry)
- 📅 **Appointment Booking** by patients with doctor selection
- ✅ **Appointment Status Management** by doctors (pending → confirmed / completed / cancelled)
- 🛡️ **End-to-End Encryption** of all appointment data stored in Firestore
- 🔏 **Digital Signatures** on every appointment for tamper detection
- 🚦 **Role-Based Access Control (RBAC)** enforced on every route
- 🎟️ **Token-Based Appointment URLs** to prevent IDOR attacks
- 📊 **Admin Dashboard** with real-time system statistics
- 🆔 **Auto-generated Custom IDs** (P001, D001, A001) per user role

---

## 👥 User Roles

| Role      | Custom ID | Permissions                                                       |
|-----------|-----------|-------------------------------------------------------------------|
| Patient   | `P001`    | Register, login, book appointments, view own appointments         |
| Doctor    | `D001`    | View assigned appointments, update appointment status             |
| Admin     | `A001`    | View all users, all appointments, system statistics               |

### Access Control Matrix (ACL)

```python
ACL = {
    "patient": { "appointments": ["view_own", "create"] },
    "doctor":  { "appointments": ["view_own", "update"] },
    "admin":   { "appointments": ["view_all"], "users": ["view_all"], "system_stats": ["view"] }
}
```

Unauthorized access returns **HTTP 403 Forbidden**.

---

## 🔐 Security Architecture

### Authentication Flow

```
[User] → Enter Email + Password
            │
            ▼
    Firebase Auth Verify
            │
            ▼
    PBKDF2 Hash Verify (server-side)
            │
            ▼
    OTP Generated (6-digit, 5-min expiry)
            │
            ▼
    OTP Verified → Session Granted ✅
```

### Appointment Data Flow

```
[Book Appointment]
      │
      ├─ Digital Signature (RSA-PSS + SHA-256)
      ├─ Integrity Hash   (SHA-256)
      ├─ AES-256-CFB Encrypt (with random IV)
      └─ RSA-OAEP Encrypt AES Key
             │
             ▼
      Stored in Firestore (ciphertext + iv + encrypted_key)

[View / Update Appointment]
      │
      ├─ RSA Decrypt AES Key
      ├─ AES Decrypt Appointment Data
      ├─ SHA-256 Hash Verify (integrity)
      └─ RSA Signature Verify (authenticity)
```

---

## 🌐 API Endpoints

### Public Routes

| Method | Endpoint        | Description               |
|--------|----------------|---------------------------|
| GET    | `/`             | Home / Redirect           |
| GET    | `/register`     | Registration page         |
| POST   | `/register`     | Submit registration       |
| GET    | `/login`        | Login page                |
| POST   | `/login`        | Submit login credentials  |
| GET    | `/generate-otp` | Generate & send OTP       |
| GET    | `/otp`          | OTP verification page     |
| POST   | `/otp`          | Submit OTP                |
| GET    | `/logout`       | Clear session & logout    |

### Patient Routes (🔒 Role: patient)

| Method | Endpoint                 | Description                    |
|--------|-------------------------|-------------------------------|
| GET    | `/patient`              | Patient dashboard              |
| GET    | `/book-appointment`     | Appointment booking page       |
| POST   | `/book-appointment`     | Submit appointment booking     |
| GET    | `/my-appointments`      | Fetch own appointments (JSON)  |
| GET    | `/appointment/<token>`  | View single appointment detail |

### Doctor Routes (🔒 Role: doctor)

| Method | Endpoint                              | Description                    |
|--------|--------------------------------------|-------------------------------|
| GET    | `/doctor`                            | Doctor dashboard               |
| GET    | `/my-appointments`                   | Fetch assigned appointments    |
| POST   | `/update_appointment_status/<id>`    | Update appointment status      |

### Admin Routes (🔒 Role: admin)

| Method | Endpoint                   | Description                      |
|--------|---------------------------|----------------------------------|
| GET    | `/admin`                  | Admin dashboard                  |
| GET    | `/api/admin/stats`        | System statistics (JSON)         |
| GET    | `/api/admin/doctors`      | List of all doctors (JSON)       |
| GET    | `/api/admin/appointments` | List of all appointments (JSON)  |

---

## ⚙️ Setup & Installation

### Prerequisites

- Python 3.8+
- A Firebase project with **Firestore** and **Authentication** enabled
- Firebase Admin SDK `serviceAccountKey.json`

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd Project
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install flask firebase-admin cryptography requests
```

### 4. Configure Firebase

- Download your `serviceAccountKey.json` from Firebase Console → Project Settings → Service Accounts
- Place it in the project root directory
- Update `FIREBASE_API_KEY` in `app.py` with your Firebase Web API Key

### 5. RSA Key Generation (Auto)

RSA keys (`private_key.pem`, `public_key.pem`) are **automatically generated** on first run by the `DigitalSignatureManager` class if they don't already exist.

> ⚠️ **Keep `private_key.pem` secret!** Never commit it to version control.

---

## 🚀 Running the App

```bash
python app.py
```

The app runs at: **http://127.0.0.1:5000**

---

## 🔐 Cybersecurity Topics Implemented

### 1. 🧂 Password Hashing — PBKDF2-HMAC-SHA256

- **File:** `Security_utils.py`
- Passwords are hashed using `PBKDF2` with a **random 16-byte salt** and **100,000 iterations**
- Never stored in plaintext
- Defends against: **Rainbow Table Attacks, Dictionary Attacks, Brute Force**

```python
salt = os.urandom(16)
hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
```

---

### 2. 🔑 Two-Factor Authentication (2FA) — OTP

- **File:** `app.py`
- After password login, a **6-digit OTP** is generated and expires in **5 minutes**
- Session is only fully established after OTP verification
- Defends against: **Credential Stuffing, Account Takeover**

---

### 3. 🚦 Role-Based Access Control (RBAC)

- **File:** `app.py`
- ACL dictionary defines permissions per role (`patient`, `doctor`, `admin`)
- Every protected route calls `check_acl_permission()` before processing
- Violations return `HTTP 403 Forbidden`
- Implements: **Principle of Least Privilege**

---

### 4. 🔒 Symmetric Encryption — AES-256-CFB

- **File:** `crypto_utils.py`
- All appointment data encrypted using **AES-256** in **CFB mode**
- A **random IV** is generated per encryption to ensure uniqueness
- Defends against: **Data Breach, Unauthorized Database Access**

```python
key = os.urandom(32)   # AES-256
iv  = os.urandom(16)   # Fresh IV every time
cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
```

---

### 5. 🗝️ Asymmetric Encryption — RSA-OAEP (Hybrid Encryption)

- **File:** `crypto_utils.py`
- The AES session key is encrypted using the **RSA public key** with **OAEP padding**
- Only the holder of the **RSA private key** can decrypt the AES key
- Pattern: **Hybrid Encryption** (AES for speed + RSA for secure key distribution)

```python
PUBLIC_KEY.encrypt(aes_key, padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256()
))
```

---

### 6. 🔏 Digital Signatures — RSA-PSS with SHA-256

- **File:** `Security_utils.py`
- Every appointment is **signed** with the RSA private key at creation
- Signature is **verified** on every read and update
- Provides: **Authenticity & Non-Repudiation**

```python
signature = private_key.sign(data_bytes,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
```

---

### 7. 🛡️ Data Integrity — SHA-256 Hashing

- **File:** `Security_utils.py`
- A SHA-256 hash of critical appointment fields is stored alongside encrypted data
- On every access, the hash is **recomputed and compared**
- If tampered: `"Data integrity check failed - data has been modified"` ❌
- Defends against: **Man-in-the-Middle Attacks, Data Tampering**

---

### 8. 🎟️ IDOR Prevention — Base64 Encoded Tokens

- **File:** `Security_utils.py`, `app.py`
- Appointment URLs use **Base64 encoded tokens** embedding `patient_id` + `confirmation_token`
- The `patient_id` in the token is always verified against the active session
- Mismatch → `HTTP 403 Access Denied`
- Defends against: **Insecure Direct Object Reference (IDOR)**

---

## 🗺️ Security Coverage (CIA Triad)

| Principle            | Mechanism                                        |
|---------------------|--------------------------------------------------|
| **Confidentiality** | AES-256 + RSA-OAEP Hybrid Encryption             |
| **Integrity**       | SHA-256 Hash + RSA Digital Signature             |
| **Availability**    | Session Management, Role-Based Route Guards      |
| **Authentication**  | Firebase Auth + PBKDF2 Verify + OTP (2FA)        |
| **Authorization**   | ACL / RBAC enforced on every protected route     |
| **Non-Repudiation** | RSA-PSS Digital Signatures on all appointments   |

---

## ⚠️ Important Security Notes

- ❌ Do **NOT** commit `serviceAccountKey.json` or `private_key.pem` to version control — add them to `.gitignore`
- 🔑 Move `FIREBASE_API_KEY` to an environment variable (`.env` file) in production
- 📧 OTP is currently printed to the console — integrate an **Email/SMS service** (e.g., SendGrid, Twilio) in production
- 🔒 Change `app.secret_key` to a strong, randomly generated secret before deploying

---

## 👨‍💻 Author

Developed as a **Cybersecurity-focused Hospital Appointment Management System**, demonstrating real-world application of cryptographic principles (CIA Triad, 2FA, RBAC, Hybrid Encryption, Digital Signatures) within a Flask web application.
