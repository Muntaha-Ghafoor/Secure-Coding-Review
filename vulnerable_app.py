"""
vulnerable_app.py
A sample Python web application with intentional security vulnerabilities.
Used for Secure Coding Review — CodeAlpha Internship Task 3.
Author: Muntaha Ghafoor
"""

import sqlite3
import hashlib
import os
import subprocess
import pickle
import re

# ============================================================
# VULNERABILITY 1: Hardcoded Credentials (CWE-798)
# ============================================================
DB_PASSWORD   = "admin123"          # Hardcoded database password
SECRET_KEY    = "mysecretkey"       # Hardcoded secret key
ADMIN_USER    = "admin"
ADMIN_PASS    = "password"          # Plaintext hardcoded credential


# ============================================================
# VULNERABILITY 2: SQL Injection (CWE-89)
# ============================================================
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: Direct string formatting — attacker can inject SQL
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


# ============================================================
# VULNERABILITY 3: Weak Hashing — MD5 (CWE-327)
# ============================================================
def hash_password(password):
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# ============================================================
# VULNERABILITY 4: Command Injection (CWE-78)
# ============================================================
def ping_host(hostname):
    # VULNERABLE: User input passed directly to shell
    result = subprocess.call("ping -c 1 " + hostname, shell=True)
    return result


# ============================================================
# VULNERABILITY 5: Insecure Deserialization (CWE-502)
# ============================================================
def load_user_session(data):
    # VULNERABLE: pickle.loads on untrusted data allows RCE
    return pickle.loads(data)


# ============================================================
# VULNERABILITY 6: Path Traversal (CWE-22)
# ============================================================
def read_file(filename):
    # VULNERABLE: No sanitization — attacker can read ../../etc/passwd
    base_path = "/var/www/uploads/"
    full_path = base_path + filename
    with open(full_path, "r") as f:
        return f.read()


# ============================================================
# VULNERABILITY 7: Sensitive Data in Logs (CWE-532)
# ============================================================
def login(username, password):
    # VULNERABLE: Password logged in plaintext
    print(f"[LOG] Login attempt: username={username}, password={password}")
    if username == ADMIN_USER and password == ADMIN_PASS:
        return True
    return False


# ============================================================
# VULNERABILITY 8: Broad Exception Handling (CWE-390)
# ============================================================
def divide(a, b):
    try:
        return a / b
    except:
        # VULNERABLE: Catches all exceptions, hides real errors
        pass


# ============================================================
# VULNERABILITY 9: Weak Random (CWE-338)
# ============================================================
import random
def generate_token():
    # VULNERABLE: random is not cryptographically secure
    return str(random.randint(100000, 999999))


# ============================================================
# VULNERABILITY 10: Debug Mode / Info Disclosure (CWE-215)
# ============================================================
DEBUG = True     # VULNERABLE: Debug mode enabled in production

def get_error_details(e):
    if DEBUG:
        # VULNERABLE: Full stack trace exposed to user
        import traceback
        return traceback.format_exc()
    return "An error occurred."
