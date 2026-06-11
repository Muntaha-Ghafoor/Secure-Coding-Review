# 🔐 Secure Coding Review — Python Security Audit

<div align="center">

![Security](https://img.shields.io/badge/Cybersecurity-Secure%20Code%20Review-blue?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-yellow?style=for-the-badge&logo=python&logoColor=white)
![Bandit](https://img.shields.io/badge/Tool-Bandit-red?style=for-the-badge)
![Pylint](https://img.shields.io/badge/Tool-Pylint-orange?style=for-the-badge)
![CodeAlpha](https://img.shields.io/badge/CodeAlpha-Internship%20Task%203-brightgreen?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)

**A professional Python application security audit performed using industry-standard static analysis tools — Bandit, Pylint, Safety, and a custom AST-based scanner.**

[📋 Vulnerabilities Found](#-vulnerabilities-found) • [🛠️ Tools Used](#️-tools-used) • [▶️ How to Run](#️-how-to-run-the-audit) • [👩‍💻 Author](#-author)

</div>

---

## 📌 Project Overview

This project is **Task 3 — Secure Coding Review** of the **CodeAlpha Cybersecurity Internship Program**.

A deliberately vulnerable Python web application (`vulnerable_app.py`) was created and audited using multiple static analysis tools. The audit identified **10 security vulnerabilities** across 9 CWE categories, along with detailed remediation steps and secure code fixes for each finding.

> ⚠️ **Disclaimer:** The file `vulnerable_app.py` contains **intentional security vulnerabilities for educational purposes ONLY**. This code must **never** be used in any real or production application. It exists solely to demonstrate common insecure coding patterns and how to detect and fix them.

---

## 🎯 Objectives

- ✅ Select a Python application and perform a full security audit
- ✅ Use professional static analysis tools (Bandit, Pylint, Safety)
- ✅ Build a custom AST-based security scanner
- ✅ Identify and classify vulnerabilities using CWE/MITRE framework
- ✅ Provide secure code fixes and remediation recommendations
- ✅ Document all findings in a professional report

---

## 🗂️ Repository Structure

```
Secure-Coding-Review/
│
├── vulnerable_app.py        # ⚠️ Intentionally vulnerable Python app (for audit)
├── security_scanner.py      # 🔍 Custom AST-based static analysis scanner
├── Secure_Coding_Review.pptx  # 📊 Full 12-slide presentation
├── Secure_Coding_Review.pdf   # 📄 PDF version (LinkedIn ready)
├── bandit_report.txt        # 🔴 Bandit scan results
├── bandit_report.json       # 🔴 Bandit scan results (JSON)
├── pylint_report.txt        # 🟡 Pylint analysis results
├── safety_report.txt        # 🟢 Dependency vulnerability report
├── full_report.txt          # 📋 Combined report from all tools
└── README.md                # 📖 This file
```

---

## 🚨 Vulnerabilities Found

| ID | Vulnerability | CWE | Severity | Line |
|----|---------------|-----|----------|------|
| V-01 | Hardcoded Credentials | CWE-798 | 🔴 HIGH | L.18-21 |
| V-02 | SQL Injection | CWE-89 | 🔴 HIGH | L.33 |
| V-03 | Weak Password Hashing (MD5) | CWE-327 | 🔴 HIGH | L.41 |
| V-04 | OS Command Injection | CWE-78 | 🔴 HIGH | L.49 |
| V-05 | Insecure Deserialization (pickle) | CWE-502 | 🔴 HIGH | L.58 |
| V-06 | Path Traversal | CWE-22 | 🟡 MEDIUM | L.65 |
| V-07 | Sensitive Data in Logs | CWE-532 | 🔴 HIGH | L.77 |
| V-08 | Broad Exception Handling | CWE-390 | 🟢 LOW | L.89 |
| V-09 | Cryptographically Weak PRNG | CWE-338 | 🟡 MEDIUM | L.100 |
| V-10 | Debug Mode Enabled | CWE-215 | 🟡 MEDIUM | L.106 |

**Total: 10 vulnerabilities | 6 High | 2 Medium | 1 Low**

---

## 🛠️ Tools Used

| Tool | Purpose | Command |
|------|---------|---------|
| **Bandit** | Python SAST — detects dangerous functions & patterns | `bandit -v vulnerable_app.py` |
| **Pylint** | Code quality + security linting | `pylint vulnerable_app.py` |
| **Safety** | Checks dependencies for known CVEs | `safety check -r requirements.txt` |
| **Python AST** | Custom syntax tree analysis scanner | `python3 security_scanner.py vulnerable_app.py` |
| **Manual Review** | Human inspection for logic flaws | Line-by-line code review |

---

## ▶️ How to Run the Audit

### Prerequisites

```bash
# Update your system
sudo apt update

# Install pip
sudo apt install python3-pip -y

# Install all required tools
pip3 install bandit pylint safety
```

### Clone the Repository

```bash
git clone https://github.com/Muntaha-Ghafoor/Secure-Coding-Review.git
cd Secure-Coding-Review
```

### Run Bandit (Primary Scanner)

```bash
# Quick scan
bandit vulnerable_app.py

# Detailed verbose scan
bandit -v vulnerable_app.py

# Save as text report
bandit vulnerable_app.py -o bandit_report.txt -f txt

# Save as JSON report
bandit vulnerable_app.py -o bandit_report.json -f json
```

### Run Pylint

```bash
# Full analysis
pylint vulnerable_app.py

# Save report
pylint vulnerable_app.py > pylint_report.txt
```

### Run Safety (Dependency Check)

```bash
# Generate requirements
pip3 freeze > requirements.txt

# Check for CVEs
safety check -r requirements.txt

# Save report
safety check -r requirements.txt --output text > safety_report.txt
```

### Run Custom Scanner

```bash
python3 security_scanner.py vulnerable_app.py
```

### Run All Tools at Once

```bash
echo "=== BANDIT REPORT ===" > full_report.txt
bandit -v vulnerable_app.py >> full_report.txt

echo "=== PYLINT REPORT ===" >> full_report.txt
pylint vulnerable_app.py >> full_report.txt

echo "=== CUSTOM SCANNER ===" >> full_report.txt
python3 security_scanner.py vulnerable_app.py >> full_report.txt

cat full_report.txt
```

---

## 🔒 Key Vulnerability Highlights

### 🔴 SQL Injection (CWE-89)
```python
# VULNERABLE ❌
query = "SELECT * FROM users WHERE username = '" + username + "'"

# SECURE ✅
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

### 🔴 Hardcoded Credentials (CWE-798)
```python
# VULNERABLE ❌
DB_PASSWORD = "admin123"
SECRET_KEY  = "mysecretkey"

# SECURE ✅
import os
from dotenv import load_dotenv
load_dotenv()
DB_PASSWORD = os.getenv("DB_PASSWORD")
SECRET_KEY  = os.getenv("SECRET_KEY")
```

### 🔴 Command Injection (CWE-78)
```python
# VULNERABLE ❌
subprocess.call("ping -c 1 " + hostname, shell=True)

# SECURE ✅
subprocess.call(['ping', '-c', '1', hostname], shell=False)
```

### 🔴 Weak Hashing (CWE-327)
```python
# VULNERABLE ❌
hashlib.md5(password.encode()).hexdigest()

# SECURE ✅
import bcrypt
bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

---

## ✅ Secure Coding Best Practices

1. 🔑 **Never hardcode secrets** — use environment variables or vaults
2. 🛡️ **Always use parameterized queries** — prevent SQL injection
3. 🔐 **Use bcrypt/argon2 for passwords** — never MD5 or SHA1
4. ⚡ **Validate all user input** — allowlists over blocklists
5. 🎲 **Use `secrets` module** — not `random` for tokens
6. 📝 **Never log passwords or PII** — log actions only
7. 🚫 **Avoid `pickle` on untrusted data** — use JSON instead
8. ⚙️ **Set DEBUG=False in production** — no stack traces exposed

---

## 🏢 Internship Details

| Field | Details |
|-------|---------|
| **Internship** | CodeAlpha |
| **Domain** | Cybersecurity |
| **Task** | Task 3 — Secure Coding Review |
| **Language Audited** | Python 3 |
| **Tools Used** | Bandit, Pylint, Safety, Custom AST Scanner |
| **Platform** | Kali Linux on VMware |

---

## 👩‍💻 Author

<div align="center">

### Muntaha Ghafoor
**Cybersecurity Intern @ CodeAlpha**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muntaha%20Ghafoor-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/muntaha-ghafoor-2b87a9386)
[![GitHub](https://img.shields.io/badge/GitHub-Muntaha--Ghafoor-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Muntaha-Ghafoor)

*Passionate about cybersecurity, secure coding, and protecting digital systems.*

</div>

---

## 📄 License

This project is open-source under the [MIT License](LICENSE).
You are free to use and adapt this material for educational purposes with proper attribution.

---

<div align="center">

⭐ **If this project helped you, please give it a star!** ⭐

*Secure code is not optional — it's a responsibility. 🛡️*

</div>
