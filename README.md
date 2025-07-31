# CryptaShield
A secure file transfer tool with AES encryption, HMAC, replay attack prevention, and unit tests.

## 📜 Overview

This project is a **simple secure file transfer tool** demonstrating core **cybersecurity principles** such as:

- **Password-based key derivation (PBKDF2)**
- **AES-style encryption & decryption (mocked with XOR for testing)**
- **HMAC message authentication**
- **Replay attack prevention using timestamps and nonces**
- **Rate limiting with a Token Bucket algorithm**
- **Full unit testing for all components**

It’s built for a **coursework assignment** to show **secure coding**, **object-oriented programming**, **unit testing**, and **version control best practices**.

---

## 🗂️ Project Structure
project/
├── core/ # Core modules (KeyManager, CryptoManager, etc.)
├── test_files/ # Sample files for encryption/decryption
├── unit_testing.py # Main test suite (unittest)
├── requirements.txt # No external dependencies
├── .gitignore # Files/folders to ignore in version control
├── README.md # This file


---

## 🔑 How It Works

1. **Encrypt a file**  
   - Derives keys from password.
   - Encrypts file data (mock XOR for test).
   - Generates nonce, timestamp, HMAC for integrity.
   - Produces secure JSON output.

2. **Decrypt a file**  
   - Verifies timestamp & nonce to prevent replays.
   - Checks HMAC.
   - Decrypts data and restores the original file.

3. **Rate limiting**  
   - Blocks repeated rapid requests to simulate DoS protection.

---

## ✅ How to Run Tests

Run **all unit tests**:
```bash
python unit_testing.py
