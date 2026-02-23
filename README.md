# 🔐 AES File Locker

A Cryptography project - Building a high-level data security tool using Python.

## 🚀 Core Features
- **Military-Grade Encryption:** Utilizes the `AES-256-CBC` standard.
- **Tamper Resistance (Data Integrity):** Implements the `Encrypt-then-MAC` architecture with `HMAC-SHA256` signatures.
- **Anti-Brute-Force:** Key derivation using `PBKDF2` with 1,000,000 iterations.
- **True Locker Mechanism:** Features Atomic Write and Secure Delete (overwriting the original file with `0x00` bytes before deletion).
- **Memory Optimization:** Employs a streaming technique (64KB chunks) for smooth processing of massive files without RAM overflow.

## 💻 Source Code Structure
The project is designed with a Modular Architecture, strictly separating the User Interface from the Cryptographic Engine:
1. `config.py`: Configuration file for cryptographic constants.
2. `core_crypto.py`: The mathematical core handling AES, HMAC, and PBKDF2 operations.
3. `utils.py`: Gatekeeper utilities for input validation, error handling, and CLI progress bar rendering.
4. `main.py`: The main entry point, serving as the CLI interface to coordinate the system securely (e.g., hiding password inputs).
5. `test_demo.py`: An automated testing script simulating a hacker tampering with the ciphertext.

## 🛠 How to Run

**1. Clone the repository and set up the environment:**
It is recommended to use a virtual environment (`venv`).
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
