# 🔐 AES FILE LOCKER SYSTEM

Cryptography Project - Building a high-level data security tool using Python.

## 🚀 Core Features
- **Military-grade encryption:** Utilizes the `AES-256-CBC` algorithm.
- **Anti-tampering (Data Integrity):** Implements the `Encrypt-then-MAC` standard with `HMAC-SHA256` signatures.
- **Anti-Brute-force:** Key derivation using `PBKDF2` with 1,000,000 iterations.
- **True Locker mechanism:** Features Atomic Write and Secure Delete (safe destruction of the original file).
- **RAM Optimization:** Applies the Streaming technique (reading in 64KB chunks) to smoothly process massive files.

## 💻 Source Code Structure
The project is designed with a Modular architecture, completely separating the User Interface from the Algorithm Core:
1. `config.py`: Configuration file for cryptographic constants.
2. `core_crypto.py`: The mathematical core handling AES and HMAC processing.
3. `utils.py`: Gatekeeper utilities (Validation) and progress bar rendering.
4. `main.py`: The main program, serving as the CLI interface to coordinate the system.
5. `test_demo.py`: Automated testing script simulating a hacker tampering with the file.

## 🛠 How to Run
1. Install the required library: `pip install pycryptodome`
2. Run the system: `python main.py`
3. Run the test script: `python test_demo.py`
