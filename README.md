# 🛡️ Secure Messaging Blockchain System (v2.0)

[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.14-00C2FF?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.0-22C55E?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![WebSockets](https://img.shields.io/badge/RealTime-Socket.IO-BD00FF?style=for-the-badge&logo=socketdotio&logoColor=white)](https://flask-socketio.readthedocs.io/)
[![Cryptography](https://img.shields.io/badge/Security-RSA%202048%20%7C%20AES--GCM-FFB300?style=for-the-badge&logo=shield&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Storage](https://img.shields.io/badge/Decentralized-IPFS%20Pinata-00FF41?style=for-the-badge&logo=ipfs&logoColor=black)](https://pinata.cloud/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

A cyber-themed, end-to-end encrypted (E2EE) messaging platform with cryptographic blockchain ledger auditing, Merkle tree integrity verification, IPFS decentralized storage, and Zero-Knowledge client-side key vaults.

---

## ⚡ Key Architectural Features

### 🔐 1. End-to-End Cryptography (Web Crypto API)
- **RSA-OAEP 2048-bit Encryption:** All messages are encrypted strictly in the client's browser before transmission. The server operates under a **Zero-Knowledge** model and cannot read message contents.
- **RSA-PSS Digital Signatures:** Messages are signed with the sender's private key to guarantee sender authenticity and non-repudiation.
- **Client-Side PIN Key Vault (AES-256-GCM + PBKDF2):** Private keys are encrypted locally using a user-chosen 6-digit PIN before encrypted backup to the server. If the browser cache is cleared, users can restore keys seamlessly across devices.

### ⛓️ 2. Cryptographic Blockchain Ledger
- **SHA-256 Proof-of-Work (PoW):** Blocks are mined with a verifiable difficulty target (`"00"`), chaining previous and current block hashes sequentially.
- **Binary Merkle Tree:** Every block's hash is anchored into a hierarchical Merkle tree. Provides cryptographic root verification and audit paths (`/api/blockchain/merkle`).
- **Interactive Integrity Audits & Tamper Simulation:** Real-time ledger audit tool (`/api/blockchain/audit`) that verifies every sequential link, plus an intruder attack simulation tool (`/api/blockchain/tamper`) to demonstrate tamper detection in action.

### 🌐 3. IPFS Distributed Storage (Pinata Cloud)
- **Decentralized Payload Storage:** Encrypted payloads are pinned asynchronously to IPFS via the Pinata REST API, returning standard IPFS Content Identifiers (`ipfs://Qm...`).
- **Sub-Millisecond Local Cache:** Includes an automatic local storage cache (`database/instance/ipfs_storage/`) ensuring zero-latency messaging even if network connectivity to IPFS gateways drops.

### 🛡️ 4. Enterprise-Grade Authentication & Hardening
- **TOTP Two-Factor Authentication:** Built-in QR code generator compatible with Google Authenticator, Authy, and 1Password.
- **Account Lockout & Rate Limiting:** Automatic account lockout after consecutive failed attempts, alongside IP-based request throttling powered by `Flask-Limiter`.
- **Google OAuth 2.0:** One-click single sign-on support.
- **JWT API Authentication:** Issue and verify JWT access and refresh tokens for headless/API clients.

### 🗄️ 5. Resilient Dual-Database Architecture
- **Automatic Failover:** Supports both local SQLite (instant, zero-configuration development) and cloud PostgreSQL/Supabase (production).
- If the remote PostgreSQL instance is unreachable, the system automatically fails over to the local SQLite database without downtime.

---

## 🏗️ System Architecture

```
[ User Browser ]
  │
  ├── 1. Generate RSA-OAEP & RSA-PSS Key Pairs (Web Crypto API)
  ├── 2. Encrypt plaintext message with Recipient's Public Key
  ├── 3. Encrypt sender's copy with Sender's Public Key
  ├── 4. Sign SHA-256 digest with RSA-PSS Private Key
  ├── 5. Pin encrypted blobs to IPFS (CIDs generated)
  │
  ▼  (HTTPS / WebSocket TLS)
[ Flask + Socket.IO Backend ]
  │
  ├── 6. Verify RSA Digital Signature
  ├── 7. Calculate SHA-256 & Mine Block (Proof-of-Work)
  ├── 8. Store Block in Ledger (PostgreSQL / SQLite)
  ├── 9. Update Merkle Tree Root
  └── 10. Broadcast "new_message" via WebSockets to recipient
```

---

## 📂 Project Directory Structure

```plaintext
secure-messaging-blockchain-system/
├── backend/
│   ├── app.py                     # Main Flask application & WebSocket handlers
│   ├── config.py                  # Environment & unified database configuration
│   ├── auth/
│   │   ├── jwt_helper.py          # JWT issuance & verification helpers
│   │   └── two_fa.py              # TOTP secret generation & QR code rendering
│   └── blockchain/
│       ├── ipfs_pinata.py         # Pinata IPFS integration & local cache fallback
│       ├── merkle.py              # Binary Merkle Tree implementation & proofs
│       └── signatures.py          # Server-side RSA-PSS signature verification
├── database/
│   └── instance/
│       ├── database.db            # Local SQLite database
│       └── ipfs_storage/          # Local filesystem IPFS cache
├── frontend/
│   ├── static/
│   │   ├── css/                   # Cyber hacker visual themes & layouts
│   │   ├── img/logo.png           # Project brand assets
│   │   └── js/
│   │       ├── script.js          # WebCrypto encryption, vault & chat controller
│   │       └── hero-animation.js  # Canvas Matrix rain animation
│   └── templates/
│       ├── base.html              # Core layout, modals, navbar & notifications
│       ├── home.html              # Landing hero page with interactive animations
│       ├── login.html             # Secure login & lockout countdown
│       ├── register.html          # User registration
│       ├── dashboard.html         # Ops Center overview & activity metrics
│       ├── chat.html              # Real-time E2EE messaging channel
│       ├── keys.html              # RSA Key Vault generator & recovery
│       ├── blockchain.html        # Ledger visualizer, Merkle root & audit tools
│       ├── admin.html             # Administrative user management console
│       ├── profile.html           # User profile & 2FA toggles
│       ├── two_fa_setup.html      # QR code scanning for authenticator apps
│       └── two_fa_verify.html     # 6-digit TOTP verification step
├── Procfile                       # Gunicorn start command for cloud containers
├── render.yaml                    # Infrastructure-as-code for Render deployment
├── requirements.txt               # Production Python dependencies
└── run.py                         # Local application entrypoint
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.11, 3.12, and 3.14)
- Git

### 2. Clone Repository & Setup Virtual Environment
```bash
# Clone the repository
git clone https://github.com/divu638/Secure-Messaging-Blockchain.git
cd Secure-Messaging-Blockchain

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env` (or update `.env`):
```ini
# Flask Secret Key
SECRET_KEY=your-random-secret-key-change-this

# Database Mode (Leave blank to use instant local SQLite)
# DATABASE_URL=postgresql://user:pass@host:5432/dbname?sslmode=require
DATABASE_URL=

# Pinata IPFS (Optional — falls back to local storage automatically if omitted)
PINATA_API_KEY=your_pinata_api_key
PINATA_SECRET_KEY=your_pinata_secret_key

# Google OAuth (Optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

FLASK_DEBUG=true
```

### 5. Run Locally
```bash
python run.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

---

## 🌐 Cloud Deployment (Render / Railway / Heroku)

### Render (Recommended)
This repository includes a pre-configured `render.yaml` and `Procfile`.

1. Go to your **[Render Dashboard](https://dashboard.render.com)**.
2. Click **New +** → **Web Service** → Connect your repository `divu638/Secure-Messaging-Blockchain`.
3. Set the following build settings (if not automatically loaded from `render.yaml`):
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --chdir backend --worker-class gthread --threads 8 --timeout 120 -b 0.0.0.0:$PORT app:app`
4. Click **Deploy Web Service**.

---

## 📡 API Reference

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | `GET` | Public | System status, database health & block count |
| `/api/users` | `GET` | Session | List registered agents & key availability |
| `/api/keys/upload` | `POST` | Session | Upload RSA public keys & encrypted vault blobs |
| `/api/keys/<username>` | `GET` | Session | Fetch a recipient's public key for encryption |
| `/api/messages/send` | `POST` | Session | Mine block & dispatch E2EE message |
| `/api/messages/history`| `GET` | Session | Retrieve conversation ledger history |
| `/api/blockchain/blocks` | `GET` | Session | List all mined blocks in the ledger |
| `/api/blockchain/audit` | `POST` | Session | Run sequential cryptographic integrity audit |
| `/api/blockchain/tamper`| `POST` | Session | Simulate database modification attack |
| `/api/blockchain/merkle`| `GET` | Session | Calculate chain Merkle root hash |
| `/api/auth/login` | `POST` | Public | Issue JWT Access & Refresh token pair |
| `/api/ipfs/status` | `GET` | Public | Pinata cloud status & local CID cache count |

---

## 🔒 Security Best Practices
- **Zero Server Plaintext:** Private keys are never transmitted to or held in plaintext by the backend.
- **Vault PIN Entropy:** Use at least a 6-digit high-entropy PIN to protect the AES-GCM vault blob.
- **Rate-Limiting Protection:** Registration, login, and message submission endpoints are protected against brute-force and spam attacks.
- **Security Headers:** Strict HTTP headers are applied automatically (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`).

---

## 👤 Author
**Divya Maurya**
- GitHub: [@divu638](https://github.com/divu638)
- Project: [Secure-Messaging-Blockchain](https://github.com/divu638/Secure-Messaging-Blockchain)

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).

