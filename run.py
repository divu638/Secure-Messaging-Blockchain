"""
run.py
------
Project entry point. Run this from the project root:

    python run.py

This file adds the backend/ directory to the Python path so that
app.py and config.py can be imported cleanly.
"""

import sys
import os

# Add backend/ to path so `from config import Config` works inside app.py
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

from app import app, socketio, init_db
from config import Config

if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Secure Messaging Blockchain System on http://127.0.0.1:{port}")
    socketio.run(app, host="127.0.0.1", port=port, debug=Config.DEBUG, allow_unsafe_werkzeug=True)
