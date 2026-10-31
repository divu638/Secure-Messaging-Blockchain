"""
wsgi.py (Standard WSGI compatibility entrypoint)
"""
from app import app

if __name__ == "__main__":
    app.run()
