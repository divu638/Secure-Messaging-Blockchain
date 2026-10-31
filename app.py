"""
app.py (Root WSGI Entrypoint)
------------------------------
Enables cloud platforms (Render, Railway, Heroku) to run:
    gunicorn app:app
directly from the repository root without configuration errors.
"""
import os
import sys
import importlib.util

_root_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.join(_root_dir, "backend")

# Ensure backend directory is at the front of sys.path
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# Explicitly load backend/app.py avoiding circular import
_backend_app_path = os.path.join(_backend_dir, "app.py")
_spec = importlib.util.spec_from_file_location("backend_main_app", _backend_app_path)
_backend_module = importlib.util.module_from_spec(_spec)
sys.modules["backend_main_app"] = _backend_module
_spec.loader.exec_module(_backend_module)

# Expose WSGI targets
app = _backend_module.app
socketio = _backend_module.socketio
init_db = _backend_module.init_db

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Auto-initialize database on startup
with app.app_context():
    try:
        init_db()
    except Exception as e:
        app.logger.warning(f"Database auto-init warning: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)

