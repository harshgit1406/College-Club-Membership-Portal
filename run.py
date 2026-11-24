"""
Application Entry Point
========================
Run with:
    python run.py                   # development server (default)
    FLASK_ENV=production python run.py

Or via Flask CLI:
    flask run --host=0.0.0.0 --port=5000
"""

import os

from dotenv import load_dotenv

# Load .env before importing the app factory so env vars are available
load_dotenv()

from app import create_app  # noqa: E402  (import after dotenv)

# Determine environment from FLASK_ENV (defaults to 'development')
env = os.environ.get("FLASK_ENV", "development")
app = create_app(env)

if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug = env == "development"

    print(f"[run.py] Starting '{env}' server on http://{host}:{port}/")
    print(f"[run.py] Debug mode: {debug}")

    app.run(host=host, port=port, debug=debug)
