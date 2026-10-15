import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Tell the app it's running in Vercel environment if not explicitly set
os.environ.setdefault('VERCEL', '1')

from server import app

# Vercel's Python WSGI runtime imports `app` from api/index.py
