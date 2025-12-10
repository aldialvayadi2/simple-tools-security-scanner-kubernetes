import os

API_PORT = int(os.environ.get('SERVER_PORT', 8888))
API_HOST = os.environ.get('SERVER_HOST', '0.0.0.0')

# Configuration (using existing API_PORT from top of file)
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour