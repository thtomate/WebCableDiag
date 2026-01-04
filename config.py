
# Flask configuration
APP_HOST = "0.0.0.0"
APP_PORT = 5000
DEBUG = True
SECRET_KEY = "change_this_secret_change_in_prod"

# Cache configuration
TDR_CACHE_TTL = 60  # seconds
INTERFACES_CACHE_TTL = 30  # seconds

# Thread pool configuration
MAX_WORKERS = 5
