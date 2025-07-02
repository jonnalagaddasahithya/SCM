# app/config.py
import logging
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

# --- Configure Logger ---
# Get the logger instance for the 'SCMxpert' application
logger = logging.getLogger("SCMxpert")
logger.setLevel(logging.DEBUG) # Set the logging level to DEBUG

# File handler: logs messages to 'app.log'
file_handler = logging.FileHandler('app.log')
# Define the format for log messages in the file
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler) # Add the file handler to the logger

# Stream handler: logs messages to the console (standard output)
stream_handler = logging.StreamHandler()
# Define the format for log messages in the console
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(stream_handler) # Add the stream handler to the logger

logger.info("Logger initialized in config.py.") # Log a message indicating logger initialization

# --- Load environment variables ---
# DEBUG PRINT: Show current working directory to help diagnose .env loading issues
print(f"DEBUG: Attempting to load .env from current working directory: {os.getcwd()}")
# Load variables from the .env file. `override=True` allows new variables to overwrite existing ones.
loaded = load_dotenv(override=True)
logger.info(f".env file loaded: {loaded}") # Log whether the .env file was loaded successfully
# DEBUG PRINT: Confirm if .env file was loaded
print(f"DEBUG: .env file loaded status: {loaded}")

# --- Configuration Constants ---
# Retrieve JWT secret key from environment variables
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
# Retrieve JWT algorithm from environment variables
ALGORITHM = os.getenv("JWT_ALGORITHM")
# Retrieve access token expiration minutes, default to "10" if not set
raw_expire_minutes = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10")
logger.debug(f"DEBUG: Raw value from os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'): '{raw_expire_minutes}'")
# Convert expiration minutes to an integer
ACCESS_TOKEN_EXPIRE_MINUTES = int(raw_expire_minutes)

# Retrieve reCAPTCHA site key from environment variables
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
# Retrieve reCAPTCHA secret key from environment variables
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
# Retrieve MongoDB URI from environment variables
MONGO_URI = os.getenv("MONGO_URI")

# DEBUG PRINTS: Show the values of critical environment variables
print(f"DEBUG: SECRET_KEY from .env: {SECRET_KEY}")
print(f"DEBUG: ALGORITHM from .env: {ALGORITHM}")
print(f"DEBUG: RECAPTCHA_SITE_KEY from .env: {RECAPTCHA_SITE_KEY}")
print(f"DEBUG: RECAPTCHA_SECRET_KEY from .env: {RECAPTCHA_SECRET_KEY}")
print(f"DEBUG: MONGO_URI from .env: {MONGO_URI}")


# Validate critical environment variables
# Check if all required environment variables are set. If any are missing, log a critical error.
if not all([SECRET_KEY, ALGORITHM, RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY, MONGO_URI]):
    logger.critical("Missing critical environment variables. Please check your .env file.")
    # Temporarily commented out to allow the app to start and show debug info
    # In a production environment, you would uncomment the line below to stop the app
    # raise ValueError("Missing critical environment variables. Check your .env file.")
    print("WARNING: Critical environment variables are missing, but ValueError is temporarily commented out.")


# --- URL Path Constants ---
# Define constants for various application routes to avoid hardcoding URLs
LOGIN_ROUTE = "/login"
SIGNUP_ROUTE = "/signup"
DASHBOARD_ROUTE = "/dashboard"
ADMIN_DASHBOARD_ROUTE = "/admin-dashboard"
USER_MANAGEMENT_ROUTE = "/user_management"
CREATE_SHIPMENT_ROUTE = "/create-shipment"
EDIT_SHIPMENT_ROUTE = "/edit-shipment"
FORGOT_PASSWORD_ROUTE = "/forgot-password"
RESET_PASSWORD_ROUTE = "/reset-password"

# --- Datetime Format Constant ---
# Define a standard format for displaying datetime objects
DATETIME_DISPLAY_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

# Get the current UTC time for timestamping
def get_current_utc_time():
    return datetime.now(timezone.utc)

