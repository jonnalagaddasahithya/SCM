# app/database.py
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from app.config import MONGO_URI, logger # Import logger from config

# Global variables for MongoDB client and database
client = None
db = None
users_collection = None
logins_collection = None
shipment_collection = None
device_data_collection = None
admin_requests_collection = None  # Added back admin_requests_collection
audit_log_collection = None  # Added back audit_log_collection

def initialize_db():                            
    """
    Initializes the MongoDB connection and collections.
    This function should be called once at application startup.
    """
    global client, db, users_collection, logins_collection, shipment_collection, device_data_collection, admin_requests_collection, audit_log_collection
    try:
        if MONGO_URI is None:
            logger.critical("MONGO_URI is not set. Cannot connect to MongoDB.")
            raise ValueError("MONGO_URI environment variable is missing.")

        # Connect to MongoDB using the URI from config
        logger.info("Attempting to connect to MongoDB...")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)  # 5 second timeout
        # Access the 'scmexpert' database
        db = client.scmexpert

        # Test the connection
        client.admin.command('ping')
        logger.info("MongoDB connection successful.")

        # Initialize all collections
        users_collection = db.users
        logins_collection = db.logins
        shipment_collection = db.shipments
        device_data_collection = db.device_data
        admin_requests_collection = db.admin_requests  # Added back admin_requests_collection
        audit_log_collection = db.audit_log  # Added back audit_log_collection

        # Create indexes for better performance
        users_collection.create_index("email", unique=True)
        logins_collection.create_index("user_email")
        shipment_collection.create_index("shipment_id", unique=True)
        device_data_collection.create_index("device_id")
        admin_requests_collection.create_index("user_email")  # Added back admin_requests_collection index
        audit_log_collection.create_index("timestamp")  # Added back audit_log_collection index

        logger.info("Database initialized successfully with all collections.")
        return True
    except ServerSelectionTimeoutError as e:
        logger.critical(f"MongoDB connection timeout: {e}")
        logger.error("Please check your internet connection and MongoDB URI configuration.")
        return False
    except ConnectionFailure as e:
        logger.critical(f"MongoDB connection failed: {e}")
        return False
    except Exception as e:
        logger.critical(f"Failed to initialize database: {e}")
        return False

# Initialize the database when this module is imported
# This ensures that collections are available when routes are imported
logger.info("Initializing database connection...")
if not initialize_db():
    logger.critical("Database initialization failed. Application may not function correctly.")