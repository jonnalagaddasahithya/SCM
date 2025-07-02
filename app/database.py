# app/database.py
from pymongo import MongoClient
from app.config import MONGO_URI, logger # Import logger from config

# Global variables for MongoDB client and database
client = None
db = None
users_collection = None
logins_collection = None
shipment_collection = None
device_data_collection = None

def initialize_db():
    """
    Initializes the MongoDB connection and collections.
    This function should be called once at application startup.
    """
    global client, db, users_collection, logins_collection, shipment_collection, device_data_collection
    try:
        if MONGO_URI is None:
            logger.critical("MONGO_URI is not set. Cannot connect to MongoDB.")
            raise ValueError("MONGO_URI environment variable is missing.")

        # Connect to MongoDB using the URI from config
        client = MongoClient(MONGO_URI)
        # Access the 'scmexpert' database
        db = client["scmexpert"]
        # Initialize collection objects for various data types
        users_collection = db["user"]
        logins_collection = db["logins"]
        shipment_collection = db["shipments"]
        device_data_collection = db["device_data"]
        logger.info("MongoDB connection established and collections initialized.")
    except Exception as e:
        # If connection fails, log a critical error and re-raise the exception
        logger.critical(f"Failed to connect to MongoDB: {e}")
        raise # Re-raise the exception to stop the app if DB connection fails

# Call initialize_db directly when this module is imported
# This ensures collections are ready when other modules import them
initialize_db()

