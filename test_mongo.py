import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
print(f"MONGO_URI: {MONGO_URI}")

if not MONGO_URI:
    print("MONGO_URI not found in environment variables")
    exit(1)

try:
    print("Attempting to connect to MongoDB...")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("MongoDB connection successful!")
    
    # List databases
    print("Available databases:")
    for db_name in client.list_database_names():
        print(f"  - {db_name}")
        
    # Check if scmexpert database exists
    if 'scmexpert' in client.list_database_names():
        print("scmexpert database found")
        db = client.scmexpert
        print("Collections in scmexpert database:")
        for collection_name in db.list_collection_names():
            print(f"  - {collection_name}")
    else:
        print("scmexpert database not found")
        
except ServerSelectionTimeoutError as e:
    print(f"MongoDB connection timeout: {e}")
    print("Please check your internet connection and MongoDB URI configuration.")
except ConnectionFailure as e:
    print(f"MongoDB connection failed: {e}")
except Exception as e:
    print(f"Error: {e}")