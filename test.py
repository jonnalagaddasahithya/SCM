from pymongo import MongoClient

# Replace with your MongoDB URI
uri = "mongodb+srv://sahithya:sahithya@cluster0.qozzsoj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)

# Select the database and collection
db = client['hi']
collection = db['hi']

# Step 3: Push (Insert) Data
document = {"name": "John Doe", "age": 30}
insert_result = collection.insert_one(document)
print(f"Inserted document ID: {insert_result.inserted_id}")

# Step 4: Get (Retrieve) Data
retrieved_document = collection.find_one({"_id": insert_result.inserted_id})
print("Retrieved document:", retrieved_document)

# Close the connection
client.close()
