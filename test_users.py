from app.database import users_collection
from app.auth import pwd_context

print("Checking users in database...")

# List all users
users = list(users_collection.find())
print(f"Total users found: {len(users)}")

for user in users:
    print(f"Email: {user.get('email')}")
    print(f"Name: {user.get('name')}")
    print(f"Role: {user.get('role')}")
    print(f"Verified: {user.get('is_verified')}")
    print("---")

print("Done.")