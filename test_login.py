from app.database import users_collection
from app.auth import pwd_context

# Test user credentials
test_email = "jonnalagaddasahithya@gmail.com"
test_password = "your_actual_password_here"  # Replace with actual password

print(f"Testing login for: {test_email}")

# Find user
user = users_collection.find_one({"email": test_email})
if not user:
    print("User not found!")
    exit()

print(f"User found: {user.get('email')}")
print(f"User verified: {user.get('is_verified')}")

# Check password
password_hash = user.get("password_hash")
if not password_hash:
    print("No password hash found!")
    exit()

print(f"Password hash: {password_hash}")

# Verify password
try:
    is_valid = pwd_context.verify(test_password, password_hash)
    print(f"Password valid: {is_valid}")
except Exception as e:
    print(f"Password verification error: {e}")

# Also test with wrong password
try:
    is_valid_wrong = pwd_context.verify("wrong_password", password_hash)
    print(f"Wrong password valid: {is_valid_wrong}")
except Exception as e:
    print(f"Wrong password verification error: {e}")