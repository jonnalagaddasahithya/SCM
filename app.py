 # app.py
from fastapi import FastAPI, Request, Form, status, Depends, HTTPException, Response, Query
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pymongo import MongoClient
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import requests
import os
from pydantic import ValidationError as RequestValidationError, BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from dotenv import load_dotenv
import logging
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
import secrets

# --- Configure Logger ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('app.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(stream_handler)

logger.info("Logger initialized.")

# --- Load environment variables ---
loaded = load_dotenv(override=True)
logger.info(f".env file loaded: {loaded}")

# --- Configuration ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
raw_expire_minutes = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10")
logger.debug(f"DEBUG: Raw value from os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'): '{raw_expire_minutes}'")
ACCESS_TOKEN_EXPIRE_MINUTES = int(raw_expire_minutes)

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
MONGO_URI = os.getenv("MONGO_URI")

# Validate critical environment variables
if not all([SECRET_KEY, ALGORITHM, RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY, MONGO_URI]):
    logger.critical("Missing critical environment variables. Please check your .env file.")
    raise ValueError("Missing critical environment variables. Check your .env file.")

# --- URL Path Constants ---
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
DATETIME_DISPLAY_FORMAT = "%Y-%m-%d %H:%M:%S UTC"
   

logger.info("Creating FastAPI app")
# Initialize app
app = FastAPI()

# Static files setup
app.mount("/static", StaticFiles(directory="static"), name="static")

# Jinja2 Templates setup
templates = Jinja2Templates(directory="templates")

# Session middleware setup
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
logger.info("SessionMiddleware added.")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB connection setup
try:
    client = MongoClient(MONGO_URI)
    db = client["scmexpert"]
    users_collection = db["user"]
    logins_collection = db["logins"]
    shipment_collection = db["shipments"]
    device_data_collection = db["device_data"]
    logger.info("MongoDB connection established and collections initialized.")
except Exception as e:
    logger.critical(f"Failed to connect to MongoDB: {e}")
    raise

# ---------------------------
# JWT TOKEN UTILITIES
# ---------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    jwt_token = request.cookies.get("access_token")
    logger.debug(f"JWT token from cookie: {jwt_token}")
    if not jwt_token and token:
        jwt_token = token
    if not jwt_token:
        logger.error("JWT token not found in cookie or header.")
        raise credentials_exception
         
    try:
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.error("Username not found in JWT payload.")
            raise credentials_exception
        token_data = TokenData(username=username, role=payload.get("role"))
    except JWTError as e:
        logger.error(f"JWT decode error: {e}")
        raise credentials_exception

    user = users_collection.find_one({"email": token_data.username})
    if user is None:
        logger.error("User not found for given token data.")
        raise credentials_exception
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def verify_admin(current_user: dict = Depends(get_current_active_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

# ---------------------------
# GLOBAL ERROR HANDLERS
# ---------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.error(f"HTTP Exception caught: {exc.status_code} - {exc.detail}")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation Error caught: {exc.errors()}")
    return JSONResponse({"detail": exc.errors()}, status_code=status.HTTP_400_BAD_REQUEST)

# ---------------------------
# Pydantic Models for Form Data
# ---------------------------
class ShipmentCreateData(BaseModel):
    shipment_id: str
    po_number: str
    route_details: str
    device: str
    ndc_number: str
    serial_number: str
    container_number: str
    goods_type: str
    expected_delivery_date: str # Consider validating as date
    delivery_number: str
    batch_id: str
    origin: str
    destination: str
    shipment_description: str


# ---------------------------
# ROUTES
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def root():
    logger.info(f"Root endpoint accessed, redirecting to {LOGIN_ROUTE}.")
    return RedirectResponse(url=LOGIN_ROUTE)


@app.get(LOGIN_ROUTE, response_class=HTMLResponse, name="login")
def get_login(request: Request):
    logger.info("Login page requested.")
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("login.html", {"request": request, "site_key": RECAPTCHA_SITE_KEY, "flash": flash})


@app.get(SIGNUP_ROUTE, response_class=HTMLResponse, name="signup")
def get_signup(request: Request):
    logger.info("Signup page requested.")
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("signup.html", {"request": request, "flash": flash})


@app.post(SIGNUP_ROUTE)
async def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form(...)
):
    logger.info(f"Signup form submitted for email: {email}")
    if password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        logger.warning("Signup failed: Passwords do not match.")
        return RedirectResponse(url=SIGNUP_ROUTE, status_code=status.HTTP_302_FOUND)

    if users_collection.find_one({"email": email}):
        request.session["flash"] = "Email already registered."
        logger.warning(f"Signup failed: Email {email} already registered.")
        return RedirectResponse(url=SIGNUP_ROUTE, status_code=status.HTTP_302_FOUND)

    if role not in ["user", "admin"]:
        logger.warning(f"Invalid role '{role}' provided for signup. Defaulting to 'user'.")
        role = "user"

    password_hash = pwd_context.hash(password)
    try:
        users_collection.insert_one({
            "name": fullname,
            "email": email,
            "password_hash": password_hash,
            "role": role,
            "created_at": datetime.now(timezone.utc)
        })
        logger.info(f"Account created successfully for {email} with role {role}.")
        request.session["flash"] = "Account created successfully! Please log in."
    except Exception as e:
        logger.error(f"Database error during signup for {email}: {e}")
        request.session["flash"] = f"Error creating account: {str(e)}"

    return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)


@app.post(LOGIN_ROUTE)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    g_recaptcha_response: str = Form(alias="g-recaptcha-response")
):
    logger.info(f"Login attempt for username: {form_data.username}")

    recaptcha_verify_url = "https://www.google.com/recaptcha/api/siteverify"
    recaptcha_data = {"secret": RECAPTCHA_SECRET_KEY, "response": g_recaptcha_response}
    try:
        recaptcha_response = requests.post(recaptcha_verify_url, data=recaptcha_data)
        recaptcha_result = recaptcha_response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"reCAPTCHA API call failed: {e}")
        request.session["flash"] = "reCAPTCHA service unavailable."
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)

    if not recaptcha_result.get("success"):
        logger.warning("reCAPTCHA verification failed.")
        request.session["flash"] = "reCAPTCHA verification failed."
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)

    user = users_collection.find_one({"email": form_data.username})
    if not user or not pwd_context.verify(form_data.password, user["password_hash"]):
        logger.warning("Invalid credentials provided.")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials",
            "site_key": RECAPTCHA_SITE_KEY
        })

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username, "role": user.get("role", "user")},
        expires_delta=access_token_expires
    )

    logins_collection.insert_one({
        "email": form_data.username,
        "login_time": datetime.now(timezone.utc),
        "status": "success"
    })
    logger.info(f"Login successful for {form_data.username} with role {user.get('role', 'user')}.")

    redirect_url = ADMIN_DASHBOARD_ROUTE if user.get("role") == "admin" else DASHBOARD_ROUTE
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False, 
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    return response


@app.post("/token", response_model=Token)
async def login_for_api_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not pwd_context.verify(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username, "role": user.get("role", "user")},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get(DASHBOARD_ROUTE, response_class=HTMLResponse)
async def get_dashboard(request: Request, current_user: dict = Depends(get_current_active_user)):
    logger.info(f"Dashboard requested by {current_user['email']} (Role: {current_user['role']}).")
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "name": current_user["email"],
        "flash": flash,
        "role": current_user["role"]
    })


@app.get(ADMIN_DASHBOARD_ROUTE, response_class=HTMLResponse)
async def get_admin_dashboard(request: Request, current_user: dict = Depends(verify_admin)):
    logger.info(f"Admin dashboard requested by {current_user['email']}.")
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "name": current_user["email"],
        "flash": flash
    })


@app.get(CREATE_SHIPMENT_ROUTE, response_class=HTMLResponse)
async def get_create_shipment(request: Request, current_user: dict = Depends(get_current_active_user)):
    logger.info(f"Create shipment page requested by {current_user['email']}.")
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("create_shipment.html", {
        "request": request,
        "user_name": current_user["email"],
        "role": current_user["role"],
        "flash": flash
    })


@app.post(CREATE_SHIPMENT_ROUTE)
async def create_shipment(
    request: Request,
    current_user: dict = Depends(get_current_active_user)
):
    # Manually parse form data and validate with Pydantic model
    form_data = await request.form()
    try:
        shipment_data = ShipmentCreateData(
            shipment_id=form_data.get("shipment_id"),
            po_number=form_data.get("po_number"),
            route_details=form_data.get("route_details"),
            device=form_data.get("device"),
            ndc_number=form_data.get("ndc_number"),
            serial_number=form_data.get("serial_number"),
            container_number=form_data.get("container_number"),
            goods_type=form_data.get("goods_type"),
            expected_delivery_date=form_data.get("expected_delivery_date"),
            delivery_number=form_data.get("delivery_number"),
            batch_id=form_data.get("batch_id"),
            origin=form_data.get("origin"),
            destination=form_data.get("destination"),
            shipment_description=form_data.get("shipment_description")
        )
    except RequestValidationError as e:
        logger.error(f"Validation error during shipment creation: {e.errors()}")
        request.session["flash"] = f"Validation error: {e.errors()}"
        return RedirectResponse(url=CREATE_SHIPMENT_ROUTE, status_code=status.HTTP_302_FOUND)

    logger.info(f"Shipment creation submitted by {current_user['email']} for shipment ID: {shipment_data.shipment_id}.")
    if shipment_collection.find_one({"shipment_id": shipment_data.shipment_id}):
        request.session["flash"] = f"Shipment ID '{shipment_data.shipment_id}' already exists."
        logger.warning(f"Duplicate shipment ID: {shipment_data.shipment_id}.")
        return RedirectResponse(url=CREATE_SHIPMENT_ROUTE, status_code=status.HTTP_302_FOUND)

    shipment_dict = shipment_data.model_dump() # Pydantic v2
    shipment_dict["created_at"] = datetime.now(timezone.utc)
    shipment_dict["created_by"] = current_user["email"]
    
    try:
        shipment_collection.insert_one(shipment_dict)
        request.session["flash"] = f"Shipment {shipment_data.shipment_id} created successfully!"
        logger.info(f"Shipment {shipment_data.shipment_id} created successfully.")
    except Exception as e:
        logger.error(f"Error creating shipment {shipment_data.shipment_id}: {e}")
        request.session["flash"] = f"Error creating shipment: {str(e)}"
    return RedirectResponse(url=CREATE_SHIPMENT_ROUTE, status_code=status.HTTP_302_FOUND)


@app.get(USER_MANAGEMENT_ROUTE, response_class=HTMLResponse)
async def user_management(request: Request, current_user: dict = Depends(verify_admin)):
    logger.info(f"User management page requested by {current_user['email']}.")
    users_cursor = users_collection.find({}, {"_id": 0, "password_hash":0})
    users = []
    for user in users_cursor:
        if isinstance(user.get("created_at"), datetime):
             user["created_at"] = user["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
        users.append(user)

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("user_management.html", {"request": request, "users": users, "flash": flash})


@app.get("/edit-user/{email}", response_class=HTMLResponse)
async def edit_user(email: str, request: Request, current_user: dict = Depends(verify_admin)):
    logger.info(f"Editing user {email} requested by admin {current_user['email']}.")
    user = users_collection.find_one({"email": email}, {"_id": 0, "password_hash": 0})
    if not user:
        logger.error(f"User not found for editing: {email}")
        request.session["flash"] = "User not found."
        return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("edit_user.html", {"request": request, "user": user, "flash": flash})


@app.post("/update-user/{email}")
async def update_user(
    email: str,
    request: Request,
    current_user: dict = Depends(verify_admin),
    name: str = Form(...),
    new_email: str = Form(...),
    role: str = Form(...)
):
    logger.info(f"Admin {current_user['email']} updating user: {email} -> {new_email}.")
    if role not in ["user", "admin"]:
        role = "user"
    if email != new_email and users_collection.find_one({"email": new_email}):
        request.session["flash"] = "New email already exists for another user."
        return RedirectResponse(url=f"/edit-user/{email}", status_code=status.HTTP_303_SEE_OTHER)
    
    update_data = {
        "name": name,
        "email": new_email,
        "role": role,
        "updated_at": datetime.now(timezone.utc)
    }
    result = users_collection.update_one({"email": email}, {"$set": update_data})

    if result.modified_count > 0:
        request.session["flash"] = "User updated successfully."
        logger.info(f"User {email} updated to {new_email}.")
    else:
        request.session["flash"] = "No changes made or user not found."
        logger.warning(f"No update performed for user {email}.")
    return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/assign-admin/{email}")
async def assign_admin(email: str, request: Request, current_user: dict = Depends(verify_admin)):
    logger.info(f"Admin {current_user['email']} assigning admin role to {email}.")
    if email == current_user["email"]:
        request.session["flash"] = "You cannot change your own role."
        return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    
    result = users_collection.update_one(
        {"email": email},
        {"$set": {"role": "admin", "updated_at": datetime.now(timezone.utc)}}
    )
    if result.modified_count > 0:
        request.session["flash"] = f"User {email} promoted to admin successfully."
        logger.info(f"User {email} promoted to admin.")
    else:
        request.session["flash"] = "Failed to update user role or user not found."
        logger.warning(f"Admin assignment failed for user {email}.")
    return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/delete-user/{email}")
async def delete_user(email: str, request: Request, current_user: dict = Depends(verify_admin)):
    logger.info(f"Admin {current_user['email']} deleting user {email}.")
    if email == current_user["email"]:
        request.session["flash"] = "You cannot delete your own account."
        return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    try:
        result = users_collection.delete_one({"email": email})
        if result.deleted_count > 0:
            request.session["flash"] = f"User {email} deleted successfully."
            logger.info(f"User {email} deleted.")
        else:
            request.session["flash"] = f"User {email} not found."
            logger.warning(f"Delete attempted on non-existent user {email}.")
    except Exception as e:
        request.session["flash"] = f"Error deleting user: {str(e)}"
        logger.error(f"Error deleting user {email}: {e}")
    return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)


@app.get(EDIT_SHIPMENT_ROUTE, response_class=HTMLResponse)
async def get_edit_shipment(request: Request, current_user: dict = Depends(verify_admin)):
    logger.info(f"Edit shipment page requested by {current_user['email']}.")
    flash = request.session.pop("flash", None)
    shipments_cursor = shipment_collection.find({}, {"_id": 0})
    shipments = []
    for shipment in shipments_cursor:
        if isinstance(shipment.get("created_at"), datetime):
            shipment["created_at"] = shipment["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
        if isinstance(shipment.get("last_updated"), datetime):
            shipment["last_updated"] = shipment["last_updated"].strftime(DATETIME_DISPLAY_FORMAT)
        shipments.append(shipment)
    return templates.TemplateResponse("edit_shipment.html", {"request": request, "shipments": shipments, "flash": flash})


@app.post(EDIT_SHIPMENT_ROUTE)
async def post_edit_shipment(
    request: Request,
    current_user: dict = Depends(verify_admin),
    shipment_id: str = Form(...),
    status_value: str = Form(...),
    destination: str = Form(...),
    expected_delivery_date: str = Form(...)
):
    logger.info(f"Admin {current_user['email']} updating shipment {shipment_id}.")
    update_data = {
        "status": status_value,
        "destination": destination,
        "expected_delivery_date": expected_delivery_date,
        "last_updated": datetime.now(timezone.utc),
        "updated_by": current_user["email"]
    }
    result = shipment_collection.update_one(
        {"shipment_id": shipment_id},
        {"$set": update_data}
    )
    if result.modified_count > 0:
        request.session["flash"] = "Shipment updated successfully."
        logger.info(f"Shipment {shipment_id} updated successfully.")
    else:
        request.session["flash"] = "No changes made or shipment not found."
        logger.warning(f"No update performed for shipment {shipment_id}.")
    return RedirectResponse(url=EDIT_SHIPMENT_ROUTE, status_code=status.HTTP_302_FOUND)


@app.get("/delete-shipment/{shipment_id}")
async def delete_shipment(shipment_id: str, request: Request, current_user: dict = Depends(verify_admin)):
    logger.info(f"Admin {current_user['email']} deleting shipment {shipment_id}.")
    try:
        result = shipment_collection.delete_one({"shipment_id": shipment_id})
        if result.deleted_count > 0:
            request.session["flash"] = "Shipment deleted successfully."
            logger.info(f"Shipment {shipment_id} deleted.")
        else:
            request.session["flash"] = "Shipment not found or already deleted."
            logger.warning(f"Delete attempted on non-existent shipment {shipment_id}.")
    except Exception as e:
        request.session["flash"] = f"Error deleting shipment: {str(e)}"
        logger.error(f"Error deleting shipment {shipment_id}: {e}")
    return RedirectResponse(url=EDIT_SHIPMENT_ROUTE, status_code=status.HTTP_302_FOUND)


@app.get("/all-shipments", response_class=HTMLResponse)
async def get_all_shipments(request: Request, current_user: dict = Depends(get_current_active_user)):
    logger.info(f"All shipments page requested by {current_user['email']}.")
    shipments_cursor = shipment_collection.find({}, {"_id": 0})
    shipments = []
    for shipment in shipments_cursor:
        if isinstance(shipment.get("created_at"), datetime):
            shipment["created_at"] = shipment["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
        # Add other datetime fields if necessary
        shipments.append(shipment)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("all_shipments.html", {
        "request": request,
        "shipments": shipments,
        "role": current_user["role"],
        "flash": flash
    })


@app.get("/account", response_class=HTMLResponse)
async def account_page(request: Request, current_user: dict = Depends(get_current_active_user)):
    logger.info(f"Account page requested by {current_user['email']}.")
    user_data = users_collection.find_one({"email": current_user["email"]}, {"_id": 0, "name": 1, "email": 1, "role": 1, "created_at": 1})
    if not user_data:
        request.session["flash"] = "User data not found."
        logger.error(f"User data not found for {current_user['email']}.")
        return RedirectResponse(url=DASHBOARD_ROUTE, status_code=status.HTTP_302_FOUND)
    
    if isinstance(user_data.get("created_at"), datetime):
        user_data["created_at_str"] = user_data["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
    else:
        user_data["created_at_str"] = str(user_data.get("created_at", "N/A"))


    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("account.html", {"request": request, "user": user_data, "flash": flash})


@app.get("/logout")
async def logout(request: Request):
    logger.info("User logged out.")
    response = RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response


@app.get("/device-data", response_class=HTMLResponse)
async def get_device_data(
    request: Request,
    current_user: dict = Depends(get_current_active_user),
    device_id: Optional[str] = Query(None)
):
    logger.info(f"Device data page requested by {current_user['email']}.")
    try:
        device_ids_cursor = device_data_collection.distinct("Device_ID")
        device_ids = sorted([str(did) for did in device_ids_cursor])

        query_filter = {}
        if device_id:
            try:
                query_filter["Device_ID"] = int(device_id)
            except ValueError:
                query_filter["Device_ID"] = device_id

        devices_cursor = device_data_collection.find(query_filter, {"_id": 0}).sort("timestamp", -1).limit(50)
        
        devices = []
        for dev in devices_cursor:
            if isinstance(dev.get("timestamp"), datetime):
                dev["timestamp_str"] = dev["timestamp"].strftime("%Y-%m-%d %H:%M:%S") # This specific one doesn't need UTC suffix
            else:
                dev["timestamp_str"] = str(dev.get("timestamp", "N/A"))
            devices.append(dev)

        logger.info(f"Fetched records for Device ID: {device_id if device_id else 'all (latest)'}")
        
        flash = request.session.pop("flash", None)
        return templates.TemplateResponse("device_data.html", {
            "request": request,
            "devices": devices,
            "device_ids": device_ids,
            "selected_device_id": device_id if device_id else "",
            "flash": flash,
            "username": current_user["email"]
        })
    except Exception as e:
        logger.error(f"Error in device data route: {e}")
        request.session["flash"] = "Error fetching device data"
        return templates.TemplateResponse("device_data.html", {
            "request": request,
            "devices": [],
            "device_ids": [],
            "selected_device_id": "",
            "flash": "Error fetching device data",
            "username": current_user["email"]
        })


@app.get(FORGOT_PASSWORD_ROUTE, response_class=HTMLResponse)
def forgot_password(request: Request):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("forgot_password.html", {"request": request, "flash": flash})

@app.post(FORGOT_PASSWORD_ROUTE)
async def process_forgot_password(request: Request, email: str = Form(...)):
    user = users_collection.find_one({"email": email})
    if user:
        reset_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        users_collection.update_one(
            {"email": email},
            {"$set": {"reset_token": reset_token, "reset_token_expires_at": expires_at, "updated_at": datetime.now(timezone.utc)}}
        )
        
        reset_url = request.url_for('reset_password_get').include_query_params(token=reset_token)
        logger.info(f"Password reset requested for {email}. Token: {reset_token}. Reset URL (simulated): {reset_url}")

    request.session["flash"] = "If an account with that email exists, instructions to reset your password have been sent."
    return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)


@app.get(RESET_PASSWORD_ROUTE, response_class=HTMLResponse, name="reset_password_get")
def reset_password_get(request: Request, token: Optional[str] = Query(None)):
    flash = request.session.pop("flash", None)
    if not token:
        request.session["flash"] = "Invalid or missing password reset token."
        return RedirectResponse(url=FORGOT_PASSWORD_ROUTE, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("password_reset.html", {"request": request, "token": token, "flash": flash})


@app.post(RESET_PASSWORD_ROUTE)
async def reset_password_post(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    if new_password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        return RedirectResponse(url=f"{RESET_PASSWORD_ROUTE}?token={token}", status_code=status.HTTP_303_SEE_OTHER)
    
    user = users_collection.find_one({
        "reset_token": token,
        "reset_token_expires_at": {"$gt": datetime.now(timezone.utc)}
    })

    if user:
        hashed_password = pwd_context.hash(new_password)
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "password_hash": hashed_password, 
                "updated_at": datetime.now(timezone.utc),
                "reset_token": None,
                "reset_token_expires_at": None 
             }}
        )
        request.session["flash"] = "Password reset successful. Please log in with your new password."
        logger.info(f"Password reset successful for user {user['email']}.")
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    else:
        request.session["flash"] = "Invalid or expired password reset link. Please try again."
        logger.warning(f"Invalid or expired token used for password reset: {token}")
        return RedirectResponse(url=FORGOT_PASSWORD_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
