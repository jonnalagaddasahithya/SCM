# app/routes/auth_routes.py
import secrets
from fastapi import APIRouter, Request, Form, status, Depends, HTTPException, Response, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm # <--- THIS IS THE MISSING IMPORT!
from typing import Optional
from datetime import timedelta

from app.config import (
    LOGIN_ROUTE, SIGNUP_ROUTE, DASHBOARD_ROUTE, ADMIN_DASHBOARD_ROUTE,
    FORGOT_PASSWORD_ROUTE, RESET_PASSWORD_ROUTE, ACCESS_TOKEN_EXPIRE_MINUTES,
    logger, get_current_utc_time
)
from app.database import users_collection, logins_collection
from app.auth import pwd_context, create_access_token
from app.models import Token
from app.email_utils import send_verification_email, send_password_reset_email, verify_recaptcha

# Create an APIRouter instance for authentication-related routes
router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def root():
    logger.info(f"Root endpoint accessed, redirecting to {LOGIN_ROUTE}.")
    return RedirectResponse(url=LOGIN_ROUTE)

@router.get(LOGIN_ROUTE, response_class=HTMLResponse, name="login")
def get_login(request: Request):
    logger.info("Login page requested.")
    flash = request.session.pop("flash", None)
    from app.config import RECAPTCHA_SITE_KEY
    return request.app.state.templates.TemplateResponse(
        "login.html", {"request": request, "flash": flash, "site_key": RECAPTCHA_SITE_KEY}
    )


@router.get(SIGNUP_ROUTE, response_class=HTMLResponse, name="signup")
def get_signup(request: Request):
    logger.info("Signup page requested.")
    flash = request.session.pop("flash", None)
    from app.config import RECAPTCHA_SITE_KEY
    return request.app.state.templates.TemplateResponse(
        "signup.html", {"request": request, "flash": flash, "site_key": RECAPTCHA_SITE_KEY}
    )


@router.post(SIGNUP_ROUTE)
async def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
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

    assigned_role = "user"
    logger.info(f"Assigning default role '{assigned_role}' for new signup: {email}.")

    password_hash = pwd_context.hash(password)
    
    # Generate verification token and code
    verification_token = secrets.token_urlsafe(32)
    verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    try:
        users_collection.insert_one({
            "name": fullname,
            "email": email,
            "password_hash": password_hash,
            "role": assigned_role,
            "created_at": get_current_utc_time(),
            "is_verified": False,  # User is not verified initially
            "verification_token": verification_token,
            "verification_code": verification_code,
            "verification_token_expires_at": get_current_utc_time() + timedelta(hours=24)  # Token expires in 24 hours
        })
        logger.info(f"Account created successfully for {email} with role {assigned_role}. Verification token: {verification_token}")
        
        # Generate verification URL with localhost for testing
        verification_url = f"http://localhost:8000/verify-email?token={verification_token}"
        logger.info(f"Verification URL (for testing): {verification_url}")
        logger.info(f"Verification Code (for testing): {verification_code}")
        
        # Send verification email
        email_sent = send_verification_email(email, verification_url, verification_code)
        if email_sent:
            logger.info(f"Verification email sent to {email}")
            request.session["flash"] = "Account created successfully! Please check your email for verification instructions."
        else:
            logger.error(f"Failed to send verification email to {email}")
            request.session["flash"] = "Account created successfully, but we couldn't send the verification email. Please contact support."
    except Exception as e:
        logger.error(f"Database error during signup for {email}: {e}")
        request.session["flash"] = f"Error creating account: {str(e)}"

    return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)

@router.get("/verify-email", response_class=HTMLResponse, name="verify_email_get")
def verify_email_get(request: Request, token: Optional[str] = Query(None)):
    """Display the verification code to the user when they click the verification link"""
    logger.info("Email verification page requested.")
    
    if not token:
        request.session["flash"] = "Invalid or missing verification token."
        return RedirectResponse(url=SIGNUP_ROUTE, status_code=status.HTTP_302_FOUND)
    
    # Find user with this verification token
    user = users_collection.find_one({"verification_token": token})
    if not user:
        request.session["flash"] = "Invalid verification token."
        return RedirectResponse(url=SIGNUP_ROUTE, status_code=status.HTTP_302_FOUND)
    
    # Check if token has expired
    if user.get("verification_token_expires_at"):
        # Ensure both datetimes are timezone-aware for comparison
        expiry_time = user["verification_token_expires_at"]
        current_time = get_current_utc_time()
        
        # If expiry_time is naive, make it timezone-aware
        if expiry_time.tzinfo is None:
            from datetime import timezone
            expiry_time = expiry_time.replace(tzinfo=timezone.utc)
            
        if expiry_time < current_time:
            request.session["flash"] = "Verification token has expired."
            return RedirectResponse(url=SIGNUP_ROUTE, status_code=status.HTTP_302_FOUND)
    
    # If user is already verified, redirect to login
    if user.get("is_verified", False):
        request.session["flash"] = "Email already verified. Please log in."
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)
    
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse(
        "verify.html", {
            "request": request, 
            "verification_code": user["verification_code"],
            "flash": flash
        }
    )

@router.get("/verify-code", response_class=HTMLResponse)
def verify_code_get(request: Request):
    """Display the form for entering the verification code"""
    logger.info("Verify code page requested.")
    logger.info(f"Request URL: {request.url}")
    logger.info(f"Request method: {request.method}")
    flash = request.session.pop("flash", None)
    logger.info(f"Flash message: {flash}")
    return request.app.state.templates.TemplateResponse(
        "verify_code.html", {"request": request, "flash": flash}
    )

@router.post("/verify-code")
async def verify_code_post(request: Request, verification_code: str = Form(...)):
    """Process the verification code entered by the user"""
    logger.info(f"Verification code submitted: {verification_code}")
    
    # Find user with this verification code
    user = users_collection.find_one({"verification_code": verification_code.upper()})
    if not user:
        request.session["flash"] = "Invalid verification code. Please enter the correct code."
        return RedirectResponse(url="/verify-code", status_code=status.HTTP_302_FOUND)
    
    # Check if token has expired
    if user.get("verification_token_expires_at"):
        # Ensure both datetimes are timezone-aware for comparison
        expiry_time = user["verification_token_expires_at"]
        current_time = get_current_utc_time()
        
        # If expiry_time is naive, make it timezone-aware
        if expiry_time.tzinfo is None:
            from datetime import timezone
            expiry_time = expiry_time.replace(tzinfo=timezone.utc)
            
        if expiry_time < current_time:
            request.session["flash"] = "Verification code has expired. Please sign up again."
            return RedirectResponse(url=SIGNUP_ROUTE, status_code=status.HTTP_302_FOUND)
    
    # If user is already verified, redirect to login
    if user.get("is_verified", False):
        request.session["flash"] = "Email already verified. Please log in."
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)
    
    # Mark user as verified
    try:
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "is_verified": True,
                "verification_token": None,
                "verification_code": None,
                "verification_token_expires_at": None,
                "updated_at": get_current_utc_time()
            }}
        )
        logger.info(f"User {user['email']} successfully verified.")
        request.session["flash"] = "Email verified successfully! Please log in."
    except Exception as e:
        logger.error(f"Error updating verification status for {user['email']}: {e}")
        request.session["flash"] = "Error verifying email. Please try again."
        return RedirectResponse(url="/verify-code", status_code=status.HTTP_302_FOUND)
    
    return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)

@router.post("/token", response_model=Token)
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

@router.post(LOGIN_ROUTE) # <--- Re-adding the POST login route
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    recaptcha_response: str = Form(...),  # Add reCAPTCHA response parameter
):
    """
    Handles user login and sets an access token cookie.
    """
    logger.info(f"Login attempt for username: {form_data.username}")
    
    # Verify reCAPTCHA
    if not verify_recaptcha(recaptcha_response):
        logger.warning(f"reCAPTCHA verification failed for login attempt: {form_data.username}")
        return request.app.state.templates.TemplateResponse(
            "login.html", {
                "request": request,
                "error": "Please complete the reCAPTCHA verification."
            }
        )
    
    # Check if database is properly initialized
    if users_collection is None:
        logger.error("Database not initialized. Users collection is None.")
        return request.app.state.templates.TemplateResponse(
            "login.html", {
                "request": request,
                "error": "System error. Please contact administrator."
            }
        )
    
    # Find user in database
    user = users_collection.find_one({"email": form_data.username})
    logger.info(f"User lookup result: {user is not None}")
    
    if not user:
        logger.warning(f"User not found for email: {form_data.username}")
        return request.app.state.templates.TemplateResponse(
            "login.html", {
                "request": request,
                "error": "Invalid credentials"
            }
        )
    
    # Log user details for debugging (excluding sensitive info)
    logger.info(f"User found - Email: {user.get('email')}, Verified: {user.get('is_verified')}, Role: {user.get('role')}")
    
    # Check password
    password_valid = False
    try:
        password_valid = pwd_context.verify(form_data.password, user["password_hash"])
        logger.info(f"Password verification result: {password_valid}")
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return request.app.state.templates.TemplateResponse(
            "login.html", {
                "request": request,
                "error": "Invalid credentials"
            }
        )
    
    # Verify user existence and password
    if not password_valid:
        logger.warning(f"Invalid password for user: {form_data.username}")
        return request.app.state.templates.TemplateResponse(
            "login.html", {
                "request": request,
                "error": "Invalid credentials"
            }
        )

    # Check if user's email is verified
    if not user.get("is_verified", False):
        logger.warning(f"Login attempt for unverified user: {form_data.username}")
        return request.app.state.templates.TemplateResponse(
            "login.html", {
                "request": request,
                "error": "Please verify your email address before logging in."
            }
        )

    # Create an access token for the user
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username, "role": user.get("role", "user")},
        expires_delta=access_token_expires
    )

    # Log the successful login attempt
    logins_collection.insert_one({
        "email": form_data.username,
        "login_time": get_current_utc_time(),
        "status": "success"
    })
    logger.info(f"Login successful for {form_data.username} with role {user.get('role', 'user')}.")

    # Redirect based on user role (case-insensitive comparison)
    user_role = user.get("role", "user")
    redirect_url = ADMIN_DASHBOARD_ROUTE if str(user_role).lower() == "admin" else DASHBOARD_ROUTE
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
    
    # Set the access token as an HTTP-only cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False, # Set to True in production with HTTPS
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60, # max_age in seconds
        path="/"
    )
    return response


@router.get(FORGOT_PASSWORD_ROUTE, response_class=HTMLResponse)
def forgot_password(request: Request):
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse("forgot_password.html", {"request": request, "flash": flash})

@router.post(FORGOT_PASSWORD_ROUTE)
async def process_forgot_password(request: Request, email: str = Form(...)):
    user = users_collection.find_one({"email": email})
    if user:
        reset_token = secrets.token_urlsafe(32)
        expires_at = get_current_utc_time() + timedelta(hours=1)
        users_collection.update_one(
            {"email": email},
            {"$set": {"reset_token": reset_token, "reset_token_expires_at": expires_at, "updated_at": get_current_utc_time()}}
        )
        # reset_url = request.url_for('reset_password_get').include_query_params(token=reset_token)
        reset_url = f"http://localhost:8000/reset-password?token={reset_token}"
        logger.info(f"Password reset requested for {email}. Token: {reset_token}. Reset URL (simulated): {reset_url}")
        
        # TODO: In a real application, you would send an email here with the reset link
        # For now, we'll just log it with localhost URL for testing
        logger.info(f"Password reset URL (for testing): {reset_url}")
        
        # Send password reset email
        email_sent = send_password_reset_email(email, reset_url)
        if email_sent:
            logger.info(f"Password reset email sent to {email}")
        else:
            logger.error(f"Failed to send password reset email to {email}")
    request.session["flash"] = "If an account with that email exists, instructions to reset your password have been sent."
    return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)

@router.get(RESET_PASSWORD_ROUTE, response_class=HTMLResponse, name="reset_password_get")
def reset_password_get(request: Request, token: Optional[str] = Query(None)):
    flash = request.session.pop("flash", None)
    if not token:
        request.session["flash"] = "Invalid or missing password reset token."
        return RedirectResponse(url=FORGOT_PASSWORD_ROUTE, status_code=status.HTTP_302_FOUND)
    
    # Find user with this reset token
    user = users_collection.find_one({
        "reset_token": token,
        "reset_token_expires_at": {"$gt": get_current_utc_time()}
    })
    
    # Check if token has expired
    if user and user.get("reset_token_expires_at"):
        # Ensure both datetimes are timezone-aware for comparison
        expiry_time = user["reset_token_expires_at"]
        current_time = get_current_utc_time()
        
        # If expiry_time is naive, make it timezone-aware
        if expiry_time.tzinfo is None:
            from datetime import timezone
            expiry_time = expiry_time.replace(tzinfo=timezone.utc)
            
        if expiry_time < current_time:
            request.session["flash"] = "Password reset token has expired."
            return RedirectResponse(url=FORGOT_PASSWORD_ROUTE, status_code=status.HTTP_302_FOUND)
    
    if not user:
        request.session["flash"] = "Invalid or expired password reset token."
        return RedirectResponse(url=FORGOT_PASSWORD_ROUTE, status_code=status.HTTP_302_FOUND)
    return request.app.state.templates.TemplateResponse("password_reset.html", {"request": request, "token": token, "flash": flash})

@router.post(RESET_PASSWORD_ROUTE)
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
        "reset_token_expires_at": {"$gt": get_current_utc_time()}
    })
    if user:
        hashed_password = pwd_context.hash(new_password)
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "password_hash": hashed_password,
                "updated_at": get_current_utc_time(),
                "reset_token": None,
                "reset_token_expires_at": None
            }}
        )
        request.session["flash"] = "Password reset successful. Please log in with your new password."
    else:
        request.session["flash"] = "Invalid or expired password reset token."
        logger.warning(f"Invalid or expired reset token received: {token}")
    return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)


@router.get("/login/google", name="login_google")
async def login_via_google(request: Request):
    """
    Redirects the user to Google's authentication page.
    """
    # The redirect_uri must match what you've configured in Google Cloud Console
    redirect_uri = request.url_for('auth_google')
    logger.info(f"Redirecting to Google for SSO. Callback URL: {redirect_uri}")
    return await request.app.state.oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/auth/google", name="auth_google")
async def auth_via_google(request: Request):
    """
    Callback endpoint for Google SSO. Handles token exchange and user session.
    """
    try:
        token = await request.app.state.oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        logger.info(f"Google SSO callback successful. User info: {user_info.get('email')}")

        if user_info:
            email = user_info.get('email')
            user = users_collection.find_one({"email": email})

            if not user:
                logger.info(f"User {email} not found. Creating new SSO user.")
                # If user does not exist, create a new one
                users_collection.insert_one({
                    "name": user_info.get('name'),
                    "email": email,
                    "password_hash": None,  # No password for SSO users
                    "role": "user", # Default role
                    "created_at": get_current_utc_time(),
                    "is_verified": True, # SSO users are considered verified
                    "is_sso_user": True
                })
                user = users_collection.find_one({"email": email})

            # Create a session for the user
            access_token = create_access_token(data={"sub": user['email'], "role": user.get("role", "user")})
            response = RedirectResponse(url=DASHBOARD_ROUTE, status_code=status.HTTP_302_FOUND)
            response.set_cookie(key="access_token", value=access_token, httponly=True)
            return response

    except Exception as e:
        logger.error(f"Error during Google SSO auth callback: {e}")
        request.session["flash"] = "An error occurred during Google login. Please try again."
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)

