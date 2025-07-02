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
    RECAPTCHA_SITE_KEY, logger, get_current_utc_time
)
from app.database import users_collection, logins_collection
from app.auth import pwd_context, create_access_token
from app.models import Token

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
    return request.app.state.templates.TemplateResponse(
        "login.html", {"request": request, "site_key": RECAPTCHA_SITE_KEY, "flash": flash}
    )

@router.get(SIGNUP_ROUTE, response_class=HTMLResponse, name="signup")
def get_signup(request: Request):
    logger.info("Signup page requested.")
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse(
        "signup.html", {"request": request, "flash": flash}
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
    try:
        users_collection.insert_one({
            "name": fullname,
            "email": email,
            "password_hash": password_hash,
            "role": assigned_role,
            "created_at": get_current_utc_time()
        })
        logger.info(f"Account created successfully for {email} with role {assigned_role}.")
        request.session["flash"] = "Account created successfully! Please log in."
    except Exception as e:
        logger.error(f"Database error during signup for {email}: {e}")
        request.session["flash"] = f"Error creating account: {str(e)}"

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
):
    """
    Handles user login and sets an access token cookie.
    """
    logger.info(f"Login attempt for username: {form_data.username}")

    user = users_collection.find_one({"email": form_data.username})
    # Verify user existence and password
    if not user or not pwd_context.verify(form_data.password, user["password_hash"]):
        logger.warning("Invalid credentials provided.")
        return request.app.state.templates.TemplateResponse(
            "login.html", {
                "request": request,
                "error": "Invalid credentials",
                "site_key": RECAPTCHA_SITE_KEY
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

    # Redirect based on user role
    redirect_url = ADMIN_DASHBOARD_ROUTE if user.get("role") == "admin" else DASHBOARD_ROUTE
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
        reset_url = request.url_for('reset_password_get').include_query_params(token=reset_token)
        logger.info(f"Password reset requested for {email}. Token: {reset_token}. Reset URL (simulated): {reset_url}")
    request.session["flash"] = "If an account with that email exists, instructions to reset your password have been sent."
    return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_302_FOUND)

@router.get(RESET_PASSWORD_ROUTE, response_class=HTMLResponse, name="reset_password_get")
def reset_password_get(request: Request, token: Optional[str] = Query(None)):
    flash = request.session.pop("flash", None)
    if not token:
        request.session["flash"] = "Invalid or missing password reset token."
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

