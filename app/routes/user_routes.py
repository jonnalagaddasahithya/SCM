# app/routes/user_routes.py
from fastapi import APIRouter, Request, Form, status, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from datetime import datetime # Ensure datetime is imported here

from app.config import (
    DASHBOARD_ROUTE, ADMIN_DASHBOARD_ROUTE, USER_MANAGEMENT_ROUTE,
    DATETIME_DISPLAY_FORMAT, logger, get_current_utc_time
)
from app.database import users_collection
from app.auth import get_current_active_user, verify_admin

# Create an APIRouter instance for user-related routes
router = APIRouter() # <--- THIS LINE IS CRUCIAL FOR EXPORTING THE ROUTER

@router.get(DASHBOARD_ROUTE, response_class=HTMLResponse)
async def get_dashboard(request: Request, current_user: dict = Depends(get_current_active_user)):
    """
    Renders the user dashboard page.
    Requires an active authenticated user.
    """
    logger.info(f"Dashboard requested by {current_user['email']} (Role: {current_user['role']}).")
    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "dashboard.html", {
            "request": request,
            "name": current_user["email"],
            "flash": flash,
            "role": current_user["role"]
        }
    )

@router.get(ADMIN_DASHBOARD_ROUTE, response_class=HTMLResponse)
async def get_admin_dashboard(request: Request, current_user: dict = Depends(verify_admin)):
    """
    Renders the admin dashboard page.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin dashboard requested by {current_user['email']}.")
    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "admin_dashboard.html", {
            "request": request,
            "name": current_user["email"],
            "flash": flash
        }
    )

@router.get(USER_MANAGEMENT_ROUTE, response_class=HTMLResponse)
async def user_management(request: Request, current_user: dict = Depends(verify_admin)):
    """
    Renders the user management page for admins, listing all users.
    Requires an active authenticated admin user.
    """
    logger.info(f"User management page requested by {current_user['email']}.")
    # Fetch all users, excluding sensitive fields like _id and password_hash
    users_cursor = users_collection.find({}, {"_id": 0, "password_hash":0})
    users = []
    for user in users_cursor:
        # Format 'created_at' datetime objects for display
        if isinstance(user.get("created_at"), datetime):
            user["created_at"] = user["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
        users.append(user)

    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "user_management.html", {"request": request, "users": users, "flash": flash}
    )

@router.get("/edit-user/{email}", response_class=HTMLResponse)
async def edit_user(email: str, request: Request, current_user: dict = Depends(verify_admin)):
    """
    Renders the edit user page for a specific user.
    Requires an active authenticated admin user.
    """
    logger.info(f"Editing user {email} requested by admin {current_user['email']}.")
    # Find the user to be edited, excluding sensitive fields
    user = users_collection.find_one({"email": email}, {"_id": 0, "password_hash": 0})
    if not user:
        logger.error(f"User not found for editing: {email}")
        request.session["flash"] = "User not found."
        return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "edit_user.html", {"request": request, "user": user, "flash": flash}
    )

@router.post("/update-user/{email}")
async def update_user(
    email: str,
    request: Request,
    current_user: dict = Depends(verify_admin),
    name: str = Form(...),
    new_email: str = Form(...),
    role: str = Form(...)
):
    """
    Handles updating user information by an admin.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin {current_user['email']} updating user: {email} -> {new_email}.")
    # Validate role, default to 'user' if invalid
    if role not in ["user", "admin"]:
        role = "user"
    
    # Check if the new email already exists for another user
    if email != new_email and users_collection.find_one({"email": new_email}):
        request.session["flash"] = "New email already exists for another user."
        return RedirectResponse(url=f"/edit-user/{email}", status_code=status.HTTP_303_SEE_OTHER)
    
    # Prepare update data
    update_data = {
        "name": name,
        "email": new_email,
        "role": role,
        "updated_at": get_current_utc_time()
    }
    
    # Update the user document in MongoDB
    result = users_collection.update_one({"email": email}, {"$set": update_data})

    if result.modified_count > 0:
        request.session["flash"] = "User updated successfully."
        logger.info(f"User {email} updated to {new_email}.")
    else:
        request.session["flash"] = "No changes made or user not found."
        logger.warning(f"No update performed for user {email}.")
    return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)

@router.get("/assign-admin/{email}")
async def assign_admin(email: str, request: Request, current_user: dict = Depends(verify_admin)):
    """
    Assigns the 'admin' role to a specified user.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin {current_user['email']} assigning admin role to {email}.")
    # Prevent an admin from changing their own role via this endpoint
    if email == current_user["email"]:
        request.session["flash"] = "You cannot change your own role."
        return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    
    # Update the user's role to 'admin'
    result = users_collection.update_one(
        {"email": email},
        {"$set": {"role": "admin", "updated_at": get_current_utc_time()}}
    )
    if result.modified_count > 0:
        request.session["flash"] = f"User {email} promoted to admin successfully."
        logger.info(f"User {email} promoted to admin.")
    else:
        request.session["flash"] = "Failed to update user role or user not found."
        logger.warning(f"Admin assignment failed for user {email}.")
    return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)

@router.get("/delete-user/{email}")
async def delete_user(email: str, request: Request, current_user: dict = Depends(verify_admin)):
    """
    Deletes a specified user account.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin {current_user['email']} deleting user {email}.")
    # Prevent an admin from deleting their own account
    if email == current_user["email"]:
        request.session["flash"] = "You cannot delete your own account."
        return RedirectResponse(url=USER_MANAGEMENT_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    try:
        # Delete the user document from MongoDB
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

@router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request, current_user: dict = Depends(get_current_active_user)):
    """
    Renders the user's account details page.
    Requires an active authenticated user.
    """
    logger.info(f"Account page requested by {current_user['email']}.")
    # Fetch user data, excluding sensitive fields
    user_data = users_collection.find_one(
        {"email": current_user["email"]},
        {"_id": 0, "name": 1, "email": 1, "role": 1, "created_at": 1}
    )
    if not user_data:
        request.session["flash"] = "User data not found."
        logger.error(f"User data not found for {current_user['email']}.")
        return RedirectResponse(url=DASHBOARD_ROUTE, status_code=status.HTTP_302_FOUND)
    
    # Format 'created_at' for display
    if isinstance(user_data.get("created_at"), datetime):
        user_data["created_at_str"] = user_data["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
    else:
        user_data["created_at_str"] = str(user_data.get("created_at", "N/A"))

    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "account.html", {"request": request, "user": user_data, "flash": flash}
    )

@router.get("/logout")
async def logout(request: Request):
    """
    Handles user logout by deleting the access token cookie.
    """
    logger.info("User logged out.")
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND) # Redirect to login page
    response.delete_cookie("access_token") # Delete the access token cookie
    return response

