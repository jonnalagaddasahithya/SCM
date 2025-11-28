# app/routes/user_routes.py
from fastapi import APIRouter, Request, Form, status, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from datetime import datetime # Ensure datetime is imported here

from app.config import (
    DASHBOARD_ROUTE, ADMIN_DASHBOARD_ROUTE, USER_MANAGEMENT_ROUTE,
    DATETIME_DISPLAY_FORMAT, logger, get_current_utc_time
)
from app.database import users_collection, admin_requests_collection
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
    
    # Count pending admin requests
    pending_requests_count = 0
    try:
        pending_requests_count = admin_requests_collection.count_documents({"status": "pending"})
    except Exception as e:
        logger.error(f"Error counting pending admin requests: {e}")
    
    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "admin_dashboard.html", {
            "request": request,
            "name": current_user["email"],
            "flash": flash,
            "pending_requests_count": pending_requests_count
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
    
    # Check if admin is changing their own role to user
    is_self_demotion = (email == current_user["email"] and role == "user")
    
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
        if is_self_demotion:
            request.session["flash"] = "You are a user now."
            logger.info(f"Admin {email} demoted themselves to user.")
            # Clear the session and redirect to login
            response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
            response.delete_cookie("access_token")
            return response
        else:
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


@router.get("/request-admin", response_class=HTMLResponse)
async def request_admin_form(request: Request, current_user: dict = Depends(get_current_active_user)):
    """
    Renders the admin access request form.
    Requires an active authenticated user.
    """
    logger.info(f"Admin access request form requested by {current_user['email']}.")
    
    # Check if user is already an admin
    if current_user.get("role") == "admin":
        request.session["flash"] = "You are already an administrator."
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)
    
    # Check if user already has a pending request
    existing_request = admin_requests_collection.find_one({
        "user_email": current_user["email"],
        "status": "pending"
    })
    
    if existing_request:
        request.session["flash"] = "You already have a pending admin access request."
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)
    
    # Fetch user data for the form
    user_data = users_collection.find_one(
        {"email": current_user["email"]},
        {"_id": 0, "name": 1, "email": 1}
    )
    
    if not user_data:
        request.session["flash"] = "User data not found."
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)
    
    flash = request.session.pop("flash", None)
    return request.app.state.templates.TemplateResponse(
        "request_admin.html", {"request": request, "user": user_data, "flash": flash}
    )


@router.post("/request-admin", response_class=HTMLResponse)
async def submit_admin_request(
    request: Request, 
    reason: str = Form(None),
    current_user: dict = Depends(get_current_active_user)
):
    """
    Handles submission of admin access request.
    Requires an active authenticated user.
    """
    logger.info(f"Admin access request submitted by {current_user['email']}.")
    
    # Check if user is already an admin
    if current_user.get("role") == "admin":
        request.session["flash"] = "You are already an administrator."
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)
    
    # Check if user already has a pending request
    existing_request = admin_requests_collection.find_one({
        "user_email": current_user["email"],
        "status": "pending"
    })
    
    if existing_request:
        request.session["flash"] = "You already have a pending admin access request."
        return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)
    
    # Create admin request record
    admin_request = {
        "user_name": current_user["name"],
        "user_email": current_user["email"],
        "reason": reason or "",
        "status": "pending",
        "requested_at": get_current_utc_time(),
        "processed_at": None,
        "processed_by": None,
        "processed_by_name": None,
        "decision_notes": None
    }
    
    try:
        # Insert the request into the database
        result = admin_requests_collection.insert_one(admin_request)
        if result.inserted_id:
            request.session["flash"] = "Your admin access request has been submitted successfully. Administrators will review your request."
            logger.info(f"Admin access request submitted for {current_user['email']}.")
        else:
            request.session["flash"] = "Failed to submit your request. Please try again."
            logger.error(f"Failed to insert admin request for {current_user['email']}.")
    except Exception as e:
        request.session["flash"] = "An error occurred while submitting your request. Please try again."
        logger.error(f"Error submitting admin request for {current_user['email']}: {e}")
    
    return RedirectResponse(url="/account", status_code=status.HTTP_302_FOUND)


@router.get("/logout")
async def logout(request: Request):
    """
    Handles user logout by deleting the access token cookie.
    """
    logger.info("User logged out.")
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND) # Redirect to login page
    response.delete_cookie("access_token") # Delete the access token cookie
    return response

@router.get("/admin-requests", response_class=HTMLResponse)
async def admin_requests_page(request: Request, current_user: dict = Depends(verify_admin)):
    """
    Renders the admin requests page, listing all pending and processed requests.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin requests page requested by {current_user['email']}.")
    
    try:
        # Fetch all admin requests, sorted by request date (newest first)
        requests_cursor = admin_requests_collection.find({}).sort("requested_at", -1)
        admin_requests = []
        
        for req in requests_cursor:
            # Format datetime objects for display
            if isinstance(req.get("requested_at"), datetime):
                req["requested_at_str"] = req["requested_at"].strftime(DATETIME_DISPLAY_FORMAT)
            else:
                req["requested_at_str"] = str(req.get("requested_at", "N/A"))
                
            if isinstance(req.get("processed_at"), datetime):
                req["processed_at_str"] = req["processed_at"].strftime(DATETIME_DISPLAY_FORMAT)
            else:
                req["processed_at_str"] = str(req.get("processed_at", "N/A"))
            
            admin_requests.append(req)
        
        flash = request.session.pop("flash", None)
        return request.app.state.templates.TemplateResponse(
            "admin_requests.html", {
                "request": request,
                "admin_requests": admin_requests,
                "flash": flash
            }
        )
    except Exception as e:
        logger.error(f"Error fetching admin requests: {e}")
        request.session["flash"] = "Error loading admin requests."
        return RedirectResponse(url=ADMIN_DASHBOARD_ROUTE, status_code=status.HTTP_302_FOUND)

@router.post("/admin-requests/{request_id}/approve", response_class=HTMLResponse)
async def approve_admin_request(request: Request, request_id: str, current_user: dict = Depends(verify_admin)):
    """
    Approves an admin access request.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin request approval attempted by {current_user['email']} for request {request_id}.")
    
    try:
        # Validate ObjectId format
        from bson import ObjectId
        try:
            obj_id = ObjectId(request_id)
        except Exception:
            request.session["flash"] = "Invalid request ID."
            return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)
        
        # Atomically update the request status to approved only if it's still pending
        update_result = admin_requests_collection.update_one(
            {"_id": obj_id, "status": "pending"},
            {
                "$set": {
                    "status": "approved",
                    "processed_at": datetime.utcnow(),
                    "processed_by": current_user["email"],
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Check if the update was successful (document was found and updated)
        if update_result.matched_count == 0:
            # Check if request exists but is already processed
            admin_request = admin_requests_collection.find_one({"_id": obj_id})
            if admin_request and admin_request.get("status") != "pending":
                request.session["flash"] = "This request has already been processed."
                return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)
            else:
                request.session["flash"] = "Admin request not found."
                return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)
        
        # Get the request details for further processing
        admin_request = admin_requests_collection.find_one({"_id": obj_id})
        
        # Update the user's role to admin
        users_collection.update_one(
            {"email": admin_request["user_email"]},
            {"$set": {"role": "admin"}}
        )
        
        # Log audit event
        from app.config import log_audit_event
        log_audit_event(
            action="ADMIN_REQUEST_APPROVED",
            actor=current_user["email"],
            target=admin_request["user_email"],
            details={"request_id": request_id}
        )
        
        # Send approval email notification to the user
        from app.email_utils import send_admin_request_approved_email
        email_sent = send_admin_request_approved_email(admin_request["user_email"])
        if email_sent:
            logger.info(f"Admin request approval email sent to {admin_request['user_email']}")
        else:
            logger.error(f"Failed to send admin request approval email to {admin_request['user_email']}")
        
        request.session["flash"] = f"Admin request for {admin_request['user_email']} has been approved."
        logger.info(f"Admin request for {admin_request['user_email']} approved by {current_user['email']}.")
        
    except Exception as e:
        logger.error(f"Error approving admin request {request_id}: {e}")
        request.session["flash"] = "An error occurred while processing the request."
    
    return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)


@router.post("/admin-requests/{request_id}/reject", response_class=HTMLResponse)
async def reject_admin_request(request: Request, request_id: str, current_user: dict = Depends(verify_admin)):
    """
    Rejects an admin access request.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin request rejection attempted by {current_user['email']} for request {request_id}.")
    
    try:
        # Validate ObjectId format
        from bson import ObjectId
        try:
            obj_id = ObjectId(request_id)
        except Exception:
            request.session["flash"] = "Invalid request ID."
            return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)
        
        # Atomically update the request status to rejected only if it's still pending
        update_result = admin_requests_collection.update_one(
            {"_id": obj_id, "status": "pending"},
            {
                "$set": {
                    "status": "rejected",
                    "processed_at": datetime.utcnow(),
                    "processed_by": current_user["email"],
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Check if the update was successful (document was found and updated)
        if update_result.matched_count == 0:
            # Check if request exists but is already processed
            admin_request = admin_requests_collection.find_one({"_id": obj_id})
            if admin_request and admin_request.get("status") != "pending":
                request.session["flash"] = "This request has already been processed."
                return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)
            else:
                request.session["flash"] = "Admin request not found."
                return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)
        
        # Get the request details for further processing
        admin_request = admin_requests_collection.find_one({"_id": obj_id})
        
        # Log audit event
        from app.config import log_audit_event
        log_audit_event(
            action="ADMIN_REQUEST_REJECTED",
            actor=current_user["email"],
            target=admin_request["user_email"],
            details={"request_id": request_id}
        )
        
        # Send rejection email notification to the user
        from app.email_utils import send_admin_request_rejected_email
        email_sent = send_admin_request_rejected_email(admin_request["user_email"])
        if email_sent:
            logger.info(f"Admin request rejection email sent to {admin_request['user_email']}")
        else:
            logger.error(f"Failed to send admin request rejection email to {admin_request['user_email']}")
        
        request.session["flash"] = f"Admin request for {admin_request['user_email']} has been rejected."
        logger.info(f"Admin request for {admin_request['user_email']} rejected by {current_user['email']}.")
        
    except Exception as e:
        logger.error(f"Error rejecting admin request {request_id}: {e}")
        request.session["flash"] = "An error occurred while processing the request."
    
    return RedirectResponse(url="/admin-requests", status_code=status.HTTP_302_FOUND)
