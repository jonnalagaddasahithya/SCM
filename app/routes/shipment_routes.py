# app/routes/shipment_routes.py
from fastapi import APIRouter, Request, Form, status, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import ValidationError as RequestValidationError
from datetime import datetime # Ensure datetime is imported here

from app.config import (
    CREATE_SHIPMENT_ROUTE, EDIT_SHIPMENT_ROUTE,
    DATETIME_DISPLAY_FORMAT, logger, get_current_utc_time
)
from app.database import shipment_collection
from app.auth import get_current_active_user, verify_admin
from app.models import ShipmentCreateData # Import the Pydantic model

# Create an APIRouter instance for shipment-related routes
router = APIRouter() # <--- THIS LINE IS CRUCIAL FOR EXPORTING THE ROUTER

@router.get(CREATE_SHIPMENT_ROUTE, response_class=HTMLResponse)
async def get_create_shipment(request: Request, current_user: dict = Depends(get_current_active_user)):
    """
    Renders the page for creating a new shipment.
    Requires an active authenticated user.
    """
    logger.info(f"Create shipment page requested by {current_user['email']}.")
    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "create_shipment.html", {
            "request": request,
            "user_name": current_user["email"],
            "role": current_user["role"],
            "flash": flash
        }
    )

@router.post(CREATE_SHIPMENT_ROUTE)
async def create_shipment(
    request: Request,
    current_user: dict = Depends(get_current_active_user)
):
    """
    Handles the submission for creating a new shipment.
    Requires an active authenticated user.
    """
    # Manually parse form data and validate with Pydantic model
    form_data = await request.form()
    try:
        # Create a ShipmentCreateData instance from form data for validation
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
    
    # Check for duplicate shipment ID
    if shipment_collection.find_one({"shipment_id": shipment_data.shipment_id}):
        request.session["flash"] = f"Shipment ID '{shipment_data.shipment_id}' already exists."
        logger.warning(f"Duplicate shipment ID: {shipment_data.shipment_id}.")
        return RedirectResponse(url=CREATE_SHIPMENT_ROUTE, status_code=status.HTTP_302_FOUND)

    shipment_dict = shipment_data.model_dump() # Convert Pydantic model to dictionary (Pydantic v2)
    shipment_dict["created_at"] = get_current_utc_time() # Add creation timestamp
    shipment_dict["created_by"] = current_user["email"] # Record who created the shipment
    
    try:
        # Insert the new shipment into the database
        shipment_collection.insert_one(shipment_dict)
        request.session["flash"] = f"Shipment {shipment_data.shipment_id} created successfully!"
        logger.info(f"Shipment {shipment_data.shipment_id} created successfully.")
    except Exception as e:
        logger.error(f"Error creating shipment {shipment_data.shipment_id}: {e}")
        request.session["flash"] = f"Error creating shipment: {str(e)}"
    return RedirectResponse(url=CREATE_SHIPMENT_ROUTE, status_code=status.HTTP_302_FOUND)


@router.get(EDIT_SHIPMENT_ROUTE, response_class=HTMLResponse)
async def get_edit_shipment(request: Request, current_user: dict = Depends(verify_admin)):
    """
    Renders the page for editing existing shipments.
    Requires an active authenticated admin user.
    """
    logger.info(f"Edit shipment page requested by {current_user['email']}.")
    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    
    # Fetch all shipments, excluding the MongoDB internal _id
    shipments_cursor = shipment_collection.find({}, {"_id": 0})
    shipments = []
    for shipment in shipments_cursor:
        # Format datetime fields for display
        if isinstance(shipment.get("created_at"), datetime):
            shipment["created_at"] = shipment["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
        if isinstance(shipment.get("last_updated"), datetime):
            shipment["last_updated"] = shipment["last_updated"].strftime(DATETIME_DISPLAY_FORMAT)
        shipments.append(shipment)
    
    return request.app.state.templates.TemplateResponse(
        "edit_shipment.html", {"request": request, "shipments": shipments, "flash": flash}
    )

@router.post(EDIT_SHIPMENT_ROUTE)
async def post_edit_shipment(
    request: Request,
    current_user: dict = Depends(verify_admin),
    shipment_id: str = Form(...),
    status_value: str = Form(...),
    destination: str = Form(...),
    expected_delivery_date: str = Form(...)
):
    """
    Handles the submission for updating an existing shipment.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin {current_user['email']} updating shipment {shipment_id}.")
    
    # Prepare update data
    update_data = {
        "status": status_value,
        "destination": destination,
        "expected_delivery_date": expected_delivery_date,
        "last_updated": get_current_utc_time(), # Update timestamp
        "updated_by": current_user["email"] # Record who updated the shipment
    }
    
    # Update the shipment document in MongoDB
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


@router.get("/delete-shipment/{shipment_id}")
async def delete_shipment(shipment_id: str, request: Request, current_user: dict = Depends(verify_admin)):
    """
    Deletes a specified shipment.
    Requires an active authenticated admin user.
    """
    logger.info(f"Admin {current_user['email']} deleting shipment {shipment_id}.")
    try:
        # Delete the shipment document from MongoDB
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


@router.get("/all-shipments", response_class=HTMLResponse)
async def get_all_shipments(request: Request, current_user: dict = Depends(get_current_active_user)):
    """
    Renders a page displaying all shipments.
    Requires an active authenticated user.
    """
    logger.info(f"All shipments page requested by {current_user['email']}.")
    
    # Fetch all shipments, excluding the MongoDB internal _id
    shipments_cursor = shipment_collection.find({}, {"_id": 0})
    shipments = []
    for shipment in shipments_cursor:
        # Format 'created_at' datetime for display
        if isinstance(shipment.get("created_at"), datetime):
            shipment["created_at"] = shipment["created_at"].strftime(DATETIME_DISPLAY_FORMAT)
        # Add other datetime fields if necessary (e.g., 'last_updated')
        if isinstance(shipment.get("last_updated"), datetime):
            shipment["last_updated"] = shipment["last_updated"].strftime(DATETIME_DISPLAY_FORMAT)
        shipments.append(shipment)
    
    flash = request.session.pop("flash", None) # Retrieve and clear flash messages
    return request.app.state.templates.TemplateResponse(
        "all_shipments.html", {
            "request": request,
            "shipments": shipments,
            "role": current_user["role"],
            "flash": flash
        }
    )

