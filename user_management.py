from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os
 
# Load .env variables
load_dotenv()
 
router = APIRouter()
templates = Jinja2Templates(directory="templates")
 
 
client = MongoClient(os.getenv("MONGO_URI"))
db = client['scmexpert']
users_collection = db['user']
 
@router.get("/Manageusers")
async def manage_users(request: Request):
    users = list(users_collection.find())
 
    for user in users:
        user['_id'] = str(user['_id'])
 
 
    return templates.TemplateResponse("user_management.html", {
        "request": request,
        "users": users
    })
 