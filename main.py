import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
from bson import ObjectId

from database import db

# App setup
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth setup
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Models
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    email: Optional[str] = None

class AdminCreate(BaseModel):
    email: EmailStr
    password: str

class AdminInDB(BaseModel):
    email: EmailStr
    password_hash: str
    role: str = "admin"
    is_active: bool = True

class MediaItemIn(BaseModel):
    title: str
    description: Optional[str] = None
    media_type: str = Field(..., pattern="^(photo|video)$")
    url: str
    tags: Optional[List[str]] = None
    is_published: bool = True

class MediaItemOut(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    media_type: str
    url: str
    tags: Optional[List[str]] = None
    is_published: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

# Helpers

def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password[:72], password_hash)


def get_password_hash(password: str) -> str:
    # bcrypt safely handles up to 72 bytes; ensure no surprises with unicode
    return pwd_context.hash(password[:72])


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_admin_by_email(email: str) -> Optional[dict]:
    if db is None:
        return None
    return db["admin"].find_one({"email": email})


def create_default_admin():
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")
    if not db:
        return
    if email and password:
        existing = get_admin_by_email(email)
        if not existing:
            db["admin"].insert_one({
                "email": email,
                "password_hash": get_password_hash(password),
                "role": "admin",
                "is_active": True,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            })

# Initialize default admin if env provided
create_default_admin()

# Dependencies
async def get_current_admin(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = get_admin_by_email(token_data.email)
    if user is None or not user.get("is_active", False):
        raise credentials_exception
    return user

# Public endpoints
@app.get("/")
def read_root():
    return {"message": "Mala Ceramic API running"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        from database import db as _db
        if _db is not None:
            response["database"] = "✅ Connected & Working"
            response["database_url"] = "✅ Set"
            response["database_name"] = _db.name
            response["connection_status"] = "Connected"
            try:
                collections = _db.list_collection_names()
                response["collections"] = collections[:10]
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response

# Auth endpoints
@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = get_admin_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/register", response_model=dict)
async def register_admin(payload: AdminCreate, admin: dict = Depends(get_current_admin)):
    # Only an existing admin can create another admin
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if get_admin_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Admin already exists")

    db["admin"].insert_one({
        "email": payload.email,
        "password_hash": get_password_hash(payload.password),
        "role": "admin",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    return {"status": "ok"}

# Media endpoints
@app.get("/media", response_model=List[MediaItemOut])
async def list_published_media():
    if db is None:
        return []
    docs = db["mediaitem"].find({"is_published": True}).sort("created_at", -1)
    results = []
    for d in docs:
        results.append(MediaItemOut(
            id=str(d.get("_id")),
            title=d.get("title"),
            description=d.get("description"),
            media_type=d.get("media_type"),
            url=d.get("url"),
            tags=d.get("tags"),
            is_published=d.get("is_published", True),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        ))
    return results

@app.get("/admin/media", response_model=List[MediaItemOut])
async def admin_list_media(admin: dict = Depends(get_current_admin)):
    docs = db["mediaitem"].find({}).sort("created_at", -1)
    results = []
    for d in docs:
        results.append(MediaItemOut(
            id=str(d.get("_id")),
            title=d.get("title"),
            description=d.get("description"),
            media_type=d.get("media_type"),
            url=d.get("url"),
            tags=d.get("tags"),
            is_published=d.get("is_published", True),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        ))
    return results

@app.post("/admin/media", response_model=dict)
async def admin_create_media(item: MediaItemIn, admin: dict = Depends(get_current_admin)):
    data = item.model_dump()
    data["created_at"] = datetime.now(timezone.utc)
    data["updated_at"] = datetime.now(timezone.utc)
    inserted = db["mediaitem"].insert_one(data)
    return {"id": str(inserted.inserted_id)}

@app.put("/admin/media/{item_id}", response_model=dict)
async def admin_update_media(item_id: str, item: MediaItemIn, admin: dict = Depends(get_current_admin)):
    from bson import ObjectId as _ObjectId
    try:
        oid = _ObjectId(item_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    update = item.model_dump()
    update["updated_at"] = datetime.now(timezone.utc)
    result = db["mediaitem"].update_one({"_id": oid}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "ok"}

@app.delete("/admin/media/{item_id}", response_model=dict)
async def admin_delete_media(item_id: str, admin: dict = Depends(get_current_admin)):
    from bson import ObjectId as _ObjectId
    try:
        oid = _ObjectId(item_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    result = db["mediaitem"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
