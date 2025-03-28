from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import jwt, JWTError  # Changed from import jwt
from passlib.context import CryptContext

# ...rest of your code remains the same...

# Initialize FastAPI app
app = FastAPI()

# Security setup
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Data models
class PatientBase(BaseModel):
    name: str
    age: int
    gender: str
    medical_history: Optional[str] = None

class PatientCreate(PatientBase):
    pass

class Patient(PatientBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

# Mock database
patients_db = {}
users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("password123"),
    }
}

# Authentication functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in users_db:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    return username

# API endpoints
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/patients/", response_model=Patient)
async def create_patient(
    patient: PatientCreate, 
    current_user: str = Depends(get_current_user)
):
    patient_id = len(patients_db) + 1
    patient_dict = patient.dict()
    patient_dict.update({
        "id": patient_id,
        "created_at": datetime.utcnow()
    })
    patients_db[patient_id] = patient_dict
    return patient_dict

@app.get("/patients/", response_model=List[Patient])
async def read_patients(
    skip: int = 0, 
    limit: int = 10,
    current_user: str = Depends(get_current_user)
):
    return list(patients_db.values())[skip : skip + limit]

@app.get("/patients/{patient_id}", response_model=Patient)
async def read_patient(
    patient_id: int,
    current_user: str = Depends(get_current_user)
):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patients_db[patient_id]

@app.put("/patients/{patient_id}", response_model=Patient)
async def update_patient(
    patient_id: int,
    patient: PatientCreate,
    current_user: str = Depends(get_current_user)
):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    patient_dict = patient.dict()
    patient_dict.update({
        "id": patient_id,
        "created_at": patients_db[patient_id]["created_at"]
    })
    patients_db[patient_id] = patient_dict
    return patient_dict

@app.delete("/patients/{patient_id}")
async def delete_patient(
    patient_id: int,
    current_user: str = Depends(get_current_user)
):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    del patients_db[patient_id]
    return {"message": "Patient deleted successfully"}