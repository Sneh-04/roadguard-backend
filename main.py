"""
RoadGuard-AI — Complete Backend
FastAPI + SQLite  |  No ML models required  |  Render-ready
All routes match what the React Native frontend calls.
"""
import os
import uuid
import logging
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List

import bcrypt
from jose import JWTError, jwt
from fastapi import (
    FastAPI, HTTPException, Depends, status,
    UploadFile, File, Form, WebSocket, WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    Boolean, DateTime, ForeignKey, Text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ─────────────────────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────────────────────
JWT_SECRET    = os.environ.get("JWT_SECRET",    "roadguard-super-secret-2026-xyz")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE    = int(os.environ.get("JWT_EXPIRE_DAYS", "30"))
PORT          = int(os.environ.get("PORT", 8000))

DB_URL = os.environ.get("DATABASE_URL", "sqlite:///./roadguard.db")
if DB_URL.startswith("postgres://"):           # Render uses postgres:// prefix
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("roadguard")

# ─────────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────────
kwargs = {}
if "sqlite" in DB_URL:
    kwargs["connect_args"] = {"check_same_thread": False}

engine       = create_engine(DB_URL, **kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()


class User(Base):
    __tablename__ = "users"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    email           = Column(String, unique=True, nullable=False, index=True)
    username        = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role            = Column(String, default="user")
    is_active       = Column(Boolean, default=True)
    is_banned       = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=datetime.utcnow)
    last_login      = Column(DateTime, nullable=True)
    reports_count   = Column(Integer, default=0)
    safety_score    = Column(Float, default=100.0)


class HazardEvent(Base):
    __tablename__ = "hazard_events"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    timestamp    = Column(DateTime, default=datetime.utcnow)
    latitude     = Column(Float, nullable=False)
    longitude    = Column(Float, nullable=False)
    label        = Column(Integer, nullable=False)   # 0=Normal 1=SpeedBreaker 2=Pothole
    label_name   = Column(String, nullable=False)
    hazard_type  = Column(Integer, nullable=True)    # alias for label (frontend compat)
    p_sensor     = Column(Float, nullable=True)
    p_vision     = Column(Float, nullable=True)
    p_final      = Column(Float, nullable=True)
    confidence   = Column(Float, nullable=True)
    is_duplicate = Column(Boolean, default=False)
    status       = Column(String, default="ACTIVE")
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=True)
    description  = Column(Text, nullable=True)
    distance     = Column(Float, nullable=True)


class HazardReport(Base):
    __tablename__ = "hazard_reports"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    latitude    = Column(Float, nullable=False)
    longitude   = Column(Float, nullable=False)
    description = Column(String, nullable=True)
    image_path  = Column(String, nullable=True)
    status      = Column(String, default="pending")
    hazard_type = Column(Integer, nullable=True)
    confidence  = Column(Float, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_db():
    """Create tables and seed default users + sample hazards."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed admin
        if not db.query(User).filter_by(email="admin@roadguard.com").first():
            db.add(User(
                email="admin@roadguard.com",
                username="admin",
                hashed_password=_hash("Admin@123"),
                role="admin",
            ))
        # Seed default user
        if not db.query(User).filter_by(email="user@roadguard.com").first():
            db.add(User(
                email="user@roadguard.com",
                username="roadguard_user",
                hashed_password=_hash("User@123"),
                role="user",
            ))
        db.commit()

        # Seed sample hazard events if empty
        if db.query(HazardEvent).count() == 0:
            sample_hazards = [
                # Hyderabad coords ±0.05 scatter
                (17.3850 + random.uniform(-0.04, 0.04),
                 78.4867 + random.uniform(-0.04, 0.04),
                 2, "POTHOLE",  0.87),
                (17.3850 + random.uniform(-0.04, 0.04),
                 78.4867 + random.uniform(-0.04, 0.04),
                 1, "SPEED_BREAKER", 0.92),
                (17.3850 + random.uniform(-0.04, 0.04),
                 78.4867 + random.uniform(-0.04, 0.04),
                 2, "POTHOLE", 0.78),
                (17.3850 + random.uniform(-0.04, 0.04),
                 78.4867 + random.uniform(-0.04, 0.04),
                 1, "SPEED_BREAKER", 0.95),
                (17.3850 + random.uniform(-0.04, 0.04),
                 78.4867 + random.uniform(-0.04, 0.04),
                 2, "POTHOLE", 0.81),
            ]
            for lat, lng, label, name, conf in sample_hazards:
                db.add(HazardEvent(
                    latitude=lat, longitude=lng,
                    label=label, label_name=name, hazard_type=label,
                    confidence=conf, p_sensor=conf,
                    status="ACTIVE",
                    timestamp=datetime.utcnow() - timedelta(minutes=random.randint(5, 120)),
                ))
            db.commit()
            log.info("Seeded sample hazard events")
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────
#  Security
# ─────────────────────────────────────────────────────────────
security = HTTPBearer(auto_error=False)


def _hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def _verify(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def _token(data: dict) -> str:
    payload = {**data, "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRE)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = _decode(creds.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter_by(id=int(payload["sub"])).first()
    if not user or not user.is_active or user.is_banned:
        raise HTTPException(status_code=401, detail="User inactive or not found")
    return user


def get_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# ─────────────────────────────────────────────────────────────
#  Pydantic models
# ─────────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    email: str
    password: str

class SignupReq(BaseModel):
    email: str
    username: str
    password: str
    role: str = "user"

class ChatReq(BaseModel):
    message: str
    history: list = []

class SensorReq(BaseModel):
    data: list          # [[x,y,z] * 100]
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    speed: Optional[float] = None

class EventUpdateReq(BaseModel):
    status: Optional[str] = None


# ─────────────────────────────────────────────────────────────
#  App
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="RoadGuard-AI Backend",
    version="1.0.0",
    description="Complete backend — auth, hazards, events, sensor inference",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    seed_db()
    log.info("RoadGuard-AI backend started")


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────
def _fmt_event(e: HazardEvent) -> dict:
    return {
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "latitude": e.latitude,
        "longitude": e.longitude,
        "label": e.label,
        "label_name": e.label_name,
        "hazard_type": e.hazard_type or e.label,
        "p_sensor": e.p_sensor,
        "p_vision": e.p_vision,
        "p_final": e.p_final,
        "confidence": e.confidence,
        "is_duplicate": e.is_duplicate,
        "status": e.status or "ACTIVE",
        "description": e.description,
        "distance": e.distance,
    }


def _fmt_user(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "is_banned": u.is_banned,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "reports_count": u.reports_count or 0,
        "safety_score": u.safety_score or 100.0,
    }


def _token_response(user: User) -> dict:
    token = _token({"sub": str(user.id), "username": user.username, "role": user.role})
    return {
        "token": token,
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "email": user.email,
    }


# ─────────────────────────────────────────────────────────────
#  Health
# ─────────────────────────────────────────────────────────────
@app.get("/")
@app.get("/api/health")
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "RoadGuard-AI Backend",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "models_loaded": True,
        "stage1_model": "simulation",
        "stage2_model": "simulation",
        "vision_model": "simulation",
        "device": "cpu",
    }


# ─────────────────────────────────────────────────────────────
#  AUTH  — /api/auth/*
# ─────────────────────────────────────────────────────────────
@app.post("/api/auth/signup")
def signup(req: SignupReq, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=req.email).first():
        raise HTTPException(400, "Email already registered")
    if db.query(User).filter_by(username=req.username).first():
        raise HTTPException(400, "Username already taken")
    if req.role not in ("user", "admin"):
        raise HTTPException(400, "role must be 'user' or 'admin'")
    user = User(
        email=req.email,
        username=req.username,
        hashed_password=_hash(req.password),
        role=req.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log.info(f"New user: {user.username} ({user.role})")
    return _token_response(user)


@app.post("/api/auth/login")
def login(req: LoginReq, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=req.email).first()
    if not user or not _verify(req.password, user.hashed_password):
        raise HTTPException(401, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")
    if user.is_banned:
        raise HTTPException(403, "Account banned")
    user.last_login = datetime.utcnow()
    db.commit()
    log.info(f"Login: {user.username}")
    return _token_response(user)


@app.get("/api/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return _fmt_user(current_user)


@app.get("/api/auth/refresh")
def refresh_token(current_user: User = Depends(get_current_user)):
    return _token_response(current_user)


# ─────────────────────────────────────────────────────────────
#  EVENTS  — /api/events  +  /api/hazards/*
# ─────────────────────────────────────────────────────────────
@app.get("/api/events")
def get_events(
    lat: Optional[float] = None,
    lng: Optional[float] = None,
    radius_km: Optional[float] = None,
    db: Session = Depends(get_db),
):
    events = db.query(HazardEvent).filter(
        HazardEvent.is_duplicate == False,
        HazardEvent.status != "IGNORED",
    ).order_by(HazardEvent.timestamp.desc()).all()

    result = []
    for e in events:
        d = _fmt_event(e)
        # compute distance from caller if coords supplied
        if lat and lng:
            import math
            dlat = math.radians(e.latitude - lat)
            dlng = math.radians(e.longitude - lng)
            a = (math.sin(dlat/2)**2
                 + math.cos(math.radians(lat))
                 * math.cos(math.radians(e.latitude))
                 * math.sin(dlng/2)**2)
            d["distance"] = round(6371 * 2 * math.asin(math.sqrt(a)), 3)
        result.append(d)

    return {"events": result, "count": len(result)}


@app.get("/api/events/{label}")
def get_events_by_label(label: int, db: Session = Depends(get_db)):
    if label not in (0, 1, 2):
        raise HTTPException(400, "label must be 0, 1, or 2")
    events = db.query(HazardEvent).filter_by(label=label, is_duplicate=False).all()
    return {"events": [_fmt_event(e) for e in events]}


@app.patch("/api/events/{event_id}/solve")
def solve_event(event_id: int, db: Session = Depends(get_db)):
    e = db.query(HazardEvent).filter_by(id=event_id).first()
    if not e:
        raise HTTPException(404, "Event not found")
    e.status = "SOLVED"
    db.commit()
    return {"message": "updated", "status": "SOLVED"}


@app.patch("/api/events/{event_id}/ignore")
def ignore_event(event_id: int, db: Session = Depends(get_db)):
    e = db.query(HazardEvent).filter_by(id=event_id).first()
    if not e:
        raise HTTPException(404, "Event not found")
    e.status = "IGNORED"
    db.commit()
    return {"message": "updated", "status": "IGNORED"}


@app.post("/api/hazards/report")
async def report_hazard(
    image: Optional[UploadFile] = File(None),
    latitude: float  = Form(...),
    longitude: float = Form(...),
    description: str = Form(default="Road hazard detected"),
    hazard_type: Optional[int] = Form(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    image_path = None
    if image:
        os.makedirs("reports", exist_ok=True)
        ext  = Path(image.filename).suffix if image.filename else ".jpg"
        name = f"{uuid.uuid4()}{ext}"
        path = f"reports/{name}"
        with open(path, "wb") as f:
            f.write(await image.read())
        image_path = path

    # Run simulated YOLOv8 inference
    confidence = round(random.uniform(0.70, 0.97), 3)
    detected_type = hazard_type if hazard_type is not None else random.choice([1, 2])
    label_names = {0: "NORMAL", 1: "SPEED_BREAKER", 2: "POTHOLE"}

    # Store as a HazardEvent too (so it appears on map)
    event = HazardEvent(
        latitude=latitude, longitude=longitude,
        label=detected_type,
        label_name=label_names.get(detected_type, "POTHOLE"),
        hazard_type=detected_type,
        confidence=confidence,
        p_sensor=None, p_vision=confidence,
        status="ACTIVE",
        user_id=current_user.id,
        description=description,
    )
    db.add(event)

    report = HazardReport(
        user_id=current_user.id,
        latitude=latitude, longitude=longitude,
        description=description,
        image_path=image_path,
        hazard_type=detected_type,
        confidence=confidence,
        status="pending",
    )
    db.add(report)

    current_user.reports_count = (current_user.reports_count or 0) + 1
    db.commit()
    db.refresh(report)

    return {
        "success": True,
        "message": "Report submitted and analysed",
        "report_id": report.id,
        "event_id": event.id,
        "status": "pending",
        "analysis": {
            "hazard_detected": True,
            "hazard_type": detected_type,
            "hazard_label": label_names.get(detected_type),
            "confidence": confidence,
            "bounding_boxes": [
                {"x1": 120, "y1": 80, "x2": 340, "y2": 260,
                 "class": label_names.get(detected_type), "conf": confidence}
            ],
        },
    }


# ─────────────────────────────────────────────────────────────
#  SENSOR INFERENCE  — /api/predict + /api/predict-multimodal
# ─────────────────────────────────────────────────────────────
def _simulate_cnn(data: list) -> dict:
    """Simulate 2-stage CNN inference on accelerometer window."""
    if not data or len(data) < 10:
        return {"hazard_detected": False, "hazard_type": 0, "confidence": 0.1}
    import math
    # Compute magnitude
    mags = [math.sqrt(x**2 + y**2 + z**2) for x, y, z in (row[:3] for row in data)]
    mean_mag = sum(mags) / len(mags)
    std_mag  = (sum((m - mean_mag)**2 for m in mags) / len(mags))**0.5

    # Stage 1: hazard vs normal
    stage1_conf = min(0.99, max(0.01, (std_mag * 2.5)))
    hazard_detected = stage1_conf > 0.5

    if not hazard_detected:
        return {"hazard_detected": False, "hazard_type": 0,
                "confidence": round(1 - stage1_conf, 3), "stage2_confidence": None}

    # Stage 2: pothole vs speed_breaker
    max_spike = max(mags) - mean_mag
    pothole_score = min(0.99, max(0.01, max_spike * 0.6))
    hazard_type  = 2 if pothole_score > 0.5 else 1

    return {
        "hazard_detected": True,
        "hazard_type": hazard_type,
        "confidence": round(stage1_conf, 3),
        "stage2_confidence": round(pothole_score, 3),
        "severity_score": round(min(0.99, std_mag), 3),
    }


@app.post("/api/predict")
def predict(req: SensorReq, db: Session = Depends(get_db)):
    result = _simulate_cnn(req.data)

    # Persist if hazard detected and coords given
    if result["hazard_detected"] and req.latitude and req.longitude:
        label     = result["hazard_type"]
        lbl_names = {1: "SPEED_BREAKER", 2: "POTHOLE"}
        db.add(HazardEvent(
            latitude=req.latitude, longitude=req.longitude,
            label=label, label_name=lbl_names.get(label, "POTHOLE"),
            hazard_type=label,
            confidence=result["confidence"],
            p_sensor=result["confidence"],
            status="ACTIVE",
        ))
        db.commit()

    return result


@app.post("/api/predict-multimodal")
async def predict_multimodal(
    sensor: str = Form(default="[]"),
    image:  Optional[UploadFile] = File(None),
    latitude:  float = Form(default=0.0),
    longitude: float = Form(default=0.0),
    speed:     float = Form(default=0.0),
):
    import json
    try:
        data = json.loads(sensor)
    except Exception:
        data = []
    sensor_result = _simulate_cnn(data)
    vision_conf   = round(random.uniform(0.70, 0.95), 3) if image else None

    alpha = 0.6
    if vision_conf is not None:
        final_conf = alpha * sensor_result["confidence"] + (1 - alpha) * vision_conf
    else:
        final_conf = sensor_result["confidence"]

    return {
        **sensor_result,
        "final_confidence": round(final_conf, 3),
        "sensor_confidence": sensor_result["confidence"],
        "vision_confidence": vision_conf,
    }


@app.post("/api/predict-batch")
def predict_batch(payload: dict):
    results = [_simulate_cnn(s) for s in payload.get("sensor_batch", [])]
    return {"predictions": results}


# ─────────────────────────────────────────────────────────────
#  WEATHER  — /api/weather
# ─────────────────────────────────────────────────────────────
@app.get("/api/weather")
def weather(lat: float = 17.385, lon: float = 78.486):
    conditions = ["Clear", "Cloudy", "Partly Cloudy", "Overcast", "Light Rain"]
    return {
        "temperature": round(random.uniform(28, 38), 1),
        "condition":   random.choice(conditions),
        "humidity":    random.randint(45, 85),
        "wind_speed":  round(random.uniform(5, 25), 1),
        "precipitation": round(random.uniform(0, 5), 1),
        "visibility":  round(random.uniform(5, 15), 1),
        "timestamp":   datetime.utcnow().isoformat(),
        "location":    {"lat": lat, "lon": lon},
    }


# ─────────────────────────────────────────────────────────────
#  CHAT / AI ASSISTANT  — /api/chat
# ─────────────────────────────────────────────────────────────
CHAT_RESPONSES = {
    "pothole":      "Potholes are dangerous! RoadGuard detects them via accelerometer spikes. Drive carefully and reduce speed.",
    "speed":        "Speed bumps are identified by the Stage-2 CNN classifier. They're marked yellow on the map.",
    "map":          "The Live Map tab shows all hazards near you in real time. Tap any marker for details.",
    "report":       "Go to the Hazard Report tab, take a photo, and submit — our YOLOv8 model analyses it instantly.",
    "safe":         "Your safety score is computed from nearby hazards. Drive safe and it stays green!",
    "monitor":      "The Monitor tab shows live accelerometer data. Tap 'Start Monitoring' to begin sensor detection.",
    "help":         "I can help with: hazard detection, map navigation, reporting, safety scores, and route planning.",
    "hello":        "Hi! I'm the RoadGuard AI assistant. Ask me about potholes, speed bumps, or how to use the app.",
    "accuracy":     "The 2-stage CNN achieves ~86% accuracy. YOLOv8 visual validation reduces false positives further.",
    "route":        "Use the Safe Route planner to find paths that avoid known hazard clusters.",
    "default":      "I'm here to help with road safety and hazard detection. Try asking about potholes, the map, or monitoring.",
}

@app.post("/api/chat")
def chat(req: ChatReq):
    msg   = req.message.lower()
    reply = CHAT_RESPONSES["default"]
    for key, response in CHAT_RESPONSES.items():
        if key in msg:
            reply = response
            break
    return {
        "response": reply,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "ok",
    }


# ─────────────────────────────────────────────────────────────
#  ADMIN — /api/admin/*
# ─────────────────────────────────────────────────────────────
@app.get("/api/admin/stats")
def admin_stats(
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    total     = db.query(HazardEvent).count()
    potholes  = db.query(HazardEvent).filter_by(label=2).count()
    bumps     = db.query(HazardEvent).filter_by(label=1).count()
    normal    = db.query(HazardEvent).filter_by(label=0).count()
    since_24h = datetime.utcnow() - timedelta(hours=24)
    last_24h  = db.query(HazardEvent).filter(HazardEvent.timestamp >= since_24h).count()
    t_users   = db.query(User).count()
    a_users   = db.query(User).filter_by(is_active=True).count()

    # Hourly counts (last 24h)
    by_hour = []
    for h in range(24):
        t0 = datetime.utcnow() - timedelta(hours=24 - h)
        t1 = t0 + timedelta(hours=1)
        cnt = db.query(HazardEvent).filter(
            HazardEvent.timestamp >= t0,
            HazardEvent.timestamp < t1,
        ).count()
        by_hour.append({"hour": t0.strftime("%H:00"), "count": cnt})

    return {
        "total_events": total,
        "events_by_label": {
            "normal": normal,
            "speed_breaker": bumps,
            "pothole": potholes,
        },
        "events_last_24h": last_24h,
        "events_by_hour": by_hour,
        "top_hazard_locations": [],
        "active_users_count": a_users,
        "total_users_count": t_users,
    }


@app.get("/api/admin/users")
def admin_list_users(
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    users = db.query(User).all()
    return {
        "users": [_fmt_user(u) for u in users],
        "total_count": len(users),
    }


@app.get("/api/admin/reports")
def admin_reports(
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    reports = db.query(HazardReport).order_by(HazardReport.created_at.desc()).all()
    return {"reports": [
        {
            "id": r.id,
            "user_id": r.user_id,
            "latitude": r.latitude,
            "longitude": r.longitude,
            "description": r.description,
            "status": r.status,
            "hazard_type": r.hazard_type,
            "confidence": r.confidence,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]}


@app.put("/api/admin/users/{user_id}/ban")
def ban_user(
    user_id: int,
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter_by(id=user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    u.is_banned = True
    db.commit()
    return {"message": f"User {u.username} banned"}


@app.put("/api/admin/users/{user_id}/unban")
def unban_user(
    user_id: int,
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter_by(id=user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    u.is_banned = False
    db.commit()
    return {"message": f"User {u.username} unbanned"}


@app.put("/api/admin/users/{user_id}/activate")
def activate_user(
    user_id: int,
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter_by(id=user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    u.is_active = True
    db.commit()
    return {"message": f"User {u.username} activated"}


@app.get("/api/admin/analytics")
def admin_analytics(
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    return admin_stats(_, db)


# ─────────────────────────────────────────────────────────────
#  WEBSOCKET  — /ws/live  (real-time sensor stream)
# ─────────────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket, db: Session = Depends(get_db)):
    await websocket.accept()
    await websocket.send_json({"type": "status", "message": "Connected to RoadGuard backend"})
    try:
        while True:
            raw = await websocket.receive_json()
            sensor = raw.get("sensor", [])
            loc    = raw.get("location", {})
            result = _simulate_cnn(sensor)

            if result["hazard_detected"]:
                label     = result["hazard_type"]
                lbl_names = {1: "speed_bump", 2: "pothole"}
                hazard_name = lbl_names.get(label, "pothole")

                # Persist
                db.add(HazardEvent(
                    latitude=loc.get("lat", 0),
                    longitude=loc.get("lng", 0),
                    label=label,
                    label_name=hazard_name.upper(),
                    hazard_type=label,
                    confidence=result["confidence"],
                    p_sensor=result["confidence"],
                    status="ACTIVE",
                ))
                db.commit()

                await websocket.send_json({
                    "type":            "hazard_alert",
                    "hazard_detected": True,
                    "hazard_type":     hazard_name,
                    "confidence":      result["confidence"],
                    "location":        loc,
                    "timestamp":       datetime.utcnow().isoformat(),
                })
            else:
                await websocket.send_json({
                    "type":            "hazard_alert",
                    "hazard_detected": False,
                    "hazard_type":     "normal",
                    "confidence":      result["confidence"],
                })
    except WebSocketDisconnect:
        log.info("WebSocket client disconnected")
    except Exception as e:
        log.error(f"WebSocket error: {e}")


# ─────────────────────────────────────────────────────────────
#  Run (local dev)
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
