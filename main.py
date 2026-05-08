"""
RoadGuard-AI — Complete Backend
FastAPI + SQLite  |  No ML models required  |  Render-ready
All routes match what the React Native frontend calls.
"""
import os
import uuid
import logging
import random
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List

import bcrypt
from jose import JWTError, jwt
from fastapi import (
    FastAPI, HTTPException, Depends, status,
    UploadFile, File, Form, WebSocket, WebSocketDisconnect,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
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
    timestamp    = Column(DateTime, default=datetime.utcnow, index=True)
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
    report_count = Column(Integer, default=1)
    device_count = Column(Integer, default=1)
    cluster_id   = Column(Integer, ForeignKey("event_clusters.id"), nullable=True)
    image_path   = Column(String, nullable=True)
    last_seen    = Column(DateTime, default=datetime.utcnow)
    created_at   = Column(DateTime, default=datetime.utcnow)


class HazardReport(Base):
    __tablename__ = "hazard_reports"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    user_id         = Column(Integer, ForeignKey("users.id"), nullable=True)
    device_id       = Column(String, nullable=False, index=True)
    latitude        = Column(Float, nullable=False)
    longitude       = Column(Float, nullable=False)
    description     = Column(String, nullable=True)
    image_path      = Column(String, nullable=True)
    status          = Column(String, default="pending")
    hazard_type     = Column(Integer, nullable=True)
    confidence      = Column(Float, nullable=True)
    hazard_event_id = Column(Integer, ForeignKey("hazard_events.id"), nullable=True)
    source          = Column(String, default="user_report")
    created_at      = Column(DateTime, default=datetime.utcnow)
    reviewed_at     = Column(DateTime, nullable=True)


class SensorCandidate(Base):
    __tablename__ = "sensor_candidates"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    device_id       = Column(String, nullable=False, index=True)
    latitude        = Column(Float, nullable=False)
    longitude       = Column(Float, nullable=False)
    speed           = Column(Float, nullable=True)
    confidence      = Column(Float, nullable=False)
    hazard_type     = Column(Integer, nullable=True)
    status          = Column(String, default="pending")
    timestamp       = Column(DateTime, nullable=False, index=True)
    hazard_event_id = Column(Integer, ForeignKey("hazard_events.id"), nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)


class DeviceSession(Base):
    __tablename__ = "device_sessions"
    id                 = Column(Integer, primary_key=True, autoincrement=True)
    device_id          = Column(String, nullable=False, unique=True, index=True)
    first_seen         = Column(DateTime, default=datetime.utcnow)
    last_seen          = Column(DateTime, default=datetime.utcnow)
    last_submission_at = Column(DateTime, nullable=True)
    submissions_total  = Column(Integer, default=0)
    is_throttled       = Column(Boolean, default=False)
    banned_until       = Column(DateTime, nullable=True)


class EventCluster(Base):
    __tablename__ = "event_clusters"
    id                 = Column(Integer, primary_key=True, autoincrement=True)
    cluster_latitude   = Column(Float, nullable=False)
    cluster_longitude  = Column(Float, nullable=False)
    hazard_type        = Column(Integer, nullable=False)
    confidence_score   = Column(Float, nullable=True)
    event_count        = Column(Integer, default=0)
    device_count       = Column(Integer, default=0)
    status             = Column(String, default="ACTIVE")
    first_report_ts    = Column(DateTime, default=datetime.utcnow)
    last_report_ts     = Column(DateTime, default=datetime.utcnow)
    created_at         = Column(DateTime, default=datetime.utcnow)
    updated_at         = Column(DateTime, default=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_sqlite_schema():
    if "sqlite" not in DB_URL:
        return

    conn = engine.raw_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(hazard_events)")
        hazard_cols = [row[1] for row in cursor.fetchall()]
        if "image_path" not in hazard_cols:
            cursor.execute("ALTER TABLE hazard_events ADD COLUMN image_path TEXT")
        conn.commit()
    finally:
        conn.close()


def seed_db():
    """Create tables and seed default users."""
    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_schema()

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

        # Sample hazard seeding is disabled so analytics and counts reflect real user data only.
        # if db.query(HazardEvent).count() == 0:
        #     ...
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


def get_optional_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not creds:
        return None
    try:
        payload = _decode(creds.credentials)
    except JWTError:
        return None
    user = db.query(User).filter_by(id=int(payload["sub"]) ).first()
    if not user or not user.is_active or user.is_banned:
        return None
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


class ReportRequest(BaseModel):
    type: str
    latitude: float
    longitude: float
    timestamp: datetime
    image: Optional[str] = None   # base64 string


class SensorEventReq(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    timestamp: datetime
    confidence: float
    speed: Optional[float] = None
    hazard_type: Optional[int] = None
    source: Optional[str] = "sensor"


class HazardReportReq(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    timestamp: datetime
    confidence: float
    hazard_type: int
    description: Optional[str] = None


class HazardStatusReq(BaseModel):
    status: str


hazard_subscribers = []


def _haversine_meters(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    import math
    r = 6371000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


def _validate_coordinates(latitude: float, longitude: float):
    if latitude is None or longitude is None:
        raise HTTPException(400, "latitude and longitude are required")
    if not (-90.0 <= latitude <= 90.0 and -180.0 <= longitude <= 180.0):
        raise HTTPException(400, "Invalid latitude or longitude")


def _validate_timestamp(timestamp: datetime):
    if timestamp.tzinfo is not None:
        timestamp = timestamp.replace(tzinfo=None)  # Make naive
    now = datetime.utcnow()
    if timestamp > now + timedelta(minutes=2):
        raise HTTPException(400, "timestamp cannot be in the future")
    if timestamp < now - timedelta(hours=1):
        raise HTTPException(400, "timestamp is too old")


def _validate_confidence(confidence: float):
    if confidence is None or not (0.0 <= confidence <= 1.0):
        raise HTTPException(400, "confidence must be between 0.0 and 1.0")
    if confidence < 0.30:
        raise HTTPException(400, "confidence is too low for confirmed hazard reporting")


def _validate_speed(speed: Optional[float]):
    if speed is None:
        return
    if speed < 0 or speed > 180:
        raise HTTPException(400, "speed is out of realistic range")


def _validate_device_id(device_id: str):
    if not device_id or len(device_id) > 64:
        raise HTTPException(400, "device_id is required and must be under 64 chars")
    normalized = device_id.replace("-", "").replace("_", "")
    if not normalized.isalnum():
        raise HTTPException(400, "device_id contains invalid characters")


def _check_rate_limit(device_id: str, db: Session):
    now = datetime.utcnow()
    session = db.query(DeviceSession).filter_by(device_id=device_id).first()
    window_start = now - timedelta(minutes=10)
    recent_sensor = db.query(SensorCandidate).filter(
        SensorCandidate.device_id == device_id,
        SensorCandidate.created_at >= window_start,
    ).count()
    recent_reports = db.query(HazardReport).filter(
        HazardReport.device_id == device_id,
        HazardReport.created_at >= window_start,
    ).count()
    total_recent = recent_sensor + recent_reports
    if total_recent >= 12:
        msg = "Rate limit exceeded: too many confirmed hazard submissions from this device"
        raise HTTPException(status_code=429, detail=msg)
    if session and session.banned_until and session.banned_until > now:
        raise HTTPException(status_code=429, detail="Device blocked from submitting hazards")
    if not session:
        session = DeviceSession(device_id=device_id, first_seen=now, last_seen=now)
        db.add(session)
    session.last_seen = now
    session.last_submission_at = now
    session.submissions_total = (session.submissions_total or 0) + 1
    db.add(session)
    db.commit()


def _normalize_timestamp(timestamp: datetime) -> datetime:
    if timestamp.tzinfo is not None:
        return timestamp.replace(tzinfo=None)
    return timestamp


def _find_existing_hazard(
    db: Session,
    latitude: float,
    longitude: float,
    timestamp: datetime,
    hazard_type: Optional[int],
    confidence: float,
) -> Optional[HazardEvent]:
    timestamp = _normalize_timestamp(timestamp)
    max_distance = 20.0 if confidence >= 0.85 else 50.0
    max_age = 30 if confidence >= 0.85 else 120
    candidates = db.query(HazardEvent).filter(
        HazardEvent.is_duplicate == False,
        HazardEvent.status != "IGNORED",
    ).all()
    best = None
    best_dist = float("inf")
    for event in candidates:
        if hazard_type is not None and event.hazard_type is not None and event.hazard_type != hazard_type:
            continue
        event_ts = _normalize_timestamp(event.timestamp)
        age = abs((event_ts - timestamp).total_seconds())
        if age > max_age:
            continue
        dist = _haversine_meters(latitude, longitude, event.latitude, event.longitude)
        if dist > max_distance:
            continue
        if dist < best_dist:
            best_dist = dist
            best = event
    return best


def _update_hazard_confidence(
    event: HazardEvent,
    device_id: str,
    confidence: float,
    timestamp: datetime,
    db: Session,
    image_path: Optional[str] = None,
):
    if timestamp.tzinfo is not None:
        timestamp = timestamp.replace(tzinfo=None)  # Make naive
    event.report_count = (event.report_count or 1) + 1
    existing_device = db.query(HazardReport).filter_by(hazard_event_id=event.id, device_id=device_id).count()
    existing_device += db.query(SensorCandidate).filter_by(hazard_event_id=event.id, device_id=device_id).count()
    if existing_device == 0:
        event.device_count = (event.device_count or 1) + 1
    if event.confidence is None:
        event.confidence = confidence
    else:
        event.confidence = round((event.confidence * (event.report_count - 1) + confidence) / event.report_count, 4)
    event.last_seen = max(event.last_seen or event.timestamp, timestamp)
    if timestamp > event.timestamp:
        event.timestamp = timestamp
    if image_path and not event.image_path:
        event.image_path = image_path
    event.p_final = event.confidence
    event.is_duplicate = False
    db.add(event)
    db.commit()
    return event


def _lookup_cluster(db: Session, event: HazardEvent) -> Optional[EventCluster]:
    clusters = db.query(EventCluster).filter(
        EventCluster.hazard_type == event.hazard_type,
        EventCluster.status != "IGNORED",
    ).all()
    closest = None
    closest_distance = float("inf")
    for cluster in clusters:
        dist = _haversine_meters(
            event.latitude, event.longitude,
            cluster.cluster_latitude, cluster.cluster_longitude,
        )
        event_seen = _normalize_timestamp(event.last_seen)
        cluster_seen = _normalize_timestamp(cluster.last_report_ts)
        age = abs((event_seen - cluster_seen).total_seconds())
        if dist <= 50 and age <= 120 and dist < closest_distance:
            closest = cluster
            closest_distance = dist
    return closest


def _sync_event_cluster(event: HazardEvent, db: Session):
    cluster = _lookup_cluster(db, event)
    if cluster:
        cluster.event_count += 1
        cluster.device_count = max(cluster.device_count, event.device_count)
        cluster.confidence_score = round((cluster.confidence_score * (cluster.event_count - 1) + (event.confidence or 0.0)) / cluster.event_count, 4)
        cluster.last_report_ts = max(cluster.last_report_ts, event.last_seen)
        cluster.updated_at = datetime.utcnow()
    else:
        cluster = EventCluster(
            cluster_latitude=event.latitude,
            cluster_longitude=event.longitude,
            hazard_type=event.hazard_type or 0,
            confidence_score=event.confidence or 0.0,
            event_count=1,
            device_count=event.device_count or 1,
            first_report_ts=event.timestamp,
            last_report_ts=event.last_seen,
            updated_at=datetime.utcnow(),
        )
        db.add(cluster)
    db.commit()
    event.cluster_id = cluster.id
    db.add(event)
    db.commit()
    return cluster


async def _broadcast_hazard_update(payload: dict):
    stale = []
    for ws in list(hazard_subscribers):
        try:
            await ws.send_json(payload)
        except Exception:
            stale.append(ws)
    for ws in stale:
        if ws in hazard_subscribers:
            hazard_subscribers.remove(ws)


async def _create_or_merge_hazard_event(
    db: Session,
    latitude: float,
    longitude: float,
    timestamp: datetime,
    confidence: float,
    hazard_type: Optional[int],
    device_id: str,
    description: Optional[str] = None,
    user_id: Optional[int] = None,
    image_path: Optional[str] = None,
    source: Optional[str] = "sensor",
) -> HazardEvent:
    if timestamp.tzinfo is not None:
        timestamp = timestamp.replace(tzinfo=None)  # Make naive
    existing = _find_existing_hazard(db, latitude, longitude, timestamp, hazard_type, confidence)
    if existing:
        event = _update_hazard_confidence(existing, device_id, confidence, timestamp, db, image_path=image_path)
        if description and not event.description:
            event.description = description
        _sync_event_cluster(event, db)
        await _broadcast_hazard_update({"type": "hazard_update", "action": "merged", "hazard": _fmt_event(event)})
        return event

    label = hazard_type if hazard_type is not None else 2
    label_names = {0: "NORMAL", 1: "SPEED_BREAKER", 2: "POTHOLE"}
    status = "ACTIVE" if source == "sensor" else "PENDING"
    event = HazardEvent(
        latitude=latitude,
        longitude=longitude,
        label=label,
        label_name=label_names.get(label, "POTHOLE"),
        hazard_type=label,
        confidence=confidence,
        p_sensor=confidence,
        p_final=confidence,
        status=status,
        user_id=user_id,
        description=description,
        image_path=image_path,
        report_count=1,
        device_count=1,
        timestamp=timestamp,
        last_seen=timestamp,
        created_at=datetime.utcnow(),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    _sync_event_cluster(event, db)
    await _broadcast_hazard_update({"type": "hazard_update", "action": "created", "hazard": _fmt_event(event)})
    return event


# ─────────────────────────────────────────────────────────────
#  App
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="RoadGuard-AI Backend",
    version="1.0.0",
    description="Complete backend — auth, hazards, events, sensor inference",
)

Path("uploads").mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    log.info(f"Incoming request: {request.method} {request.url.path}")
    response = await call_next(request)
    return response


@app.on_event("startup")
def startup():
    seed_db()
    log.info("RoadGuard-AI backend started")


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────
def _build_image_url(request: Request, image_path: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/uploads/{image_path}"


def _fmt_event(e: HazardEvent, request: Optional[Request] = None) -> dict:
    image_url = None
    if e.image_path and request is not None:
        image_url = _build_image_url(request, e.image_path)

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
        "image_url": image_url,
    }


def _save_hazard_image(image: UploadFile) -> str:
    uploads_dir = Path("uploads/hazard-images")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(image.filename).suffix or ".jpg"
    filename = f"{uuid.uuid4()}{ext}"
    destination = uploads_dir / filename
    with open(destination, "wb") as f:
        f.write(image.file.read())
    return f"hazard-images/{filename}"


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


@app.post("/report")
def create_report(req: ReportRequest):
    log.info("POST /report received")
    log.info(f"Report payload: {req.dict()}")

    report = {
        "id": len(reports) + 1,
        "type": req.type,
        "latitude": req.latitude,
        "longitude": req.longitude,
        "timestamp": req.timestamp.isoformat(),
        "image": req.image,
        "status": "pending"   # NEW
    }
    reports.append(report)

    return {
        "success": True,
        "message": "Report received",
        "report": report,
    }


@app.get("/reports")
def get_reports():
    log.info("GET /reports requested")
    return reports


@app.put("/report/{id}")
def update_report(id: int, payload: dict):
    status = payload.get("status")
    if not status:
        return {"success": False, "error": "status required"}
    for r in reports:
        if r["id"] == id:
            r["status"] = status
            return {"success": True}
    return {"success": False}


@app.post("/sensor-events")
async def ingest_sensor_event(req: SensorEventReq, db: Session = Depends(get_db)):
    _validate_device_id(req.device_id)
    _validate_coordinates(req.latitude, req.longitude)
    _validate_timestamp(req.timestamp)
    _validate_confidence(req.confidence)
    _validate_speed(req.speed)
    if req.speed is None or req.speed <= 8:
        raise HTTPException(400, "speed must be greater than 8 km/h")
    _check_rate_limit(req.device_id, db)

    candidate = SensorCandidate(
        device_id=req.device_id,
        latitude=req.latitude,
        longitude=req.longitude,
        speed=req.speed,
        confidence=req.confidence,
        hazard_type=req.hazard_type,
        status="validated",
        timestamp=req.timestamp,
    )
    db.add(candidate)
    db.commit()
    db.refresh(candidate)

    event = await _create_or_merge_hazard_event(
        db=db,
        latitude=req.latitude,
        longitude=req.longitude,
        timestamp=req.timestamp,
        confidence=req.confidence,
        hazard_type=req.hazard_type,
        device_id=req.device_id,
        description=None,
        user_id=None,
        source="sensor",
    )
    candidate.hazard_event_id = event.id
    db.add(candidate)
    db.commit()

    return {
        "success": True,
        "hazard": _fmt_event(event),
        "candidate_id": candidate.id,
    }


UPLOAD_DIR = "uploads/hazard-images"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/hazard-reports")
async def create_hazard_report(
    image: UploadFile = File(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    hazard_type: int = Form(...),
    confidence: float = Form(...),
    description: Optional[str] = Form(None),
    request: Request = None,
    db: Session = Depends(get_db),
):
    _validate_coordinates(latitude, longitude)
    _validate_confidence(confidence)

    image_path = _save_hazard_image(image)
    timestamp = datetime.utcnow()

    event = await _create_or_merge_hazard_event(
        db=db,
        latitude=latitude,
        longitude=longitude,
        timestamp=timestamp,
        confidence=confidence,
        hazard_type=hazard_type,
        device_id="anonymous",
        description=description,
        user_id=None,
        image_path=image_path,
        source="user_report",
    )

    report = HazardReport(
        user_id=None,
        device_id="anonymous",
        latitude=latitude,
        longitude=longitude,
        description=description,
        image_path=image_path,
        status="pending",
        hazard_type=hazard_type,
        confidence=confidence,
        hazard_event_id=event.id,
        source="user_report",
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return {
        "success": True,
        "message": "Hazard report accepted",
        "report_id": report.id,
        "hazard": _fmt_event(event, request),
    }


@app.get("/hazards")
def list_hazards(
    request: Request,
    lat: Optional[float] = None,
    lng: Optional[float] = None,
    radius_m: Optional[float] = None,
    hazard_type: Optional[int] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(HazardEvent).filter(HazardEvent.is_duplicate == False)
    if status:
        statuses = [s.strip().upper() for s in status.split(",") if s.strip()]
        if "ALL" not in statuses:
            query = query.filter(HazardEvent.status.in_(statuses))
    if hazard_type is not None:
        query = query.filter(HazardEvent.hazard_type == hazard_type)

    hazards = []
    for event in query.order_by(HazardEvent.timestamp.desc()).all():
        hazard = _fmt_event(event, request)
        if lat is not None and lng is not None:
            hazard["distance"] = round(_haversine_meters(lat, lng, event.latitude, event.longitude), 1)
            if radius_m is not None and hazard["distance"] > radius_m:
                continue
        hazards.append(hazard)

    return {"hazards": hazards, "count": len(hazards)}


@app.put("/hazards/{hazard_id}/status")
async def update_hazard_status(
    hazard_id: int,
    req: HazardStatusReq,
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
    request: Request = None,
):
    allowed = {"PENDING", "ACTIVE", "VERIFIED", "SOLVED", "IGNORED", "CONFIRMED"}
    status_value = req.status.strip().upper()
    if status_value not in allowed:
        raise HTTPException(400, "Invalid status value")
    event = db.query(HazardEvent).filter_by(id=hazard_id).first()
    if not event:
        raise HTTPException(404, "Hazard not found")
    event.status = status_value
    db.add(event)
    if event.cluster_id:
        cluster = db.query(EventCluster).filter_by(id=event.cluster_id).first()
        if cluster:
            cluster.status = status_value
            db.add(cluster)
    db.commit()
    await _broadcast_hazard_update({"type": "hazard_update", "action": "status_changed", "hazard": _fmt_event(event, request)})
    return {"success": True, "hazard": _fmt_event(event, request)}


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

    _validate_coordinates(latitude, longitude)
    _validate_timestamp(datetime.utcnow())

    confidence = round(random.uniform(0.70, 0.97), 3)
    detected_type = hazard_type if hazard_type is not None else random.choice([1, 2])

    event = await _create_or_merge_hazard_event(
        db=db,
        latitude=latitude,
        longitude=longitude,
        timestamp=datetime.utcnow(),
        confidence=confidence,
        hazard_type=detected_type,
        device_id=str(current_user.id),
        description=description,
        user_id=current_user.id,
        image_path=image_path,
        source="user_report",
    )

    report = HazardReport(
        user_id=current_user.id,
        device_id=str(current_user.id),
        latitude=latitude, longitude=longitude,
        description=description,
        image_path=image_path,
        hazard_type=detected_type,
        confidence=confidence,
        status="pending",
        hazard_event_id=event.id,
        source="user_report",
    )
    db.add(report)

    current_user.reports_count = (current_user.reports_count or 0) + 1
    db.commit()
    db.refresh(report)

    return {
        "success": True,
        "message": "Report submitted and analysed",
        "report_id": report.id,
        "hazard_id": event.id,
        "status": "pending",
        "analysis": {
            "hazard_detected": True,
            "hazard_type": detected_type,
            "hazard_label": {1: "SPEED_BREAKER", 2: "POTHOLE"}.get(detected_type),
            "confidence": confidence,
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
    request: Request,
    _: User = Depends(get_admin),
    db: Session = Depends(get_db),
):
    reports = db.query(HazardReport).order_by(HazardReport.created_at.desc()).all()
    result = []
    for r in reports:
        event = db.query(HazardEvent).filter_by(id=r.hazard_event_id).first()
        result.append({
            "id": r.id,
            "user_id": r.user_id,
            "latitude": r.latitude,
            "longitude": r.longitude,
            "description": r.description,
            "status": r.status,
            "hazard_type": r.hazard_type,
            "confidence": r.confidence,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "hazard": _fmt_event(event, request) if event else None,
        })
    return {"reports": result, "count": len(result)}


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
#  WEBSOCKET  — /ws/hazards  (confirmed hazard updates only)
# ─────────────────────────────────────────────────────────────
@app.websocket("/ws/hazards")
async def ws_hazards(websocket: WebSocket):
    await websocket.accept()
    hazard_subscribers.append(websocket)
    await websocket.send_json({"type": "status", "message": "Connected to confirmed hazard updates"})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        log.info("Hazard update websocket disconnected")
    except Exception as e:
        log.error(f"WebSocket error: {e}")
    finally:
        if websocket in hazard_subscribers:
            hazard_subscribers.remove(websocket)


# ─────────────────────────────────────────────────────────────
#  Run (local dev)
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
