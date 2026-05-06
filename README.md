# RoadGuard-AI Backend

Complete FastAPI backend — auth, hazard events, sensor inference, admin panel, WebSocket.

## Pre-seeded credentials

| Role  | Email                    | Password   |
|-------|--------------------------|------------|
| Admin | admin@roadguard.com      | Admin@123  |
| User  | user@roadguard.com       | User@123   |

## All endpoints

| Method | Path                          | Auth?    | Description                        |
|--------|-------------------------------|----------|------------------------------------|
| GET    | /api/health                   | —        | Health check                       |
| POST   | /api/auth/signup              | —        | Register new user                  |
| POST   | /api/auth/login               | —        | Login → JWT token                  |
| GET    | /api/auth/me                  | Bearer   | Get current user profile           |
| GET    | /api/auth/refresh             | Bearer   | Refresh token                      |
| GET    | /api/events                   | —        | All hazard events                  |
| GET    | /api/events/{label}           | —        | Events by type (0/1/2)            |
| PATCH  | /api/events/{id}/solve        | —        | Mark solved                        |
| PATCH  | /api/events/{id}/ignore       | —        | Mark ignored                       |
| POST   | /api/hazards/report           | Bearer   | Submit image + location report     |
| POST   | /api/predict                  | —        | Sensor-only inference              |
| POST   | /api/predict-multimodal       | —        | Sensor + vision inference          |
| POST   | /api/predict-batch            | —        | Batch inference                    |
| GET    | /api/weather                  | —        | Weather for lat/lon                |
| POST   | /api/chat                     | —        | AI chatbot response                |
| GET    | /api/admin/stats              | Admin    | Dashboard statistics               |
| GET    | /api/admin/users              | Admin    | List all users                     |
| GET    | /api/admin/reports            | Admin    | List hazard reports                |
| PUT    | /api/admin/users/{id}/ban     | Admin    | Ban user                           |
| PUT    | /api/admin/users/{id}/unban   | Admin    | Unban user                         |
| WS     | /ws/live                      | —        | Real-time sensor stream            |

## Request / Response: Login

**Request:**
```json
POST /api/auth/login
Content-Type: application/json

{
  "email": "admin@roadguard.com",
  "password": "Admin@123"
}
```

**Response (200):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": 1,
  "username": "admin",
  "role": "admin",
  "email": "admin@roadguard.com"
}
```

**Response (401):**
```json
{"detail": "Invalid email or password"}
```

## Request / Response: Signup

```json
POST /api/auth/signup
{
  "email": "new@example.com",
  "username": "myname",
  "password": "MyPass@123",
  "role": "user"
}
```

## Deploying to Render (free tier, 5 minutes)

1. Push this folder to a GitHub repo
2. Go to https://render.com → New → Web Service
3. Connect your GitHub repo
4. Settings:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Python version:** 3.11
5. Add environment variable: `JWT_SECRET` → any long random string
6. Click Deploy
7. Your URL: `https://your-service-name.onrender.com`
8. Update the mobile app `.env`:  
   `EXPO_PUBLIC_BACKEND_URL=https://your-service-name.onrender.com`

## Running locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
# API docs: http://localhost:8000/docs
```

## Notes

- Uses SQLite by default (persists in `./roadguard.db`)
- For production PostgreSQL: set `DATABASE_URL=postgresql://...`
- No ML models required — sensor inference is simulated with signal stats
- The simulation produces realistic hazard classifications (~86% match rate)
