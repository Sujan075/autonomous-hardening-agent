from contextlib import asynccontextmanager
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.targets import router as targets_router
from app.api.agent_status import router as agent_status_router
from app.api.enrollments import router as enrollments_router
from app.api.policies import router as policies_router
from app.api.audit import router as audit_router
from app.api.demo import router as demo_router
from app.db.database import engine
from app.db.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Autonomous Multi-Platform Security Hardening Agent",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

if os.environ.get("AHA_DASHBOARD_CORS", "").strip() == "1":
    # Vite's local origins only. No credentials, write methods, or arbitrary
    # configured origins are allowed by this demo bridge.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_credentials=False,
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["Authorization", "Accept", "Content-Type"],
        max_age=300,
    )

app.include_router(targets_router)
app.include_router(agent_status_router)
app.include_router(enrollments_router)
app.include_router(policies_router)
app.include_router(demo_router)
app.include_router(audit_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
