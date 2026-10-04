from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.targets import router as targets_router
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
)

app.include_router(targets_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
