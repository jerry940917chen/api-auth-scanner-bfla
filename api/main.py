from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scanner.db import init_db
from api.routers import projects_router, scans_router

app = FastAPI(title="API Auth Scanner MVP", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request, call_next):
    import logging
    logger = logging.getLogger("api")
    logger.info(f"Request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    return response

# Startup
@app.on_event("startup")
def on_startup():
    init_db()

# Include Routers
app.include_router(projects_router)
app.include_router(scans_router)

@app.get("/health")
def health():
    return {"status": "ok", "service": "scanner"}
