"""Main FastAPI application."""

import logging
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .core.config import settings
from .core.database import engine, get_db, Base
from .api import techniques, queries, threat_intel, campaigns, enrichment, cves, threat_actors, enhanced_queries

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title="Automated Threat Hunt Generator",
    description="Generate platform-specific threat hunting queries from MITRE ATT&CK techniques",
    version="0.1.0",
    debug=settings.DEBUG
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(techniques.router, prefix="/api/techniques", tags=["techniques"])
app.include_router(queries.router, prefix="/api/queries", tags=["queries"])
app.include_router(enhanced_queries.router, prefix="/api/enhanced-queries", tags=["enhanced-queries"])
app.include_router(threat_intel.router, prefix="/api/threat-intel", tags=["threat-intel"])
app.include_router(campaigns.router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(enrichment.router)  # Already has prefix
app.include_router(cves.router)  # Already has prefix
app.include_router(threat_actors.router)  # Already has prefix


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Automated Threat Hunt Generator API",
        "version": "0.1.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )
