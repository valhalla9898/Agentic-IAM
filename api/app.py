"""
Simplified Agentic-IAM API Server - No circular imports
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Create the FastAPI app
app = FastAPI(
    title="Agentic-IAM API",
    description="Comprehensive Agent Identity & Access Management Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root endpoint
@app.get("/")
async def root():
    return {
        "name": "Agentic-IAM API",
        "version": "1.0.0",
        "description": "Comprehensive Agent Identity & Access Management Platform",
        "docs": "/docs",
        "health": "/health",
        "graphql": "/graphql",
        "mobile": "/api/v1/mobile"
    }

# Health endpoint
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "agentic-iam-api"}

# GraphQL endpoint stub
@app.get("/graphql")
async def graphql_playground():
    return {
        "message": "GraphQL endpoint available",
        "schema": "Query { agents, agent, trustScore }",
        "documentation": "See /docs for details"
    }

# Mobile API endpoints
@app.post("/api/v1/mobile/register")
async def mobile_register(agent_name: str, platform: str = "mobile"):
    """Register a mobile agent"""
    agent_id = f"agent_mobile_{agent_name}_{hash(agent_name) & 0xffffffff:x}"
    return {
        "agent_id": agent_id,
        "registration_id": f"reg_{agent_id}",
        "status": "registered"
    }

@app.post("/api/v1/mobile/heartbeat")
async def mobile_heartbeat(agent_id: str):
    """Mobile agent heartbeat"""
    return {
        "status": "ok",
        "agent_id": agent_id,
        "timestamp": "2025-12-28T00:00:00Z"
    }

# API info endpoint
@app.get("/api/v1")
async def api_info():
    return {
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "mobile": "/api/v1/mobile",
            "graphql": "/graphql"
        },
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "api.app:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
