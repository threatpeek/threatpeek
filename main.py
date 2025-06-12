from fastapi import FastAPI
from routes import scan

app = FastAPI(title="ThreatPeek PH API")

# Register your modular route files here
app.include_router(scan.router, prefix="/api", tags=["Scan"])

@app.get("/")
def root():
    return {"message": "ThreatPeek PH API is live."}
