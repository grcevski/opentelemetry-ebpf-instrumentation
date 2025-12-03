# Using FastAPI
from fastapi import FastAPI, APIRouter, Request
import uvicorn
import requests
import os
import asyncio

app = FastAPI()
router = APIRouter()

@router.post("/collect")
async def collect(request: Request):
    data = await request.json()
    resp = await asyncio.to_thread(lambda: requests.get("https://github.com", json=data))
    return {"status": "sent to embedding"}

app.include_router(router)

if __name__ == '__main__':
    print(f"Server running: port=8180 process_id={os.getpid()}")
    uvicorn.run(app, host="localhost", port=8180)
