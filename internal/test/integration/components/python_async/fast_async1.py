# Using FastAPI
from fastapi import FastAPI
import uvicorn
import requests
import os
import asyncio

app = FastAPI()

async def make_request() -> None:
    # Runs the blocking IO in a thread pool
    status_code = await asyncio.to_thread(
        lambda: requests.get("https://github.com").status_code
    )
    print(status_code)

@app.get("/request")
async def smoke():
    response = await make_request()
    return {"status": "ok"}

if __name__ == "__main__":
    print(f"Server running: port={8180} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8180)