# Using FastAPI
from fastapi import FastAPI
import httpx  # async HTTP client
import uvicorn
import os

app = FastAPI()

@app.get("/request")
async def smoke():
    async with httpx.AsyncClient() as client:
        response = await client.get("https://github.com")
        print(response.status_code)
    return {"status": "ok"}

if __name__ == "__main__":
    print(f"Server running: port={8180} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8180)