# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests",
# ]
# ///

import asyncio

import requests

from flask import Flask, request, Response
import os
import requests

app = Flask(__name__)


@app.route("/request")
def smoke():
    asyncio.run(make_request())
    return Response(status=200)

async def make_request() -> None:
    # Runs the blocking IO in a thread pool
    status_code = await asyncio.to_thread(
        lambda: requests.get("https://github.com").status_code
    )
    print(status_code)


if __name__ == '__main__':
    print(f"Server running: port={8380} process_id={os.getpid()}")
    app.run(host="localhost", port=8380, debug=False)
