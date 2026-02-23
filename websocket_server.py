import asyncio
import websockets
import json
from collections import deque

connected_clients = set()
alert_queue = deque()

async def handler(websocket):
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.discard(websocket)

async def queue_alert(data: dict):
    alert_queue.append(data)

async def process_queue():
    while True:
        if alert_queue and connected_clients:
            data = alert_queue.popleft()
            message = json.dumps(data)
            await asyncio.gather(*[c.send(message) for c in connected_clients])
        await asyncio.sleep(0.2)

async def start_server():
    async with websockets.serve(handler, "localhost", 8765):
        asyncio.create_task(process_queue())
        await asyncio.Future()