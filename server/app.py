"""Voan Firewall dashboard server.

A tiny FastAPI app the SDK streams decisions to. It keeps a rolling buffer of
recent events, serves a live web dashboard, and pushes every new decision to
connected browsers over a WebSocket — so you literally watch the firewall allow
and block agent actions in real time.

Run:  uvicorn server.app:app --port 8088   (or: python server/app.py)
Then open http://127.0.0.1:8088
"""
import asyncio
import collections
import pathlib

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI(title="Voan Firewall")

_EVENTS = collections.deque(maxlen=500)   # rolling audit buffer
_CLIENTS = set()                          # connected dashboard sockets
_HTML = (pathlib.Path(__file__).parent / "dashboard.html").read_text("utf-8")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return _HTML


@app.get("/api/events")
def recent():
    """Replay the buffer so a freshly opened dashboard isn't empty."""
    return list(_EVENTS)


@app.post("/api/event")
async def ingest(request: Request):
    """The SDK posts one decision here; we buffer it and fan it out live."""
    evt = await request.json()
    _EVENTS.append(evt)
    await _broadcast(evt)
    return {"ok": True}


@app.websocket("/ws")
async def feed(ws: WebSocket):
    await ws.accept()
    _CLIENTS.add(ws)
    try:
        while True:
            await ws.receive_text()   # keep-alive; client never really sends
    except WebSocketDisconnect:
        pass
    finally:
        _CLIENTS.discard(ws)


async def _broadcast(evt):
    dead = []
    for ws in list(_CLIENTS):
        try:
            await ws.send_json(evt)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _CLIENTS.discard(ws)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8088)
