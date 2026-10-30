#!/usr/bin/env python3
"""Smoke-test OSC 7501 program-status parsing through a rux PTY block."""
import os
import sys
import time
import base64

sys.path.insert(0, os.path.dirname(__file__))
from rexclient import WS  # noqa: E402


ws = WS()
ws.send_json(
    {
        "type": "hello",
        "client": {
            "kind": "cli",
            "platform": "macos",
            "name": "rux-status-probe",
            "version": "0.0.0",
        },
        "api_revision": 7,
    }
)
ws.recv_json()
counter = 0


def request(method, payload=None, allow_error=False):
    global counter
    counter += 1
    request_id = f"status-{counter}"
    ws.send_json(
        {"type": "request", "id": request_id, "method": method, "payload": payload or {}}
    )
    while True:
        message = ws.recv_json()
        if message.get("type") == "response" and message.get("id") == request_id:
            if "error" in message and not allow_error:
                raise RuntimeError(message["error"])
            return message if "error" in message else message["payload"]


clipboard_text = "A" * 50_000 + "🙂"
clipboard_encoded = base64.b64encode(clipboard_text.encode()).decode()
command = (
    r"printf '\033]7501;state=working:app=rux-probe:msg=V29ya2luZw==\033\\'; "
    + rf"printf '\033]52;c;{clipboard_encoded}\007'; "
    + r"sleep 0.7; printf '\033]7501;state=clear\033\\'; sleep 30"
)
created = request(
    "session.create",
    {
        "label": "rux-status-probe",
        "initial_windows": [
            {
                "window_label": "status",
                "layout": {
                    "block": {
                        "flavor": "com.superlogical.terminal.shell",
                        "label": "status",
                        "options": {"command": ["/bin/sh", "-c", command]},
                    }
                },
            }
        ],
    },
)
session_id = created["session_id"]
block_id = created["initial_windows"][0]["block_ids"][0]
request("session.attach", {"session_id": session_id})
try:
    records = []
    for _ in range(30):
        records = request(
            "block.method",
            {
                "session_id": session_id,
                "block_id": block_id,
                "method": "program_status",
                "args": {},
            },
        )["records"]
        if records:
            break
        time.sleep(0.05)
    assert records and records[0]["state"] == "working", records
    assert records[0]["app"] == "rux-probe" and records[0]["msg"] == "Working", records

    copied = None
    for _ in range(30):
        response = request(
            "block.method",
            {
                "session_id": session_id,
                "block_id": block_id,
                "method": "clipboard_read",
                "args": {"id": 0, "offset": 0, "max_bytes": 512},
            },
            allow_error=True,
        )
        if "error" not in response:
            copied = response
            break
        time.sleep(0.05)
    assert copied is not None, "clipboard copy was not retained"
    assert copied["total"] == len(clipboard_text.encode()), copied
    assert copied["data"].startswith("A" * 100), copied

    cleared = []
    for _ in range(30):
        cleared = request(
            "block.method",
            {
                "session_id": session_id,
                "block_id": block_id,
                "method": "program_status",
                "args": {},
            },
        )["records"]
        if not cleared:
            break
        time.sleep(0.05)
    assert cleared == [], cleared
    print("OSC 7501 status and OSC 52 clipboard reads passed")
finally:
    request("session.destroy", {"session_id": session_id})
    try:
        ws._frame(8, b"")
    except Exception:
        pass
