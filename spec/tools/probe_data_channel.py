#!/usr/bin/env python3
"""Check a terminal data ticket and the data-channel handshake against rux."""
import os
import re
import sys
import base64
import struct
import select
import time

sys.path.insert(0, os.path.dirname(__file__))
from rexclient import WS  # noqa: E402

CONTROL_EVENTS = []


def control_request(ws, request_id, method, payload):
    ws.send_json(
        {"type": "request", "id": request_id, "method": method, "payload": payload}
    )
    last_event_seq = 0
    while True:
        message = ws.recv_json()
        if message.get("type") == "event":
            CONTROL_EVENTS.append(message)
            last_event_seq = max(last_event_seq, message.get("seq", 0))
        if message.get("type") == "response" and message.get("id") == request_id:
            if "error" in message:
                raise RuntimeError(message["error"])
            assert message.get("seq", -1) >= last_event_seq, (
                f"response seq {message.get('seq')} is behind already-queued "
                f"event seq {last_event_seq} for {method}"
            )
            return message["payload"]


def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def validate_snapshot(snapshot):
    assert snapshot.startswith(b"GHOSTSNP\x01\x00"), snapshot[:16].hex()
    offset = 10
    tags = []
    finish_end = None
    while offset + 10 <= len(snapshot):
        tag, length, checksum = struct.unpack_from("<HII", snapshot, offset)
        end = offset + 10 + length
        assert end <= len(snapshot), f"truncated snapshot record {tag}"
        prefix = snapshot[offset : offset + 6]
        payload = snapshot[offset + 10 : end]
        assert crc32c(prefix + payload) == checksum, f"bad CRC32C on record {tag}"
        tags.append(tag)
        offset = end
        if tag == 6:  # FINISH
            finish_end = end
            break
    assert finish_end is not None, "snapshot has no FINISH record"
    assert tags == [1, 2, 3, 7, 5, 4, 6], tags
    return snapshot[finish_end:]


control = WS()
control.send_json(
    {
        "type": "hello",
        "client": {
            "kind": "cli",
            "platform": "macos",
            "name": "rux-data-probe",
            "version": "0.0.0",
        },
        "api_revision": 7,
    }
)
control.recv_json()
created = control_request(
    control,
    "create",
    "session.create",
    {
        "label": "rux-data-channel-probe",
        "initial_windows": [
            {
                "layout": {
                    "block": {
                        "flavor": "com.superlogical.terminal.shell",
                        "label": "data",
                        "options": {
                            "command": [
                                "/bin/sh",
                                "-c",
                                "sleep 0.3; printf '\\033]0;RUX_TITLE_PROBE\\007'; "
                                "IFS= read -r line; printf RUX_DATA_STREAM_OK; exec /bin/sleep 10",
                            ]
                        },
                    }
                },
            }
        ],
    },
)
session_id = created["session_id"]
block_id = created["initial_windows"][0]["block_ids"][0]
try:
    attached = control_request(
        control, "attach", "session.attach", {"session_id": session_id}
    )
    assert attached["view"]["windows"][0]["label"].startswith("Window "), attached
    ticket = control_request(
        control,
        "ticket",
        "data.connect",
        {
            "session_id": session_id,
            "block_id": block_id,
            "data_ref_id": "terminal",
            "subprotocol": "rex.data.terminal.v1",
        },
    )["ticket"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", ticket), ticket
    data = WS(path="/api/data", protocol="rex.data.terminal.v1")
    ticket_bytes = base64.urlsafe_b64decode(ticket + "==")
    assert len(ticket_bytes) == 16
    data._frame(2, b"\x01" + ticket_bytes)  # binary HELLO
    opcode, welcome = data.recv_frame()
    assert opcode == 2 and len(welcome) == 32, (opcode, len(welcome), welcome.hex())
    assert welcome[0] == 0x81 and welcome[17:20] == b"\x00\x00\x00", welcome.hex()
    nonce = struct.unpack_from("<Q", welcome, 24)[0]
    assert nonce != 0, welcome.hex()
    opcode, snapshot = data.recv_frame()
    assert opcode == 2, opcode
    post_snapshot = validate_snapshot(snapshot)
    assert post_snapshot.startswith(f"\x1b_rex1;{nonce};".encode()), post_snapshot[:80]
    control_request(
        control,
        "write",
        "block.method",
        {
            "session_id": session_id,
            "block_id": block_id,
            "method": "write",
            "args": {"data": "go\n"},
        },
    )
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        found_title = False
        found_sleep_process = False
        for message in CONTROL_EVENTS:
            session_event = message.get("payload", {}).get("payload", {})
            block_event = session_event.get("event", {})
            if block_event.get("type") != "block_event":
                continue
            details = block_event.get("payload", {})
            event_payload = details.get("payload", {})
            if details.get("name") == "title_changed":
                found_title |= event_payload.get("title") == "RUX_TITLE_PROBE"
            if details.get("name") == "process_changed":
                found_sleep_process |= bool(
                    event_payload.get("generation", 0)
                    and event_payload.get("foreground", {}).get("name") == "sleep"
                )
        if found_title and found_sleep_process:
            break
        ready, _, _ = select.select(
            [control.s], [], [], max(0.0, deadline - time.monotonic())
        )
        if not ready:
            break
        message = control.recv_json()
        if message.get("type") == "event":
            CONTROL_EVENTS.append(message)
    assert found_title, CONTROL_EVENTS
    assert found_sleep_process, CONTROL_EVENTS
    data.s.settimeout(3)
    output = bytearray()
    for _ in range(8):
        message_opcode, message = data.recv_frame()
        assert message_opcode == 2, message_opcode
        output.extend(message)
        if b"RUX_DATA_STREAM_OK" in output:
            break
    assert b"RUX_DATA_STREAM_OK" in output, bytes(output[:160])
    print("binary data handshake, Ghostty snapshot, title/process events, and live output passed")
    try:
        data._frame(8, b"")
    except Exception:
        pass
finally:
    control_request(
        control, "destroy", "session.destroy", {"session_id": session_id}
    )
    try:
        control._frame(8, b"")
    except Exception:
        pass
