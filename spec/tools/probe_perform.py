#!/usr/bin/env python3
"""Exercise client.perform and client.reply on two rux control connections."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from rexclient import WS  # noqa: E402


def connect(name):
    ws = WS()
    ws.send_json(
        {
            "type": "hello",
            "client": {
                "kind": "cli",
                "platform": "macos",
                "name": name,
                "version": "0.0.0",
            },
            "api_revision": 7,
        }
    )
    return ws, ws.recv_json()


def request(ws, request_id, method, payload):
    ws.send_json(
        {"type": "request", "id": request_id, "method": method, "payload": payload}
    )
    while True:
        message = ws.recv_json()
        if message.get("type") == "response" and message.get("id") == request_id:
            return message


def read_perform_event(ws):
    while True:
        message = ws.recv_json()
        if (
            message.get("type") == "event"
            and message.get("payload", {}).get("type") == "client_perform_requested"
        ):
            return message["payload"]["payload"]


def read_performed_event(ws):
    while True:
        message = ws.recv_json()
        payload = message.get("payload", {})
        if message.get("type") == "event" and payload.get("type") == "client_performed":
            return payload["payload"]


def call_and_reply(caller, target, target_id, request_id, reply):
    caller.send_json(
        {
            "type": "request",
            "id": request_id,
            "method": "client.perform",
            "payload": {
                "client_id": target_id,
                "action": "probe.echo",
                "args": {"value": request_id},
                "timeout_ms": 2000,
            },
        }
    )
    event = read_perform_event(target)
    assert event["action"] == "probe.echo"
    assert event["args"] == {"value": request_id}
    assert event["requester"]["client_id"]
    reply_payload = {"call_id": event["call_id"], **reply}
    result = request(target, f"reply-{request_id}", "client.reply", reply_payload)
    assert "error" not in result, result

    while True:
        response = caller.recv_json()
        if response.get("type") == "response" and response.get("id") == request_id:
            return response


target = None
caller = None
watcher = None
try:
    target, welcome = connect("rux-perform-target")
    target_id = welcome["client"]["id"]
    watcher, _ = connect("rux-perform-watch")
    assert "error" not in request(
        watcher, "attach-all", "session.attach_all", {"event_scope": "all"}
    )
    assert "error" not in request(
        target, "label", "client.set_label", {"label": "  perform target  "}
    )
    inspected = request(
        target, "inspect", "client.inspect", {"client_id": target_id}
    )
    assert inspected["payload"]["client"]["info"]["label"] == "perform target"
    keymap = request(
        target,
        "keymap",
        "client.keymap",
        {"actions": [{"name": "probe.echo", "kind": "client"}]},
    )
    assert "error" not in keymap, keymap
    caller, _ = connect("rux-perform-caller")

    success = call_and_reply(
        caller, target, target_id, "perform-success", {"result": {"done": True}}
    )
    assert success["payload"] == {
        "performed_by": target_id,
        "result": {"done": True},
    }, success
    success_event = read_performed_event(watcher)
    assert success_event["action"] == "probe.echo" and success_event["client_id"] == target_id

    refused = call_and_reply(
        caller,
        target,
        target_id,
        "perform-refused",
        {"error": {"code": "refused", "message": "declined by test client"}},
    )
    assert refused.get("error", {}).get("code") == "refused", refused
    refused_event = read_performed_event(watcher)
    assert refused_event["error"]["code"] == "refused", refused_event
    print("client.perform/client.reply success and refusal paths passed")
finally:
    for ws in (caller, target, watcher):
        if ws is not None:
            try:
                ws._frame(8, b"")
            except Exception:
                pass
