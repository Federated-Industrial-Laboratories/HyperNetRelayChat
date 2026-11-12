#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reply to !external with a scoped local Agent; retain exact plans before sending."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time


def save(path, value):
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--credential", type=Path, required=True)
    parser.add_argument("--room", required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--consumer", default="external-example")
    args = parser.parse_args()
    if args.state.parent.stat().st_mode & 0o077 or args.state.parent.stat().st_uid != os.geteuid():
        parser.error("The state directory must be private (mode 0700).")
    if args.credential.is_symlink() or args.credential.stat().st_mode & 0o077:
        parser.error("The credential must be private (mode 0600).")
    lock = os.open(args.state.with_name(args.state.name + ".lock"),
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("Another process owns this state file.")
    credential = json.loads(args.credential.read_text())
    if args.state.is_symlink() or (args.state.exists() and args.state.stat().st_mode & 0o077):
        parser.error("The state file must be private (mode 0600).")
    context = {"credential": credential["id"], "room": args.room, "consumer": args.consumer}
    state = json.loads(args.state.read_text()) if args.state.exists() else {
        "context": context, "pending": None, "batch": None, "handled": [], "ack": None}
    if state.get("context") != context:
        parser.error("Use the original credential, room and consumer for this state file.")

    def call(method, params=None):
        request = {"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": params or {}, "auth": credential}
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(45)
            stream.connect(str(args.socket))
            stream.sendall(json.dumps(request).encode() + b"\n")
            response = stream.makefile("rb").readline(1024 * 1024 + 1)
        if not response.endswith(b"\n") or len(response) > 1024 * 1024:
            raise RuntimeError("Invalid API response")
        response = json.loads(response)
        if "error" in response:
            if response["error"].get("data", {}).get("retryable"):
                raise TimeoutError(response["error"]["message"])
            raise RuntimeError(response["error"]["message"])
        return response["result"]

    opened = False
    while True:
        try:
            if not opened:
                call("events.open", {"consumer": args.consumer, "room": args.room})
                opened = True
            if state["pending"]:
                result = call("messages.reply", state["pending"])
                if result["status"] != "terminal":
                    time.sleep(2)
                    continue
                state["handled"].append(state["pending"]["trigger"])
                state["pending"] = None
                save(args.state, state)
            if state["ack"]:
                call("events.ack", {"consumer": args.consumer, "batch": state["ack"]})
                state.update(batch=None, handled=[], ack=None)
                save(args.state, state)
            batch = call("events.next", {"consumer": args.consumer})
            if state["batch"] != batch["id"]:
                state.update(batch=batch["id"], handled=[])
                save(args.state, state)
            if not batch["historical"]:
                content = dict(batch["content"])
                for event in batch["events"]:
                    if event["actor"].get("mode") != "direct":
                        continue
                    body = event.get("body", {})
                    decrypted = content.get(event["event"], {})
                    text = body.get("text") if isinstance(body, dict) else None
                    if isinstance(decrypted, dict):
                        text = decrypted.get("Decrypted", {}).get("text", text)
                    if text != "!external" or event["event"] in state["handled"]:
                        continue
                    status = call("status")
                    state["pending"] = {
                        "clientRequestId": status["nextClientRequestId"],
                        "room": args.room, "consumer": args.consumer,
                        "batch": batch["id"], "trigger": event["event"],
                        "text": "This reply came from the external Agent example."}
                    save(args.state, state)
                    break
            if not state["pending"]:
                state["ack"] = batch["id"]
                save(args.state, state)
            time.sleep(1)
        except (OSError, TimeoutError):
            # A lost response retains the exact pending ID, content and acknowledgement.
            time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped; retained state can be resumed.", file=sys.stderr)
    except RuntimeError as error:
        print(str(error) or "Stopped; retained state can be resumed.", file=sys.stderr)
        sys.exit(1)
