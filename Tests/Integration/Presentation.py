#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise installed TUI/GUI draft persistence in an explicit synthetic offline fixture."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import struct
import subprocess
import tempfile
import termios
import time


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=10, **kwargs)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def draft(args):
    result = run([args.binary, "draft", "get", "--profile", args.profile, "--room", args.room], capture_output=True)
    return json.loads(result.stdout)["draft"]


def tui(args):
    initial = draft(args)
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 100, 0, 0))
    process = subprocess.Popen([args.binary, "tui", "--profile", args.profile, "--offline"], stdin=slave, stdout=slave, stderr=slave, env={**os.environ, "TERM": "xterm-256color"})
    os.close(slave)
    captured = bytearray()

    def wait_for(predicate):
        end = time.monotonic() + 12
        while time.monotonic() < end:
            if select.select([master], [], [], 0.1)[0]:
                captured.extend(os.read(master, 65536))
                del captured[:-131072]
                if predicate(re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", bytes(captured))):
                    return
            if process.poll() is not None:
                raise AssertionError("TUI exited before its expected state")
        raise AssertionError("TUI state deadline expired")

    text = "TUI durable draft: e\u0301 👩‍🚀 漢字 " + secrets.token_hex(3)
    try:
        wait_for(lambda data: b"laboratory" in data and initial.encode() in data)
        captured.clear()
        os.write(master, b"\x01\x1b[200~" + text.encode() + b"\x1b[201~")
        wait_for(lambda data: text.encode() in data and data.rfind(b"Draft saved locally") > data.rfind(text.encode()))
        os.write(master, b"\x11")
        assert process.wait(timeout=5) == 0
        assert draft(args) == text
    finally:
        stop(process)
        os.close(master)
    return {"unicodeDraftPersistedAcrossExit": True}


def gui(args, output):
    with tempfile.TemporaryDirectory(prefix="hrc-ui-") as directory:
        auth = Path(directory) / "Xauthority"
        auth.touch(mode=0o600)
        display = next(f":{i}" for i in range(180, 250) if not Path(f"/tmp/.X11-unix/X{i}").exists())
        run(["xauth", "-f", str(auth)], input=f"add {display} . {secrets.token_hex(16)}\n".encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env = {**os.environ, "DISPLAY": display, "XAUTHORITY": str(auth), "LIBGL_ALWAYS_SOFTWARE": "1", "GALLIUM_DRIVER": "llvmpipe"}
        server = subprocess.Popen(["Xvfb", display, "-auth", str(auth), "-nolisten", "tcp", "-screen", "0", "1280x900x24"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process = None
        clipboard = None
        try:
            end = time.monotonic() + 10
            while not Path(f"/tmp/.X11-unix/X{display[1:]}").exists():
                assert server.poll() is None and time.monotonic() < end
                time.sleep(0.05)
            with (output / "Gui.log").open("wb") as log:
                process = subprocess.Popen([args.binary, "gui", "--profile", args.profile, "--offline"], env=env, stdout=log, stderr=log)
                end = time.monotonic() + 15
                window = None
                while time.monotonic() < end:
                    result = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid", str(process.pid), "--name", "HyperNet Relay Chat"], env=env, capture_output=True, timeout=2)
                    if result.returncode == 0 and result.stdout.strip():
                        window = result.stdout.splitlines()[0].decode()
                        break
                    assert process.poll() is None, "GUI exited during startup"
                    time.sleep(0.1)
                assert window, "GUI startup deadline expired"
                run(["xdotool", "windowfocus", "--sync", window], env=env)
                time.sleep(0.5)
                run(["import", "-window", "root", str(output / "GuiBefore.png")], env=env)
                text = "GUI durable draft: e\u0301 👩‍🚀 漢字 " + secrets.token_hex(3)
                run(["xdotool", "key", "ctrl+l", "ctrl+a"], env=env)
                clipboard = subprocess.Popen(["xclip", "-quiet", "-selection", "clipboard", "-loops", "1"], env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                clipboard.stdin.write(text.encode())
                clipboard.stdin.close()
                time.sleep(0.1)
                run(["xdotool", "key", "ctrl+v"], env=env)
                time.sleep(0.8)
                run(["import", "-window", "root", str(output / "GuiAfter.png")], env=env)
                run(["xdotool", "key", "ctrl+q"], env=env)
                assert process.wait(timeout=8) == 0
                assert draft(args) == text
        finally:
            if clipboard is not None:
                stop(clipboard)
            if process is not None:
                stop(process)
            stop(server)
    return {"unicodeClipboardDraftPersistedAcrossExit": True, "softwareRenderer": True, "isolatedDisplayCleaned": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--room", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--interface", choices=["both", "gui", "tui"], default="both")
    args = parser.parse_args()
    marker = Path(args.profile) / "Fixture.txt"
    assert marker.read_text().startswith("OFFLINE PRESENTATION FIXTURE\n"), "Refuse a normal user profile"
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = {"scope": "Synthetic offline persistence and presentation only; no native admission or delivery claim", "binarySha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(), "passed": False}
    try:
        if args.interface in ("both", "tui"):
            report["tui"] = tui(args)
        if args.interface in ("both", "gui"):
            report["gui"] = gui(args, output)
        report["passed"] = True
    finally:
        path = output / "Presentation.json"
        previous = json.loads(path.read_text()) if path.exists() else {}
        attempts = previous.get("attempts", [previous] if previous else [])
        attempts.append(report)
        path.write_text(json.dumps({"attempts": attempts}, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
