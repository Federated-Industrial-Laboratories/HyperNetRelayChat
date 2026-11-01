# SPDX-License-Identifier: Apache-2.0
"""Bounded transparent Unix fault injector; it never fabricates HyperNet context."""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time


def exact(stream, count):
    value = bytearray()
    while len(value) < count:
        part = stream.recv(count - len(value))
        if not part:
            raise EOFError('peer closed')
        value.extend(part)
    return bytes(value)


def control(stream):
    header = exact(stream, 4)
    length = int.from_bytes(header, 'big')
    if not 0 < length <= 16384:
        raise ValueError('companion frame exceeds bound')
    body = exact(stream, length)
    return header + body, json.loads(body)


class DropResponseProxy:
    """Forward real companion responses exactly, dropping one complete HRC response.

    The original companion must be stopped before this listener takes its path.
    Its actual replacement runs in `upstream`; all credentials and authority
    decisions remain there. Only one explicitly armed response is discarded.
    """
    def __init__(self, directory, upstream):
        self.directory = Path(directory).resolve(strict=True)
        self.upstream = Path(upstream).resolve(strict=True)
        for directory in (self.directory, self.upstream):
            meta = directory.stat()
            if meta.st_uid != os.geteuid() or meta.st_mode & 0o777 != 0o700:
                raise ValueError('fault proxy requires private owner directories')
        self.stop = threading.Event()
        self.dropped = threading.Event()
        self.lock = threading.Lock()
        self.armed = False
        self.evidence = None
        self.errors = []
        self.sockets = set()
        self.workers = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.path = self.directory / 'Control.sock'
        self.listener.bind(str(self.path))
        self.path.chmod(0o600)
        self.listener.listen(8)
        self.listener.settimeout(.2)
        self.thread = threading.Thread(target=self._accept, name='hrc-fault-listener', daemon=True)
        self.thread.start()

    def arm(self):
        with self.lock:
            if self.armed or self.dropped.is_set():
                raise RuntimeError('one fault per proxy instance')
            self.armed = True

    def _accept(self):
        while not self.stop.is_set():
            try:
                caller, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                if len(self.sockets) >= 16:
                    caller.close()
                    continue
                self.sockets.add(caller)
            worker = threading.Thread(target=self._connection, args=(caller,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _connection(self, caller):
        remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            caller.settimeout(30)
            remote.settimeout(30)
            remote.connect(str(self.upstream / 'Control.sock'))
            _, uid, _ = struct.unpack('3i', remote.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid():
                raise ValueError('real companion owner differs')
            with self.lock:
                self.sockets.add(remote)
            request_bytes, request = control(caller)
            remote.sendall(request_bytes)
            response_bytes, response = control(remote)
            caller.sendall(response_bytes)
            if request.get('action') != 'connect' or not response.get('ok'):
                return
            forwarding = threading.Thread(target=self._upstream, args=(caller, remote), daemon=True)
            forwarding.start()
            end = time.monotonic() + 60
            while not self.stop.is_set() and time.monotonic() < end:
                header = exact(remote, 5)
                length = int.from_bytes(header[:4], 'big')
                if not 2 <= length <= 262144:
                    raise ValueError('HRC frame exceeds bound')
                frame = header + exact(remote, length - 1)
                with self.lock:
                    drop = self.armed and header[4] == 6
                    if drop:
                        self.armed = False
                        self.evidence = {'frameKind': 6, 'bytes': len(frame),
                                         'sha256': hashlib.sha256(frame).hexdigest(),
                                         'realCompanionMetadataUnchanged': True}
                        self.dropped.set()
                if drop:
                    break
                caller.sendall(frame)
            self._close(caller)
            self._close(remote)
            forwarding.join(timeout=2)
        except (EOFError, ConnectionError, socket.timeout):
            pass
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append(type(error).__name__)
        except Exception as error:
            self.errors.append(type(error).__name__)
        finally:
            self._close(caller)
            self._close(remote)

    def _upstream(self, caller, remote):
        try:
            while not self.stop.is_set():
                data = caller.recv(16384)
                if not data:
                    remote.shutdown(socket.SHUT_WR)
                    return
                remote.sendall(data)
        except (OSError, EOFError):
            return

    def _close(self, stream):
        try:
            stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        stream.close()
        with self.lock:
            self.sockets.discard(stream)

    def close(self):
        self.stop.set()
        self.listener.close()
        with self.lock:
            active = list(self.sockets)
        for stream in active:
            self._close(stream)
        self.thread.join(timeout=2)
        end = time.monotonic() + 5
        for worker in self.workers:
            worker.join(timeout=max(0, end-time.monotonic()))
        self.path.unlink(missing_ok=True)
        if any(worker.is_alive() for worker in self.workers):
            raise RuntimeError('fault proxy worker did not stop')
