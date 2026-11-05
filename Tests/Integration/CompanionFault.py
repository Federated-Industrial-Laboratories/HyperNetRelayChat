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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def exact(stream, count, end=None):
    value = bytearray()
    while len(value) < count:
        if end is not None:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('fault proxy connection deadline')
            stream.settimeout(min(30, remaining))
        part = stream.recv(count - len(value))
        if not part:
            raise EOFError('peer closed')
        value.extend(part)
    return bytes(value)


def control(stream, end=None):
    header = exact(stream, 4, end)
    length = int.from_bytes(header, 'big')
    if not 0 < length <= 16384:
        raise ValueError('companion frame exceeds bound')
    body = exact(stream, length, end)
    return header + body, json.loads(body)


def frame(stream, end):
    header = exact(stream, 5, end)
    length, kind = int.from_bytes(header[:4], 'big'), header[4]
    maximum = 262144 if kind in (10, 11, 12, 17) else 65536
    if not 1 <= kind <= 18 or not 2 <= length <= maximum:
        raise ValueError('HRC frame exceeds bound')
    return header + exact(stream, length - 1, end)


def decode(data, depth_limit=16, maximum=65535):
    """The bounded canonical CBOR subset in WireProtocol.md, without coercion."""
    if not isinstance(data, bytes) or len(data) > maximum:
        raise ValueError('CBOR byte bound')
    position, nodes = 0, 0

    def take(count):
        nonlocal position
        if count > len(data) - position:
            raise ValueError('truncated CBOR')
        result = data[position:position + count]
        position += count
        return result

    def item(depth):
        nonlocal nodes
        nodes += 1
        if depth > depth_limit or nodes > 4096:
            raise ValueError('CBOR work bound')
        first = take(1)[0]
        major, info = first >> 5, first & 31
        if major == 7 and info in (20, 21, 22):
            return {20: False, 21: True, 22: None}[info]
        if major >= 6 or info > 27:
            raise ValueError('unsupported CBOR')
        if info < 24:
            argument = info
        else:
            size = 1 << (info - 24)
            argument = int.from_bytes(take(size), 'big')
            if argument < {1: 24, 2: 256, 4: 65536, 8: 4294967296}[size]:
                raise ValueError('noncanonical CBOR argument')
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major in (2, 3):
            value = take(argument)
            return value if major == 2 else value.decode('utf-8')
        if argument > 256:
            raise ValueError('CBOR collection bound')
        if major == 4:
            return [item(depth + 1) for _ in range(argument)]
        result, previous = {}, None
        for _ in range(argument):
            start = position
            key = item(depth + 1)
            encoded = data[start:position]
            if not (type(key) is int and key >= 0 or isinstance(key, str)):
                raise ValueError('CBOR map key')
            if previous is not None and previous >= encoded:
                raise ValueError('noncanonical CBOR map')
            previous = encoded
            result[key] = item(depth + 1)
        return result

    result = item(1)
    if position != len(data):
        raise ValueError('trailing CBOR')
    return result


def byte_string(value):
    length = len(value)
    if length < 24:
        return bytes([0x40 + length]) + value
    if length <= 255:
        return b'\x58' + bytes([length]) + value
    return b'\x59' + length.to_bytes(2, 'big') + value


def envelope(payload, role):
    parts = decode(payload)
    if not isinstance(parts, list) or len(parts) != 4:
        raise ValueError('COSE envelope')
    protected, unprotected, body, signature = parts
    if unprotected != {} or not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError('COSE headers or signature')
    headers = decode(protected, depth_limit=2, maximum=512)
    content = decode(body, depth_limit=14)
    if (not isinstance(content, list) or len(content) != 3
            or type(content[0]) is not int or content[0] != 1
            or type(content[1]) is not int or content[1] != role
            or not isinstance(content[2], dict)):
        raise ValueError('signed payload role')
    return headers, protected, body, signature, content[2]


def identifier(value):
    return isinstance(value, bytes) and len(value) == 32


def operation_key(value):
    if (not isinstance(value, dict) or set(value) != {'window', 'operation'}
            or not all(identifier(part) for part in value.values())):
        raise ValueError('operation ID')
    return value['window'], value['operation']


class CommittedSend:
    """Observe exact requests; only the independently pinned service can attest commit."""
    def __init__(self, signing_key, home, room):
        self.public = signing_key
        self.key = Ed25519PublicKey.from_public_bytes(signing_key)
        self.home, self.room = home, room
        self.pending = {}

    def request(self, payload):
        _, _, body, _, action = envelope(payload, 1)
        if (set(action) != {'home', 'operationId', 'actor', 'target', 'operation',
                           'body', 'expected', 'approval', 'agreement'}
                or type(action['operation']) is not int or action['operation'] != 20
                or action['home'] != self.home
                or action['target'] != {'kind': 'room', 'id': self.room}):
            return
        key = operation_key(action['operationId'])
        if key not in self.pending and len(self.pending) >= 16:
            raise ValueError('fault correlation bound')
        # This is the Action payload digest, not a hash of its signature or frame.
        self.pending[key] = hashlib.sha256(body).digest()

    def response(self, payload):
        headers, protected, body, signature, response = envelope(payload, 7)
        if set(response) != {'home', 'operationId', 'actionDigest', 'outcome'}:
            return False
        key = operation_key(response['operationId'])
        if (response['home'] != self.home or key not in self.pending
                or response['actionDigest'] != self.pending[key]):
            return False
        outcome = response['outcome']
        if (not isinstance(outcome, dict)
                or set(outcome) != {'status', 'event', 'position', 'body'}
                or outcome['status'] != 'committed' or not identifier(outcome['event'])
                or type(outcome['position']) is not int or outcome['position'] <= 0):
            return False
        if headers != {1: -19, 3: 'application/hrc-response+cbor;v=1',
                       4: hashlib.sha256(self.public).digest()}:
            return False
        signed = b'\x84\x6aSignature1' + byte_string(protected) + byte_string(b'HRC/1') + byte_string(body)
        self.key.verify(signature, signed)
        return True


def wire_home(home):
    return {'network': {key: bytes.fromhex(home['network'][key])
                        for key in ('network', 'incarnation')},
            'service': bytes.fromhex(home['service'])}


class DropResponseProxy:
    """Forward real responses exactly, losing one verified MessageSend commit.

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
        self.binding = None
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

    def arm(self, signing_key, home, room):
        public = bytes.fromhex(signing_key)
        home = wire_home(home)
        room = {'home': wire_home(room['home']), 'local': bytes.fromhex(room['local'])}
        if (len(public) != 32 or room['home'] != home or not identifier(room['local'])
                or not identifier(home['service']) or not all(map(identifier, home['network'].values()))):
            raise ValueError('fault selection binding')
        with self.lock:
            if self.armed or self.dropped.is_set():
                raise RuntimeError('one fault per proxy instance')
            self.armed = True
            self.binding = public, home, room

    def _accept(self):
        while not self.stop.is_set():
            try:
                caller, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.workers = [worker for worker in self.workers if worker.is_alive()]
                if len(self.workers) >= 8:
                    caller.close()
                    continue
                self.sockets.add(caller)
            worker = threading.Thread(target=self._connection, args=(caller,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _connection(self, caller):
        remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        forwarding = None
        try:
            end = time.monotonic() + 60
            with self.lock:
                if self.stop.is_set():
                    return
                self.sockets.add(remote)
            caller.settimeout(30)
            remote.settimeout(30)
            remote.connect(str(self.upstream / 'Control.sock'))
            _, uid, _ = struct.unpack('3i', remote.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid():
                raise ValueError('real companion owner differs')
            request_bytes, request = control(caller, end)
            remote.sendall(request_bytes)
            response_bytes, response = control(remote, end)
            caller.sendall(response_bytes)
            if request.get('action') != 'connect' or not response.get('ok'):
                return
            with self.lock:
                selection = CommittedSend(*self.binding) if self.armed else None
            forwarding = threading.Thread(target=self._upstream, args=(caller, remote, end, selection), daemon=True)
            forwarding.start()
            while not self.stop.is_set() and time.monotonic() < end:
                received = frame(remote, end)
                with self.lock:
                    drop = False
                    if self.armed and received[4] == 6 and selection is not None:
                        try:
                            drop = selection.response(received[5:])
                        except (ValueError, TypeError, InvalidSignature):
                            pass  # An unverified or unrelated response is never the injected loss.
                    if drop:
                        self.armed = False
                        self.evidence = {'frameKind': 6, 'operation': 'MessageSend',
                                         'verifiedCommittedResponse': True, 'bytes': len(received),
                                         'sha256': hashlib.sha256(received).hexdigest(),
                                         'realCompanionMetadataUnchanged': True}
                        self.dropped.set()
                if drop:
                    break
                caller.sendall(received)
        except (EOFError, ConnectionError, socket.timeout):
            pass
        except OSError as error:
            if not self.stop.is_set():
                self._error(error)
        except Exception as error:
            self._error(error)
        finally:
            self._close(caller)
            self._close(remote)
            if forwarding is not None:
                forwarding.join(timeout=2)

    def _upstream(self, caller, remote, end, selection):
        try:
            while not self.stop.is_set():
                data = frame(caller, end)
                with self.lock:
                    if self.armed and data[4] == 5 and selection is not None:
                        try:
                            selection.request(data[5:])
                        except (ValueError, TypeError):
                            # Pass malformed input unchanged; it cannot qualify as an ACK loss.
                            selection.pending.clear()
                remote.sendall(data)
        except (OSError, EOFError):
            return
        except Exception as error:
            self._error(error)
        finally:
            try:
                remote.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _error(self, error):
        with self.lock:
            if len(self.errors) < 16:
                self.errors.append(type(error).__name__[:64])

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
