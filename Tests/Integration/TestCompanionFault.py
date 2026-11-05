# SPDX-License-Identifier: Apache-2.0
"""Opaque transport context and exact, authenticated MessageSend acknowledgement loss."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

spec = importlib.util.spec_from_file_location('CompanionFault', Path(__file__).with_name('CompanionFault.py'))
fault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fault)


def cbor(value):
    def head(major, number):
        if number < 24:
            return bytes([major * 32 + number])
        for size, info in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if number < 1 << (8 * size):
                return bytes([major * 32 + info]) + number.to_bytes(size, 'big')
        raise ValueError('integer too large')
    if value is None:
        return b'\xf6'
    if type(value) is bool:
        return b'\xf5' if value else b'\xf4'
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode('utf-8')
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(map(cbor, value))
    entries = sorted((cbor(key), cbor(item)) for key, item in value.items())
    return head(5, len(entries)) + b''.join(key + item for key, item in entries)


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def signed(key, role, content):
    media = {1: 'action', 7: 'response'}[role]
    protected = cbor({1: -19, 3: 'application/hrc-' + media + '+cbor;v=1',
                      4: hashlib.sha256(public(key)).digest()})
    body = cbor([1, role, content])
    signature = key.sign(cbor(['Signature1', protected, b'HRC/1', body]))
    return cbor([protected, {}, body, signature])


def framed(kind, payload):
    return (len(payload) + 1).to_bytes(4, 'big') + bytes([kind]) + payload


class FaultBoundary(unittest.TestCase):
    def setUp(self):
        self.server = Ed25519PrivateKey.generate()
        self.client = Ed25519PrivateKey.generate()
        self.home = {'network': {'network': bytes([1]) * 32, 'incarnation': bytes([2]) * 32},
                     'service': bytes([3]) * 32}
        self.room = {'home': self.home, 'local': bytes([4]) * 32}
        self.json_home = {'network': {key: value.hex() for key, value in self.home['network'].items()},
                          'service': self.home['service'].hex()}
        self.json_room = {'home': self.json_home, 'local': self.room['local'].hex()}

    def action(self, operation=20, number=1):
        acting = {'account': {'origin': self.home['network'], 'local': bytes([5]) * 32},
                  'endpoint': bytes([6]) * 32, 'securityGeneration': 1, 'enrolmentGeneration': 1,
                  'bindingDigest': bytes([7]) * 32}
        return dict(home=self.home, operationId={'window': bytes([8]) * 32, 'operation': bytes([number]) * 32},
                    actor={'mode': 'direct', 'acting': acting}, target={'kind': 'room', 'id': self.room},
                    operation=operation, body={'text': 'Persisted message'} if operation == 20 else {},
                    expected={}, approval=None, agreement=None)

    def response(self, action, outcome=None):
        return dict(home=self.home, operationId=action['operationId'],
                    actionDigest=hashlib.sha256(cbor([1, 1, action])).digest(),
                    outcome=outcome or dict(status='committed', event=bytes([9]) * 32, position=1, body={}))

    def exchange(self, exchanges):
        """Each peer reply must pass intact except the last exact committed send."""
        with tempfile.TemporaryDirectory(prefix='hrc-fault-') as root:
            root = Path(root)
            visible, actual = root / 'Visible', root / 'Actual'
            visible.mkdir(mode=0o700); actual.mkdir(mode=0o700)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(actual / 'Control.sock')); (actual / 'Control.sock').chmod(0o600)
            listener.listen(1); listener.settimeout(3)
            request = b'{"version":2,"action":"connect","timeoutMs":1000,"service":"opaque"}'
            metadata = b'{"version":2,"ok":true,"id":"opaque","peer":{"unmodified":"context"}}'
            ready = framed(4, cbor([0]))  # Irrelevant payloads remain opaque to the injector.
            observed, failures = [], []

            def upstream():
                try:
                    with listener.accept()[0] as stream:
                        stream.settimeout(3)
                        observed.append(fault.exact(stream, 4 + len(request)))
                        stream.sendall(len(metadata).to_bytes(4, 'big') + metadata + ready)
                        for sent, reply in exchanges:
                            observed.append(fault.exact(stream, len(sent)))
                            stream.sendall(reply)
                except Exception as error:
                    failures.append(error)

            worker = threading.Thread(target=upstream)
            worker.start()
            proxy = fault.DropResponseProxy(visible, actual)
            try:
                proxy.arm(public(self.server).hex(), self.json_home, self.json_room)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(3); client.connect(str(visible / 'Control.sock'))
                    client.sendall(len(request).to_bytes(4, 'big') + request)
                    self.assertEqual(fault.exact(client, 4 + len(metadata)),
                                     len(metadata).to_bytes(4, 'big') + metadata)
                    self.assertEqual(fault.exact(client, len(ready)), ready)
                    for index, (sent, reply) in enumerate(exchanges):
                        client.sendall(sent)
                        if index + 1 == len(exchanges):
                            self.assertEqual(client.recv(1), b'')
                        else:
                            self.assertEqual(fault.exact(client, len(reply)), reply)
                            self.assertFalse(proxy.dropped.is_set())
                self.assertTrue(proxy.dropped.wait(1))
                self.assertEqual(proxy.evidence['bytes'], len(exchanges[-1][1]))
                self.assertEqual(proxy.evidence['sha256'], hashlib.sha256(exchanges[-1][1]).hexdigest())
                self.assertTrue(proxy.evidence['verifiedCommittedResponse'])
                self.assertEqual(proxy.errors, [])
                with self.assertRaisesRegex(RuntimeError, 'one fault'):
                    proxy.arm(public(self.server).hex(), self.json_home, self.json_room)
            finally:
                proxy.close(); listener.close(); worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(observed, [len(request).to_bytes(4, 'big') + request]
                             + [sent for sent, _ in exchanges])

    def test_preparatory_read_then_exact_committed_message(self):
        read, send = self.action(15, 10), self.action()
        self.exchange([
            (framed(5, signed(self.client, 1, read)), framed(6, signed(
                self.server, 7, self.response(read, {'status': 'result', 'body': {'confidentiality': 'community'}})))),
            (framed(5, signed(self.client, 1, send)), framed(6, signed(self.server, 7, self.response(send)))),
        ])

    def test_refusals_nonmatching_and_unverified_responses_pass(self):
        send = self.action()
        exchanges = []
        for field in ('refused', 'operation', 'digest', 'home', 'event', 'signature', 'role'):
            response = self.response(send)
            if field == 'refused':
                response['outcome'] = dict(status='refused', code='Unavailable', detail='CurrentAuthorityUnavailable',
                                           retryAfterMs=1000)
            elif field == 'operation':
                response['operationId'] = self.action(number=11)['operationId']
            elif field == 'digest':
                response['actionDigest'] = bytes([12]) * 32
            elif field == 'home':
                response['home'] = {**self.home, 'service': bytes([13]) * 32}
            elif field == 'event':
                response['outcome']['event'] = None
            signer = Ed25519PrivateKey.generate() if field == 'signature' else self.server
            reply = signed(signer, 1 if field == 'role' else 7, response)
            exchanges.append((framed(5, signed(self.client, 1, send)), framed(6, reply)))
        exchanges.append((framed(5, signed(self.client, 1, send)),
                          framed(6, signed(self.server, 7, self.response(send)))))
        self.exchange(exchanges)

    def test_other_room_or_operation_cannot_arm_a_matching_commit(self):
        selector = fault.CommittedSend(public(self.server), self.home, self.room)
        for action in (self.action(21), self.action()):
            if action['operation'] == 20:
                action['target'] = copy.deepcopy(action['target'])
                action['target']['id']['local'] = bytes([14]) * 32
            selector.request(signed(self.client, 1, action))
            self.assertFalse(selector.response(signed(self.server, 7, self.response(action))))

    def test_canonical_bounds_and_exact_signature_input(self):
        for invalid in (b'\x18\x01', b'\xa2\x01\x00\x01\x01', b'\x9f\xff',
                        b'\x81' * 16 + b'\x00', cbor([[]] * 257), b'\x00\x00'):
            with self.subTest(encoded=invalid[:8]), self.assertRaises(ValueError):
                fault.decode(invalid)
        self.assertEqual(fault.decode(b'\x81' * 15 + b'\x00'), [[[[[[[[[[[[[[[0]]]]]]]]]]]]]]])
        action = self.action()
        selector = fault.CommittedSend(public(self.server), self.home, self.room)
        selector.request(signed(self.client, 1, action))
        response = signed(self.server, 7, self.response(action))
        parts = fault.decode(response)
        parts[3] = bytes([parts[3][0] ^ 1]) + parts[3][1:]
        with self.assertRaises(fault.InvalidSignature):
            selector.response(cbor(parts))
        self.assertTrue(selector.response(response))


if __name__ == '__main__':
    unittest.main()
