#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the public COSE vector using Python cryptography and RFC8949 encoding.
Input: fixed public RFC8032 seed and fixed protocol fields. Output: Vector.json.
Exit0 writes the vector; dependency or encoding failure exits nonzero.
"""
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def head(major, value):
    if value < 24:
        return bytes([major * 32 + value])
    for size, additional in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if value < 1 << (size * 8):
            return bytes([major * 32 + additional]) + value.to_bytes(size, "big")
    raise ValueError("integer bound")


def cbor(value):
    if isinstance(value, int):
        return head(0 if value >= 0 else 1, value if value >= 0 else -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(cbor, value))
    if isinstance(value, dict):
        pairs = sorted((cbor(k), cbor(v)) for k, v in value.items())
        return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError("unsupported vector field")


# RFC8032 section7.1 TEST1 seed is public test material, never a deployment key.
seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
key = Ed25519PrivateKey.from_private_bytes(seed)
public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
identifier = lambda n: bytes([n]) * 32
network = dict(network=identifier(1), incarnation=identifier(2))
proof = dict(home=dict(network=network, service=identifier(3)),
             account=dict(origin=network, local=identifier(4)), endpoint=identifier(5),
             clientNonce=identifier(6), challengeDigest=identifier(7))
payload = cbor([1, 5, proof])
protected = cbor({1: -19, 3: "application/hrc-session-proof+cbor;v=1", 4: hashlib.sha256(public).digest()})
to_sign = cbor(["Signature1", protected, b"HRC/1", payload])
signature = key.sign(to_sign)
key.public_key().verify(signature, to_sign)
encoded = cbor([protected, {}, payload, signature])
result = dict(seed=seed.hex(), publicKey=public.hex(), protected=protected.hex(),
              payload=payload.hex(), toBeSigned=to_sign.hex(), signature=signature.hex(),
              coseSign1=encoded.hex(), digest=hashlib.sha256(payload).hexdigest())
Path(__file__).with_name("Vector.json").write_text(json.dumps(result, indent=2) + "\n")
