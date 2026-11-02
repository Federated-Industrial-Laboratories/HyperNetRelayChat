use super::*;
use std::collections::BTreeMap;
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn home() -> ServiceId {
    ServiceId {
        network: NetworkId {
            network: id(1),
            incarnation: id(2),
        },
        service: id(3),
    }
}
fn account() -> AccountId {
    AccountId {
        origin: home().network,
        local: id(4),
    }
}
#[test]
fn compound_identifier_text_is_exact_and_round_trips() {
    assert_eq!(home().to_string().parse::<ServiceId>().unwrap(), home());
    assert_eq!(
        account().to_string().parse::<AccountId>().unwrap(),
        account()
    );
    let room = RoomId {
        home: home(),
        local: Id::from_bytes([0xab; 32]),
    };
    assert_eq!(room.to_string().parse::<RoomId>().unwrap(), room);
    for invalid in [
        room.to_string().to_uppercase(),
        format!("{}:", room),
        format!(" {}", room),
        account().to_string(),
    ] {
        assert!(invalid.parse::<RoomId>().is_err());
    }
}
#[test]
fn opaque_bytes_have_bounded_json_hex_without_changing_cbor() {
    let blob = Blob(vec![0, 0xab, 0xff]);
    assert_eq!(serde_json::to_string(&blob).unwrap(), "\"00abff\"");
    assert_eq!(serde_json::from_str::<Blob>("\"00abff\"").unwrap(), blob);
    let value = Value::serialized(&blob).unwrap();
    assert_eq!(value, Value::Bytes(vec![0, 0xab, 0xff]));
    assert_eq!(
        canonical_encode(&value, 1024).unwrap(),
        [0x43, 0, 0xab, 0xff]
    );
    for invalid in ["\"AB\"", "\"a\"", "[0,1]", "\"gg\""] {
        assert!(serde_json::from_str::<Blob>(invalid).is_err());
    }
    assert!(serde_json::to_string(&Blob(vec![0; CRYPTO_FRAME_BYTES])).is_err());
}
fn acting() -> EndpointActor {
    EndpointActor {
        account: account(),
        endpoint: id(5),
        security_generation: 1,
        enrolment_generation: 1,
        binding_digest: id(6),
    }
}
fn action() -> Action {
    Action {
        home: home(),
        operation_id: OperationId {
            window: id(7),
            operation: id(8),
        },
        actor: Actor::Direct { acting: acting() },
        target: Target::Room(RoomId {
            home: home(),
            local: id(9),
        }),
        operation: Operation::MessageSend,
        body: Value::Map(vec![(
            Value::Text("text".into()),
            Value::Text("Hello, e\u{301} 👩‍👩‍👧‍👧".into()),
        )]),
        expected: BTreeMap::from([(Revision::Room, 1)]),
        approval: None,
        agreement: None,
    }
}
#[test]
fn canonical_input_rejects_ambiguous_and_unbounded_cbor() {
    for bytes in [
        vec![0x18, 0],
        vec![0x9f, 1, 0xff],
        vec![0xa2, 1, 1, 1, 2],
        vec![0xa2, 2, 1, 1, 2],
        vec![0x61, 0xff],
        vec![0xc0, 0],
        vec![0xf9, 0, 0],
        vec![0xf7],
        vec![0, 0],
        vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        assert!(
            canonical_decode(&bytes, 1024).is_err(),
            "accepted {bytes:?}"
        );
    }
    let mut deep = vec![0x81; 17];
    deep.push(0);
    assert_eq!(canonical_decode(&deep, 1024), Err(Error::Limit));
    assert_eq!(canonical_decode(&[0x99, 1, 1], 1024), Err(Error::Limit));
    assert!(
        canonical_encode(
            &Value::Map(vec![
                (Value::Text("a".into()), Value::Null),
                (Value::Text("a".into()), Value::Null)
            ]),
            1024
        )
        .is_err()
    );
}

#[test]
fn bounded_generated_input_preserves_canonical_and_frame_boundaries() {
    // A fixed corpus seed makes malformed-input failures reproducible. This is
    // bounded parser coverage, not a coverage-guided fuzzing campaign.
    let mut state = 0x6ad3_8eb1_5c04_729fu64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for case in 0..4096 {
        let length = match case {
            0..=255 => 1,
            256..=263 => [
                0,
                4,
                5,
                255,
                256,
                4096,
                ORDINARY_FRAME_BYTES,
                CRYPTO_FRAME_BYTES,
            ][case - 256],
            _ => (next() % 4097) as usize,
        };
        let mut bytes = vec![0u8; length];
        for byte in &mut bytes {
            *byte = next() as u8;
        }
        if case <= 255 {
            bytes[0] = case as u8;
        }
        if let Ok(value) = canonical_decode(&bytes, ORDINARY_FRAME_BYTES) {
            assert_eq!(
                canonical_encode(&value, ORDINARY_FRAME_BYTES).unwrap(),
                bytes,
                "accepted noncanonical corpus case {case}"
            );
        }
        if let Ok(frame) = Frame::decode(&bytes) {
            assert_eq!(frame.encode().unwrap(), bytes, "frame case {case}");
        }
    }
}

#[test]
fn every_signed_action_byte_is_bound_and_every_truncation_is_rejected() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let signed = sign_action(&action(), &key).unwrap();
    let public = key.verifying_key();
    for index in 0..signed.len() {
        assert!(
            verify_action(&signed[..index], &public).is_err(),
            "accepted truncation at {index}"
        );
        let mut changed = signed.clone();
        changed[index] ^= 1 << (index % 8);
        assert!(
            verify_action(&changed, &public).is_err(),
            "accepted mutation at {index}"
        );
    }
    let mut trailing = signed;
    trailing.push(0);
    assert!(verify_action(&trailing, &public).is_err());
}
#[test]
fn signed_action_round_trip_preserves_text_and_exact_bytes() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let action = action();
    let signed = sign_action(&action, &key).unwrap();
    let verified = verify_action(&signed, &key.verifying_key()).unwrap();
    assert_eq!(verified.action(), &action);
    assert_eq!(
        verified.signer_key().as_bytes(),
        key.verifying_key().as_bytes()
    );
    assert_eq!(verified.digest(), action_digest(&action).unwrap());
    assert_eq!(verified.signed_bytes(), signed);
    assert_eq!(sign_action(verified.action(), &key).unwrap(), signed);
    let frame = Frame::new(FrameKind::Action, signed.clone()).unwrap();
    assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
    assert!(verify_action(&signed, &SigningKey::from_bytes(&[43; 32]).verifying_key()).is_err());
    let mut tampered = signed;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(verify_action(&tampered, &key.verifying_key()).is_err());
}

#[test]
fn cose_profile_matches_independent_python_signature_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!("Vector.json")).unwrap();
    let bytes = hex::decode(vector["coseSign1"].as_str().unwrap()).unwrap();
    let seed: [u8; 32] = hex::decode(vector["seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&seed);
    let proof = SessionProof {
        home: home(),
        account: account(),
        endpoint: id(5),
        client_nonce: id(6),
        challenge_digest: id(7),
    };
    assert_eq!(sign_proof(&proof, &key).unwrap(), bytes);
    let verified = verify_proof(&bytes, &key.verifying_key()).unwrap();
    assert_eq!(verified.value(), &proof);
    assert_eq!(verified.digest().as_hex(), vector["digest"]);
    assert_eq!(hex::encode(verified.bytes()), vector["payload"]);
    let cose = <coset::CoseSign1 as coset::CborSerializable>::from_slice(&bytes).unwrap();
    assert_eq!(hex::encode(cose.tbs_data(b"HRC/1")), vector["toBeSigned"]);
}

fn changed_action(action: &Action, key: &SigningKey, change: impl FnOnce(&mut Value)) -> Vec<u8> {
    use coset::{CborSerializable, CoseSign1, CoseSign1Builder};
    use ed25519_dalek::Signer;
    let signed = CoseSign1::from_slice(&sign_action(action, key).unwrap()).unwrap();
    let mut payload =
        canonical_decode(signed.payload.as_ref().unwrap(), ORDINARY_FRAME_BYTES).unwrap();
    change(&mut payload);
    CoseSign1Builder::new()
        .protected(signed.protected.header)
        .payload(canonical_encode(&payload, ORDINARY_FRAME_BYTES).unwrap())
        .create_signature(b"HRC/1", |bytes| key.sign(bytes).to_bytes().to_vec())
        .build()
        .to_vec()
        .unwrap()
}
#[test]
fn valid_signatures_do_not_authorize_unknown_or_missing_wire_fields() {
    let key = SigningKey::from_bytes(&[42; 32]);
    for missing in [false, true] {
        let changed = changed_action(&action(), &key, |payload| {
            let Value::Array(parts) = payload else {
                panic!()
            };
            let Value::Map(fields) = &mut parts[2] else {
                panic!()
            };
            if missing {
                fields.retain(|(k, _)| k != &Value::Text("approval".into()));
            } else {
                fields.push((Value::Text("futureAuthority".into()), Value::Bool(true)));
            }
        });
        assert_eq!(
            verify_action(&changed, &key.verifying_key()).unwrap_err(),
            Error::Encoding
        );
    }
}
#[test]
fn protected_headers_roles_and_unprotected_fields_cannot_substitute() {
    use coset::{CborSerializable, CoseSign1, HeaderBuilder, iana};
    let key = SigningKey::from_bytes(&[42; 32]);
    let bytes = sign_action(&action(), &key).unwrap();
    assert!(verify_response(&bytes, &key.verifying_key()).is_err());
    let mut cose = CoseSign1::from_slice(&bytes).unwrap();
    cose.unprotected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::Ed25519)
        .build();
    assert_eq!(
        verify_action(&cose.to_vec().unwrap(), &key.verifying_key()).unwrap_err(),
        Error::Encoding
    );
    let mut cose = CoseSign1::from_slice(&bytes).unwrap();
    cose.protected.original_data = None;
    cose.protected.header.alg = Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA));
    assert_eq!(
        verify_action(&cose.to_vec().unwrap(), &key.verifying_key()).unwrap_err(),
        Error::Binding
    );
}
#[test]
fn frame_limits_are_checked_before_allocating_the_payload() {
    assert_eq!(
        FrameHeader::decode([0, 1, 0, 1, FrameKind::Action as u8]),
        Err(Error::Limit)
    );
    assert_eq!(
        FrameHeader::decode([0, 4, 0, 1, FrameKind::CryptoAction as u8]),
        Err(Error::Limit)
    );
    assert_eq!(
        FrameHeader::decode([0, 0, 0, 1, FrameKind::Action as u8]),
        Err(Error::Limit)
    );
    assert_eq!(FrameHeader::decode([0, 0, 0, 2, 255]), Err(Error::Feature));
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut large = action();
    large.body = Value::Bytes(vec![0; 70_000]);
    assert_eq!(sign_action(&large, &key), Err(Error::Limit));
    large.operation = Operation::CryptoCommit;
    let signed = sign_action(&large, &key).unwrap();
    assert!(Frame::new(FrameKind::Action, signed.clone()).is_err());
    let frame = Frame::new(FrameKind::CryptoAction, signed).unwrap();
    assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
    assert_eq!(
        verify_action(&frame.payload, &key.verifying_key())
            .unwrap()
            .action(),
        &large
    );
}
#[test]
fn enrolment_and_session_roles_bind_the_exact_keys_and_target() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let other = SigningKey::from_bytes(&[43; 32]);
    let registration = AccountRegistration {
        home: home(),
        account: account(),
        endpoint: id(5),
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        transport_principal: id(8),
        recovery_key: Id::from_bytes(other.verifying_key().to_bytes()),
        classification: AccountClass::Human,
        invitation: id(9),
    };
    let bytes = sign_registration(&registration, &key).unwrap();
    assert_eq!(
        verify_registration_request(&bytes).unwrap().value(),
        &registration
    );
    assert_eq!(
        verify_registration(&bytes, &key.verifying_key())
            .unwrap()
            .value(),
        &registration
    );
    assert_eq!(
        sign_registration(&registration, &other),
        Err(Error::Binding)
    );
    assert!(verify_endpoint_binding(&bytes, &key.verifying_key()).is_err());
    let mut crossed = action();
    if let Target::Room(room) = &mut crossed.target {
        room.home.service = id(90);
    }
    assert_eq!(sign_action(&crossed, &key), Err(Error::Binding));
    let hello = SessionHello {
        home: home(),
        account: account(),
        endpoint: id(5),
        client_nonce: id(6),
        versions: vec![VERSION],
        required_capabilities: vec!["text/1".into()],
        optional_capabilities: vec![],
    };
    assert_eq!(decode_hello(&encode_hello(&hello).unwrap()).unwrap(), hello);
    let mut duplicate = hello;
    duplicate.optional_capabilities.push("text/1".into());
    assert!(encode_hello(&duplicate).is_err());
}
#[test]
fn exact_approval_and_cursor_data_are_not_action_authority() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let action = action();
    let approval = Approval {
        id: id(12),
        home: home(),
        owner: acting(),
        grant: GrantRef {
            id: id(13),
            generation: 1,
        },
        action_digest: action_digest(&action).unwrap(),
        decision: ApprovalDecision::Approve,
        expires_ms: 2_000,
    };
    let signed = sign_approval(&approval, &key).unwrap();
    assert_eq!(
        verify_approval(&signed, &key.verifying_key())
            .unwrap()
            .value(),
        &approval
    );
    assert!(verify_action(&signed, &key.verifying_key()).is_err());
    let cursor = HistoryCursor {
        home: home(),
        room: RoomId {
            home: home(),
            local: id(9),
        },
        account: account(),
        sequence: 25,
        membership_revision: 2,
        filter_revision: 3,
        access_digest: id(15),
        expires_ms: 5_000,
    };
    let signed = sign_cursor(&cursor, &key).unwrap();
    assert_eq!(
        verify_cursor(&signed, &key.verifying_key())
            .unwrap()
            .value(),
        &cursor
    );
    assert!(verify_challenge(&signed, &key.verifying_key()).is_err());
}

#[test]
fn preadmission_refusal_is_distinct_from_durable_rejection() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut response = Response {
        home: home(),
        operation_id: action().operation_id,
        action_digest: action_digest(&action()).unwrap(),
        outcome: Outcome::Refused {
            code: ErrorCode::Overloaded,
            detail: "QueueFull".into(),
            retry_after_ms: Some(1000),
        },
    };
    let first = sign_response(&response, &key).unwrap();
    assert_eq!(
        verify_response(&first, &key.verifying_key())
            .unwrap()
            .value(),
        &response
    );
    response.outcome = Outcome::Rejected {
        code: ErrorCode::Denied,
        detail: "Scope".into(),
    };
    let second = sign_response(&response, &key).unwrap();
    assert_ne!(first, second);
    response.outcome = Outcome::Refused {
        code: ErrorCode::Overloaded,
        detail: "QueueFull".into(),
        retry_after_ms: Some(60_001),
    };
    assert_eq!(sign_response(&response, &key), Err(Error::Invalid));
}

#[test]
fn forwarding_preserves_a_combined_depth_bound() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut action = action();
    let mut nested = Value::Null;
    for _ in 0..10 {
        nested = Value::Array(vec![nested]);
    }
    action.body = nested;
    let signed = sign_action(&action, &key).unwrap();
    assert!(verify_action(&signed, &key.verifying_key()).is_ok());
    let envelope = FederationEnvelope {
        profile: FEDERATION_PROFILE,
        admission: AdmissionRef {
            id: id(25),
            revision: 1,
        },
        agreement: AgreementRef {
            id: id(20),
            revision: 1,
            digest: id(21),
        },
        action: Blob(signed.clone()),
        endpoint_binding: Blob(signed.clone()),
        challenge: Blob(signed.clone()),
        origin_assertion: Blob(signed),
    };
    assert_eq!(encode_federation(&envelope), Err(Error::Limit));
}

#[test]
fn crypto_response_keeps_role_binding_and_ordinary_size_admission() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let a = action();
    let response = Response {
        home: a.home,
        operation_id: a.operation_id,
        action_digest: action_digest(&a).unwrap(),
        outcome: Outcome::Result {
            body: Value::Bytes(vec![0; 70_000]),
        },
    };
    assert_eq!(sign_response(&response, &key), Err(Error::Limit));
    let signed = sign_crypto_response(&response, &key).unwrap();
    assert!(Frame::new(FrameKind::Response, signed.clone()).is_err());
    assert!(verify_response(&signed, &key.verifying_key()).is_err());
    let frame = Frame::new(FrameKind::CryptoResponse, signed).unwrap();
    let decoded = Frame::decode(&frame.encode().unwrap()).unwrap();
    assert_eq!(
        verify_crypto_response(&decoded.payload, &key.verifying_key())
            .unwrap()
            .value(),
        &response
    );
    assert!(verify_action(&decoded.payload, &key.verifying_key()).is_err());
}
