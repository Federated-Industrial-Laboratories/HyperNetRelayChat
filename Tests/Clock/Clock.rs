use super::*;
use ed25519_dalek::{Signer, SigningKey};
fn witness(key: &SigningKey, wall: u64, boot: u64) -> Vec<u8> {
    let payload = canonical_encode(
        &Value::Array(vec![
            44u64.into(),
            1u64.into(),
            Value::Text("boot".into()),
            wall.into(),
            boot.into(),
            (boot + 1000).into(),
            20u64.into(),
            Value::Text("192.0.2.1".into()),
        ]),
        4096,
    )
    .unwrap();
    let public = key.verifying_key().to_bytes();
    let mut message = b"HyperNet/RecordSignature/1\0".to_vec();
    message.extend((payload.len() as u32).to_be_bytes());
    message.extend(&payload);
    message.extend(public);
    let signature = key.sign(&message).to_bytes();
    canonical_encode(
        &Value::Array(vec![
            0u64.into(),
            1u64.into(),
            Value::Bytes(payload),
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(public.to_vec()),
                Value::Bytes(signature.to_vec()),
            ])]),
        ]),
        4096,
    )
    .unwrap()
}
#[test]
fn signed_clock_refuses_stale_shifted_wrong_boot_and_wrong_signer() {
    let key = SigningKey::from_bytes(&[4; 32]);
    let bytes = witness(&key, 10000, 2000);
    let public = key.verifying_key().to_bytes();
    let now = verify(&bytes, public, "boot", 10500, 2500).unwrap();
    assert_eq!((now.lower_ms, now.upper_ms), (10250, 10750));
    assert!(now.permits(10250, 10751));
    assert!(!now.permits(10251, 10751));
    assert!(!now.permits(10250, 10750));
    assert!(verify(&bytes, public, "other", 10500, 2500).is_err());
    assert!(verify(&bytes, [3; 32], "boot", 10500, 2500).is_err());
    assert!(verify(&bytes, public, "boot", 11000, 3000).is_err());
    assert!(verify(&bytes, public, "boot", 10500, 1999).is_err());
    assert!(verify(&bytes, public, "boot", 10800, 2500).is_err());
    assert!(now.after_floor(10251).is_err());
}
