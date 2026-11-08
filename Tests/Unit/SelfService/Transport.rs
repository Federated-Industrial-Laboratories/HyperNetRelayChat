// SPDX-License-Identifier: Apache-2.0
//! The certificate keys below are deterministic, public test data, never deployment credentials.
use super::*;
use std::{net::TcpListener, thread};
const CA: &[u8] = include_bytes!("../../Fixtures/Admission/Authority.pem");
const CERT: &[u8] = include_bytes!("../../Fixtures/Admission/Endpoint.pem");
const KEY: &[u8] = include_bytes!("../../Fixtures/Admission/PublicTest.key");
fn invitation(address: std::net::SocketAddrV4) -> Invitation {
    let leaf = CertificateDer::pem_slice_iter(CERT)
        .next()
        .unwrap()
        .unwrap();
    Invitation {
        format: super::super::INVITATION_FORMAT.into(),
        name: "Public test fixture".into(),
        address,
        certificate_authority_pem: String::from_utf8(CA.to_vec()).unwrap(),
        server_certificate_sha256: digest(leaf.as_ref()),
        network: "01".repeat(32),
        incarnation: "02".repeat(32),
        bootstrap_sha256: "03".repeat(32),
        bootstrap_fingerprint: "04".repeat(32),
        id: "05".repeat(32),
        secret: "06".repeat(32),
        expires_ms: u64::MAX - 1,
        access_expires_ms: u64::MAX,
    }
}

#[test]
fn real_tls13_connection_requires_the_exact_pinned_certificate() {
    for correct_pin in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("IPv4 fixture")
        };
        let mut invitation = invitation(address);
        if !correct_pin {
            invitation.server_certificate_sha256 = "ff".repeat(32);
        }
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let cancel = AtomicBool::new(false);
            let mut tls = match accept(stream, server_config(CERT, KEY).unwrap(), &cancel) {
                Ok(tls) => tls,
                Err(e) => return Err(e),
            };
            assert_eq!(
                tls.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let value: serde_json::Value = read(&mut tls, 1024)?;
            write(&mut tls, &value, 1024)
        });
        let cancel = AtomicBool::new(false);
        let connection = connect(
            &invitation,
            &cancel,
            Instant::now() + Duration::from_secs(5),
        );
        if correct_pin {
            let mut tls = connection.unwrap();
            assert_eq!(
                tls.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let value = serde_json::json!({"challenge":"fresh"});
            write(&mut tls, &value, 1024).unwrap();
            assert_eq!(read::<serde_json::Value>(&mut tls, 1024).unwrap(), value);
            server.join().unwrap().unwrap();
        } else {
            assert!(connection.is_err());
            assert!(server.join().unwrap().is_err());
        }
    }
}

#[test]
fn pin_does_not_bypass_certificate_identity_validity_or_trust() {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::pem_slice_iter(CA).next().unwrap().unwrap())
        .unwrap();
    let leaf = CertificateDer::pem_slice_iter(CERT)
        .next()
        .unwrap()
        .unwrap();
    let verifier = Pinned {
        standard: WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .unwrap(),
        leaf_sha256: digest(leaf.as_ref()),
    };
    let name = ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into());
    let valid = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
    assert!(
        verifier
            .verify_server_cert(&leaf, &[], &name, &[], valid)
            .is_ok()
    );
    let wrong = ServerName::IpAddress(std::net::Ipv4Addr::new(127, 0, 0, 2).into());
    assert!(
        verifier
            .verify_server_cert(&leaf, &[], &wrong, &[], valid)
            .is_err()
    );
    for timestamp in [1_500_000_000, 4_102_444_800] {
        assert!(
            verifier
                .verify_server_cert(
                    &leaf,
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(timestamp))
                )
                .is_err()
        );
    }
    let cancel = AtomicBool::new(false);
    let mut invitation = invitation("127.0.0.1:25444".parse().unwrap());
    invitation.certificate_authority_pem = "invalid authority".into();
    assert!(
        connect(
            &invitation,
            &cancel,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
}

#[test]
fn socket_deadline_and_cancellation_refuse_even_readable_data() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (receiver, _) = listener.accept().unwrap();
    sender.write_all(b"ready").unwrap();
    let cancel = AtomicBool::new(false);
    let mut socket = Socket {
        inner: receiver,
        cancel: &cancel,
        end: Instant::now() - Duration::from_secs(1),
    };
    assert_eq!(
        socket.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    socket.end = Instant::now() + Duration::from_secs(10);
    cancel.store(true, Ordering::Release);
    assert!(socket.read(&mut [0; 1]).is_err());
}
