// SPDX-License-Identifier: Apache-2.0
//! Pinned TLS1.3 and bounded invitation frames; never a chat transport.
use super::{Error, Invitation, Result, digest};
use rustls::{
    ClientConnection, RootCertStore, ServerConnection, StreamOwned,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) const ALPN: &[u8] = b"HrcAdmission/1";
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
#[derive(Debug)]
struct Pinned {
    standard: Arc<WebPkiServerVerifier>,
    leaf_sha256: String,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if digest(leaf.as_ref()) != self.leaf_sha256 {
            return Err(rustls::Error::General(
                "invitation endpoint certificate differs".into(),
            ));
        }
        self.standard
            .verify_server_cert(leaf, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        bytes: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls12_signature(bytes, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        bytes: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls13_signature(bytes, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}
pub(super) struct Socket<'a> {
    inner: TcpStream,
    cancel: &'a AtomicBool,
    end: Instant,
}
impl Socket<'_> {
    fn check(&self) -> io::Result<()> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(io::Error::other("cancelled"));
        }
        let left = self
            .end
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline"))?;
        let timeout = left
            .min(Duration::from_secs(5))
            .max(Duration::from_millis(1));
        self.inner.set_read_timeout(Some(timeout))?;
        self.inner.set_write_timeout(Some(timeout))
    }
}
impl Read for Socket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.inner.read(bytes)
    }
}
impl Write for Socket<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}
pub(super) fn connect<'a>(
    invitation: &Invitation,
    cancel: &'a AtomicBool,
    end: Instant,
) -> Result<StreamOwned<ClientConnection, Socket<'a>>> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(invitation.certificate_authority_pem.as_bytes()) {
        roots
            .add(cert.map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
    }
    if roots.is_empty() {
        return Err(Error::Invalid);
    }
    let standard = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .map_err(|_| Error::Invalid)?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Connection)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            standard,
            leaf_sha256: invitation.server_certificate_sha256.clone(),
        }))
        .with_no_client_auth();
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let timeout = end
        .checked_duration_since(Instant::now())
        .ok_or(Error::Deadline)?
        .min(Duration::from_secs(5));
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    let stream = TcpStream::connect_timeout(&invitation.address.into(), timeout)
        .map_err(|_| Error::Connection)?;
    stream.set_nodelay(true).map_err(|_| Error::Connection)?;
    let name = ServerName::IpAddress((*invitation.address.ip()).into());
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(|_| Error::Connection)?;
    let mut tls = StreamOwned::new(
        connection,
        Socket {
            inner: stream,
            cancel,
            end,
        },
    );
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|_| Error::Connection)?;
    }
    if tls.conn.alpn_protocol() != Some(ALPN) {
        return Err(Error::Connection);
    }
    Ok(tls)
}
pub(super) fn server_config(certificate: &[u8], key: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    let certs = CertificateDer::pem_slice_iter(certificate)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::Invalid)?;
    let private = PrivateKeyDer::from_pem_slice(key).map_err(|_| Error::Invalid)?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Connection)?
        .with_no_client_auth()
        .with_single_cert(certs, private)
        .map_err(|_| Error::Invalid)?;
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}
pub(super) fn accept<'a>(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    cancel: &'a AtomicBool,
) -> Result<StreamOwned<ServerConnection, Socket<'a>>> {
    stream.set_nodelay(true).map_err(|_| Error::Connection)?;
    let connection = ServerConnection::new(config).map_err(|_| Error::Connection)?;
    let mut tls = StreamOwned::new(
        connection,
        Socket {
            inner: stream,
            cancel,
            end: Instant::now() + Duration::from_secs(15),
        },
    );
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|_| Error::Connection)?;
    }
    if tls.conn.alpn_protocol() != Some(ALPN) {
        return Err(Error::Connection);
    }
    Ok(tls)
}
pub(super) fn read<T: DeserializeOwned>(input: &mut impl Read, maximum: usize) -> Result<T> {
    let mut header = [0; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| Error::Connection)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > maximum {
        return Err(Error::Invalid);
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0; size]);
    input
        .read_exact(&mut bytes)
        .map_err(|_| Error::Connection)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)
}
pub(super) fn write(output: &mut impl Write, value: &impl Serialize, maximum: usize) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Invalid)?);
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error::Invalid);
    }
    output
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|()| output.write_all(&bytes))
        .and_then(|()| output.flush())
        .map_err(|_| Error::Connection)
}

#[cfg(test)]
#[path = "../../Tests/Unit/SelfService/Transport.rs"]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_frame_refuses_before_allocation_or_body_read() {
        let mut bytes = std::io::Cursor::new(u32::MAX.to_be_bytes());
        assert!(matches!(
            read::<serde_json::Value>(&mut bytes, 4096),
            Err(Error::Invalid)
        ));
        assert_eq!(bytes.position(), 4);
    }
    #[test]
    fn exact_bounded_frame_round_trip_and_truncation() {
        let value = serde_json::json!({"phase":"ready"});
        let mut bytes = Vec::new();
        write(&mut bytes, &value, 64).unwrap();
        assert_eq!(
            read::<serde_json::Value>(&mut bytes.as_slice(), 64).unwrap(),
            value
        );
        bytes.pop();
        assert!(read::<serde_json::Value>(&mut bytes.as_slice(), 64).is_err());
    }
}
