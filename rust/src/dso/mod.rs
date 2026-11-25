//! DNS Stateful Operations (DSO, RFC 8490) over Strict-Privacy TLS-over-TCP
//! using standard WebPKI system-root certificates.

use crate::wire::{frame_tcp, DnsMessage, DsoMessage, DsoTlv, Opcode, MAX_PUSH_MESSAGE_LEN};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub type ServerKey = (String, u16);

#[derive(Debug)]
pub enum DsoIncoming {
    Push(DsoMessage),
    ServerRetryDelay(u32),
    SessionClosed,
}

/// Build a `rustls::ClientConfig` using system-root WebPKI certificates.
pub fn build_webpki_tls_config() -> io::Result<Arc<rustls::ClientConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        let _ = root_store.add(cert);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub struct DsoSession {
    next_id: AtomicU16,
    write_tx: mpsc::Sender<Vec<u8>>,
    pending_dso: Arc<Mutex<HashMap<u16, oneshot::Sender<DsoMessage>>>>,
    pending_dns: Arc<Mutex<HashMap<u16, oneshot::Sender<DnsMessage>>>>,
    abort_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl DsoSession {
    pub async fn connect(
        host: &str,
        port: u16,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> io::Result<(Arc<Self>, mpsc::Receiver<DsoIncoming>)> {
        let tcp = TcpStream::connect((host, port)).await?;
        let connector = TlsConnector::from(tls_config);
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let tls = connector.connect(server_name, tcp).await?;

        Self::from_tls_stream(tls)
    }

    pub fn from_tls_stream(
        tls: TlsStream<TcpStream>,
    ) -> io::Result<(Arc<Self>, mpsc::Receiver<DsoIncoming>)> {
        let (mut reader, mut writer) = tokio::io::split(tls);
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(128);
        let (incoming_tx, incoming_rx) = mpsc::channel::<DsoIncoming>(256);
        let (abort_tx, mut abort_rx) = oneshot::channel::<()>();

        let pending_dso: Arc<Mutex<HashMap<u16, oneshot::Sender<DsoMessage>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_dns: Arc<Mutex<HashMap<u16, oneshot::Sender<DnsMessage>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let session = Arc::new(Self {
            next_id: AtomicU16::new(1),
            write_tx,
            pending_dso: Arc::clone(&pending_dso),
            pending_dns: Arc::clone(&pending_dns),
            abort_tx: Mutex::new(Some(abort_tx)),
        });

        // Writer task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut abort_rx => {
                        let _ = writer.shutdown().await;
                        break;
                    }
                    maybe_frame = write_rx.recv() => {
                        match maybe_frame {
                            Some(frame) => {
                                if writer.write_all(&frame).await.is_err() {
                                    break;
                                }
                            }
                            None => {
                                let _ = writer.shutdown().await;
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Reader task
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            loop {
                if reader.read_exact(&mut len_buf).await.is_err() {
                    let _ = incoming_tx.send(DsoIncoming::SessionClosed).await;
                    break;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len < 12 || len > MAX_PUSH_MESSAGE_LEN {
                    // RFC 8765 §6.3.1: >16,382 bytes is a fatal error -> close immediately.
                    let _ = incoming_tx.send(DsoIncoming::SessionClosed).await;
                    break;
                }
                let mut buf = vec![0u8; len];
                if reader.read_exact(&mut buf).await.is_err() {
                    let _ = incoming_tx.send(DsoIncoming::SessionClosed).await;
                    break;
                }

                let opcode = (buf[2] >> 3) & 0x0F;
                if opcode == Opcode::Dso as u8 {
                    let Ok(dso) = DsoMessage::parse(&buf) else {
                        let _ = incoming_tx.send(DsoIncoming::SessionClosed).await;
                        break;
                    };
                    if dso.qr {
                        if let Some(tx) = pending_dso.lock().await.remove(&dso.id) {
                            let _ = tx.send(dso);
                        }
                    } else {
                        match &dso.primary {
                            Some(DsoTlv::Push(_)) => {
                                if dso.id != 0 {
                                    let _ = incoming_tx.send(DsoIncoming::SessionClosed).await;
                                    break;
                                }
                                let _ = incoming_tx.send(DsoIncoming::Push(dso)).await;
                            }
                            Some(DsoTlv::RetryDelay(ms)) => {
                                let _ = incoming_tx.send(DsoIncoming::ServerRetryDelay(*ms)).await;
                            }
                            Some(DsoTlv::Subscribe { .. })
                            | Some(DsoTlv::Unsubscribe { .. })
                            | Some(DsoTlv::Reconfirm { .. }) => {
                                // RFC 8765 §6.2–6.5: server MUST NOT send client-only TLVs -> fatal error.
                                let _ = incoming_tx.send(DsoIncoming::SessionClosed).await;
                                break;
                            }
                            _ => {}
                        }
                    }
                } else if let Ok(dns) = DnsMessage::parse(&buf) {
                    if dns.header.qr {
                        if let Some(tx) = pending_dns.lock().await.remove(&dns.header.id) {
                            let _ = tx.send(dns);
                        }
                    }
                }
            }
        });

        Ok((session, incoming_rx))
    }

    pub fn alloc_id(&self) -> u16 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    pub async fn send_dso_request(&self, primary: DsoTlv) -> io::Result<DsoMessage> {
        let id = self.alloc_id();
        let msg = DsoMessage::request(id, primary);
        let (tx, rx) = oneshot::channel();
        self.pending_dso.lock().await.insert(id, tx);
        self.write_tx
            .send(frame_tcp(&msg.encode()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DSO writer closed"))?;
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DSO request timed out"))?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DSO response channel closed"))
    }

    pub async fn send_dso_unidirectional(&self, primary: DsoTlv) -> io::Result<()> {
        let msg = DsoMessage::unidirectional(primary);
        self.write_tx
            .send(frame_tcp(&msg.encode()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DSO writer closed"))
    }

    /// Send a standard DNS message (e.g., DNS UPDATE) over the shared DSO/TLS session (RFC 8765 §3).
    pub async fn send_dns_message(&self, mut msg: DnsMessage) -> io::Result<DnsMessage> {
        let id = self.alloc_id();
        msg.header.id = id;
        let (tx, rx) = oneshot::channel();
        self.pending_dns.lock().await.insert(id, tx);
        self.write_tx
            .send(frame_tcp(&msg.encode()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DSO writer closed"))?;
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS-over-DSO request timed out"))?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DSO response channel closed"))
    }

    pub async fn send_keepalive(&self, inactivity_ms: u32, interval_ms: u32) -> io::Result<DsoMessage> {
        self.send_dso_request(DsoTlv::Keepalive {
            inactivity_timeout_ms: inactivity_ms,
            keepalive_interval_ms: interval_ms,
        })
        .await
    }

    pub async fn close_gracefully(&self) {
        if let Some(tx) = self.abort_tx.lock().await.take() {
            let _ = tx.send(());
        }
    }
}
