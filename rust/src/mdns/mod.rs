//! Link-local Multicast DNS (RFC 6762) and DNS-SD (RFC 6763) engine:
//! querying with Known-Answer suppression + probing/announcing/conflict-resolution/goodbye.

use crate::cache::{RecordOrigin, RrCache};
use crate::wire::{
    DnsHeader, DnsMessage, DnsName, DnsQuestion, DnsRecord, Opcode, RData, RrClass, RrType, MDNS_PORT,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};

pub const MDNS_V4_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_V6_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

#[derive(Debug, Clone)]
pub struct LocalServiceSpec {
    pub instance_name: String,
    pub service_type: String,
    pub port: u16,
    pub txt: Vec<Vec<u8>>,
    pub host_name: DnsName,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct PublishedService {
    pub full_instance: DnsName,
    pub records: Vec<DnsRecord>,
}

pub struct MdnsEngine {
    v4_sock: Option<Arc<UdpSocket>>,
    v6_sock: Option<Arc<UdpSocket>>,
    cache: Arc<Mutex<RrCache>>,
    published: Arc<Mutex<HashMap<Vec<u8>, PublishedService>>>,
    events_tx: broadcast::Sender<DnsRecord>,
}

impl MdnsEngine {
    pub async fn bind(cache: Arc<Mutex<RrCache>>) -> io::Result<Arc<Self>> {
        let v4_sock = bind_mdns_v4().ok().map(Arc::new);
        let v6_sock = bind_mdns_v6().ok().map(Arc::new);
        if v4_sock.is_none() && v6_sock.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "failed to bind either IPv4 or IPv6 mDNS socket on port 5353",
            ));
        }

        let (events_tx, _) = broadcast::channel(256);
        let engine = Arc::new(Self {
            v4_sock,
            v6_sock,
            cache,
            published: Arc::new(Mutex::new(HashMap::new())),
            events_tx,
        });

        if let Some(ref s) = engine.v4_sock {
            let e = Arc::clone(&engine);
            let sock = Arc::clone(s);
            tokio::spawn(async move { e.recv_loop(sock).await });
        }
        if let Some(ref s) = engine.v6_sock {
            let e = Arc::clone(&engine);
            let sock = Arc::clone(s);
            tokio::spawn(async move { e.recv_loop(sock).await });
        }

        Ok(engine)
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<DnsRecord> {
        self.events_tx.subscribe()
    }

    async fn recv_loop(&self, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 9000];
        loop {
            let Ok((len, _peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let Ok(msg) = DnsMessage::parse(&buf[..len]) else {
                continue;
            };
            if msg.header.qr {
                let now = Instant::now();
                let mut cache = self.cache.lock().await;
                for rr in msg.answers.iter().chain(msg.additionals.iter()) {
                    if rr.ttl == 0 {
                        cache.remove_rr(&rr.name, rr.rtype, rr.rclass, &rr.rdata);
                    } else {
                        cache.insert(rr.clone(), RecordOrigin::LocalMulticast, now);
                    }
                    let _ = self.events_tx.send(rr.clone());
                }
            } else {
                self.handle_incoming_query(&msg).await;
            }
        }
    }

    async fn handle_incoming_query(&self, query: &DnsMessage) {
        let published = self.published.lock().await;
        if published.is_empty() {
            return;
        }
        let mut answers = Vec::new();
        for q in &query.questions {
            for svc in published.values() {
                for rr in &svc.records {
                    if rr.name == q.qname
                        && (q.qtype == RrType::ANY || q.qtype == rr.rtype)
                        && (q.qclass.raw_without_flush() == RrClass::ANY
                            || q.qclass.raw_without_flush() == rr.rclass.raw_without_flush())
                    {
                        // Known-Answer suppression (RFC 6762 §7.1): skip if caller knows it with >= half TTL.
                        let suppressed = query.answers.iter().any(|ka| {
                            ka.name == rr.name
                                && ka.rtype == rr.rtype
                                && ka.rdata == rr.rdata
                                && ka.ttl >= rr.ttl / 2
                        });
                        if !suppressed {
                            answers.push(rr.clone());
                        }
                    }
                }
            }
        }
        drop(published);

        if !answers.is_empty() {
            let resp = DnsMessage {
                header: DnsHeader {
                    id: 0,
                    qr: true,
                    opcode: Opcode::Query as u8,
                    aa: true,
                    tc: false,
                    rd: false,
                    ra: false,
                    z: 0,
                    rcode: 0,
                    qdcount: 0,
                    ancount: answers.len() as u16,
                    nscount: 0,
                    arcount: 0,
                },
                questions: Vec::new(),
                answers,
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            let _ = self.send_multicast(&resp.encode()).await;
        }
    }

    async fn send_multicast(&self, bytes: &[u8]) -> io::Result<()> {
        if let Some(ref s) = self.v4_sock {
            let _ = s.send_to(bytes, SocketAddr::V4(SocketAddrV4::new(MDNS_V4_ADDR, MDNS_PORT))).await;
        }
        if let Some(ref s) = self.v6_sock {
            let _ = s.send_to(bytes, SocketAddr::V6(SocketAddrV6::new(MDNS_V6_ADDR, MDNS_PORT, 0, 0))).await;
        }
        Ok(())
    }

    /// Issue an mDNS query with Known-Answer suppression (RFC 6762 §5.2, §7.1).
    pub async fn query_once(&self, qname: DnsName, qtype: RrType, unicast_preferred: bool) -> io::Result<()> {
        let now = Instant::now();
        let known = {
            let mut cache = self.cache.lock().await;
            cache.get(&qname, qtype, RrClass::IN, now)
        };
        let qclass = if unicast_preferred {
            RrClass(RrClass::IN.0 | 0x8000)
        } else {
            RrClass::IN
        };
        let mut msg = DnsMessage::new_query(0, qname, qtype, qclass, false);
        msg.answers = known;
        self.send_multicast(&msg.encode()).await
    }

    /// Register a local `.local.` service via RFC 6762 §8 Probing + Announcing (with auto-rename on conflict).
    pub async fn register_service(&self, mut spec: LocalServiceSpec) -> io::Result<PublishedService> {
        let mut attempt = 1u32;
        loop {
            let inst_label = if attempt == 1 {
                spec.instance_name.clone()
            } else {
                format!("{} ({attempt})", spec.instance_name)
            };
            let service_fqdn = DnsName::from_str_dotted(&format!("{}.local.", spec.service_type.trim_end_matches('.')))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let full_instance = service_fqdn
                .prepend_label(inst_label.as_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

            let srv = DnsRecord {
                name: full_instance.clone(),
                rtype: RrType::SRV,
                rclass: RrClass(RrClass::IN.0 | 0x8000),
                ttl: 120,
                rdata: RData::SRV {
                    priority: 0,
                    weight: 0,
                    port: spec.port,
                    target: spec.host_name.clone(),
                },
            };

            // RFC 6762 §8.1: 3 probes spaced 250ms apart with proposed record in Authority section.
            let mut conflict = false;
            let mut rx = self.subscribe_events();
            for _ in 0..3 {
                let probe = DnsMessage {
                    header: DnsHeader {
                        id: 0,
                        qr: false,
                        opcode: Opcode::Query as u8,
                        aa: false,
                        tc: false,
                        rd: false,
                        ra: false,
                        z: 0,
                        rcode: 0,
                        qdcount: 1,
                        ancount: 0,
                        nscount: 1,
                        arcount: 0,
                    },
                    questions: vec![DnsQuestion {
                        qname: full_instance.clone(),
                        qtype: RrType::ANY,
                        qclass: RrClass::IN,
                    }],
                    answers: Vec::new(),
                    authorities: vec![srv.clone()],
                    additionals: Vec::new(),
                };
                self.send_multicast(&probe.encode()).await?;
                let deadline = tokio::time::sleep(Duration::from_millis(250));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => break,
                        Ok(ev) = rx.recv() => {
                            if ev.name == full_instance && ev.rdata != srv.rdata {
                                conflict = true;
                                break;
                            }
                        }
                    }
                }
                if conflict {
                    break;
                }
            }

            if conflict {
                attempt += 1;
                if attempt > 16 {
                    spec.instance_name = format!("{}-{}", spec.instance_name, rand::random::<u16>());
                }
                continue;
            }

            // Build full record set: PTR (shared), SRV (unique), TXT (unique), A/AAAA (unique).
            let ptr = DnsRecord {
                name: service_fqdn,
                rtype: RrType::PTR,
                rclass: RrClass::IN,
                ttl: 4500,
                rdata: RData::PTR(full_instance.clone()),
            };
            let txt = DnsRecord {
                name: full_instance.clone(),
                rtype: RrType::TXT,
                rclass: RrClass(RrClass::IN.0 | 0x8000),
                ttl: 4500,
                rdata: RData::TXT(spec.txt.clone()),
            };
            let mut records = vec![ptr, srv, txt];
            for addr in &spec.addresses {
                let (rtype, rdata) = match addr {
                    IpAddr::V4(v4) => (RrType::A, RData::A(*v4)),
                    IpAddr::V6(v6) => (RrType::AAAA, RData::AAAA(*v6)),
                };
                records.push(DnsRecord {
                    name: spec.host_name.clone(),
                    rtype,
                    rclass: RrClass(RrClass::IN.0 | 0x8000),
                    ttl: 120,
                    rdata,
                });
            }

            let published = PublishedService {
                full_instance: full_instance.clone(),
                records: records.clone(),
            };
            self.published
                .lock()
                .await
                .insert(full_instance.canonical_key(), published.clone());

            // RFC 6762 §8.3: Announce twice, 1 second apart.
            let announce = DnsMessage {
                header: DnsHeader {
                    id: 0,
                    qr: true,
                    opcode: Opcode::Query as u8,
                    aa: true,
                    tc: false,
                    rd: false,
                    ra: false,
                    z: 0,
                    rcode: 0,
                    qdcount: 0,
                    ancount: records.len() as u16,
                    nscount: 0,
                    arcount: 0,
                },
                questions: Vec::new(),
                answers: records,
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            let encoded = announce.encode();
            self.send_multicast(&encoded).await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
            self.send_multicast(&encoded).await?;

            return Ok(published);
        }
    }

    /// Send RFC 6762 §10.1 Goodbye packets (TTL = 0) and remove from responder.
    pub async fn unregister_service(&self, full_instance: &DnsName) -> io::Result<()> {
        let removed = self.published.lock().await.remove(&full_instance.canonical_key());
        if let Some(mut svc) = removed {
            for rr in &mut svc.records {
                rr.ttl = 0;
            }
            let goodbye = DnsMessage {
                header: DnsHeader {
                    id: 0,
                    qr: true,
                    opcode: Opcode::Query as u8,
                    aa: true,
                    tc: false,
                    rd: false,
                    ra: false,
                    z: 0,
                    rcode: 0,
                    qdcount: 0,
                    ancount: svc.records.len() as u16,
                    nscount: 0,
                    arcount: 0,
                },
                questions: Vec::new(),
                answers: svc.records,
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            self.send_multicast(&goodbye.encode()).await?;
        }
        Ok(())
    }
}

fn bind_mdns_v4() -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())?;
    sock.join_multicast_v4(&MDNS_V4_ADDR, &Ipv4Addr::UNSPECIFIED)?;
    sock.set_multicast_ttl_v4(255)?;
    UdpSocket::from_std(sock.into())
}

fn bind_mdns_v6() -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_only_v6(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0)).into())?;
    sock.join_multicast_v6(&MDNS_V6_ADDR, 0)?;
    sock.set_multicast_hops_v6(255)?;
    UdpSocket::from_std(sock.into())
}
