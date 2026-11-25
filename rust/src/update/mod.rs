//! Unicast DNS Dynamic Update (RFC 2136) + TSIG (RFC 2845) registration client,
//! with DSO/TLS session sharing when `_dns-update-tls._tcp.<zone>` matches Push (RFC 8765 §3).

use crate::dso::DsoSession;
use crate::enumeration::UnicastResolver;
use crate::push::SrvTarget;
use crate::wire::{
    frame_tcp, sign_tsig, DnsHeader, DnsMessage, DnsName, DnsQuestion, DnsRecord, Opcode, RCode,
    RData, RrClass, RrType,
};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone)]
pub struct TsigKey {
    pub name: DnsName,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UnicastServiceSpec {
    pub instance_name: String,
    pub service_type: String,
    pub domain: DnsName,
    pub port: u16,
    pub txt: Vec<Vec<u8>>,
    pub host_name: DnsName,
    pub addresses: Vec<IpAddr>,
    pub ttl: u32,
}

pub struct UpdateClient {
    resolver: UnicastResolver,
    tsig: Option<TsigKey>,
}

impl UpdateClient {
    pub fn new(resolver: UnicastResolver, tsig: Option<TsigKey>) -> Self {
        Self { resolver, tsig }
    }

    pub async fn discover_update_tls_targets(&self, zone: &DnsName) -> io::Result<Vec<SrvTarget>> {
        let srv_name = zone
            .prepend_label(b"_tcp")
            .and_then(|n| n.prepend_label(b"_dns-update-tls"))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let resp = self.resolver.query(srv_name, RrType::SRV).await?;
        let mut targets = Vec::new();
        for rr in resp.answers {
            if let RData::SRV {
                priority,
                weight,
                port,
                target,
            } = rr.rdata
            {
                targets.push(SrvTarget {
                    priority,
                    weight,
                    port,
                    target,
                });
            }
        }
        targets.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| b.weight.cmp(&a.weight)));
        Ok(targets)
    }

    /// Build an RFC 2136 UPDATE message registering PTR, SRV, TXT, and A/AAAA records.
    pub fn build_register_update(&self, spec: &UnicastServiceSpec) -> io::Result<DnsMessage> {
        let service_fqdn = DnsName::from_str_dotted(&format!(
            "{}.{}",
            spec.service_type.trim_end_matches('.'),
            spec.domain.to_fqdn_string().trim_end_matches('.')
        ))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let full_instance = service_fqdn
            .prepend_label(spec.instance_name.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Prerequisite: instance SRV must not already exist (RFC 2136 §2.4.3)
        let prereq = DnsRecord {
            name: full_instance.clone(),
            rtype: RrType::SRV,
            rclass: RrClass::NONE,
            ttl: 0,
            rdata: RData::Raw(Vec::new()),
        };

        let mut updates = vec![
            DnsRecord {
                name: service_fqdn,
                rtype: RrType::PTR,
                rclass: RrClass::IN,
                ttl: spec.ttl,
                rdata: RData::PTR(full_instance.clone()),
            },
            DnsRecord {
                name: full_instance.clone(),
                rtype: RrType::SRV,
                rclass: RrClass::IN,
                ttl: spec.ttl,
                rdata: RData::SRV {
                    priority: 0,
                    weight: 0,
                    port: spec.port,
                    target: spec.host_name.clone(),
                },
            },
            DnsRecord {
                name: full_instance,
                rtype: RrType::TXT,
                rclass: RrClass::IN,
                ttl: spec.ttl,
                rdata: RData::TXT(spec.txt.clone()),
            },
        ];

        for addr in &spec.addresses {
            let (rtype, rdata) = match addr {
                IpAddr::V4(v4) => (RrType::A, RData::A(*v4)),
                IpAddr::V6(v6) => (RrType::AAAA, RData::AAAA(*v6)),
            };
            updates.push(DnsRecord {
                name: spec.host_name.clone(),
                rtype,
                rclass: RrClass::IN,
                ttl: spec.ttl,
                rdata,
            });
        }

        let mut msg = DnsMessage {
            header: DnsHeader {
                id: rand::random(),
                qr: false,
                opcode: Opcode::Update as u8,
                aa: false,
                tc: false,
                rd: false,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 1,
                nscount: updates.len() as u16,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                qname: spec.domain.clone(),
                qtype: RrType::SOA,
                qclass: RrClass::IN,
            }],
            answers: vec![prereq],
            authorities: updates,
            additionals: Vec::new(),
        };

        if let Some(ref tsig) = self.tsig {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            sign_tsig(&mut msg, &tsig.name, &tsig.secret, now, 300)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }

        Ok(msg)
    }

    /// Build an RFC 2136 UPDATE message deleting the service instance's PTR, SRV, and TXT records.
    pub fn build_unregister_update(&self, spec: &UnicastServiceSpec) -> io::Result<DnsMessage> {
        let service_fqdn = DnsName::from_str_dotted(&format!(
            "{}.{}",
            spec.service_type.trim_end_matches('.'),
            spec.domain.to_fqdn_string().trim_end_matches('.')
        ))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let full_instance = service_fqdn
            .prepend_label(spec.instance_name.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let updates = vec![
            DnsRecord {
                name: service_fqdn,
                rtype: RrType::PTR,
                rclass: RrClass::NONE,
                ttl: 0,
                rdata: RData::PTR(full_instance.clone()),
            },
            DnsRecord {
                name: full_instance,
                rtype: RrType::ANY,
                rclass: RrClass::ANY,
                ttl: 0,
                rdata: RData::Raw(Vec::new()),
            },
        ];

        let mut msg = DnsMessage {
            header: DnsHeader {
                id: rand::random(),
                qr: false,
                opcode: Opcode::Update as u8,
                aa: false,
                tc: false,
                rd: false,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: updates.len() as u16,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                qname: spec.domain.clone(),
                qtype: RrType::SOA,
                qclass: RrClass::IN,
            }],
            answers: Vec::new(),
            authorities: updates,
            additionals: Vec::new(),
        };

        if let Some(ref tsig) = self.tsig {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            sign_tsig(&mut msg, &tsig.name, &tsig.secret, now, 300)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }

        Ok(msg)
    }

    pub async fn send_over_dso(&self, session: &Arc<DsoSession>, msg: DnsMessage) -> io::Result<()> {
        let resp = session.send_dns_message(msg).await?;
        if resp.header.rcode != RCode::NOERROR.0 {
            return Err(io::Error::other(format!(
                "DNS UPDATE failed with RCODE={}",
                resp.header.rcode
            )));
        }
        Ok(())
    }

    pub async fn send_tcp(&self, server: SocketAddr, msg: DnsMessage) -> io::Result<()> {
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server)).await??;
        stream.write_all(&frame_tcp(&msg.encode())).await?;
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf)).await??;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await??;
        let resp = DnsMessage::parse(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if resp.header.rcode != RCode::NOERROR.0 {
            return Err(io::Error::other(format!(
                "DNS UPDATE failed with RCODE={}",
                resp.header.rcode
            )));
        }
        Ok(())
    }

    pub async fn send_udp(&self, server: SocketAddr, msg: DnsMessage) -> io::Result<()> {
        let bind_addr: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind_addr).await?;
        sock.send_to(&msg.encode(), server).await?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await??;
        let resp = DnsMessage::parse(&buf[..n]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if resp.header.rcode != RCode::NOERROR.0 {
            return Err(io::Error::other(format!(
                "DNS UPDATE failed with RCODE={}",
                resp.header.rcode
            )));
        }
        Ok(())
    }
}
