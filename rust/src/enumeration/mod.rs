//! Multi-link Domain Enumeration (RFC 8766 §5.2, RFC 6763 §11, RFC 8375 home.arpa.)
//! and lightweight unicast DNS query helper.

use crate::mdns::MdnsEngine;
use crate::wire::{frame_tcp, DnsMessage, DnsName, RData, RrClass, RrType};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone, Default)]
pub struct EnumeratedDomains {
    pub browse: Vec<DnsName>,
    pub default_browse: Option<DnsName>,
    pub legacy_browse: Vec<DnsName>,
    pub register: Vec<DnsName>,
    pub default_register: Option<DnsName>,
}

#[derive(Debug, Clone)]
pub struct UnicastResolver {
    pub servers: Vec<SocketAddr>,
    pub search_domains: Vec<DnsName>,
    pub timeout: Duration,
}

impl UnicastResolver {
    pub fn from_system() -> Self {
        let mut servers = Vec::new();
        let mut search_domains = Vec::new();
        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in contents.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if let Some(rest) = line.strip_prefix("nameserver") {
                    if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                        servers.push(SocketAddr::new(ip, 53));
                    }
                } else if let Some(rest) = line.strip_prefix("search").or_else(|| line.strip_prefix("domain")) {
                    for tok in rest.split_whitespace() {
                        if let Ok(name) = DnsName::from_str_dotted(tok) {
                            search_domains.push(name);
                        }
                    }
                }
            }
        }
        if servers.is_empty() {
            servers.push(SocketAddr::from(([127, 0, 0, 1], 53)));
        }
        Self {
            servers,
            search_domains,
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_servers(servers: Vec<SocketAddr>, search_domains: Vec<DnsName>) -> Self {
        Self {
            servers,
            search_domains,
            timeout: Duration::from_secs(3),
        }
    }

    /// Send a unicast DNS query (UDP first, falling back to TCP if TC=1) to configured resolvers.
    pub async fn query(&self, qname: DnsName, qtype: RrType) -> io::Result<DnsMessage> {
        let id = rand::random::<u16>();
        let msg = DnsMessage::new_query(id, qname.clone(), qtype, RrClass::IN, true);
        let wire = msg.encode();

        let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "no recursive resolver responded");
        for &server in &self.servers {
            let bind_addr: SocketAddr = if server.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let Ok(sock) = UdpSocket::bind(bind_addr).await else {
                continue;
            };
            if sock.send_to(&wire, server).await.is_err() {
                continue;
            }
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(self.timeout, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let Ok(resp) = DnsMessage::parse(&buf[..n]) {
                        if resp.header.id == id {
                            if resp.header.tc {
                                return self.query_tcp(server, &wire, id).await;
                            }
                            return Ok(resp);
                        }
                    }
                }
                Ok(Err(e)) => last_err = e,
                Err(_) => last_err = io::Error::new(io::ErrorKind::TimedOut, "DNS UDP query timed out"),
            }
        }
        Err(last_err)
    }

    async fn query_tcp(&self, server: SocketAddr, wire: &[u8], expected_id: u16) -> io::Result<DnsMessage> {
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(server)).await??;
        stream.write_all(&frame_tcp(wire)).await?;
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut len_buf)).await??;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut buf)).await??;
        let resp = DnsMessage::parse(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if resp.header.id != expected_id {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "mismatched TCP DNS ID"));
        }
        Ok(resp)
    }
}

pub struct DomainEnumerator {
    mdns: Option<Arc<MdnsEngine>>,
    resolver: UnicastResolver,
}

impl DomainEnumerator {
    pub fn new(mdns: Option<Arc<MdnsEngine>>, resolver: UnicastResolver) -> Self {
        Self { mdns, resolver }
    }

    /// Perform dual-path Domain Enumeration (multicast `.local.` + unicast search domains + `home.arpa.`).
    pub async fn enumerate(&self) -> EnumeratedDomains {
        let mut out = EnumeratedDomains::default();
        let mut seen_b = HashSet::new();
        let mut seen_lb = HashSet::new();
        let mut seen_r = HashSet::new();

        // Always include local. as a baseline browse/register domain when mDNS is active.
        if self.mdns.is_some() {
            if let Ok(local) = DnsName::from_str_dotted("local.") {
                seen_b.insert(local.clone());
                out.browse.push(local.clone());
                seen_r.insert(local.clone());
                out.register.push(local);
            }
        }

        // Multicast domain enumeration on local. (RFC 8766 §5.2.2)
        if let Some(ref mdns) = self.mdns {
            for prefix in ["b", "db", "lb", "r", "dr"] {
                if let Ok(qname) = DnsName::from_str_dotted(&format!("{prefix}._dns-sd._udp.local.")) {
                    let _ = mdns.query_once(qname, RrType::PTR, false).await;
                }
            }
        }

        // Unicast domain enumeration on configured search domains + home.arpa. (RFC 8375, RFC 8766 §5.2.1)
        let mut base_domains = self.resolver.search_domains.clone();
        if let Ok(home_arpa) = DnsName::from_str_dotted("home.arpa.") {
            if !base_domains.contains(&home_arpa) {
                base_domains.push(home_arpa);
            }
        }

        for base in &base_domains {
            let base_str = base.to_fqdn_string();
            for (prefix, kind) in [
                ("b", "b"),
                ("db", "db"),
                ("lb", "lb"),
                ("r", "r"),
                ("dr", "dr"),
            ] {
                let Ok(qname) = DnsName::from_str_dotted(&format!("{prefix}._dns-sd._udp.{base_str}")) else {
                    continue;
                };
                if let Ok(resp) = self.resolver.query(qname, RrType::PTR).await {
                    for rr in resp.answers {
                        if let RData::PTR(target) = rr.rdata {
                            match kind {
                                "b" if seen_b.insert(target.clone()) => out.browse.push(target),
                                "db" if out.default_browse.is_none() => out.default_browse = Some(target),
                                "lb" if seen_lb.insert(target.clone()) => out.legacy_browse.push(target),
                                "r" if seen_r.insert(target.clone()) => out.register.push(target),
                                "dr" if out.default_register.is_none() => out.default_register = Some(target),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // RFC 8766 §5.2.1: db MUST be in b; otherwise no default is selected.
        if let Some(ref db) = out.default_browse {
            if !seen_b.contains(db) {
                out.default_browse = None;
            }
        }
        if let Some(ref dr) = out.default_register {
            if !seen_r.contains(dr) {
                out.default_register = None;
            }
        }

        out
    }
}
