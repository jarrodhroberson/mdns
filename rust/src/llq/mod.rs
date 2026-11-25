//! Apple's DNS Long-Lived Queries (LLQ, RFC 8764) fallback client:
//! `_dns-llq._udp.<zone>` SRV discovery, 4-way UDP setup handshake, LLQ-EVENT, and LLQ-REFRESH.

use crate::cache::{RecordOrigin, RrCache};
use crate::enumeration::UnicastResolver;
use crate::push::{discover_zone_apex, SrvTarget};
use crate::wire::{
    DnsMessage, DnsName, DnsRecord, LlqOption, RData, RrClass, RrType, LLQ_DEFAULT_PORT,
};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Query `_dns-llq._udp.<zone>` SRV records (RFC 8764 §4).
pub async fn discover_llq_targets(
    resolver: &UnicastResolver,
    zone: &DnsName,
) -> io::Result<Vec<SrvTarget>> {
    let srv_name = zone
        .prepend_label(b"_udp")
        .and_then(|n| n.prepend_label(b"_dns-llq"))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let resp = resolver.query(srv_name, RrType::SRV).await?;
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
                port: if port == 0 { LLQ_DEFAULT_PORT } else { port },
                target,
            });
        }
    }
    targets.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| b.weight.cmp(&a.weight)));
    if targets.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no _dns-llq._udp SRV records found",
        ));
    }
    Ok(targets)
}

pub struct LlqClient {
    resolver: UnicastResolver,
    cache: Arc<Mutex<RrCache>>,
    next_llq_id: AtomicU64,
}

impl LlqClient {
    pub fn new(resolver: UnicastResolver, cache: Arc<Mutex<RrCache>>) -> Arc<Self> {
        Arc::new(Self {
            resolver,
            cache,
            next_llq_id: AtomicU64::new(1),
        })
    }

    /// Establish an LLQ subscription via RFC 8764 §5.2 4-way handshake and spawn event/refresh loop.
    pub async fn subscribe(
        &self,
        name: DnsName,
        rtype: RrType,
        rclass: RrClass,
        lease_life_secs: u32,
    ) -> io::Result<u64> {
        let zone = discover_zone_apex(&self.resolver, &name).await?;
        let targets = discover_llq_targets(&self.resolver, &zone).await?;
        let target = &targets[0];
        let host = target.target.to_fqdn_string();
        let addr_str = format!("{}:{port}", host.trim_end_matches('.'), port = target.port);
        let server_addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LLQ target has no IP"))?;

        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = Arc::new(UdpSocket::bind(bind_addr).await?);
        sock.connect(server_addr).await?;

        let sub_id = self.next_llq_id.fetch_add(1, Ordering::Relaxed);

        // Step 1: LLQ-SETUP Request (llq_id = 0)
        let setup_req = build_llq_message(
            rand::random(),
            name.clone(),
            rtype,
            rclass,
            LlqOption {
                vers: 1,
                llq_opcode: LlqOption::OPCODE_SETUP,
                error_code: 0,
                llq_id: 0,
                lease_life: lease_life_secs,
            },
        );
        sock.send(&setup_req).await?;

        // Step 2: Receive Setup Challenge containing server-chosen LLQ-ID
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(4), sock.recv(&mut buf)).await??;
        let challenge = DnsMessage::parse(&buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let challenge_opt = challenge
            .llq_options()
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing LLQ challenge OPT"))?;
        if challenge_opt.error_code != LlqOption::ERR_NO_ERROR {
            return Err(io::Error::other(format!(
                "LLQ challenge error code {}",
                challenge_opt.error_code
            )));
        }

        // Step 3: Challenge Response echoing server LLQ-ID
        let challenge_resp = build_llq_message(
            rand::random(),
            name.clone(),
            rtype,
            rclass,
            LlqOption {
                vers: 1,
                llq_opcode: LlqOption::OPCODE_SETUP,
                error_code: 0,
                llq_id: challenge_opt.llq_id,
                lease_life: challenge_opt.lease_life,
            },
        );
        sock.send(&challenge_resp).await?;

        // Step 4: Receive ACK + initial Answers
        let n = tokio::time::timeout(Duration::from_secs(4), sock.recv(&mut buf)).await??;
        let ack = DnsMessage::parse(&buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let now = Instant::now();
        {
            let mut cache = self.cache.lock().await;
            for rr in &ack.answers {
                cache.insert(rr.clone(), RecordOrigin::LlqSubscription(sub_id), now);
            }
        }

        let granted_lease = ack
            .llq_options()
            .into_iter()
            .next()
            .map(|o| o.lease_life)
            .unwrap_or(challenge_opt.lease_life)
            .max(30);

        // Spawn background LLQ-EVENT listener + LLQ-REFRESH timer
        let cache = Arc::clone(&self.cache);
        let llq_id = challenge_opt.llq_id;
        tokio::spawn(async move {
            let mut refresh_interval =
                tokio::time::interval(Duration::from_secs((granted_lease / 2) as u64));
            refresh_interval.tick().await;
            let mut buf = vec![0u8; 4096];
            loop {
                tokio::select! {
                    _ = refresh_interval.tick() => {
                        let refresh = build_llq_message(
                            rand::random(),
                            name.clone(),
                            rtype,
                            rclass,
                            LlqOption {
                                vers: 1,
                                llq_opcode: LlqOption::OPCODE_REFRESH,
                                error_code: 0,
                                llq_id,
                                lease_life: granted_lease,
                            },
                        );
                        if sock.send(&refresh).await.is_err() {
                            break;
                        }
                    }
                    res = sock.recv(&mut buf) => {
                        let Ok(n) = res else { break };
                        let Ok(ev) = DnsMessage::parse(&buf[..n]) else { continue };
                        let is_event = ev.llq_options().iter().any(|o| o.llq_opcode == LlqOption::OPCODE_EVENT);
                        if is_event {
                            let now = Instant::now();
                            let mut cache_g = cache.lock().await;
                            for rr in &ev.answers {
                                if rr.ttl == u32::MAX || rr.ttl == 0 {
                                    cache_g.remove_rr(&rr.name, rr.rtype, rr.rclass, &rr.rdata);
                                } else {
                                    cache_g.insert(rr.clone(), RecordOrigin::LlqSubscription(sub_id), now);
                                }
                            }
                            // Send Gratuitous Response ACK (RFC 8764 §6.3)
                            let ack_msg = build_llq_message(
                                ev.header.id,
                                name.clone(),
                                rtype,
                                rclass,
                                LlqOption {
                                    vers: 1,
                                    llq_opcode: LlqOption::OPCODE_EVENT,
                                    error_code: LlqOption::ERR_NO_ERROR,
                                    llq_id,
                                    lease_life: 0,
                                },
                            );
                            let _ = sock.send(&ack_msg).await;
                        }
                    }
                }
            }
        });

        Ok(sub_id)
    }
}

fn build_llq_message(
    id: u16,
    qname: DnsName,
    qtype: RrType,
    qclass: RrClass,
    opt: LlqOption,
) -> Vec<u8> {
    let mut msg = DnsMessage::new_query(id, qname, qtype, qclass, false);
    let mut out = msg.encode();
    // Append OPT RR in Additional section (increment ARCOUNT to 1)
    out[10..12].copy_from_slice(&1u16.to_be_bytes());
    DnsRecord::encode_opt(0, &[opt.encode_edns_option()], &mut out);
    let _ = &mut msg;
    out
}
