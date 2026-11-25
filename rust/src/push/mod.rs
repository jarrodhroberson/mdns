//! DNS Push Notifications client (RFC 8765):
//! SOA zone-cut discovery, SRV lookup, SUBSCRIBE/PUSH/UNSUBSCRIBE/RECONFIRM, and polling fallback.

use crate::cache::RrCache;
use crate::dso::{DsoIncoming, DsoSession};
use crate::enumeration::UnicastResolver;
use crate::wire::{
    DnsName, DsoTlv, RCode, RData, RrClass, RrType, DOT_PORT,
};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, Mutex};

#[derive(Debug, Clone)]
pub struct SrvTarget {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: DnsName,
}

#[derive(Debug, Clone)]
pub struct ActiveSubscription {
    pub sub_id: u64,
    pub msg_id: u16,
    pub name: DnsName,
    pub rtype: RrType,
    pub rclass: RrClass,
}

#[derive(Debug, Clone)]
pub struct PushEvent {
    pub sub_id: u64,
    pub name: DnsName,
    pub rtype: RrType,
    pub added: bool,
}

/// RFC 8765 §6.1 iterative SOA walk to find the closest enclosing zone apex.
pub async fn discover_zone_apex(resolver: &UnicastResolver, target: &DnsName) -> io::Result<DnsName> {
    let mut current = target.clone();
    loop {
        if current.label_count() <= 1 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "SOA walk reached single-label TLD without finding zone apex",
            ));
        }
        if let Ok(resp) = resolver.query(current.clone(), RrType::SOA).await {
            for rr in resp.answers.iter().chain(resp.authorities.iter()) {
                if rr.rtype == RrType::SOA {
                    return Ok(rr.name.clone());
                }
            }
        }
        current = current.strip_leading_label().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no enclosing SOA found")
        })?;
    }
}

/// Query `_dns-push-tls._tcp.<zone>` SRV records and sort by RFC 2782 priority/weight.
pub async fn discover_push_targets(
    resolver: &UnicastResolver,
    zone: &DnsName,
) -> io::Result<Vec<SrvTarget>> {
    let srv_name = zone
        .prepend_label(b"_tcp")
        .and_then(|n| n.prepend_label(b"_dns-push-tls"))
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
                port,
                target,
            });
        }
    }
    targets.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| b.weight.cmp(&a.weight)));
    if targets.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no _dns-push-tls._tcp SRV records found",
        ));
    }
    Ok(targets)
}

/// RFC 8765 §6.2.2 recommended retry delay in seconds.
pub fn retry_delay_secs(rcode: u16, additionals: &[DsoTlv]) -> u64 {
    for tlv in additionals {
        if let DsoTlv::RetryDelay(ms) = tlv {
            return (*ms as u64) / 1000;
        }
    }
    match rcode {
        x if x == RCode::SERVFAIL.0 => 60,
        x if x == RCode::NOTIMP.0 || x == RCode::DSOTYPENI.0 => 3600,
        _ => 300,
    }
}

/// RFC 8765 §6.8 polling fallback interval: `min(900s, TTL + 2s)`.
pub fn polling_interval_for_ttl(ttl_secs: u32) -> Duration {
    let secs = (ttl_secs as u64).saturating_add(2).min(900);
    Duration::from_secs(secs)
}

struct SessionEntry {
    session: Arc<DsoSession>,
    subs: Arc<Mutex<Vec<ActiveSubscription>>>,
}

pub struct PushClient {
    resolver: UnicastResolver,
    tls_config: Arc<rustls::ClientConfig>,
    cache: Arc<Mutex<RrCache>>,
    sessions: Arc<Mutex<HashMap<(String, u16), SessionEntry>>>,
    next_sub_id: AtomicU64,
    events_tx: broadcast::Sender<PushEvent>,
}

impl PushClient {
    pub fn new(
        resolver: UnicastResolver,
        tls_config: Arc<rustls::ClientConfig>,
        cache: Arc<Mutex<RrCache>>,
    ) -> Arc<Self> {
        let (events_tx, _) = broadcast::channel(256);
        Arc::new(Self {
            resolver,
            tls_config,
            cache,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_sub_id: AtomicU64::new(1),
            events_tx,
        })
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<PushEvent> {
        self.events_tx.subscribe()
    }

    /// Connect to a Push server (trying recursive resolver :853 first, then SOA walk + SRV).
    async fn get_or_connect_for(&self, name: &DnsName) -> io::Result<(String, u16, Arc<DsoSession>, Arc<Mutex<Vec<ActiveSubscription>>>)> {
        // 1. Try configured recursive resolver on TCP port 853 (RFC 8765 §6.1)
        if let Some(first_res) = self.resolver.servers.first() {
            let host = first_res.ip().to_string();
            if let Ok(entry) = self.get_or_connect_host(&host, DOT_PORT).await {
                return Ok((host, DOT_PORT, entry.0, entry.1));
            }
        }

        // 2. Direct discovery via iterative SOA walk + _dns-push-tls._tcp.<zone> SRV
        let zone = discover_zone_apex(&self.resolver, name).await?;
        let targets = discover_push_targets(&self.resolver, &zone).await?;
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "all Push SRV targets failed");
        for tgt in targets {
            let host = tgt.target.to_fqdn_string().trim_end_matches('.').to_string();
            match self.get_or_connect_host(&host, tgt.port).await {
                Ok((sess, subs)) => return Ok((host, tgt.port, sess, subs)),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    pub async fn get_or_connect_host(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<(Arc<DsoSession>, Arc<Mutex<Vec<ActiveSubscription>>>)> {
        let key = (host.to_string(), port);
        {
            let map = self.sessions.lock().await;
            if let Some(entry) = map.get(&key) {
                return Ok((Arc::clone(&entry.session), Arc::clone(&entry.subs)));
            }
        }

        let (session, incoming_rx) =
            DsoSession::connect(host, port, Arc::clone(&self.tls_config)).await?;
        // Send Keepalive to establish DSO session parameters (RFC 8765 §6).
        let _ = session.send_keepalive(15_000, 15_000).await;

        let subs = Arc::new(Mutex::new(Vec::new()));
        self.spawn_incoming_handler(key.clone(), incoming_rx, Arc::clone(&subs));

        self.sessions.lock().await.insert(
            key,
            SessionEntry {
                session: Arc::clone(&session),
                subs: Arc::clone(&subs),
            },
        );
        Ok((session, subs))
    }

    fn spawn_incoming_handler(
        &self,
        key: (String, u16),
        mut rx: mpsc::Receiver<DsoIncoming>,
        subs: Arc<Mutex<Vec<ActiveSubscription>>>,
    ) {
        let cache = Arc::clone(&self.cache);
        let sessions = Arc::clone(&self.sessions);
        let events_tx = self.events_tx.clone();

        tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                match item {
                    DsoIncoming::Push(dso) => {
                        if let Some(DsoTlv::Push(changes)) = dso.primary {
                            let active = subs.lock().await.clone();
                            let now = Instant::now();
                            let mut cache_guard = cache.lock().await;
                            for ch in &changes {
                                // RFC 8765 §6.3.1: validate against active subscriptions; silently ignore stale.
                                let matched = active.iter().find(|s| {
                                    s.name == ch.name
                                        && (s.rtype == RrType::ANY
                                            || ch.rtype == RrType::CNAME
                                            || s.rtype == ch.rtype
                                            || ch.ttl == crate::wire::PushChange::TTL_COLLECTIVE_REMOVE)
                                        && (s.rclass == RrClass::ANY
                                            || ch.rclass == RrClass::ANY
                                            || s.rclass == ch.rclass)
                                });
                                if let Some(sub) = matched {
                                    cache_guard.apply_push_change(ch, sub.sub_id, now);
                                    let _ = events_tx.send(PushEvent {
                                        sub_id: sub.sub_id,
                                        name: ch.name.clone(),
                                        rtype: ch.rtype,
                                        added: ch.ttl <= 0x7FFF_FFFF,
                                    });
                                }
                            }
                        }
                    }
                    DsoIncoming::ServerRetryDelay(_) | DsoIncoming::SessionClosed => {
                        break;
                    }
                }
            }
            let active = subs.lock().await.drain(..).collect::<Vec<_>>();
            let now = Instant::now();
            let mut cache_guard = cache.lock().await;
            for sub in active {
                cache_guard.unfreeze_subscription(sub.sub_id, now);
            }
            sessions.lock().await.remove(&key);
        });
    }

    pub async fn subscribe(
        &self,
        name: DnsName,
        rtype: RrType,
        rclass: RrClass,
    ) -> io::Result<(String, u16, u64)> {
        let (host, port, session, subs) = self.get_or_connect_for(&name).await?;
        let sub_id = self.next_sub_id.fetch_add(1, Ordering::Relaxed);

        let id = session.alloc_id();
        {
            let mut guard = subs.lock().await;
            if guard
                .iter()
                .any(|s| s.name == name && s.rtype == rtype && s.rclass == rclass)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "duplicate SUBSCRIBE on same DSO session forbidden by RFC 8765 §6.2.1",
                ));
            }
            guard.push(ActiveSubscription {
                sub_id,
                msg_id: id,
                name: name.clone(),
                rtype,
                rclass,
            });
        }

        let resp = session
            .send_dso_request(DsoTlv::Subscribe {
                name,
                rtype,
                rclass,
            })
            .await?;

        if resp.rcode != RCode::NOERROR.0 {
            subs.lock().await.retain(|s| s.sub_id != sub_id);
            let delay = retry_delay_secs(resp.rcode, &resp.additionals);
            return Err(io::Error::other(format!(
                "SUBSCRIBE rejected with RCODE={} (retry after {delay}s)",
                resp.rcode
            )));
        }

        Ok((host, port, sub_id))
    }

    pub async fn unsubscribe(&self, sub_id: u64) -> io::Result<()> {
        let map = self.sessions.lock().await;
        for entry in map.values() {
            let mut subs = entry.subs.lock().await;
            if let Some(pos) = subs.iter().position(|s| s.sub_id == sub_id) {
                let removed = subs.remove(pos);
                let _ = entry
                    .session
                    .send_dso_unidirectional(DsoTlv::Unsubscribe {
                        subscribe_msg_id: removed.msg_id,
                    })
                    .await;
                self.cache
                    .lock()
                    .await
                    .unfreeze_subscription(sub_id, Instant::now());
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn reconfirm(&self, name: DnsName, rtype: RrType, rclass: RrClass, rdata: RData) -> io::Result<()> {
        let (_, _, session, _) = self.get_or_connect_for(&name).await?;
        session
            .send_dso_unidirectional(DsoTlv::Reconfirm {
                name,
                rtype,
                rclass,
                rdata,
            })
            .await
    }
}
