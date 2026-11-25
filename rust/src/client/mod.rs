//! Unified Distributed mDNS (Scalable DNS-SD) Client API
//! combining link-local mDNS, Domain Enumeration, DSO/TLS Push, LLQ fallback, polling, and Registration.

use crate::cache::{RecordOrigin, RrCache};
use crate::dso::build_webpki_tls_config;
use crate::enumeration::{DomainEnumerator, EnumeratedDomains, UnicastResolver};
use crate::llq::LlqClient;
use crate::mdns::{LocalServiceSpec, MdnsEngine};
use crate::push::{discover_zone_apex, polling_interval_for_ttl, PushClient};
use crate::update::{TsigKey, UnicastServiceSpec, UpdateClient};
use crate::wire::{DnsName, DnsRecord, RData, RrClass, RrType};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct ResolvedService {
    pub instance: DnsName,
    pub target: DnsName,
    pub port: u16,
    pub txt: Vec<Vec<u8>>,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowseTransport {
    Mdns,
    DnsPush,
    LlqFallback,
    PollingFallback,
}

pub struct BrowseHandle {
    pub transport: BrowseTransport,
    pub sub_id: Option<u64>,
    push_client: Option<Arc<PushClient>>,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl BrowseHandle {
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let (BrowseTransport::DnsPush, Some(sub_id), Some(push)) =
            (self.transport, self.sub_id, self.push_client.take())
        {
            let _ = push.unsubscribe(sub_id).await;
        }
    }
}

pub enum RegisteredHandle {
    Local(DnsName),
    Unicast(UnicastServiceSpec),
}

pub struct DistributedClient {
    pub cache: Arc<Mutex<RrCache>>,
    pub resolver: UnicastResolver,
    pub mdns: Option<Arc<MdnsEngine>>,
    pub push: Arc<PushClient>,
    pub llq: Arc<LlqClient>,
    pub update: UpdateClient,
}

impl DistributedClient {
    pub async fn new(
        resolver: UnicastResolver,
        tls_config: Option<Arc<rustls::ClientConfig>>,
        tsig: Option<TsigKey>,
        enable_mdns: bool,
    ) -> io::Result<Arc<Self>> {
        let cache = Arc::new(Mutex::new(RrCache::new()));
        let mdns = if enable_mdns {
            MdnsEngine::bind(Arc::clone(&cache)).await.ok()
        } else {
            None
        };
        let tls = match tls_config {
            Some(c) => c,
            None => build_webpki_tls_config()?,
        };
        let push = PushClient::new(resolver.clone(), tls, Arc::clone(&cache));
        let llq = LlqClient::new(resolver.clone(), Arc::clone(&cache));
        let update = UpdateClient::new(resolver.clone(), tsig);

        Ok(Arc::new(Self {
            cache,
            resolver,
            mdns,
            push,
            llq,
            update,
        }))
    }

    pub async fn enumerate_domains(&self) -> EnumeratedDomains {
        DomainEnumerator::new(self.mdns.clone(), self.resolver.clone())
            .enumerate()
            .await
    }

    /// Start browsing `<service_type>.<domain>` using:
    /// - mDNS for `.local.`
    /// - DSO + DNS Push (RFC 8490/8765) -> LLQ fallback (RFC 8764) -> Unicast polling fallback.
    pub async fn browse(&self, service_type: &str, domain: &DnsName) -> io::Result<BrowseHandle> {
        let qname = DnsName::from_str_dotted(&format!(
            "{}.{}",
            service_type.trim_end_matches('.'),
            domain.to_fqdn_string().trim_end_matches('.')
        ))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        if domain.is_link_local() {
            let mdns = self.mdns.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "mDNS engine is not available")
            })?;
            mdns.query_once(qname, RrType::PTR, false).await?;
            return Ok(BrowseHandle {
                transport: BrowseTransport::Mdns,
                sub_id: None,
                push_client: None,
                stop_tx: None,
            });
        }

        // 1. Always try RFC 8490 + RFC 8765 DNS Push first (RFC 8764 §1.1)
        if let Ok((_host, _port, sub_id)) =
            self.push.subscribe(qname.clone(), RrType::PTR, RrClass::IN).await
        {
            return Ok(BrowseHandle {
                transport: BrowseTransport::DnsPush,
                sub_id: Some(sub_id),
                push_client: Some(Arc::clone(&self.push)),
                stop_tx: None,
            });
        }

        // 2. Fallback to RFC 8764 LLQ
        if let Ok(llq_id) = self.llq.subscribe(qname.clone(), RrType::PTR, RrClass::IN, 3600).await {
            return Ok(BrowseHandle {
                transport: BrowseTransport::LlqFallback,
                sub_id: Some(llq_id),
                push_client: None,
                stop_tx: None,
            });
        }

        // 3. Fallback to rate-limited unicast polling (RFC 8765 §6.8)
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let resolver = self.resolver.clone();
        let cache = Arc::clone(&self.cache);
        let push = Arc::clone(&self.push);
        tokio::spawn(async move {
            loop {
                let mut min_ttl = 60u32;
                if let Ok(resp) = resolver.query(qname.clone(), RrType::PTR).await {
                    let now = Instant::now();
                    let mut c = cache.lock().await;
                    for rr in resp.answers {
                        min_ttl = min_ttl.min(rr.ttl.max(1));
                        c.insert(rr, RecordOrigin::UnicastPoll, now);
                    }
                }
                let wait = polling_interval_for_ttl(min_ttl);
                tokio::select! {
                    _ = &mut stop_rx => break,
                    _ = tokio::time::sleep(wait) => {
                        // RFC 8765 §6.8: retry Push before each poll cycle
                        if push.subscribe(qname.clone(), RrType::PTR, RrClass::IN).await.is_ok() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(BrowseHandle {
            transport: BrowseTransport::PollingFallback,
            sub_id: None,
            push_client: None,
            stop_tx: Some(stop_tx),
        })
    }

    /// Resolve a service instance (`<Instance>.<Service>.<Domain>`) to SRV, TXT, and A/AAAA.
    pub async fn resolve(&self, instance: &DnsName) -> io::Result<ResolvedService> {
        let mut srv_records = self.query_records(instance.clone(), RrType::SRV).await?;
        if srv_records.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no SRV record found"));
        }
        let srv_rr = srv_records.remove(0);
        let (port, target) = match srv_rr.rdata {
            RData::SRV { port, target, .. } => (port, target),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected RDATA for SRV")),
        };

        let txt_records = self.query_records(instance.clone(), RrType::TXT).await.unwrap_or_default();
        let txt = txt_records
            .into_iter()
            .find_map(|r| match r.rdata {
                RData::TXT(t) => Some(t),
                _ => None,
            })
            .unwrap_or_default();

        let mut addresses = Vec::new();
        for rtype in [RrType::A, RrType::AAAA] {
            if let Ok(recs) = self.query_records(target.clone(), rtype).await {
                for r in recs {
                    match r.rdata {
                        RData::A(v4) => addresses.push(IpAddr::V4(v4)),
                        RData::AAAA(v6) => addresses.push(IpAddr::V6(v6)),
                        _ => {}
                    }
                }
            }
        }

        Ok(ResolvedService {
            instance: instance.clone(),
            target,
            port,
            txt,
            addresses,
        })
    }

    async fn query_records(&self, name: DnsName, rtype: RrType) -> io::Result<Vec<DnsRecord>> {
        let now = Instant::now();
        {
            let mut c = self.cache.lock().await;
            let cached = c.get(&name, rtype, RrClass::IN, now);
            if !cached.is_empty() {
                return Ok(cached);
            }
        }
        if name.is_link_local() {
            if let Some(ref mdns) = self.mdns {
                mdns.query_once(name.clone(), rtype, false).await?;
                tokio::time::sleep(std::time::Duration::from_millis(350)).await;
                let mut c = self.cache.lock().await;
                return Ok(c.get(&name, rtype, RrClass::IN, Instant::now()));
            }
        }
        let resp = self.resolver.query(name.clone(), rtype).await?;
        let now = Instant::now();
        let mut c = self.cache.lock().await;
        for rr in &resp.answers {
            c.insert(rr.clone(), RecordOrigin::UnicastPoll, now);
        }
        Ok(resp.answers)
    }

    pub async fn reconfirm(&self, name: DnsName, rtype: RrType, rdata: RData) -> io::Result<()> {
        if name.is_link_local() {
            if let Some(ref mdns) = self.mdns {
                return mdns.query_once(name, rtype, false).await;
            }
        }
        self.push.reconfirm(name, rtype, RrClass::IN, rdata).await
    }

    /// Register a service locally (`.local.` mDNS) or off-link (DNS Dynamic Update).
    pub async fn register_service(&self, spec: UnicastServiceSpec) -> io::Result<RegisteredHandle> {
        if spec.domain.is_link_local() {
            let mdns = self.mdns.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "mDNS engine is not available")
            })?;
            let pub_svc = mdns
                .register_service(LocalServiceSpec {
                    instance_name: spec.instance_name,
                    service_type: spec.service_type,
                    port: spec.port,
                    txt: spec.txt,
                    host_name: spec.host_name,
                    addresses: spec.addresses,
                })
                .await?;
            return Ok(RegisteredHandle::Local(pub_svc.full_instance));
        }

        let msg = self.update.build_register_update(&spec)?;
        self.send_update_for_domain(&spec.domain, msg).await?;
        Ok(RegisteredHandle::Unicast(spec))
    }

    pub async fn unregister_service(&self, handle: RegisteredHandle) -> io::Result<()> {
        match handle {
            RegisteredHandle::Local(full_instance) => {
                if let Some(ref mdns) = self.mdns {
                    mdns.unregister_service(&full_instance).await?;
                }
                Ok(())
            }
            RegisteredHandle::Unicast(spec) => {
                let msg = self.update.build_unregister_update(&spec)?;
                self.send_update_for_domain(&spec.domain, msg).await
            }
        }
    }

    async fn send_update_for_domain(&self, domain: &DnsName, msg: crate::wire::DnsMessage) -> io::Result<()> {
        let zone = discover_zone_apex(&self.resolver, domain).await.unwrap_or_else(|_| domain.clone());
        if let Ok(targets) = self.update.discover_update_tls_targets(&zone).await {
            if let Some(tgt) = targets.first() {
                let host = tgt.target.to_fqdn_string().trim_end_matches('.').to_string();
                if let Ok((session, _)) = self.push.get_or_connect_host(&host, tgt.port).await {
                    return self.update.send_over_dso(&session, msg).await;
                }
            }
        }

        // Fallback to SOA MNAME on port 53 (TCP/UDP)
        let server: SocketAddr = *self.resolver.servers.first().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no DNS server configured for UPDATE")
        })?;
        self.update.send_tcp(server, msg.clone()).await.or_else(|_| {
            // Best effort UDP fallback handled synchronously via block_in_place isn't needed; return err
            Err(io::Error::other("DNS UPDATE over TCP failed"))
        })
    }
}
