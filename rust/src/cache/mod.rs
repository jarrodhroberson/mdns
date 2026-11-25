//! Unified DNS Resource Record cache with negative caching (RFC 2308) and Push TTL freeze (RFC 8765 §6.3.1).

use crate::wire::{DnsName, DnsRecord, PushChange, RData, RrClass, RrType};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordOrigin {
    LocalMulticast,
    PushSubscription(u64),
    LlqSubscription(u64),
    UnicastPoll,
}

#[derive(Debug, Clone)]
pub struct CachedRecord {
    pub record: DnsRecord,
    pub origin: RecordOrigin,
    pub inserted_at: Instant,
    /// When true (active Push subscription), TTL countdown is frozen per RFC 8765 §6.3.1.
    pub ttl_frozen: bool,
}

impl CachedRecord {
    pub fn remaining_ttl(&self, now: Instant) -> u32 {
        if self.ttl_frozen {
            return self.record.ttl;
        }
        let elapsed = now.saturating_duration_since(self.inserted_at).as_secs();
        self.record.ttl.saturating_sub(elapsed as u32)
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        if self.ttl_frozen {
            return false;
        }
        if self.record.ttl == 0 {
            return true;
        }
        now.saturating_duration_since(self.inserted_at) >= Duration::from_secs(self.record.ttl as u64)
    }
}

#[derive(Debug, Clone)]
struct NegativeEntry {
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct RrCache {
    /// Keyed by canonical lowercase DnsName bytes.
    entries: HashMap<Vec<u8>, Vec<CachedRecord>>,
    negative: HashMap<(Vec<u8>, RrType, RrClass), NegativeEntry>,
}

impl RrCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, mut record: DnsRecord, origin: RecordOrigin, now: Instant) {
        record.rclass = record.rclass.raw_without_flush();
        let key = record.name.canonical_key();
        let ttl_frozen = matches!(origin, RecordOrigin::PushSubscription(_));
        let list = self.entries.entry(key).or_default();

        if let Some(existing) = list.iter_mut().find(|c| {
            c.record.rtype == record.rtype
                && c.record.rclass == record.rclass
                && c.record.rdata == record.rdata
        }) {
            existing.record.ttl = record.ttl;
            existing.origin = origin;
            existing.inserted_at = now;
            existing.ttl_frozen = ttl_frozen;
        } else {
            list.push(CachedRecord {
                record,
                origin,
                inserted_at: now,
                ttl_frozen,
            });
        }
    }

    pub fn remove_rr(&mut self, name: &DnsName, rtype: RrType, rclass: RrClass, rdata: &RData) {
        let key = name.canonical_key();
        if let Some(list) = self.entries.get_mut(&key) {
            list.retain(|c| {
                !(c.record.rtype == rtype
                    && c.record.rclass == rclass.raw_without_flush()
                    && &c.record.rdata == rdata)
            });
            if list.is_empty() {
                self.entries.remove(&key);
            }
        }
    }

    /// Apply RFC 8765 §6.3.1 collective removal semantics.
    pub fn collective_remove(&mut self, name: &DnsName, rtype: RrType, rclass: RrClass) {
        let key = name.canonical_key();
        if rclass == RrClass::ANY {
            self.entries.remove(&key);
            return;
        }
        if let Some(list) = self.entries.get_mut(&key) {
            let cls = rclass.raw_without_flush();
            if rtype == RrType::ANY {
                list.retain(|c| c.record.rclass != cls);
            } else {
                list.retain(|c| !(c.record.rclass == cls && c.record.rtype == rtype));
            }
            if list.is_empty() {
                self.entries.remove(&key);
            }
        }
    }

    /// Apply a PUSH change notification record (RFC 8765 §6.3.1).
    pub fn apply_push_change(&mut self, ch: &PushChange, sub_id: u64, now: Instant) {
        if ch.ttl == PushChange::TTL_COLLECTIVE_REMOVE {
            self.collective_remove(&ch.name, ch.rtype, ch.rclass);
        } else if ch.ttl == PushChange::TTL_REMOVE_RR {
            self.remove_rr(&ch.name, ch.rtype, ch.rclass, &ch.rdata);
        } else if ch.ttl <= 0x7FFF_FFFF {
            let rr = DnsRecord {
                name: ch.name.clone(),
                rtype: ch.rtype,
                rclass: ch.rclass,
                ttl: ch.ttl,
                rdata: ch.rdata.clone(),
            };
            self.insert(rr, RecordOrigin::PushSubscription(sub_id), now);
        }
    }

    /// Unfreeze TTLs for records belonging to a canceled Push subscription (RFC 8765 §6.3.1).
    /// Records with TTL == 0 are discarded immediately.
    pub fn unfreeze_subscription(&mut self, sub_id: u64, now: Instant) {
        let origin = RecordOrigin::PushSubscription(sub_id);
        self.entries.retain(|_, list| {
            list.retain_mut(|c| {
                if c.origin == origin {
                    if c.record.ttl == 0 {
                        return false;
                    }
                    c.ttl_frozen = false;
                    c.inserted_at = now;
                }
                true
            });
            !list.is_empty()
        });
    }

    pub fn get(&mut self, name: &DnsName, rtype: RrType, rclass: RrClass, now: Instant) -> Vec<DnsRecord> {
        self.purge_expired(now);
        let key = name.canonical_key();
        let cls = rclass.raw_without_flush();
        self.entries
            .get(&key)
            .map(|list| {
                list.iter()
                    .filter(|c| {
                        (rtype == RrType::ANY || c.record.rtype == rtype || c.record.rtype == RrType::CNAME)
                            && (cls == RrClass::ANY || c.record.rclass == cls)
                    })
                    .map(|c| {
                        let mut rr = c.record.clone();
                        rr.ttl = c.remaining_ttl(now);
                        rr
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn insert_negative(&mut self, name: &DnsName, rtype: RrType, rclass: RrClass, ttl_secs: u32, now: Instant) {
        self.negative.insert(
            (name.canonical_key(), rtype, rclass.raw_without_flush()),
            NegativeEntry {
                expires_at: now + Duration::from_secs(ttl_secs as u64),
            },
        );
    }

    pub fn is_negatively_cached(&self, name: &DnsName, rtype: RrType, rclass: RrClass, now: Instant) -> bool {
        self.negative
            .get(&(name.canonical_key(), rtype, rclass.raw_without_flush()))
            .is_some_and(|e| e.expires_at > now)
    }

    pub fn purge_expired(&mut self, now: Instant) {
        self.entries.retain(|_, list| {
            list.retain(|c| !c.is_expired(now));
            !list.is_empty()
        });
        self.negative.retain(|_, e| e.expires_at > now);
    }
}
