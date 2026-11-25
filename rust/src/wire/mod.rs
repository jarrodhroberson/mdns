//! Core DNS, DSO (RFC 8490), DNS Push (RFC 8765), LLQ (RFC 8764), and UPDATE/TSIG (RFC 2136/2845) wire codec.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_PUSH_MESSAGE_LEN: usize = 16_382;
pub const MDNS_PORT: u16 = 5353;
pub const DOT_PORT: u16 = 853;
pub const LLQ_DEFAULT_PORT: u16 = 5352;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    InvalidLabel(u8),
    CompressionLoop,
    NameTooLong,
    InvalidDsoHeader,
    FatalPushError(&'static str),
    InvalidRdata(&'static str),
    TsigError(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "truncated DNS/DSO message"),
            WireError::InvalidLabel(b) => write!(f, "invalid DNS label length/tag: 0x{b:02x}"),
            WireError::CompressionLoop => write!(f, "DNS name compression pointer loop"),
            WireError::NameTooLong => write!(f, "DNS name exceeds 255 octets"),
            WireError::InvalidDsoHeader => write!(f, "invalid DSO header (non-zero counts or wrong opcode)"),
            WireError::FatalPushError(msg) => write!(f, "fatal DNS Push protocol error: {msg}"),
            WireError::InvalidRdata(msg) => write!(f, "invalid RDATA: {msg}"),
            WireError::TsigError(msg) => write!(f, "TSIG error: {msg}"),
        }
    }
}

impl std::error::Error for WireError {}

/// A DNS domain name stored as raw UTF-8 labels (no Punycode translation per RFC 8766 §5.5.4).
/// Equality and hashing are US-ASCII case-insensitive per RFC 1035 / RFC 8765.
#[derive(Clone, Default)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
}

impl DnsName {
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self, WireError> {
        let total: usize = labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
        if total > 256 {
            return Err(WireError::NameTooLong);
        }
        for l in &labels {
            if l.is_empty() || l.len() > 63 {
                return Err(WireError::InvalidLabel(l.len() as u8));
            }
        }
        Ok(Self { labels })
    }

    /// Parse a dotted string into labels. Trailing dot is optional; empty or "." is root.
    pub fn from_str_dotted(s: &str) -> Result<Self, WireError> {
        let trimmed = s.strip_suffix('.').unwrap_or(s);
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        let mut labels = Vec::new();
        for part in trimmed.split('.') {
            let bytes = part.as_bytes().to_vec();
            if bytes.is_empty() || bytes.len() > 63 {
                return Err(WireError::InvalidLabel(bytes.len() as u8));
            }
            labels.push(bytes);
        }
        Self::from_labels(labels)
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Strip the leading label (used for RFC 8765 §6.1 iterative SOA zone-cut walk).
    pub fn strip_leading_label(&self) -> Option<Self> {
        if self.labels.len() <= 1 {
            None
        } else {
            Some(Self {
                labels: self.labels[1..].to_vec(),
            })
        }
    }

    /// Prepend a label (e.g., `_dns-push-tls` + `_tcp` + zone).
    pub fn prepend_label(&self, label: &[u8]) -> Result<Self, WireError> {
        let mut labels = Vec::with_capacity(self.labels.len() + 1);
        labels.push(label.to_vec());
        labels.extend_from_slice(&self.labels);
        Self::from_labels(labels)
    }

    /// Check if this name ends with the given suffix (US-ASCII case-insensitive).
    pub fn ends_with(&self, suffix: &DnsName) -> bool {
        if suffix.labels.len() > self.labels.len() {
            return false;
        }
        let start = self.labels.len() - suffix.labels.len();
        self.labels[start..]
            .iter()
            .zip(suffix.labels.iter())
            .all(|(a, b)| ascii_eq_ignore_case(a, b))
    }

    /// True if this name is `.local.` or a link-local reverse domain (RFC 6762 §3–4).
    pub fn is_link_local(&self) -> bool {
        let local = DnsName::from_str_dotted("local.").unwrap();
        let ll_v4 = DnsName::from_str_dotted("254.169.in-addr.arpa.").unwrap();
        if self.ends_with(&local) || self.ends_with(&ll_v4) {
            return true;
        }
        for prefix in ["8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa."] {
            let p = DnsName::from_str_dotted(prefix).unwrap();
            if self.ends_with(&p) {
                return true;
            }
        }
        false
    }

    pub fn to_fqdn_string(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }
        let mut out = String::new();
        for l in &self.labels {
            out.push_str(&String::from_utf8_lossy(l));
            out.push('.');
        }
        out
    }

    /// Canonical lowercase key for map lookups.
    pub fn canonical_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for l in &self.labels {
            out.push(l.len() as u8);
            for &b in l {
                out.push(b.to_ascii_lowercase());
            }
        }
        out.push(0);
        out
    }

    pub fn parse(buf: &[u8], start: usize) -> Result<(Self, usize), WireError> {
        let mut labels = Vec::new();
        let mut pos = start;
        let mut end_pos = None;
        let mut jumps = 0usize;
        let mut total_bytes = 1usize;

        loop {
            if pos >= buf.len() {
                return Err(WireError::Truncated);
            }
            let len = buf[pos];
            match len & 0xC0 {
                0x00 => {
                    pos += 1;
                    if len == 0 {
                        if end_pos.is_none() {
                            end_pos = Some(pos);
                        }
                        break;
                    }
                    let l = len as usize;
                    if pos + l > buf.len() {
                        return Err(WireError::Truncated);
                    }
                    total_bytes += 1 + l;
                    if total_bytes > 256 {
                        return Err(WireError::NameTooLong);
                    }
                    labels.push(buf[pos..pos + l].to_vec());
                    pos += l;
                }
                0xC0 => {
                    if pos + 1 >= buf.len() {
                        return Err(WireError::Truncated);
                    }
                    let ptr = (((len & 0x3F) as usize) << 8) | (buf[pos + 1] as usize);
                    if end_pos.is_none() {
                        end_pos = Some(pos + 2);
                    }
                    if ptr >= buf.len() || jumps >= 128 {
                        return Err(WireError::CompressionLoop);
                    }
                    jumps += 1;
                    pos = ptr;
                }
                _ => return Err(WireError::InvalidLabel(len)),
            }
        }

        Ok((Self { labels }, end_pos.unwrap_or(pos)))
    }

    pub fn encode_uncompressed(&self, out: &mut Vec<u8>) {
        for l in &self.labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
    }

    pub fn encode_compressed(&self, out: &mut Vec<u8>, dict: &mut HashMap<Vec<u8>, u16>) {
        for i in 0..self.labels.len() {
            let suffix = DnsName {
                labels: self.labels[i..].to_vec(),
            };
            let key = suffix.canonical_key();
            if let Some(&ptr) = dict.get(&key) {
                if ptr < 0x4000 {
                    out.push(0xC0 | ((ptr >> 8) as u8));
                    out.push((ptr & 0xFF) as u8);
                    return;
                }
            }
            let offset = out.len();
            if offset < 0x4000 {
                dict.insert(key, offset as u16);
            }
            let l = &self.labels[i];
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
    }
}

impl PartialEq for DnsName {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(other.labels.iter())
                .all(|(a, b)| ascii_eq_ignore_case(a, b))
    }
}

impl Eq for DnsName {}

impl Hash for DnsName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.labels.len().hash(state);
        for l in &self.labels {
            for &b in l {
                b.to_ascii_lowercase().hash(state);
            }
            0u8.hash(state);
        }
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsName({})", self.to_fqdn_string())
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_fqdn_string())
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    Update = 5,
    Dso = 6,
}

impl Opcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Opcode::Query),
            5 => Some(Opcode::Update),
            6 => Some(Opcode::Dso),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RCode(pub u16);

impl RCode {
    pub const NOERROR: Self = Self(0);
    pub const FORMERR: Self = Self(1);
    pub const SERVFAIL: Self = Self(2);
    pub const NXDOMAIN: Self = Self(3);
    pub const NOTIMP: Self = Self(4);
    pub const REFUSED: Self = Self(5);
    pub const YXDOMAIN: Self = Self(6);
    pub const YXRRSET: Self = Self(7);
    pub const NXRRSET: Self = Self(8);
    pub const NOTAUTH: Self = Self(9);
    pub const NOTZONE: Self = Self(10);
    pub const DSOTYPENI: Self = Self(11);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RrType(pub u16);

impl RrType {
    pub const A: Self = Self(1);
    pub const NS: Self = Self(2);
    pub const CNAME: Self = Self(5);
    pub const SOA: Self = Self(6);
    pub const PTR: Self = Self(12);
    pub const MX: Self = Self(15);
    pub const TXT: Self = Self(16);
    pub const AAAA: Self = Self(28);
    pub const SRV: Self = Self(33);
    pub const DNAME: Self = Self(39);
    pub const OPT: Self = Self(41);
    pub const NSEC: Self = Self(47);
    pub const TSIG: Self = Self(250);
    pub const ANY: Self = Self(255);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RrClass(pub u16);

impl RrClass {
    pub const IN: Self = Self(1);
    pub const NONE: Self = Self(254);
    pub const ANY: Self = Self(255);

    pub fn raw_without_flush(self) -> Self {
        Self(self.0 & 0x7FFF)
    }

    pub fn cache_flush(self) -> bool {
        (self.0 & 0x8000) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,
    pub rcode: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < 12 {
            return Err(WireError::Truncated);
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        Ok(Self {
            id,
            qr: (flags & 0x8000) != 0,
            opcode: ((flags >> 11) & 0x0F) as u8,
            aa: (flags & 0x0400) != 0,
            tc: (flags & 0x0200) != 0,
            rd: (flags & 0x0100) != 0,
            ra: (flags & 0x0080) != 0,
            z: ((flags >> 4) & 0x07) as u8,
            rcode: flags & 0x000F,
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_be_bytes());
        let mut flags = 0u16;
        if self.qr {
            flags |= 0x8000;
        }
        flags |= ((self.opcode as u16) & 0x0F) << 11;
        if self.aa {
            flags |= 0x0400;
        }
        if self.tc {
            flags |= 0x0200;
        }
        if self.rd {
            flags |= 0x0100;
        }
        if self.ra {
            flags |= 0x0080;
        }
        flags |= ((self.z as u16) & 0x07) << 4;
        flags |= self.rcode & 0x000F;
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&self.qdcount.to_be_bytes());
        out.extend_from_slice(&self.ancount.to_be_bytes());
        out.extend_from_slice(&self.nscount.to_be_bytes());
        out.extend_from_slice(&self.arcount.to_be_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: DnsName,
    pub qtype: RrType,
    pub qclass: RrClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

/// RFC 8764 §3.2 LLQ EDNS(0) Option (OPTION-CODE = 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlqOption {
    pub vers: u16,
    pub llq_opcode: u16,
    pub error_code: u16,
    pub llq_id: u64,
    pub lease_life: u32,
}

impl LlqOption {
    pub const OPTION_CODE: u16 = 1;
    pub const OPCODE_SETUP: u16 = 1;
    pub const OPCODE_REFRESH: u16 = 2;
    pub const OPCODE_EVENT: u16 = 3;

    pub const ERR_NO_ERROR: u16 = 0;
    pub const ERR_SERV_FULL: u16 = 1;
    pub const ERR_STATIC: u16 = 2;
    pub const ERR_FORMAT: u16 = 3;
    pub const ERR_NO_SUCH_LLQ: u16 = 4;
    pub const ERR_BAD_VERS: u16 = 5;
    pub const ERR_UNKNOWN: u16 = 6;

    pub fn encode_edns_option(&self) -> EdnsOption {
        let mut data = Vec::with_capacity(18);
        data.extend_from_slice(&self.vers.to_be_bytes());
        data.extend_from_slice(&self.llq_opcode.to_be_bytes());
        data.extend_from_slice(&self.error_code.to_be_bytes());
        data.extend_from_slice(&self.llq_id.to_be_bytes());
        data.extend_from_slice(&self.lease_life.to_be_bytes());
        EdnsOption {
            code: Self::OPTION_CODE,
            data,
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < 18 {
            return Err(WireError::Truncated);
        }
        Ok(Self {
            vers: u16::from_be_bytes([data[0], data[1]]),
            llq_opcode: u16::from_be_bytes([data[2], data[3]]),
            error_code: u16::from_be_bytes([data[4], data[5]]),
            llq_id: u64::from_be_bytes(data[6..14].try_into().unwrap()),
            lease_life: u32::from_be_bytes(data[14..18].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    PTR(DnsName),
    CNAME(DnsName),
    NS(DnsName),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    TXT(Vec<Vec<u8>>),
    SOA {
        mname: DnsName,
        rname: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Raw(Vec<u8>),
}

impl RData {
    pub fn parse(rrtype: RrType, buf: &[u8], rdata_start: usize, rdlen: usize) -> Result<Self, WireError> {
        let end = rdata_start + rdlen;
        if end > buf.len() {
            return Err(WireError::Truncated);
        }
        if rdlen == 0 {
            return Ok(RData::Raw(Vec::new()));
        }
        match rrtype {
            RrType::A => {
                if rdlen != 4 {
                    return Err(WireError::InvalidRdata("A record must be 4 bytes"));
                }
                Ok(RData::A(Ipv4Addr::new(
                    buf[rdata_start],
                    buf[rdata_start + 1],
                    buf[rdata_start + 2],
                    buf[rdata_start + 3],
                )))
            }
            RrType::AAAA => {
                if rdlen != 16 {
                    return Err(WireError::InvalidRdata("AAAA record must be 16 bytes"));
                }
                let arr: [u8; 16] = buf[rdata_start..end].try_into().unwrap();
                Ok(RData::AAAA(Ipv6Addr::from(arr)))
            }
            RrType::PTR => {
                let (name, _) = DnsName::parse(buf, rdata_start)?;
                Ok(RData::PTR(name))
            }
            RrType::CNAME => {
                let (name, _) = DnsName::parse(buf, rdata_start)?;
                Ok(RData::CNAME(name))
            }
            RrType::NS => {
                let (name, _) = DnsName::parse(buf, rdata_start)?;
                Ok(RData::NS(name))
            }
            RrType::SRV => {
                if rdlen < 7 {
                    return Err(WireError::InvalidRdata("SRV record too short"));
                }
                let priority = u16::from_be_bytes([buf[rdata_start], buf[rdata_start + 1]]);
                let weight = u16::from_be_bytes([buf[rdata_start + 2], buf[rdata_start + 3]]);
                let port = u16::from_be_bytes([buf[rdata_start + 4], buf[rdata_start + 5]]);
                let (target, _) = DnsName::parse(buf, rdata_start + 6)?;
                Ok(RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
            RrType::TXT => {
                let mut pos = rdata_start;
                let mut strings = Vec::new();
                while pos < end {
                    let l = buf[pos] as usize;
                    pos += 1;
                    if pos + l > end {
                        return Err(WireError::Truncated);
                    }
                    strings.push(buf[pos..pos + l].to_vec());
                    pos += l;
                }
                Ok(RData::TXT(strings))
            }
            RrType::SOA => {
                let (mname, next) = DnsName::parse(buf, rdata_start)?;
                let (rname, next) = DnsName::parse(buf, next)?;
                if next + 20 > end {
                    return Err(WireError::Truncated);
                }
                Ok(RData::SOA {
                    mname,
                    rname,
                    serial: u32::from_be_bytes(buf[next..next + 4].try_into().unwrap()),
                    refresh: u32::from_be_bytes(buf[next + 4..next + 8].try_into().unwrap()),
                    retry: u32::from_be_bytes(buf[next + 8..next + 12].try_into().unwrap()),
                    expire: u32::from_be_bytes(buf[next + 12..next + 16].try_into().unwrap()),
                    minimum: u32::from_be_bytes(buf[next + 16..next + 20].try_into().unwrap()),
                })
            }
            _ => Ok(RData::Raw(buf[rdata_start..end].to_vec())),
        }
    }

    pub fn encode_with_compression(
        &self,
        out: &mut Vec<u8>,
        dict: Option<&mut HashMap<Vec<u8>, u16>>,
    ) {
        match self {
            RData::A(ip) => out.extend_from_slice(&ip.octets()),
            RData::AAAA(ip) => out.extend_from_slice(&ip.octets()),
            RData::PTR(n) | RData::CNAME(n) | RData::NS(n) => {
                if let Some(d) = dict {
                    n.encode_compressed(out, d);
                } else {
                    n.encode_uncompressed(out);
                }
            }
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                if let Some(d) = dict {
                    target.encode_compressed(out, d);
                } else {
                    target.encode_uncompressed(out);
                }
            }
            RData::TXT(strings) => {
                if strings.is_empty() {
                    out.push(0);
                } else {
                    for s in strings {
                        let len = s.len().min(255);
                        out.push(len as u8);
                        out.extend_from_slice(&s[..len]);
                    }
                }
            }
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                if let Some(d) = dict {
                    mname.encode_compressed(out, d);
                    rname.encode_compressed(out, d);
                } else {
                    mname.encode_uncompressed(out);
                    rname.encode_uncompressed(out);
                }
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
            }
            RData::Raw(bytes) => out.extend_from_slice(bytes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: DnsName,
    pub rtype: RrType,
    pub rclass: RrClass,
    pub ttl: u32,
    pub rdata: RData,
}

impl DnsRecord {
    pub fn parse(buf: &[u8], start: usize) -> Result<(Self, usize), WireError> {
        let (name, pos) = DnsName::parse(buf, start)?;
        if pos + 10 > buf.len() {
            return Err(WireError::Truncated);
        }
        let rtype = RrType(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        let rclass = RrClass(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        if rdata_start + rdlen > buf.len() {
            return Err(WireError::Truncated);
        }
        let rdata = RData::parse(rtype, buf, rdata_start, rdlen)?;
        Ok((
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            rdata_start + rdlen,
        ))
    }

    pub fn encode(&self, out: &mut Vec<u8>, dict: &mut HashMap<Vec<u8>, u16>) {
        self.name.encode_compressed(out, dict);
        out.extend_from_slice(&self.rtype.0.to_be_bytes());
        out.extend_from_slice(&self.rclass.0.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let rdlen_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let rdata_start = out.len();
        self.rdata.encode_with_compression(out, Some(dict));
        let rdlen = (out.len() - rdata_start) as u16;
        out[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
    }

    pub fn encode_opt(payload_size: u16, options: &[EdnsOption], out: &mut Vec<u8>) {
        out.push(0); // root name
        out.extend_from_slice(&RrType::OPT.0.to_be_bytes());
        out.extend_from_slice(&payload_size.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE + flags = 0
        let rdlen_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let rdata_start = out.len();
        for opt in options {
            out.extend_from_slice(&opt.code.to_be_bytes());
            out.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&opt.data);
        }
        let rdlen = (out.len() - rdata_start) as u16;
        out[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
    }

    /// Extract EDNS(0) options if this record is an OPT pseudo-RR.
    pub fn parse_opt_options(&self) -> Vec<EdnsOption> {
        if self.rtype != RrType::OPT {
            return Vec::new();
        }
        let RData::Raw(ref bytes) = self.rdata else {
            return Vec::new();
        };
        let mut opts = Vec::new();
        let mut pos = 0;
        while pos + 4 <= bytes.len() {
            let code = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
            pos += 4;
            if pos + len > bytes.len() {
                break;
            }
            opts.push(EdnsOption {
                code,
                data: bytes[pos..pos + len].to_vec(),
            });
            pos += len;
        }
        opts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn new_query(id: u16, qname: DnsName, qtype: RrType, qclass: RrClass, rd: bool) -> Self {
        Self {
            header: DnsHeader {
                id,
                qr: false,
                opcode: Opcode::Query as u8,
                aa: false,
                tc: false,
                rd,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                qname,
                qtype,
                qclass,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        let header = DnsHeader::parse(buf)?;
        let mut pos = 12;
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let (qname, next) = DnsName::parse(buf, pos)?;
            if next + 4 > buf.len() {
                return Err(WireError::Truncated);
            }
            let qtype = RrType(u16::from_be_bytes([buf[next], buf[next + 1]]));
            let qclass = RrClass(u16::from_be_bytes([buf[next + 2], buf[next + 3]]));
            questions.push(DnsQuestion {
                qname,
                qtype,
                qclass,
            });
            pos = next + 4;
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            let (rr, next) = DnsRecord::parse(buf, pos)?;
            answers.push(rr);
            pos = next;
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            let (rr, next) = DnsRecord::parse(buf, pos)?;
            authorities.push(rr);
            pos = next;
        }

        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            let (rr, next) = DnsRecord::parse(buf, pos)?;
            additionals.push(rr);
            pos = next;
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        let mut hdr = self.header.clone();
        hdr.qdcount = self.questions.len() as u16;
        hdr.ancount = self.answers.len() as u16;
        hdr.nscount = self.authorities.len() as u16;
        hdr.arcount = self.additionals.len() as u16;
        hdr.encode(&mut out);

        let mut dict = HashMap::new();
        for q in &self.questions {
            q.qname.encode_compressed(&mut out, &mut dict);
            out.extend_from_slice(&q.qtype.0.to_be_bytes());
            out.extend_from_slice(&q.qclass.0.to_be_bytes());
        }
        for rr in &self.answers {
            rr.encode(&mut out, &mut dict);
        }
        for rr in &self.authorities {
            rr.encode(&mut out, &mut dict);
        }
        for rr in &self.additionals {
            rr.encode(&mut out, &mut dict);
        }
        out
    }

    /// Extract all LLQ options from OPT records in the Additional section.
    pub fn llq_options(&self) -> Vec<LlqOption> {
        let mut out = Vec::new();
        for rr in &self.additionals {
            for opt in rr.parse_opt_options() {
                if opt.code == LlqOption::OPTION_CODE {
                    if let Ok(llq) = LlqOption::decode(&opt.data) {
                        out.push(llq);
                    }
                }
            }
        }
        out
    }
}

/// Frame a DNS/DSO message with a 2-byte big-endian length prefix for TCP/TLS streams.
pub fn frame_tcp(msg: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + msg.len());
    framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(msg);
    framed
}

/// DSO TLV type codes (RFC 8490 §10.3 & RFC 8765 §6).
pub mod dso_type {
    pub const KEEPALIVE: u16 = 0x0001;
    pub const RETRY_DELAY: u16 = 0x0002;
    pub const ENCRYPTION_PADDING: u16 = 0x0003;
    pub const SUBSCRIBE: u16 = 0x0040;
    pub const PUSH: u16 = 0x0041;
    pub const UNSUBSCRIBE: u16 = 0x0042;
    pub const RECONFIRM: u16 = 0x0043;
}

/// A change notification record inside a DNS PUSH TLV (RFC 8765 §6.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushChange {
    pub name: DnsName,
    pub rtype: RrType,
    pub rclass: RrClass,
    /// `0..=0x7FFF_FFFF` = add RR; `0xFFFF_FFFF` = remove RR; `0xFFFF_FFFE` = collective remove.
    pub ttl: u32,
    pub rdata: RData,
}

impl PushChange {
    pub const TTL_REMOVE_RR: u32 = 0xFFFF_FFFF;
    pub const TTL_COLLECTIVE_REMOVE: u32 = 0xFFFF_FFFE;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsoTlv {
    Keepalive {
        inactivity_timeout_ms: u32,
        keepalive_interval_ms: u32,
    },
    RetryDelay(u32),
    EncryptionPadding(Vec<u8>),
    Subscribe {
        name: DnsName,
        rtype: RrType,
        rclass: RrClass,
    },
    Push(Vec<PushChange>),
    Unsubscribe {
        subscribe_msg_id: u16,
    },
    Reconfirm {
        name: DnsName,
        rtype: RrType,
        rclass: RrClass,
        rdata: RData,
    },
    Unknown {
        dso_type: u16,
        data: Vec<u8>,
    },
}

/// A DNS Stateful Operations (RFC 8490) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsoMessage {
    pub id: u16,
    pub qr: bool,
    pub rcode: u16,
    pub primary: Option<DsoTlv>,
    pub additionals: Vec<DsoTlv>,
}

impl DsoMessage {
    pub fn request(id: u16, primary: DsoTlv) -> Self {
        Self {
            id,
            qr: false,
            rcode: 0,
            primary: Some(primary),
            additionals: Vec::new(),
        }
    }

    pub fn unidirectional(primary: DsoTlv) -> Self {
        Self {
            id: 0,
            qr: false,
            rcode: 0,
            primary: Some(primary),
            additionals: Vec::new(),
        }
    }

    pub fn response(id: u16, rcode: u16, additionals: Vec<DsoTlv>) -> Self {
        Self {
            id,
            qr: true,
            rcode,
            primary: None,
            additionals,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        let hdr = DnsHeader {
            id: self.id,
            qr: self.qr,
            opcode: Opcode::Dso as u8,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: self.rcode,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        hdr.encode(&mut out);

        let mut dict = HashMap::new();
        if let Some(ref p) = self.primary {
            encode_dso_tlv(p, &mut out, &mut dict);
        }
        for add in &self.additionals {
            encode_dso_tlv(add, &mut out, &mut dict);
        }
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        let hdr = DnsHeader::parse(buf)?;
        if hdr.opcode != Opcode::Dso as u8
            || hdr.qdcount != 0
            || hdr.ancount != 0
            || hdr.nscount != 0
            || hdr.arcount != 0
        {
            return Err(WireError::InvalidDsoHeader);
        }

        let mut tlvs = Vec::new();
        let mut pos = 12;
        while pos < buf.len() {
            if pos + 4 > buf.len() {
                return Err(WireError::Truncated);
            }
            let tlv_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let tlv_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;
            if pos + tlv_len > buf.len() {
                return Err(WireError::Truncated);
            }
            let tlv_end = pos + tlv_len;
            let tlv = decode_dso_tlv(tlv_type, buf, pos, tlv_end)?;
            tlvs.push(tlv);
            pos = tlv_end;
        }

        let (primary, additionals) = if hdr.qr {
            (None, tlvs)
        } else if tlvs.is_empty() {
            (None, Vec::new())
        } else {
            let mut it = tlvs.into_iter();
            let p = it.next();
            (p, it.collect())
        };

        Ok(Self {
            id: hdr.id,
            qr: hdr.qr,
            rcode: hdr.rcode,
            primary,
            additionals,
        })
    }
}

fn encode_dso_tlv(tlv: &DsoTlv, out: &mut Vec<u8>, dict: &mut HashMap<Vec<u8>, u16>) {
    let type_code = match tlv {
        DsoTlv::Keepalive { .. } => dso_type::KEEPALIVE,
        DsoTlv::RetryDelay(_) => dso_type::RETRY_DELAY,
        DsoTlv::EncryptionPadding(_) => dso_type::ENCRYPTION_PADDING,
        DsoTlv::Subscribe { .. } => dso_type::SUBSCRIBE,
        DsoTlv::Push(_) => dso_type::PUSH,
        DsoTlv::Unsubscribe { .. } => dso_type::UNSUBSCRIBE,
        DsoTlv::Reconfirm { .. } => dso_type::RECONFIRM,
        DsoTlv::Unknown { dso_type, .. } => *dso_type,
    };
    out.extend_from_slice(&type_code.to_be_bytes());
    let len_pos = out.len();
    out.extend_from_slice(&[0, 0]);
    let data_start = out.len();

    match tlv {
        DsoTlv::Keepalive {
            inactivity_timeout_ms,
            keepalive_interval_ms,
        } => {
            out.extend_from_slice(&inactivity_timeout_ms.to_be_bytes());
            out.extend_from_slice(&keepalive_interval_ms.to_be_bytes());
        }
        DsoTlv::RetryDelay(ms) => {
            out.extend_from_slice(&ms.to_be_bytes());
        }
        DsoTlv::EncryptionPadding(pad) => {
            out.extend_from_slice(pad);
        }
        DsoTlv::Subscribe {
            name,
            rtype,
            rclass,
        } => {
            name.encode_uncompressed(out);
            out.extend_from_slice(&rtype.0.to_be_bytes());
            out.extend_from_slice(&rclass.0.to_be_bytes());
        }
        DsoTlv::Push(changes) => {
            for ch in changes {
                ch.name.encode_compressed(out, dict);
                out.extend_from_slice(&ch.rtype.0.to_be_bytes());
                out.extend_from_slice(&ch.rclass.0.to_be_bytes());
                out.extend_from_slice(&ch.ttl.to_be_bytes());
                let rdlen_pos = out.len();
                out.extend_from_slice(&[0, 0]);
                let rd_start = out.len();
                if ch.ttl != PushChange::TTL_COLLECTIVE_REMOVE {
                    ch.rdata.encode_with_compression(out, Some(dict));
                }
                let rdlen = (out.len() - rd_start) as u16;
                out[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
            }
        }
        DsoTlv::Unsubscribe { subscribe_msg_id } => {
            out.extend_from_slice(&subscribe_msg_id.to_be_bytes());
        }
        DsoTlv::Reconfirm {
            name,
            rtype,
            rclass,
            rdata,
        } => {
            name.encode_uncompressed(out);
            out.extend_from_slice(&rtype.0.to_be_bytes());
            out.extend_from_slice(&rclass.0.to_be_bytes());
            rdata.encode_with_compression(out, Some(dict));
        }
        DsoTlv::Unknown { data, .. } => {
            out.extend_from_slice(data);
        }
    }

    let len = (out.len() - data_start) as u16;
    out[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes());
}

fn decode_dso_tlv(
    tlv_type: u16,
    buf: &[u8],
    start: usize,
    end: usize,
) -> Result<DsoTlv, WireError> {
    let len = end - start;
    match tlv_type {
        dso_type::KEEPALIVE => {
            if len != 8 {
                return Err(WireError::Truncated);
            }
            Ok(DsoTlv::Keepalive {
                inactivity_timeout_ms: u32::from_be_bytes(buf[start..start + 4].try_into().unwrap()),
                keepalive_interval_ms: u32::from_be_bytes(
                    buf[start + 4..start + 8].try_into().unwrap(),
                ),
            })
        }
        dso_type::RETRY_DELAY => {
            if len != 4 {
                return Err(WireError::Truncated);
            }
            Ok(DsoTlv::RetryDelay(u32::from_be_bytes(
                buf[start..start + 4].try_into().unwrap(),
            )))
        }
        dso_type::ENCRYPTION_PADDING => Ok(DsoTlv::EncryptionPadding(buf[start..end].to_vec())),
        dso_type::SUBSCRIBE => {
            let (name, pos) = DnsName::parse(buf, start)?;
            if pos + 4 != end {
                return Err(WireError::Truncated);
            }
            Ok(DsoTlv::Subscribe {
                name,
                rtype: RrType(u16::from_be_bytes([buf[pos], buf[pos + 1]])),
                rclass: RrClass(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]])),
            })
        }
        dso_type::PUSH => {
            if buf.len() > MAX_PUSH_MESSAGE_LEN {
                return Err(WireError::FatalPushError("PUSH message exceeds 16382 bytes"));
            }
            let mut changes = Vec::new();
            let mut pos = start;
            while pos < end {
                let (name, next) = DnsName::parse(buf, pos)?;
                if next + 10 > end {
                    return Err(WireError::Truncated);
                }
                let rtype = RrType(u16::from_be_bytes([buf[next], buf[next + 1]]));
                let rclass = RrClass(u16::from_be_bytes([buf[next + 2], buf[next + 3]]));
                let ttl = u32::from_be_bytes(buf[next + 4..next + 8].try_into().unwrap());
                let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
                let rd_start = next + 10;
                if rd_start + rdlen > end {
                    return Err(WireError::Truncated);
                }
                if ttl == PushChange::TTL_COLLECTIVE_REMOVE && rdlen != 0 {
                    return Err(WireError::FatalPushError(
                        "collective remove PUSH record has non-zero RDLEN",
                    ));
                }
                if (ttl <= 0x7FFF_FFFF || ttl == PushChange::TTL_REMOVE_RR)
                    && (rtype == RrType::ANY || rclass == RrClass::ANY)
                {
                    return Err(WireError::FatalPushError(
                        "individual add/remove PUSH record has TYPE or CLASS ANY",
                    ));
                }
                let rdata = if rdlen == 0 {
                    RData::Raw(Vec::new())
                } else {
                    RData::parse(rtype, buf, rd_start, rdlen)?
                };
                changes.push(PushChange {
                    name,
                    rtype,
                    rclass,
                    ttl,
                    rdata,
                });
                pos = rd_start + rdlen;
            }
            if changes.is_empty() {
                return Err(WireError::FatalPushError("PUSH message contains zero change notifications"));
            }
            Ok(DsoTlv::Push(changes))
        }
        dso_type::UNSUBSCRIBE => {
            if len != 2 {
                return Err(WireError::Truncated);
            }
            Ok(DsoTlv::Unsubscribe {
                subscribe_msg_id: u16::from_be_bytes([buf[start], buf[start + 1]]),
            })
        }
        dso_type::RECONFIRM => {
            let (name, pos) = DnsName::parse(buf, start)?;
            if pos + 4 > end {
                return Err(WireError::Truncated);
            }
            let rtype = RrType(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
            let rclass = RrClass(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
            let rd_start = pos + 4;
            let rdata = RData::parse(rtype, buf, rd_start, end - rd_start)?;
            Ok(DsoTlv::Reconfirm {
                name,
                rtype,
                rclass,
                rdata,
            })
        }
        _ => Ok(DsoTlv::Unknown {
            dso_type: tlv_type,
            data: buf[start..end].to_vec(),
        }),
    }
}

/// Sign an encoded DNS message with an HMAC-SHA256 TSIG record (RFC 2845).
pub fn sign_tsig(
    msg: &mut DnsMessage,
    key_name: &DnsName,
    secret: &[u8],
    time_signed: u64,
    fudge: u16,
) -> Result<(), WireError> {
    let alg = DnsName::from_str_dotted("hmac-sha256.")?;
    let unsigned = msg.encode();

    let mut tsig_input = Vec::with_capacity(unsigned.len() + 64);
    tsig_input.extend_from_slice(&unsigned);
    key_name.encode_uncompressed(&mut tsig_input);
    tsig_input.extend_from_slice(&RrClass::ANY.0.to_be_bytes());
    tsig_input.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0
    alg.encode_uncompressed(&mut tsig_input);
    let ts_bytes = time_signed.to_be_bytes();
    tsig_input.extend_from_slice(&ts_bytes[2..8]); // 48-bit time signed
    tsig_input.extend_from_slice(&fudge.to_be_bytes());
    tsig_input.extend_from_slice(&0u16.to_be_bytes()); // error = 0
    tsig_input.extend_from_slice(&0u16.to_be_bytes()); // other len = 0

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WireError::TsigError("invalid key"))?;
    mac.update(&tsig_input);
    let sig = mac.finalize().into_bytes();

    let mut rdata = Vec::new();
    alg.encode_uncompressed(&mut rdata);
    rdata.extend_from_slice(&ts_bytes[2..8]);
    rdata.extend_from_slice(&fudge.to_be_bytes());
    rdata.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&sig);
    rdata.extend_from_slice(&msg.header.id.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes()); // error
    rdata.extend_from_slice(&0u16.to_be_bytes()); // other len

    msg.additionals.push(DnsRecord {
        name: key_name.clone(),
        rtype: RrType::TSIG,
        rclass: RrClass::ANY,
        ttl: 0,
        rdata: RData::Raw(rdata),
    });
    Ok(())
}
