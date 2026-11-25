# Distributed mDNS (Scalable DNS-SD)

A Rust implementation of a **distributed mDNS / Scalable DNS-SD client** (`dist-mdns` library + `dmdns` CLI) grounded in the IETF RFC specifications stored in `rfcs/`.

Traditional Multicast DNS (RFC 6762) is link-local (`.local.`) and does not cross IP routers. This project combines link-local mDNS/DNS-SD with Discovery Proxy unicast resolution (RFC 8766), DNS Stateful Operations over TLS (RFC 8490), DNS Push Notifications (RFC 8765), Apple LLQ fallback (RFC 8764), and DNS Dynamic Update + TSIG (RFC 2136 / RFC 2845) so clients can discover and register services both locally and across routed multi-link networks.

---

## Features

- **Link-Local mDNS & DNS-SD (`rust/src/mdns/`)** — UDP port `5353` (`224.0.0.251` / `FF02::FB`), Known-Answer suppression, and service registration (3-packet probing with tie-breaking & conflict auto-rename, announcing, and `TTL=0` goodbye) per RFC 6762 and RFC 6763.
- **Multi-Link Domain Enumeration (`rust/src/enumeration/`)** — Dual-path discovery of browse (`b`, `db`, `lb._dns-sd._udp`) and registration (`r`, `dr._dns-sd._udp`) domains across `.local.`, configured search domains, and `home.arpa.` (RFC 8375, RFC 8766 §5.2).
- **DSO over WebPKI TLS (`rust/src/dso/`)** — Persistent TLS-over-TCP sessions (`OPCODE=6`) using `rustls` with system-root WebPKI certificates (`rustls-native-certs`), `MESSAGE ID` multiplexing, and `Keepalive` / `Retry Delay` handling per RFC 8490.
- **DNS Push Notifications (`rust/src/push/`)** — Iterative `SOA` zone-cut walk, `_dns-push-tls._tcp.<zone>` `SRV` lookup, `SUBSCRIBE`, `PUSH` (with TTL freeze and collective removals), `UNSUBSCRIBE`, and `RECONFIRM` per RFC 8765.
- **LLQ & Polling Fallbacks (`rust/src/llq/`, `rust/src/push/`)** — Always attempts DNS Push first; falls back to `_dns-llq._udp.<zone>` 4-way UDP handshake, `LLQ-EVENT`, and `LLQ-REFRESH` (RFC 8764), and then to `min(900s, TTL + 2s)` unicast polling (RFC 8765 §6.8).
- **Unicast Service Registration (`rust/src/update/`)** — Atomic RFC 2136 `UPDATE` messages with prerequisites and HMAC-SHA256 `TSIG` signing (RFC 2845), sharing DSO/TLS sessions when `_dns-update-tls._tcp.<zone>` is co-located with Push.

---

## Repository Layout

```text
.
├── getrfc.py              # Fetches RFCs and referenced RFCs into rfcs/
├── rfc_to_markdown.py     # Converts RFC .txt files into Markdown (.md)
├── rfcs/                  # IETF RFC reference texts and Markdown conversions
└── rust/                  # Rust workspace (dist-mdns library + dmdns CLI)
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs
    │   ├── wire/          # DNS, DSO TLV, LLQ OPT, UPDATE & TSIG codecs
    │   ├── cache/         # Unified RR cache, negative cache, Push TTL freeze
    │   ├── mdns/          # Link-local mDNS querier & responder
    │   ├── enumeration/   # Multicast + Unicast + home.arpa. Domain Enumeration
    │   ├── dso/           # DSO over TLS/TCP session manager
    │   ├── push/          # DNS Push Notifications & polling fallback
    │   ├── llq/           # RFC 8764 LLQ fallback client
    │   ├── update/        # RFC 2136 DNS Dynamic Update + TSIG
    │   ├── client/        # Unified DistributedClient API
    │   └── bin/dmdns.rs   # CLI binary
    └── tests/
        └── distributed_e2e.rs
```

---

## Building & Testing

### Prerequisites
- Rust toolchain (`cargo`, `rustc`)

### Run Tests & Build CLI

```bash
cd rust
cargo test
cargo build --bin dmdns
```

### CLI Usage

```bash
# Enumerate local and unicast browse/registration domains
cargo run --bin dmdns -- domains

# Browse services in a domain (defaults to local.)
cargo run --bin dmdns -- browse _http._tcp local.

# Resolve a service instance to host, port, TXT, and IP addresses
cargo run --bin dmdns -- resolve "My Service._http._tcp.local."

# Register a service locally (.local.) or via DNS Update
cargo run --bin dmdns -- register "Test Service" _http._tcp local. 8080 --host myhost.local. --ip 192.168.1.10

# Discover all services on local. and dump them (format: json [default] or text)
cargo run --bin dmdns -- dump
cargo run --bin dmdns -- dump --format text
```

---

## RFC Utilities

- `getrfc.py` downloads RFC text files from `rfc-editor.org` into `rfcs/`.
- `rfc_to_markdown.py` converts RFC `.txt` files into structured `.md` files:

```bash
python3 rfc_to_markdown.py --unwrap rfcs/
```
