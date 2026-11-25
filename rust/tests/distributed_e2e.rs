use dist_mdns::cache::RrCache;
use dist_mdns::client::{BrowseTransport, DistributedClient};
use dist_mdns::enumeration::UnicastResolver;
use dist_mdns::push::polling_interval_for_ttl;
use dist_mdns::update::{TsigKey, UnicastServiceSpec};
use dist_mdns::wire::{
    frame_tcp, DnsHeader, DnsMessage, DnsName, DnsRecord, DsoMessage, DsoTlv, LlqOption, Opcode,
    PushChange, RCode, RData, RrClass, RrType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

#[test]
fn wire_dso_push_roundtrip_and_cache_freeze() {
    let name = DnsName::from_str_dotted("_ipp._tcp.Building 1.example.com.").unwrap();
    let inst = DnsName::from_str_dotted("My Printer._ipp._tcp.Building 1.example.com.").unwrap();

    let push = DsoMessage::unidirectional(DsoTlv::Push(vec![
        PushChange {
            name: name.clone(),
            rtype: RrType::PTR,
            rclass: RrClass::IN,
            ttl: 0, // Retain until UNSUBSCRIBE
            rdata: RData::PTR(inst.clone()),
        },
        PushChange {
            name: inst.clone(),
            rtype: RrType::SRV,
            rclass: RrClass::IN,
            ttl: 120,
            rdata: RData::SRV {
                priority: 0,
                weight: 0,
                port: 631,
                target: DnsName::from_str_dotted("prnt.bldg-1.example.com.").unwrap(),
            },
        },
    ]));

    let bytes = push.encode();
    let decoded = DsoMessage::parse(&bytes).unwrap();
    let Some(DsoTlv::Push(changes)) = decoded.primary else {
        panic!("expected Push TLV");
    };
    assert_eq!(changes.len(), 2);

    let mut cache = RrCache::new();
    let now = Instant::now();
    for ch in &changes {
        cache.apply_push_change(ch, 42, now);
    }
    assert_eq!(cache.get(&name, RrType::PTR, RrClass::IN, now).len(), 1);

    // Unfreezing subscription 42 should immediately drop TTL=0 PTR while keeping TTL=120 SRV
    cache.unfreeze_subscription(42, now);
    assert_eq!(cache.get(&name, RrType::PTR, RrClass::IN, now).len(), 0);
    assert_eq!(cache.get(&inst, RrType::SRV, RrClass::IN, now).len(), 1);

    // Collective remove should wipe SRV
    cache.collective_remove(&inst, RrType::ANY, RrClass::IN);
    assert_eq!(cache.get(&inst, RrType::SRV, RrClass::IN, now).len(), 0);
}

#[test]
fn polling_fallback_interval_bounds() {
    assert_eq!(polling_interval_for_ttl(10), Duration::from_secs(12));
    assert_eq!(polling_interval_for_ttl(898), Duration::from_secs(900));
    assert_eq!(polling_interval_for_ttl(3600), Duration::from_secs(900));
}

fn generate_localhost_tls() -> (
    Arc<rustls::ServerConfig>,
    Arc<rustls::ClientConfig>,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (Arc::new(server_cfg), Arc::new(client_cfg))
}

#[tokio::test]
async fn e2e_dso_push_discovery_and_reconfirm() {
    let (server_tls, client_tls) = generate_localhost_tls();
    let push_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let push_port = push_listener.local_addr().unwrap().port();

    let reconfirmed = Arc::new(Mutex::new(false));
    let reconfirmed_srv = Arc::clone(&reconfirmed);

    // Spawn mock DSO/TLS Push server
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(server_tls);
        let (tcp, _) = push_listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut len_buf = [0u8; 2];

        loop {
            if tls.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            tls.read_exact(&mut buf).await.unwrap();
            let dso = DsoMessage::parse(&buf).unwrap();

            match dso.primary {
                Some(DsoTlv::Keepalive { .. }) => {
                    let resp = DsoMessage::response(dso.id, RCode::NOERROR.0, Vec::new());
                    tls.write_all(&frame_tcp(&resp.encode())).await.unwrap();
                }
                Some(DsoTlv::Subscribe { name, .. }) => {
                    let resp = DsoMessage::response(dso.id, RCode::NOERROR.0, Vec::new());
                    tls.write_all(&frame_tcp(&resp.encode())).await.unwrap();

                    let inst = DnsName::from_str_dotted("Office Printer._ipp._tcp.office.example.com.").unwrap();
                    let push = DsoMessage::unidirectional(DsoTlv::Push(vec![PushChange {
                        name,
                        rtype: RrType::PTR,
                        rclass: RrClass::IN,
                        ttl: 120,
                        rdata: RData::PTR(inst),
                    }]));
                    tls.write_all(&frame_tcp(&push.encode())).await.unwrap();
                }
                Some(DsoTlv::Reconfirm { .. }) => {
                    *reconfirmed_srv.lock().await = true;
                }
                Some(DsoTlv::Unsubscribe { .. }) => {
                    break;
                }
                _ => {}
            }
        }
    });

    // Spawn mock UDP DNS server for SOA walk + _dns-push-tls._tcp SRV
    let dns_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = dns_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = dns_sock.recv_from(&mut buf).await else { break };
            let req = DnsMessage::parse(&buf[..n]).unwrap();
            let q = &req.questions[0];
            let mut resp = DnsMessage {
                header: DnsHeader {
                    id: req.header.id,
                    qr: true,
                    opcode: Opcode::Query as u8,
                    aa: true,
                    tc: false,
                    rd: true,
                    ra: true,
                    z: 0,
                    rcode: RCode::NOERROR.0,
                    qdcount: 1,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                },
                questions: req.questions.clone(),
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            };

            let zone = DnsName::from_str_dotted("office.example.com.").unwrap();
            let srv_q = DnsName::from_str_dotted("_dns-push-tls._tcp.office.example.com.").unwrap();
            if q.qtype == RrType::SOA && q.qname == zone {
                resp.answers.push(DnsRecord {
                    name: zone,
                    rtype: RrType::SOA,
                    rclass: RrClass::IN,
                    ttl: 60,
                    rdata: RData::SOA {
                        mname: DnsName::from_str_dotted("localhost.").unwrap(),
                        rname: DnsName::from_str_dotted("hostmaster.example.com.").unwrap(),
                        serial: 1,
                        refresh: 60,
                        retry: 60,
                        expire: 60,
                        minimum: 60,
                    },
                });
            } else if q.qtype == RrType::SRV && q.qname == srv_q {
                resp.answers.push(DnsRecord {
                    name: srv_q,
                    rtype: RrType::SRV,
                    rclass: RrClass::IN,
                    ttl: 60,
                    rdata: RData::SRV {
                        priority: 0,
                        weight: 0,
                        port: push_port,
                        target: DnsName::from_str_dotted("localhost.").unwrap(),
                    },
                });
            }
            let _ = dns_sock.send_to(&resp.encode(), peer).await;
        }
    });

    let resolver = UnicastResolver::with_servers(vec![dns_addr], Vec::new());
    let client = DistributedClient::new(resolver, Some(client_tls), None, false)
        .await
        .unwrap();

    let domain = DnsName::from_str_dotted("office.example.com.").unwrap();
    let handle = client.browse("_ipp._tcp", &domain).await.unwrap();
    assert_eq!(handle.transport, BrowseTransport::DnsPush);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let qname = DnsName::from_str_dotted("_ipp._tcp.office.example.com.").unwrap();
    let recs = client
        .cache
        .lock()
        .await
        .get(&qname, RrType::PTR, RrClass::IN, Instant::now());
    assert_eq!(recs.len(), 1);

    let inst = DnsName::from_str_dotted("Office Printer._ipp._tcp.office.example.com.").unwrap();
    client
        .reconfirm(qname, RrType::PTR, RData::PTR(inst))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(*reconfirmed.lock().await);

    handle.stop().await;
}

#[tokio::test]
async fn e2e_llq_fallback_and_unicast_update() {
    let llq_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let llq_port = llq_sock.local_addr().unwrap().port();

    // Mock LLQ UDP server (RFC 8764 4-way handshake)
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = llq_sock.recv_from(&mut buf).await.unwrap();
        let req1 = DnsMessage::parse(&buf[..n]).unwrap();
        let challenge_opt = LlqOption {
            vers: 1,
            llq_opcode: LlqOption::OPCODE_SETUP,
            error_code: 0,
            llq_id: 0xDEAD_BEEF_CAFE_BABE,
            lease_life: 3600,
        };
        let mut r1 = DnsMessage::new_query(req1.header.id, req1.questions[0].qname.clone(), RrType::PTR, RrClass::IN, false);
        r1.header.qr = true;
        let mut w1 = r1.encode();
        w1[10..12].copy_from_slice(&1u16.to_be_bytes());
        DnsRecord::encode_opt(0, &[challenge_opt.encode_edns_option()], &mut w1);
        llq_sock.send_to(&w1, peer).await.unwrap();

        let (n2, peer2) = llq_sock.recv_from(&mut buf).await.unwrap();
        let req2 = DnsMessage::parse(&buf[..n2]).unwrap();
        let mut ack = DnsMessage::new_query(req2.header.id, req2.questions[0].qname.clone(), RrType::PTR, RrClass::IN, false);
        ack.header.qr = true;
        ack.answers.push(DnsRecord {
            name: req2.questions[0].qname.clone(),
            rtype: RrType::PTR,
            rclass: RrClass::IN,
            ttl: 120,
            rdata: RData::PTR(DnsName::from_str_dotted("Legacy Printer._ipp._tcp.legacy.example.com.").unwrap()),
        });
        let mut w2 = ack.encode();
        w2[10..12].copy_from_slice(&1u16.to_be_bytes());
        DnsRecord::encode_opt(0, &[challenge_opt.encode_edns_option()], &mut w2);
        llq_sock.send_to(&w2, peer2).await.unwrap();
    });

    // Mock DNS server: no _dns-push-tls, only _dns-llq._udp SRV; also accepts TCP UPDATE
    let dns_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr: SocketAddr = dns_udp.local_addr().unwrap();
    let dns_tcp = TcpListener::bind(dns_addr).await.unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = dns_udp.recv_from(&mut buf).await else { break };
            let req = DnsMessage::parse(&buf[..n]).unwrap();
            let q = &req.questions[0];
            let mut resp = DnsMessage {
                header: DnsHeader {
                    id: req.header.id,
                    qr: true,
                    opcode: Opcode::Query as u8,
                    aa: true,
                    tc: false,
                    rd: true,
                    ra: true,
                    z: 0,
                    rcode: RCode::NOERROR.0,
                    qdcount: 1,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                },
                questions: req.questions.clone(),
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            let zone = DnsName::from_str_dotted("legacy.example.com.").unwrap();
            let llq_srv = DnsName::from_str_dotted("_dns-llq._udp.legacy.example.com.").unwrap();
            if q.qtype == RrType::SOA && q.qname == zone {
                resp.answers.push(DnsRecord {
                    name: zone,
                    rtype: RrType::SOA,
                    rclass: RrClass::IN,
                    ttl: 60,
                    rdata: RData::SOA {
                        mname: DnsName::from_str_dotted("127.0.0.1.").unwrap(),
                        rname: DnsName::from_str_dotted("hostmaster.example.com.").unwrap(),
                        serial: 1,
                        refresh: 60,
                        retry: 60,
                        expire: 60,
                        minimum: 60,
                    },
                });
            } else if q.qtype == RrType::SRV && q.qname == llq_srv {
                resp.answers.push(DnsRecord {
                    name: llq_srv,
                    rtype: RrType::SRV,
                    rclass: RrClass::IN,
                    ttl: 60,
                    rdata: RData::SRV {
                        priority: 0,
                        weight: 0,
                        port: llq_port,
                        target: DnsName::from_str_dotted("127.0.0.1.").unwrap(),
                    },
                });
            }
            let _ = dns_udp.send_to(&resp.encode(), peer).await;
        }
    });

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = dns_tcp.accept().await {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.unwrap();
            let req = DnsMessage::parse(&buf).unwrap();
            assert_eq!(req.header.opcode, Opcode::Update as u8);
            assert!(req.additionals.iter().any(|r| r.rtype == RrType::TSIG));
            let resp = DnsMessage {
                header: DnsHeader {
                    id: req.header.id,
                    qr: true,
                    opcode: Opcode::Update as u8,
                    aa: false,
                    tc: false,
                    rd: false,
                    ra: false,
                    z: 0,
                    rcode: RCode::NOERROR.0,
                    qdcount: 0,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                },
                questions: Vec::new(),
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            stream.write_all(&frame_tcp(&resp.encode())).await.unwrap();
        }
    });

    let resolver = UnicastResolver::with_servers(vec![dns_addr], Vec::new());
    let tsig = TsigKey {
        name: DnsName::from_str_dotted("update-key.legacy.example.com.").unwrap(),
        secret: b"super-secret-tsig-key".to_vec(),
    };
    let client = DistributedClient::new(resolver, None, Some(tsig), false)
        .await
        .unwrap();

    let domain = DnsName::from_str_dotted("legacy.example.com.").unwrap();
    let handle = client.browse("_ipp._tcp", &domain).await.unwrap();
    assert_eq!(handle.transport, BrowseTransport::LlqFallback);

    let qname = DnsName::from_str_dotted("_ipp._tcp.legacy.example.com.").unwrap();
    let recs = client
        .cache
        .lock()
        .await
        .get(&qname, RrType::PTR, RrClass::IN, Instant::now());
    assert_eq!(recs.len(), 1);
    handle.stop().await;

    // Test Unicast UPDATE + TSIG registration & unregistration
    let spec = UnicastServiceSpec {
        instance_name: "My App".to_string(),
        service_type: "_http._tcp".to_string(),
        domain,
        port: 8080,
        txt: vec![b"path=/".to_vec()],
        host_name: DnsName::from_str_dotted("app.legacy.example.com.").unwrap(),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
        ttl: 120,
    };
    let reg = client.register_service(spec).await.unwrap();
    client.unregister_service(reg).await.unwrap();
}
