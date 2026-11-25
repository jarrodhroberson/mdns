use clap::{Parser, Subcommand, ValueEnum};
use dist_mdns::client::DistributedClient;
use dist_mdns::enumeration::UnicastResolver;
use dist_mdns::update::UnicastServiceSpec;
use dist_mdns::wire::{DnsName, RData, RrClass, RrType};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum DumpFormat {
    Json,
    Text,
    Yaml,
}

#[derive(Parser)]
#[command(name = "dmdns", about = "Distributed mDNS (Scalable DNS-SD) CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enumerate local and unicast browse/registration domains
    Domains,
    /// Browse service instances in a domain
    Browse {
        service_type: String,
        #[arg(default_value = "local.")]
        domain: String,
    },
    /// Resolve a service instance to host, port, TXT, and IP addresses
    Resolve { instance: String },
    /// Register a service locally (.local.) or via DNS Update
    Register {
        instance_name: String,
        service_type: String,
        domain: String,
        port: u16,
        #[arg(long)]
        host: String,
        #[arg(long)]
        ip: Vec<IpAddr>,
    },
    /// Discover all services on local. and dump them
    Dump {
        #[arg(long, value_enum, default_value_t = DumpFormat::Json)]
        format: DumpFormat,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = DistributedClient::new(UnicastResolver::from_system(), None, None, true).await?;

    match cli.cmd {
        Command::Domains => {
            let res = client.enumerate_domains().await;
            println!("Browse domains: {:?}", res.browse);
            println!("Default browse: {:?}", res.default_browse);
            println!("Register domains: {:?}", res.register);
            println!("Default register: {:?}", res.default_register);
        }
        Command::Browse {
            service_type,
            domain,
        } => {
            let dom = DnsName::from_str_dotted(&domain)?;
            let handle = client.browse(&service_type, &dom).await?;
            println!("Browsing via {:?} (waiting 2s)...", handle.transport);
            tokio::time::sleep(Duration::from_secs(2)).await;
            let qname = DnsName::from_str_dotted(&format!(
                "{}.{}",
                service_type.trim_end_matches('.'),
                dom.to_fqdn_string().trim_end_matches('.')
            ))?;
            let records = client
                .cache
                .lock()
                .await
                .get(&qname, RrType::PTR, RrClass::IN, Instant::now());
            for rr in records {
                println!("  {} -> {:?}", rr.name, rr.rdata);
            }
            handle.stop().await;
        }
        Command::Resolve { instance } => {
            let name = DnsName::from_str_dotted(&instance)?;
            let resolved = client.resolve(&name).await?;
            println!("{resolved:#?}");
        }
        Command::Register {
            instance_name,
            service_type,
            domain,
            port,
            host,
            ip,
        } => {
            let spec = UnicastServiceSpec {
                instance_name,
                service_type,
                domain: DnsName::from_str_dotted(&domain)?,
                port,
                txt: Vec::new(),
                host_name: DnsName::from_str_dotted(&host)?,
                addresses: ip,
                ttl: 120,
            };
            let handle = client.register_service(spec).await?;
            println!("Registered! Press Ctrl+C to unregister.");
            tokio::signal::ctrl_c().await?;
            client.unregister_service(handle).await?;
        }
        Command::Dump { format } => {
            let output = dump_local_services(&client, format).await?;
            println!("{output}");
        }
    }

    Ok(())
}

struct DumpedInstance {
    instance: String,
    target: Option<String>,
    port: Option<u16>,
    txt: Vec<String>,
    addresses: Vec<IpAddr>,
    error: Option<String>,
}

struct DumpedServiceType {
    service_type: String,
    instances: Vec<DumpedInstance>,
}

async fn dump_local_services(
    client: &Arc<DistributedClient>,
    format: DumpFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    let mdns = client.mdns.as_ref().ok_or("mDNS engine unavailable")?;

    // --- Phase 1: discover service types via _services._dns-sd._udp.local. ---
    // RFC 6762 §5.2: send the query twice, 1 s apart, to improve reliability.
    let meta_qname = DnsName::from_str_dotted("_services._dns-sd._udp.local.")?;
    let mut events = mdns.subscribe_events();

    mdns.query_once(meta_qname.clone(), RrType::PTR, false).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    mdns.query_once(meta_qname.clone(), RrType::PTR, false).await?;

    // Drain all PTR events that arrive within 2 s of the second query.
    let mut service_types: BTreeSet<String> = BTreeSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            result = events.recv() => {
                match result {
                    Ok(rr) if rr.name == meta_qname && rr.rtype == RrType::PTR => {
                        if let RData::PTR(ptr) = rr.rdata {
                            service_types.insert(ptr.to_fqdn_string());
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }

    // Also pick up anything already in the cache (in case a prior run seeded it).
    {
        let cached = client.cache.lock().await.get(
            &meta_qname,
            RrType::PTR,
            RrClass::IN,
            Instant::now(),
        );
        for rr in cached {
            if let RData::PTR(ptr) = rr.rdata {
                service_types.insert(ptr.to_fqdn_string());
            }
        }
    }

    // --- Phase 2: for each service type, browse for instances. ---
    let mut dumped_services = Vec::new();

    for st in &service_types {
        // st is e.g. "_http._tcp.local." — query it directly for PTR records.
        let st_qname = DnsName::from_str_dotted(st)?;
        let mut ev2 = mdns.subscribe_events();

        mdns.query_once(st_qname.clone(), RrType::PTR, false).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        mdns.query_once(st_qname.clone(), RrType::PTR, false).await?;

        let mut instance_names: BTreeSet<String> = BTreeSet::new();
        let dl2 = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(dl2) => break,
                result = ev2.recv() => {
                    match result {
                        Ok(rr) if rr.name == st_qname && rr.rtype == RrType::PTR => {
                            if let RData::PTR(ptr) = rr.rdata {
                                instance_names.insert(ptr.to_fqdn_string());
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        }

        // Also check cache.
        {
            let cached = client.cache.lock().await.get(
                &st_qname,
                RrType::PTR,
                RrClass::IN,
                Instant::now(),
            );
            for rr in cached {
                if let RData::PTR(ptr) = rr.rdata {
                    instance_names.insert(ptr.to_fqdn_string());
                }
            }
        }

        // --- Phase 3: resolve each instance. ---
        let mut instances = Vec::new();
        for inst in instance_names {
            let inst_name = DnsName::from_str_dotted(&inst)?;
            match client.resolve(&inst_name).await {
                Ok(resolved) => instances.push(DumpedInstance {
                    instance: inst,
                    target: Some(resolved.target.to_fqdn_string()),
                    port: Some(resolved.port),
                    txt: resolved
                        .txt
                        .into_iter()
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .collect(),
                    addresses: resolved.addresses,
                    error: None,
                }),
                Err(e) => instances.push(DumpedInstance {
                    instance: inst,
                    target: None,
                    port: None,
                    txt: Vec::new(),
                    addresses: Vec::new(),
                    error: Some(e.to_string()),
                }),
            }
        }

        dumped_services.push(DumpedServiceType {
            service_type: st.clone(),
            instances,
        });
    }

    Ok(match format {
        DumpFormat::Json => format_dump_json("local.", &dumped_services),
        DumpFormat::Text => format_dump_text("local.", &dumped_services),
        DumpFormat::Yaml => format_dump_yaml("local.", &dumped_services),
    })
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn format_dump_json(domain: &str, services: &[DumpedServiceType]) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"domain\": {},", json_escape(domain));
    out.push_str("  \"services\": [");
    if services.is_empty() {
        out.push_str("]\n}");
        return out;
    }
    out.push('\n');
    for (si, svc) in services.iter().enumerate() {
        out.push_str("    {\n");
        let _ = writeln!(out, "      \"service_type\": {},", json_escape(&svc.service_type));
        out.push_str("      \"instances\": [");
        if svc.instances.is_empty() {
            out.push_str("]\n");
        } else {
            out.push('\n');
            for (ii, inst) in svc.instances.iter().enumerate() {
                out.push_str("        {\n");
                let _ = writeln!(out, "          \"instance\": {},", json_escape(&inst.instance));
                match &inst.target {
                    Some(t) => {
                        let _ = writeln!(out, "          \"target\": {},", json_escape(t));
                    }
                    None => out.push_str("          \"target\": null,\n"),
                }
                match inst.port {
                    Some(p) => {
                        let _ = writeln!(out, "          \"port\": {p},");
                    }
                    None => out.push_str("          \"port\": null,\n"),
                }
                let txt_items: Vec<String> = inst.txt.iter().map(|t| json_escape(t)).collect();
                let _ = writeln!(out, "          \"txt\": [{}],", txt_items.join(", "));
                let addr_items: Vec<String> = inst
                    .addresses
                    .iter()
                    .map(|a| json_escape(&a.to_string()))
                    .collect();
                let _ = writeln!(out, "          \"addresses\": [{}],", addr_items.join(", "));
                match &inst.error {
                    Some(e) => {
                        let _ = writeln!(out, "          \"error\": {}", json_escape(e));
                    }
                    None => out.push_str("          \"error\": null\n"),
                }
                let comma = if ii + 1 < svc.instances.len() { "," } else { "" };
                let _ = writeln!(out, "        }}{comma}");
            }
            out.push_str("      ]\n");
        }
        let comma = if si + 1 < services.len() { "," } else { "" };
        let _ = writeln!(out, "    }}{comma}");
    }
    out.push_str("  ]\n}");
    out
}

fn format_dump_text(domain: &str, services: &[DumpedServiceType]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Domain: {domain}");
    if services.is_empty() {
        out.push_str("No services discovered.");
        return out;
    }
    for svc in services {
        let _ = writeln!(out, "Service Type: {}", svc.service_type);
        if svc.instances.is_empty() {
            out.push_str("  (no instances)\n");
            continue;
        }
        for inst in &svc.instances {
            let _ = writeln!(out, "  Instance: {}", inst.instance);
            if let Some(err) = &inst.error {
                let _ = writeln!(out, "    Error: {err}");
                continue;
            }
            if let (Some(target), Some(port)) = (&inst.target, inst.port) {
                let _ = writeln!(out, "    Target: {target}:{port}");
            }
            if !inst.addresses.is_empty() {
                let addrs: Vec<String> = inst.addresses.iter().map(ToString::to_string).collect();
                let _ = writeln!(out, "    Addresses: {}", addrs.join(", "));
            }
            if !inst.txt.is_empty() {
                let _ = writeln!(out, "    TXT: {}", inst.txt.join(", "));
            }
        }
    }
    out.trim_end().to_string()
}

/// Quote a string as a YAML flow scalar, using double-quote style only when
/// the value contains characters that require escaping (control chars, `"`, `\`).
/// Plain (unquoted) style is used when the value is safe — this keeps the
/// output readable. Values that could be misread as YAML types (true, false,
/// null, numbers) are always quoted.
fn yaml_scalar(s: &str) -> String {
    // Values that must be quoted to avoid YAML type confusion.
    let needs_quoting = matches!(
        s.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
    ) || s.is_empty()
        || s.starts_with(|c: char| c == '-' || c == '&' || c == '*' || c == '!' || c == '|'
            || c == '>' || c == '\'' || c == '"' || c == '%' || c == '@' || c == '`'
            || c == '{' || c == '}' || c == '[' || c == ']' || c == '#' || c == ':')
        || s.contains(|c: char| c == ':' || c == '#' || c.is_ascii_control());

    // Check if any character requires double-quote escaping.
    let has_special = s.chars().any(|c| matches!(c, '"' | '\\') || (c as u32) < 0x20);

    if !needs_quoting && !has_special {
        return s.to_string(); // safe plain scalar
    }

    // Double-quoted scalar with minimal escaping.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn format_dump_yaml(domain: &str, services: &[DumpedServiceType]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "domain: {}", yaml_scalar(domain));
    out.push_str("services:");
    if services.is_empty() {
        out.push_str(" []\n");
        return out;
    }
    out.push('\n');
    for svc in services {
        let _ = writeln!(out, "  - service_type: {}", yaml_scalar(&svc.service_type));
        out.push_str("    instances:");
        if svc.instances.is_empty() {
            out.push_str(" []\n");
            continue;
        }
        out.push('\n');
        for inst in &svc.instances {
            let _ = writeln!(out, "      - instance: {}", yaml_scalar(&inst.instance));
            match &inst.target {
                Some(t) => {
                    let _ = writeln!(out, "        target: {}", yaml_scalar(t));
                }
                None => out.push_str("        target: null\n"),
            }
            match inst.port {
                Some(p) => {
                    let _ = writeln!(out, "        port: {p}");
                }
                None => out.push_str("        port: null\n"),
            }
            out.push_str("        txt:\n");
            if inst.txt.is_empty() {
                // Replace the "txt:\n" we just appended with "txt: []\n".
                let len = out.len();
                out.truncate(len - "        txt:\n".len());
                out.push_str("        txt: []\n");
            } else {
                for t in &inst.txt {
                    let _ = writeln!(out, "          - {}", yaml_scalar(t));
                }
            }
            out.push_str("        addresses:\n");
            if inst.addresses.is_empty() {
                let len = out.len();
                out.truncate(len - "        addresses:\n".len());
                out.push_str("        addresses: []\n");
            } else {
                for addr in &inst.addresses {
                    let _ = writeln!(out, "          - {}", yaml_scalar(&addr.to_string()));
                }
            }
            match &inst.error {
                Some(e) => {
                    let _ = writeln!(out, "        error: {}", yaml_scalar(e));
                }
                None => out.push_str("        error: null\n"),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_services() -> Vec<DumpedServiceType> {
        vec![DumpedServiceType {
            service_type: "_http._tcp.local.".to_string(),
            instances: vec![DumpedInstance {
                instance: "Web\\ \"1\"._http._tcp.local.".to_string(),
                target: Some("host.local.".to_string()),
                port: Some(8080),
                txt: vec!["path=/".to_string()],
                addresses: vec!["192.0.2.10".parse().unwrap()],
                error: None,
            }],
        }]
    }

    // --- CLI parsing ---

    #[test]
    fn cli_dump_defaults_to_json() {
        let cli = Cli::try_parse_from(["dmdns", "dump"]).expect("parse dump");
        match cli.cmd {
            Command::Dump { format } => assert_eq!(format, DumpFormat::Json),
            _ => panic!("expected Dump command"),
        }
    }

    #[test]
    fn cli_dump_accepts_all_formats() {
        for (arg, expected) in [
            ("json", DumpFormat::Json),
            ("text", DumpFormat::Text),
            ("yaml", DumpFormat::Yaml),
        ] {
            let cli = Cli::try_parse_from(["dmdns", "dump", "--format", arg])
                .unwrap_or_else(|e| panic!("parse failed for {arg}: {e}"));
            assert!(
                matches!(cli.cmd, Command::Dump { format } if format == expected),
                "wrong variant for {arg}"
            );
        }
        assert!(Cli::try_parse_from(["dmdns", "dump", "--format", "xml"]).is_err());
    }

    // --- JSON format ---

    #[test]
    fn format_dump_json_expected_output() {
        let services = sample_services();
        let json = format_dump_json("local.", &services);

        assert!(json.contains("\"domain\": \"local.\""));
        assert!(json.contains("\"service_type\": \"_http._tcp.local.\""));
        // instance name has backslash and quote, both must be escaped in JSON
        assert!(json.contains("\"instance\": \"Web\\\\ \\\"1\\\"._http._tcp.local.\""));
        assert!(json.contains("\"port\": 8080"));
        assert!(json.contains("\"addresses\": [\"192.0.2.10\"]"));
        assert!(json.contains("\"txt\": [\"path=/\"]"));
        assert!(json.contains("\"error\": null"));
    }

    #[test]
    fn format_dump_json_empty() {
        let json = format_dump_json("local.", &[]);
        assert!(json.contains("\"services\": []"));
        assert!(json.contains("\"domain\": \"local.\""));
    }

    // --- Text format ---

    #[test]
    fn format_dump_text_expected_output() {
        let services = sample_services();
        let text = format_dump_text("local.", &services);

        assert!(text.contains("Domain: local."));
        assert!(text.contains("Service Type: _http._tcp.local."));
        assert!(text.contains("Target: host.local.:8080"));
        assert!(text.contains("Addresses: 192.0.2.10"));
        assert!(text.contains("TXT: path=/"));
    }

    #[test]
    fn format_dump_text_empty() {
        let text = format_dump_text("local.", &[]);
        assert!(text.contains("No services discovered."));
    }

    // --- YAML format ---

    #[test]
    fn format_dump_yaml_expected_output() {
        let services = sample_services();
        let yaml = format_dump_yaml("local.", &services);

        assert!(yaml.starts_with("domain: local.\n"), "missing domain line:\n{yaml}");
        assert!(yaml.contains("service_type: _http._tcp.local."), "missing service_type:\n{yaml}");
        // instance name contains backslash and double-quote — must be double-quoted
        assert!(
            yaml.contains("instance: \"Web\\\\ \\\"1\\\"._http._tcp.local.\""),
            "missing or mis-escaped instance:\n{yaml}"
        );
        assert!(yaml.contains("target: host.local."), "missing target:\n{yaml}");
        assert!(yaml.contains("port: 8080"), "missing port:\n{yaml}");
        assert!(yaml.contains("- path=/"), "missing txt entry:\n{yaml}");
        assert!(yaml.contains("- 192.0.2.10"), "missing address:\n{yaml}");
        assert!(yaml.contains("error: null"), "missing null error:\n{yaml}");
    }

    #[test]
    fn format_dump_yaml_empty() {
        let yaml = format_dump_yaml("local.", &[]);
        assert!(yaml.contains("services: []"), "empty services not []:\n{yaml}");
    }

    #[test]
    fn format_dump_yaml_null_fields() {
        let services = vec![DumpedServiceType {
            service_type: "_ssh._tcp.local.".to_string(),
            instances: vec![DumpedInstance {
                instance: "My SSH._ssh._tcp.local.".to_string(),
                target: None,
                port: None,
                txt: vec![],
                addresses: vec![],
                error: Some("no SRV record found".to_string()),
            }],
        }];
        let yaml = format_dump_yaml("local.", &services);
        assert!(yaml.contains("target: null"), "expected null target:\n{yaml}");
        assert!(yaml.contains("port: null"), "expected null port:\n{yaml}");
        assert!(yaml.contains("txt: []"), "expected empty txt list:\n{yaml}");
        assert!(yaml.contains("addresses: []"), "expected empty addresses list:\n{yaml}");
        assert!(yaml.contains("error: no SRV record found"), "expected error string:\n{yaml}");
    }

    #[test]
    fn yaml_scalar_quoting_rules() {
        // Safe plain scalars — no quotes needed.
        assert_eq!(yaml_scalar("host.local."), "host.local.");
        assert_eq!(yaml_scalar("192.0.2.10"), "192.0.2.10");
        assert_eq!(yaml_scalar("path=/index.html"), "path=/index.html");

        // Reserved words must be quoted.
        assert_eq!(yaml_scalar("true"), "\"true\"");
        assert_eq!(yaml_scalar("null"), "\"null\"");
        assert_eq!(yaml_scalar(""), "\"\"");

        // Leading special chars must be quoted.
        assert_eq!(yaml_scalar("#comment"), "\"#comment\"");
        assert_eq!(yaml_scalar(":value"), "\":value\"");

        // Backslash and double-quote inside a double-quoted scalar.
        assert_eq!(yaml_scalar("a\\b"), "\"a\\\\b\"");
        assert_eq!(yaml_scalar("say \"hi\""), "\"say \\\"hi\\\"\"");
    }
}
