use clap::{Parser, Subcommand};
use dist_mdns::client::DistributedClient;
use dist_mdns::enumeration::UnicastResolver;
use dist_mdns::update::UnicastServiceSpec;
use dist_mdns::wire::{DnsName, RrClass, RrType};
use std::net::IpAddr;
use std::time::{Duration, Instant};

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
    }

    Ok(())
}
