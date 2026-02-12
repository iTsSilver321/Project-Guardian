use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use serde::Serialize;
use std::io::{self, Write};
use clap::Parser;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL of the Central API Server
    #[arg(long, default_value = "http://localhost:8080")]
    server: String,

    /// Authentication Token
    #[arg(long, default_value = "SECRET_GUARDIAN_TOKEN")]
    token: String,

    /// Network Interface Index (for non-interactive mode)
    #[arg(long)]
    iface: Option<usize>,
}

#[derive(Serialize, Debug, Clone)]
struct PacketLog {
    src: String,
    dst: String,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    proto: String,
    flags: Option<u16>,
    len: usize,
    payload: String,
}

fn main() {
    let args = Args::parse();
    println!("🔌 Connecting to Central API: {}", args.server);

    // 1. Channel for async logging (Sniffer -> Sender Thread)
    let (tx, rx) = mpsc::channel::<PacketLog>();

    // 2. Spawn Sender Thread
    let server_url = args.server.clone();
    let token = args.token.clone();
    
    thread::spawn(move || {
        let client = reqwest::blocking::Client::new();
        let url = format!("{}/log/packet", server_url);

        loop {
            // Batching could improve performance, but for now send one by one
            if let Ok(log) = rx.recv() {
                match client.post(&url)
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&log)
                    .send() {
                        Ok(resp) => {
                            if !resp.status().is_success() {
                                eprintln!("API Error: {}", resp.status());
                            }
                        },
                        Err(e) => eprintln!("Failed to send log: {}", e),
                    }
            }
        }
    });

    // 3. Network Interface Selection
    let interfaces = datalink::interfaces();
    if interfaces.is_empty() {
        eprintln!("No network interfaces found.");
        return;
    }

    let index: usize = if let Some(idx) = args.iface {
        if idx < interfaces.len() {
            idx
        } else {
            eprintln!("Provided interface index {} is invalid.", idx);
            return;
        }
    } else {
        eprintln!("Select a network interface to sniff on:");
        for (i, iface) in interfaces.iter().enumerate() {
            eprintln!("{}: {} ({:?})", i, iface.name, iface.ips);
        }

        eprint!("Enter interface index: ");
        io::stderr().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        
        match input.trim().parse() {
            Ok(idx) if idx < interfaces.len() => idx,
            _ => {
                eprintln!("Invalid selection.");
                return;
            }
        }
    };

    let interface = interfaces[index].clone();
    eprintln!("Listening on interface: {}", interface.name);

    // 4. Capture Loop
    let (_, mut rx_packet) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    loop {
        match rx_packet.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                            let protocol = ipv4_packet.get_next_level_protocol();
                            let mut src_port = None;
                            let mut dst_port = None;
                            let mut flags = None;
                            let mut payload_bytes: Vec<u8> = Vec::new();

                            match protocol {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                        src_port = Some(tcp_packet.get_source());
                                        dst_port = Some(tcp_packet.get_destination());
                                        flags = Some(tcp_packet.get_flags() as u16);
                                        payload_bytes = tcp_packet.payload().to_vec();
                                    }
                                },
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                                        src_port = Some(udp_packet.get_source());
                                        dst_port = Some(udp_packet.get_destination());
                                        payload_bytes = udp_packet.payload().to_vec();
                                    }
                                },
                                _ => {}
                            }

                            // Convert payload to lossy UTF-8 and truncate
                            let payload_string = String::from_utf8_lossy(&payload_bytes).into_owned();
                            let truncated_payload: String = payload_string.chars().take(512).collect();

                            let log = PacketLog {
                                src: ipv4_packet.get_source().to_string(),
                                dst: ipv4_packet.get_destination().to_string(),
                                src_port,
                                dst_port,
                                proto: format!("{:?}", protocol),
                                flags,
                                len: ipv4_packet.packet().len(),
                                payload: truncated_payload,
                            };
                            
                            // Send to Async Thread
                            if let Err(e) = tx.send(log) {
                                eprintln!("Failed to queue packet log: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }
}
