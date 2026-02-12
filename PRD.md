PRD: "Project Guardian" (Network Intrusion Detection System)
1. Project Overview
Objective: Build a passive network traffic analyzer that captures live packets, parses protocols (TCP/UDP/ICMP), and detects suspicious traffic anomalies in real-time. The "Vibe": "I see everything." A lightweight, home-brewed IDS (Intrusion Detection System). Architecture:

The Muscle (Rust): A high-performance sniffer that captures packets, strips the headers, aggregates metadata (Source IP, Dest IP, Port, Protocol, Size), and pushes it to a data stream.

The Brain (Python): A service that consumes the stream and runs statistical analysis to flag outliers (e.g., "Why is this IP sending 500 requests per second?").

2. Core Functional Requirements
Phase 1: The Rust Sniffer (Raw Data)
Capture Interface: Must listen on a specified network interface (e.g., eth0 or wlan0) in Promiscuous Mode (seeing traffic meant for other devices if possible, or just all local traffic).

Packet Parsing:

Strip the Ethernet Frame.

Parse the IPv4 Header (Extract Source/Dest IPs).

Parse TCP/UDP Headers (Extract Ports).

Throughput: Must handle normal traffic flow without dropping packets.

Output: Stream JSON logs to stdout or a TCP socket (e.g., {"src": "1.2.3.4", "dst": "5.6.7.8", "proto": "TCP", "len": 64}).

Phase 2: The Python Analyzer (Intelligence)
Ingestion: Read the JSON stream from the Rust engine.

Baseline Monitoring: Calculate the average bytes/sec and packets/sec for the network.

Alerting Logic:

Port Scan Detect: If one Source IP hits >10 unique ports on a Destination IP within 5 seconds -> ALERT.

SYN Flood Detect: If SYN packets from one IP exceed threshold X without completing connections -> ALERT.

Dashboard (Optional): A simple streamlit dashboard showing live traffic stats.

3. Technical Specifications
The Rust Stack
libpnet: This is the standard "low-level networking" crate for Rust. It wraps raw sockets.

Note: You will need to install Npcap (Windows) or use sudo (Linux/Mac) to run this.

serde_json: To serialize the packet metadata.

crossbeam-channel: For internal thread communication (capturing thread -> parsing thread).

The Python Stack
pandas: For maintaining a rolling window of traffic data.

scikit-learn: (Bonus) Use "Isolation Forest" for unsupervised anomaly detection.

Data Flow Diagram
[Network Card] -> (libpnet) -> [Rust Parsing Thread] -> (JSON) -> [Python Script] -> [Alert]

4. Key Security Concepts (The Learning Objectives)
Promiscuous Mode: How NICs (Network Interface Cards) normally ignore traffic not addressed to them, and how to override that.

Protocol Stacks: You will manually see how an Ethernet frame wraps an IP packet, which wraps a TCP segment.

Endianness: Network traffic is "Big Endian." Your CPU is likely "Little Endian." You will deal with byte-swapping (or let libraries handle it).

5. Non-Functional Requirements
Low Latency: The time from "packet hits wire" to "Python sees JSON" should be under 10ms.

Resilience: If the traffic volume spikes, the Rust sniffer should prioritize keeping up over perfect logging (drop packets rather than crashing).