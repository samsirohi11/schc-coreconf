//! SCHC UDP Tunnel - Interoperability Testing
//!
//! A UDP tunnel for testing SCHC interoperability with other implementations
//! (e.g., OpenSCHC, cSCHC). Both sides use the same rule file and exchange
//! compressed IPv6/UDP packets over UDP.
//!
//! Features:
//! - Supports both SOR (CBOR) and JSON rule formats
//! - Sends raw IPv6/UDP packets through the tunnel (no Ethernet header)
//! - Can operate as sender, receiver, bidirectional, or echo mode
//! - Statistics tracking for compression/decompression success rates
//!
//! Usage:
//!   # Receiver mode (decompress incoming traffic):
//!   cargo run --example udp_tunnel_interop -- --listen 127.0.0.1:9000 --rules rules/base-ipv6-udp.sor
//!
//!   # Sender mode (compress and send traffic):
//!   cargo run --example udp_tunnel_interop -- --send 127.0.0.1:9000 --rules rules/base-ipv6-udp.sor
//!
//!   # Bidirectional mode (send and receive):
//!   cargo run --example udp_tunnel_interop -- --listen 127.0.0.1:9000 --send 127.0.0.1:9001 --rules rules.sor
//!
//!   # Echo mode (decompress, re-compress, send back):
//!   cargo run --example udp_tunnel_interop -- --listen 127.0.0.1:9000 --echo --rules rules.sor
//!
//!   # Server mode for Docker interop (listen on all interfaces, auto RX direction, DOWN on TX):
//!   cargo run --example udp_tunnel_interop -- --server --rules rules/docker1.sor -v
//!
//!   # Core proxy mode (decompress, forward to CoAP server, recompress response):
//!   cargo run --example udp_tunnel_interop -- --server --coap-server user.plido.net:5683 --rules rules/docker1.sor -v
//!
//! For interop testing:
//!   1. Have the same rule file on both sides (sor or json)
//!   2. Run this example in listen or echo mode
//!   3. Configure the other implementation to send to this example's listen address    

use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rust_coreconf::SidFile;
use schc::{
    build_tree, compress_packet_with_link_layer, decompress_packet,
    Direction, LinkLayer, Rule, RuleSet, TreeNode,
};
use schc_coreconf::load_sor_rules;

const SID_FILE_PATH: &str = "samples/ietf-schc@2026-01-12.sid";

/// Statistics for tracking interop test results
#[derive(Default)]
struct Stats {
    rx_packets: AtomicU64,
    rx_decompress_ok: AtomicU64,
    rx_decompress_fail: AtomicU64,
    tx_packets: AtomicU64,
    tx_compress_ok: AtomicU64,
    tx_compress_fail: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
enum DirectionMode {
    Up,
    Down,
    Auto,
}

fn parse_direction_mode(value: &str) -> io::Result<DirectionMode> {
    match value.to_ascii_lowercase().as_str() {
        "up" => Ok(DirectionMode::Up),
        "down" | "dw" => Ok(DirectionMode::Down),
        "auto" => Ok(DirectionMode::Auto),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid direction mode '{}'. Use up, down, or auto", value),
        )),
    }
}

fn parse_direction(value: &str) -> io::Result<Direction> {
    match value.to_ascii_lowercase().as_str() {
        "up" => Ok(Direction::Up),
        "down" | "dw" => Ok(Direction::Down),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid direction '{}'. Use up or down", value),
        )),
    }
}

fn decompress_with_mode(
    schc_data: &[u8],
    rules: &[Rule],
    mode: DirectionMode,
) -> Result<(Direction, u32, u8, Vec<u8>), String> {
    let try_one = |dir: Direction| {
        decompress_packet(schc_data, rules, dir, None)
            .map(|d| (dir, d.rule_id, d.rule_id_length, d.full_data))
            .map_err(|e| format!("{:?}", e))
    };

    match mode {
        DirectionMode::Up => try_one(Direction::Up),
        DirectionMode::Down => try_one(Direction::Down),
        DirectionMode::Auto => {
            let up = try_one(Direction::Up);
            if up.is_ok() {
                return up;
            }
            let down = try_one(Direction::Down);
            if down.is_ok() {
                return down;
            }
            Err(format!(
                "AUTO direction failed. up_err={}, down_err={}",
                up.err().unwrap_or_else(|| "unknown".to_string()),
                down.err().unwrap_or_else(|| "unknown".to_string())
            ))
        }
    }
}

impl Stats {
    fn print(&self) {
        println!("\n=== Statistics ===");
        println!("RX: {} packets, {} decompressed, {} failed",
                 self.rx_packets.load(Ordering::Relaxed),
                 self.rx_decompress_ok.load(Ordering::Relaxed),
                 self.rx_decompress_fail.load(Ordering::Relaxed));
        println!("TX: {} packets, {} compressed, {} failed",
                 self.tx_packets.load(Ordering::Relaxed),
                 self.tx_compress_ok.load(Ordering::Relaxed),
                 self.tx_compress_fail.load(Ordering::Relaxed));
    }
}

fn main() -> io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();

    let server_mode = args.iter().any(|a| a == "--server");

    let schc_listen_addr = args.iter().position(|a| a == "--schc-listen")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let listen_addr = args.iter().position(|a| a == "--listen")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let listen_addr = schc_listen_addr.or(listen_addr);

    let listen_addr = if listen_addr.is_some() {
        listen_addr
    } else if server_mode {
        Some("0.0.0.0:23628")
    } else {
        None
    };

    let send_addr = args.iter().position(|a| a == "--send")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let reply_to = args.iter().position(|a| a == "--reply-to")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let downlink_target = args.iter().position(|a| a == "--downlink-target")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());
    let reply_to = downlink_target.or(reply_to);

    let coap_server = args.iter().position(|a| a == "--coap-server")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let rules_path = args.iter().position(|a| a == "--rules")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("rules/base-ipv6-udp.sor");

    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
    let echo_mode = args.iter().any(|a| a == "--echo") || server_mode;

    let rx_direction_mode = args
        .iter()
        .position(|a| a == "--rx-direction")
        .and_then(|i| args.get(i + 1))
        .map(|s| parse_direction_mode(s))
        .transpose()?
        .unwrap_or(if server_mode {
            DirectionMode::Auto
        } else {
            DirectionMode::Up
        });

    let tx_direction = args
        .iter()
        .position(|a| a == "--tx-direction")
        .and_then(|i| args.get(i + 1))
        .map(|s| parse_direction(s))
        .transpose()?
        .unwrap_or(if server_mode { Direction::Down } else { Direction::Up });

    if listen_addr.is_none() && send_addr.is_none() {
        print_usage();
        return Ok(());
    }

    println!("============================================================");
    println!("       SCHC UDP Tunnel - Interoperability Testing");
    println!("============================================================\n");

    if server_mode {
        println!("Mode: SERVER (Docker interop)");
        println!("  listen: {}", listen_addr.unwrap_or("0.0.0.0:23628"));
        println!("  rx-direction: {:?}", rx_direction_mode);
        println!("  tx-direction: {:?}", tx_direction);
        if let Some(coap) = coap_server {
            println!("  coap-server: {}", coap);
        }
        if let Some(dst) = reply_to {
            println!("  downlink-target: {}", dst);
        } else {
            println!("  downlink-target: source sender");
        }
        println!();
    }

    // Load rules (auto-detect format)
    let rules = load_rules(rules_path)?;
    println!("Loaded {} rules from {}", rules.len(), rules_path);

    for rule in &rules {
        println!("  Rule {}/{}: {} fields", rule.rule_id, rule.rule_id_length, rule.compression.len());
    }

    let ruleset = Arc::new(RuleSet { rules: rules.clone() });
    let tree = Arc::new(build_tree(&ruleset.rules));
    let stats = Arc::new(Stats::default());
    let running = Arc::new(AtomicBool::new(true));

    // Handle Ctrl+C
    {
        let running_clone = running.clone();
        let stats_clone = stats.clone();
        ctrlc::set_handler(move || {
            println!("\nShutting down...");
            stats_clone.print();
            running_clone.store(false, Ordering::SeqCst);
            std::process::exit(0);
        }).expect("Error setting Ctrl-C handler");
    }

    println!();

    // Determine mode
    match (listen_addr, send_addr, echo_mode) {
        // Echo mode: listen and echo back compressed packets
        (Some(addr), _, true) => {
            run_echo_mode(
                addr,
                reply_to,
                &ruleset,
                &tree,
                &stats,
                verbose,
                rx_direction_mode,
                tx_direction,
                coap_server,
            )?;
        }
        // Bidirectional mode: both listen and send
        (Some(listen), Some(send), false) => {
            run_bidirectional(
                listen,
                send,
                &ruleset,
                &tree,
                &stats,
                &running,
                verbose,
                rx_direction_mode,
                tx_direction,
            )?;
        }
        // Receive only
        (Some(addr), None, false) => {
            run_receiver(addr, &ruleset, &stats, verbose, rx_direction_mode)?;
        }
        // Send only
        (None, Some(addr), false) => {
            run_sender(addr, &ruleset, &tree, &stats, verbose, tx_direction)?;
        }
        _ => {
            print_usage();
        }
    }

    stats.print();
    Ok(())
}

fn print_usage() {
    println!("SCHC UDP Tunnel - Interoperability Testing\n");
    println!("Usage:");
    println!("  --listen <addr:port>  Listen for incoming SCHC packets");
    println!("  --schc-listen <addr:port> Alias for --listen");
    println!("  --send <addr:port>    Send SCHC packets to address");
    println!("  --rules <path>        Path to rules file (SOR or JSON)");
    println!("  --echo                Echo mode: decompress and send back re-compressed");
    println!("  --server              Server mode for Docker interop (equivalent to --listen 0.0.0.0:23628 --echo)");
    println!("  --coap-server <host:port> Forward decompressed CoAP and recompress response");
    println!("  --reply-to <addr:port> Send echoed packets to this address instead of source");
    println!("  --downlink-target <addr:port> Alias for --reply-to");
    println!("  --rx-direction <up|down|auto>  Direction used to decompress incoming SCHC");
    println!("  --tx-direction <up|down>       Direction used when compressing outbound SCHC");
    println!("  -v, --verbose         Verbose output\n");
    println!("Examples:");
    println!("  # Receiver mode:");
    println!("  cargo run --example udp_tunnel_interop -- --listen 127.0.0.1:9000 --rules rules.sor");
    println!();
    println!("  # Sender mode:");
    println!("  cargo run --example udp_tunnel_interop -- --send 127.0.0.1:9000 --rules rules.sor");
    println!();
    println!("  # Echo mode (for testing round-trip):");
    println!("  cargo run --example udp_tunnel_interop -- --listen 127.0.0.1:9000 --echo --rules rules.sor");
    println!();
    println!("  # Server mode for Docker interop with test-rule.json:");
    println!("  cargo run --example udp_tunnel_interop -- --server --rules rules/test-rule.json --rx-direction auto --tx-direction down -v");
    println!();
    println!("  # Server + CoAP proxy mode:");
    println!("  cargo run --example udp_tunnel_interop -- --server --coap-server user.plido.net:5683 --rules rules/test-rule.json -v");
    println!();
    println!("  # Bidirectional mode:");
    println!("  cargo run --example udp_tunnel_interop -- --listen 127.0.0.1:9000 --send 127.0.0.1:9001 --rules rules.sor");
}

fn resolve_socket_addrs(addr: &str, arg_name: &str) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid {} '{}': {}", arg_name, addr, e),
        )
    })?.collect();
    if addrs.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} '{}' resolved to no socket address", arg_name, addr),
        ))
    } else {
        Ok(addrs)
    }
}

fn resolve_socket_addr(addr: &str, arg_name: &str) -> io::Result<SocketAddr> {
    Ok(resolve_socket_addrs(addr, arg_name)?[0])
}

fn load_rules(path: &str) -> io::Result<Vec<Rule>> {
    if path.ends_with(".sor") || path.ends_with(".cbor") {
        println!("Loading SOR rules with SID file: {}", SID_FILE_PATH);
        let sid_file = SidFile::from_file(SID_FILE_PATH)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SID file error: {}", e)))?;
        load_sor_rules(path, &sid_file)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SOR parse error: {}", e)))
    } else {
        println!("Loading JSON rules");
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("JSON parse error: {}", e)))
    }
}

fn run_receiver(
    addr: &str,
    ruleset: &RuleSet,
    stats: &Stats,
    verbose: bool,
    rx_direction_mode: DirectionMode,
) -> io::Result<()> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;

    println!("Listening on {} for SCHC packets...", addr);
    println!("Press Ctrl+C to stop\n");

    let mut buf = [0u8; 2048];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                let count = stats.rx_packets.load(Ordering::Relaxed);
                let schc_data = &buf[..len];

                println!("[{}] Received {} bytes from {}", count, len, src);
                if verbose {
                    println!("  SCHC: {}", hex::encode(schc_data));
                }

                match decompress_with_mode(schc_data, &ruleset.rules, rx_direction_mode) {
                    Ok((used_direction, rule_id, rule_id_length, full_data)) => {
                        stats.rx_decompress_ok.fetch_add(1, Ordering::Relaxed);
                        println!(
                            "  Decompressed: {} bytes (Rule {}/{}, Direction={:?})",
                            full_data.len(),
                            rule_id,
                            rule_id_length,
                            used_direction
                        );
                        display_packet_structure(&full_data, verbose);
                    }
                    Err(e) => {
                        stats.rx_decompress_fail.fetch_add(1, Ordering::Relaxed);
                        println!("  Decompress error: {}", e);
                    }
                }
                println!();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                print!(".");
                io::stdout().flush()?;
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
            }
        }
    }
}

fn run_sender(
    addr: &str,
    ruleset: &RuleSet,
    tree: &TreeNode,
    stats: &Stats,
    verbose: bool,
    tx_direction: Direction,
) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(addr)?;

    println!("Sending SCHC packets to {}", addr);
    println!("Commands: 'send [N]' to send N test packets, 'stats', 'quit'\n");

    let stdin = io::stdin();

    loop {
        print!("sender> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "send" => {
                let count: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                send_test_packets(&socket, ruleset, tree, stats, count, verbose, tx_direction)?;
            }
            "stats" => stats.print(),
            "quit" | "exit" | "q" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Unknown command. Use 'send [N]', 'stats', or 'quit'"),
        }
    }

    Ok(())
}

fn run_echo_mode(
    addr: &str,
    reply_to: Option<&str>,
    ruleset: &RuleSet,
    tree: &TreeNode,
    stats: &Stats,
    verbose: bool,
    rx_direction_mode: DirectionMode,
    tx_direction: Direction,
    coap_server: Option<&str>,
) -> io::Result<()> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;

    let fixed_reply_target: Option<SocketAddr> = match reply_to {
        Some(dst) => Some(resolve_socket_addr(dst, "--reply-to/--downlink-target")?),
        None => None,
    };
    let coap_targets = match coap_server {
        Some(dst) => Some(resolve_socket_addrs(dst, "--coap-server")?),
        None => None,
    };

    println!("Echo/server mode listening on {}", addr);
    if let Some(targets) = coap_targets.as_ref() {
        let targets = targets
            .iter()
            .map(|target| target.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "Will decompress, proxy CoAP to [{}], and send compressed response.",
            targets
        );
    } else {
        println!("Will decompress, re-compress, and send back to sender.");
    }
    println!("RX direction mode: {:?}", rx_direction_mode);
    println!("TX direction: {:?}", tx_direction);
    if let Some(dst) = fixed_reply_target {
        println!("Reply target: {}", dst);
    } else {
        println!("Reply target: source sender");
    }
    println!("Press Ctrl+C to stop\n");

    let mut buf = [0u8; 2048];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                let count = stats.rx_packets.load(Ordering::Relaxed);
                let schc_data = &buf[..len];

                println!("[{}] Received {} bytes from {}", count, len, src);

                // Decompress
                match decompress_with_mode(schc_data, &ruleset.rules, rx_direction_mode) {
                    Ok((used_direction, rule_id, rule_id_length, full_data)) => {
                        stats.rx_decompress_ok.fetch_add(1, Ordering::Relaxed);
                        println!(
                            "  Decompressed: {} bytes (rule {}/{}, Direction={:?})",
                            full_data.len(),
                            rule_id,
                            rule_id_length,
                            used_direction
                        );

                        display_packet_structure(&full_data, verbose);

                        let tx_packet = if let Some(targets) = coap_targets.as_deref() {
                            match forward_to_coap_and_build_response(&full_data, targets, verbose) {
                                Ok(packet) => packet,
                                Err(e) => {
                                    stats.tx_compress_fail.fetch_add(1, Ordering::Relaxed);
                                    println!("  CoAP proxy error: {}", e);
                                    println!();
                                    continue;
                                }
                            }
                        } else {
                            full_data
                        };

                        // Re-compress using explicit TX direction for true server/device interoperability
                        match compress_packet_with_link_layer(
                            tree,
                            &tx_packet,
                            tx_direction,
                            &ruleset.rules,
                            verbose,
                            LinkLayer::None,
                        ) {
                            Ok(compressed) => {
                                stats.tx_compress_ok.fetch_add(1, Ordering::Relaxed);
                                stats.tx_packets.fetch_add(1, Ordering::Relaxed);

                                let target = fixed_reply_target.unwrap_or(src);
                                socket.send_to(&compressed.data, target)?;
                                println!(
                                    "  Echo sent: {} bytes to {} (rule {}/{}, Direction={:?})",
                                    compressed.data.len(),
                                    target,
                                    compressed.rule_id,
                                    compressed.rule_id_length,
                                    tx_direction
                                );
                            }
                            Err(e) => {
                                stats.tx_compress_fail.fetch_add(1, Ordering::Relaxed);
                                println!("  Re-compress error: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        stats.rx_decompress_fail.fetch_add(1, Ordering::Relaxed);
                        println!("  Decompress error: {}", e);
                    }
                }
                println!();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                print!(".");
                io::stdout().flush()?;
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
            }
        }
    }
}

fn forward_to_coap_and_build_response(
    ipv6_udp_packet: &[u8],
    coap_targets: &[SocketAddr],
    verbose: bool,
) -> io::Result<Vec<u8>> {
    if ipv6_udp_packet.len() < 48 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Decompressed packet too short for IPv6/UDP: {} bytes", ipv6_udp_packet.len()),
        ));
    }

    let request_coap = &ipv6_udp_packet[48..];
    let mut last_error = None;
    for coap_target in coap_targets {
        match forward_to_single_coap_target(request_coap, *coap_target, verbose) {
            Ok(coap_response) => return build_ipv6_udp_response(ipv6_udp_packet, &coap_response),
            Err(e) => {
                println!("  CoAP target {} failed: {}", coap_target, e);
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "No CoAP targets resolved")
    }))
}

fn forward_to_single_coap_target(
    request_coap: &[u8],
    coap_target: SocketAddr,
    verbose: bool,
) -> io::Result<Vec<u8>> {
    let coap_socket = match coap_target {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0")?,
    };
    coap_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    if verbose {
        println!("  CoAP request bytes (hex): {}", hex::encode(request_coap));
    }
    coap_socket.send_to(request_coap, coap_target)?;
    println!("  CoAP forwarded: {} bytes to {}", request_coap.len(), coap_target);

    let mut response_buf = [0u8; 2048];
    let (resp_len, resp_src) = match coap_socket.recv_from(&mut response_buf) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timeout waiting 5s for CoAP response from {}", coap_target),
            ));
        }
        Err(e) => return Err(e),
    };
    println!("  CoAP response: {} bytes from {}", resp_len, resp_src);
    Ok(response_buf[..resp_len].to_vec())
}

fn build_ipv6_udp_response(request_packet: &[u8], coap_response: &[u8]) -> io::Result<Vec<u8>> {
    if request_packet.len() < 48 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Request packet too short for IPv6/UDP: {} bytes", request_packet.len()),
        ));
    }

    let mut response = Vec::with_capacity(40 + 8 + coap_response.len());

    response.extend_from_slice(&request_packet[0..4]); // Version/TC/FL

    let payload_length = (8 + coap_response.len()) as u16;
    response.extend_from_slice(&payload_length.to_be_bytes());
    response.push(request_packet[6]); // Next Header
    response.push(request_packet[7]); // Hop Limit

    // Swap source/destination IPv6 addresses.
    response.extend_from_slice(&request_packet[24..40]); // source = previous destination
    response.extend_from_slice(&request_packet[8..24]);  // destination = previous source

    // Swap UDP ports.
    response.extend_from_slice(&request_packet[42..44]); // src port = previous dst port
    response.extend_from_slice(&request_packet[40..42]); // dst port = previous src port
    response.extend_from_slice(&payload_length.to_be_bytes());
    response.extend_from_slice(&[0x00, 0x00]); // checksum left to compute-CDA/rule behavior

    response.extend_from_slice(coap_response);
    Ok(response)
}

fn run_bidirectional(
    listen_addr: &str,
    send_addr: &str,
    ruleset: &Arc<RuleSet>,
    tree: &Arc<TreeNode>,
    stats: &Arc<Stats>,
    running: &Arc<AtomicBool>,
    verbose: bool,
    rx_direction_mode: DirectionMode,
    tx_direction: Direction,
) -> io::Result<()> {
    let socket = UdpSocket::bind(listen_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let send_target: SocketAddr = send_addr.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid send address: {}", e)))?;

    println!("Bidirectional mode:");
    println!("  Listening on: {}", listen_addr);
    println!("  Sending to: {}", send_addr);
    println!("Commands: 'send [N]', 'stats', 'quit'\n");

    let socket_clone = socket.try_clone()?;
    let ruleset_clone = ruleset.clone();
    let stats_clone = stats.clone();
    let running_clone = running.clone();

    // Receiver thread
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while running_clone.load(Ordering::Relaxed) {
            match socket_clone.recv_from(&mut buf) {
                Ok((len, src)) => {
                    stats_clone.rx_packets.fetch_add(1, Ordering::Relaxed);
                    let count = stats_clone.rx_packets.load(Ordering::Relaxed);
                    let schc_data = &buf[..len];

                    println!("\n[RX {}] {} bytes from {}", count, len, src);
                    if let Ok((used_direction, rule_id, rule_id_length, full_data)) =
                        decompress_with_mode(schc_data, &ruleset_clone.rules, rx_direction_mode)
                    {
                        stats_clone.rx_decompress_ok.fetch_add(1, Ordering::Relaxed);
                        println!(
                            "  Decompressed: {} bytes (Rule {}/{}, Direction={:?})",
                            full_data.len(),
                            rule_id,
                            rule_id_length,
                            used_direction
                        );
                    } else {
                        stats_clone.rx_decompress_fail.fetch_add(1, Ordering::Relaxed);
                        println!("  Decompress failed");
                    }
                    print!("sender> ");
                    let _ = io::stdout().flush();
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
    });

    // Sender loop
    let stdin = io::stdin();
    while running.load(Ordering::Relaxed) {
        print!("sender> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "send" => {
                let count: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                for _ in 0..count {
                    let packet = build_test_ipv6_udp_packet("bidirectional test");
                    if let Ok(compressed) = compress_packet_with_link_layer(
                        tree,
                        &packet,
                        tx_direction,
                        &ruleset.rules,
                        verbose,
                        LinkLayer::None,
                    ) {
                        stats.tx_compress_ok.fetch_add(1, Ordering::Relaxed);
                        stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                        socket.send_to(&compressed.data, send_target)?;
                        println!("Sent {} bytes to {}", compressed.data.len(), send_target);
                    } else {
                        stats.tx_compress_fail.fetch_add(1, Ordering::Relaxed);
                        println!("Compression failed");
                    }
                }
            }
            "stats" => stats.print(),
            "quit" | "exit" | "q" => {
                running.store(false, Ordering::SeqCst);
                break;
            }
            _ => println!("Unknown command"),
        }
    }

    Ok(())
}

fn send_test_packets(
    socket: &UdpSocket,
    ruleset: &RuleSet,
    tree: &TreeNode,
    stats: &Stats,
    count: usize,
    verbose: bool,
    tx_direction: Direction,
) -> io::Result<()> {
    for i in 0..count {
        let payload = format!("Test packet #{}", stats.tx_packets.load(Ordering::Relaxed) + 1);
        let packet = build_test_ipv6_udp_packet(&payload);

        if verbose {
            println!("[{}] IPv6/UDP: {} bytes", i + 1, packet.len());
        }

        match compress_packet_with_link_layer(
            tree,
            &packet,
            tx_direction,
            &ruleset.rules,
            verbose,
            LinkLayer::None,
        ) {
            Ok(compressed) => {
                stats.tx_compress_ok.fetch_add(1, Ordering::Relaxed);
                stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                socket.send(&compressed.data)?;
                println!("[{}] Sent: {} -> {} bytes (Rule {}/{})",
                         i + 1, packet.len(), compressed.data.len(),
                         compressed.rule_id, compressed.rule_id_length);
            }
            Err(e) => {
                stats.tx_compress_fail.fetch_add(1, Ordering::Relaxed);
                println!("[{}] Compression failed: {:?}", i + 1, e);
            }
        }
    }
    Ok(())
}

fn build_test_ipv6_udp_packet(payload: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(40 + 8 + payload.len());

    // IPv6 header (40 bytes)
    let version_tc_fl: u32 = (6 << 28) | 0x12345;
    packet.extend_from_slice(&version_tc_fl.to_be_bytes());

    let payload_length = (8 + payload.len()) as u16;
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.push(17); // UDP
    packet.push(64); // Hop Limit

    // Source: 2001:db8::1
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

    // Destination: 2001:41d0:0302:2200::5043
    packet.extend_from_slice(&[0x20, 0x01, 0x41, 0xd0, 0x03, 0x02, 0x22, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xb3]);

    // UDP header
    packet.extend_from_slice(&12345u16.to_be_bytes()); // Src port
    packet.extend_from_slice(&5680u16.to_be_bytes());  // Dst port
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum

    packet.extend_from_slice(payload.as_bytes());
    packet
}

fn display_packet_structure(data: &[u8], verbose: bool) {
    if data.len() < 40 {
        println!("  [Too short for IPv6]");
        return;
    }

    let version = (data[0] >> 4) & 0x0F;
    let traffic_class = (data[0] >> 0) & 0x0F;
    let flow_label = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let src_addr: [u8; 16] = data[8..24].try_into().unwrap();
    let dst_addr: [u8; 16] = data[24..40].try_into().unwrap();

    println!("  IPv6: ver={} tc={} fl={} len={} nxt={} hop={}",
        version, traffic_class, flow_label, payload_len, next_header, hop_limit);
    println!("    src: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        u16::from_be_bytes([src_addr[0], src_addr[1]]),
        u16::from_be_bytes([src_addr[2], src_addr[3]]),
        u16::from_be_bytes([src_addr[4], src_addr[5]]),
        u16::from_be_bytes([src_addr[6], src_addr[7]]),
        u16::from_be_bytes([src_addr[8], src_addr[9]]),
        u16::from_be_bytes([src_addr[10], src_addr[11]]),
        u16::from_be_bytes([src_addr[12], src_addr[13]]),
        u16::from_be_bytes([src_addr[14], src_addr[15]]));
    println!("    dst: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        u16::from_be_bytes([dst_addr[0], dst_addr[1]]),
        u16::from_be_bytes([dst_addr[2], dst_addr[3]]),
        u16::from_be_bytes([dst_addr[4], dst_addr[5]]),
        u16::from_be_bytes([dst_addr[6], dst_addr[7]]),
        u16::from_be_bytes([dst_addr[8], dst_addr[9]]),
        u16::from_be_bytes([dst_addr[10], dst_addr[11]]),
        u16::from_be_bytes([dst_addr[12], dst_addr[13]]),
        u16::from_be_bytes([dst_addr[14], dst_addr[15]]));

    if next_header == 17 && data.len() >= 48 {
        let udp = &data[40..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]);
        let udp_checksum = u16::from_be_bytes([udp[6], udp[7]]);
        println!("  UDP: {}:{}, len={}, checksum={}", src_port, dst_port, udp_len, udp_checksum);

        let coap = &data[48..];
        println!("  CoAP bytes: {}", coap.len());
        if verbose {
            display_coap_structure(coap);
        }
    }

    if verbose {
        println!("  Full decompressed hex ({} bytes): {}", data.len(), hex::encode(data));
    }
}

fn display_coap_structure(coap: &[u8]) {
    if coap.is_empty() {
        println!("    CoAP: empty payload");
        return;
    }
    if coap.len() < 4 {
        println!("    CoAP: too short ({} bytes): {}", coap.len(), hex::encode(coap));
        return;
    }

    let ver = (coap[0] >> 6) & 0x03;
    let typ = (coap[0] >> 4) & 0x03;
    let tkl = (coap[0] & 0x0F) as usize;
    let code = coap[1];
    let mid = u16::from_be_bytes([coap[2], coap[3]]);

    let type_name = match typ {
        0 => "CON",
        1 => "NON",
        2 => "ACK",
        3 => "RST",
        _ => "UNK",
    };
    println!(
        "    CoAP: ver={} type={}({}) code={}.{} (0x{:02x}) mid={} tkl={}",
        ver,
        typ,
        type_name,
        code >> 5,
        code & 0x1f,
        code,
        mid,
        tkl
    );

    if coap.len() < 4 + tkl {
        println!(
            "    CoAP decode error: token length {} exceeds packet size {}",
            tkl,
            coap.len()
        );
        return;
    }

    let token = &coap[4..4 + tkl];
    println!("    Token: {}", hex::encode(token));

    let mut idx = 4 + tkl;
    let mut option_number: u16 = 0;
    let mut option_count = 0usize;
    let mut payload: &[u8] = &[];
    let mut parse_error: Option<String> = None;
    let mut uri_path_parts: Vec<String> = Vec::new();
    let mut uri_host_parts: Vec<String> = Vec::new();

    while idx < coap.len() {
        if coap[idx] == 0xff {
            idx += 1;
            payload = &coap[idx..];
            break;
        }

        let hdr = coap[idx];
        idx += 1;

        let delta = match parse_coap_nibble((hdr >> 4) & 0x0f, coap, &mut idx) {
            Ok(v) => v,
            Err(e) => {
                parse_error = Some(format!("option delta decode failed: {}", e));
                break;
            }
        };
        let length = match parse_coap_nibble(hdr & 0x0f, coap, &mut idx) {
            Ok(v) => v,
            Err(e) => {
                parse_error = Some(format!("option length decode failed: {}", e));
                break;
            }
        };

        let length = length as usize;
        if idx + length > coap.len() {
            parse_error = Some(format!(
                "option value length {} exceeds remaining bytes {}",
                length,
                coap.len().saturating_sub(idx)
            ));
            break;
        }

        option_number = option_number.saturating_add(delta);
        option_count += 1;
        let value = &coap[idx..idx + length];
        let ascii = ascii_preview(value);
        println!(
            "    Option {}: num={} len={} hex={} ascii=\"{}\"",
            option_count,
            option_number,
            length,
            hex::encode(value),
            ascii
        );
        if option_number == 11 {
            uri_path_parts.push(ascii_preview(value));
        } else if option_number == 3 {
            uri_host_parts.push(ascii_preview(value));
        }
        idx += length;
    }

    if option_count == 0 {
        println!("    Options: none");
    }
    if let Some(err) = parse_error {
        println!("    CoAP option parse error: {}", err);
    }
    if !uri_host_parts.is_empty() {
        println!("    URI-Host: {}", uri_host_parts.join(","));
    }
    if !uri_path_parts.is_empty() {
        let uri_path = format!("/{}", uri_path_parts.join("/"));
        println!("    URI-Path: {}", uri_path);
    } else {
        println!("    URI-Path: <none>");
    }

    println!(
        "    CoAP payload: {} bytes hex={} ascii=\"{}\"",
        payload.len(),
        hex::encode(payload),
        ascii_preview(payload)
    );
}

fn parse_coap_nibble(raw: u8, data: &[u8], idx: &mut usize) -> io::Result<u16> {
    match raw {
        0..=12 => Ok(raw as u16),
        13 => {
            if *idx >= data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing extended nibble byte",
                ));
            }
            let ext = data[*idx] as u16;
            *idx += 1;
            Ok(13 + ext)
        }
        14 => {
            if *idx + 1 >= data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing extended nibble 16-bit value",
                ));
            }
            let ext = u16::from_be_bytes([data[*idx], data[*idx + 1]]);
            *idx += 2;
            Ok(269 + ext)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reserved nibble value 15",
        )),
    }
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect()
}

