//! SCHC Endpoint Bridge Example
//!
//! General endpoint-style SCHC runtime similar to H-SCHC position model.
//! It bridges between:
//! - SCHC endpoint (compressed datagrams)
//! - Plain endpoint (uncompressed IPv6/UDP(/CoAP) datagrams)
//!
//! New flow only (legacy flags removed).
//! Usage:
//!   cargo run --example udp_tunnel_interop -- --position core --schc-listen 0.0.0.0:23628 --plain-listen 0.0.0.0:23629 --plain-peer 127.0.0.1:5683 --plain-mode coap --coap-target packet --rules rules/docker1.sor -v

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use rust_coreconf::SidFile;
use schc::{Direction, LinkLayer, Rule, RuleSet, TreeNode, build_tree, compress_packet_with_link_layer, decompress_packet};
use schc_coreconf::load_sor_rules;

const SID_FILE_PATH: &str = "samples/ietf-schc@2026-01-12.sid";

#[derive(Debug, Clone, Copy)]
enum Position {
    Device,
    Core,
}

#[derive(Debug, Clone, Copy)]
enum DirectionMode {
    Up,
    Down,
    Auto,
}

#[derive(Debug, Clone, Copy)]
enum PlainMode {
    Coap,
    Ipv6,
}

#[derive(Debug, Clone, Copy)]
enum CoapTargetMode {
    Packet,
    PlainPeer,
}

#[derive(Default)]
struct Stats {
    schc_rx_packets: AtomicU64,
    schc_decompress_ok: AtomicU64,
    schc_decompress_fail: AtomicU64,
    plain_rx_packets: AtomicU64,
    schc_tx_packets: AtomicU64,
    schc_compress_ok: AtomicU64,
    schc_compress_fail: AtomicU64,
    plain_tx_packets: AtomicU64,
}

impl Stats {
    fn print(&self) {
        println!("\n=== Bridge Statistics ===");
        println!(
            "SCHC RX: {} packets, {} decompressed, {} failed",
            self.schc_rx_packets.load(Ordering::Relaxed),
            self.schc_decompress_ok.load(Ordering::Relaxed),
            self.schc_decompress_fail.load(Ordering::Relaxed),
        );
        println!(
            "Plain TX: {} packets",
            self.plain_tx_packets.load(Ordering::Relaxed)
        );
        println!(
            "Plain RX: {} packets",
            self.plain_rx_packets.load(Ordering::Relaxed)
        );
        println!(
            "SCHC TX: {} packets, {} compressed, {} failed",
            self.schc_tx_packets.load(Ordering::Relaxed),
            self.schc_compress_ok.load(Ordering::Relaxed),
            self.schc_compress_fail.load(Ordering::Relaxed),
        );
    }
}

fn main() -> io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }

    let position = parse_position(
        &arg_value(&args, "--position")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing --position <device|core>"))?,
    )?;

    let schc_listen = arg_value(&args, "--schc-listen")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing --schc-listen <ip:port>"))?;
    let plain_listen = arg_value(&args, "--plain-listen")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing --plain-listen <ip:port>"))?;
    let plain_peer = arg_value(&args, "--plain-peer")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing --plain-peer <ip:port>"))?;

    let schc_peer = arg_value(&args, "--schc-peer");
    let rules_path = arg_value(&args, "--rules").unwrap_or_else(|| "rules/base-ipv6-udp.sor".to_string());
    let plain_mode = arg_value(&args, "--plain-mode")
        .map(|s| parse_plain_mode(&s))
        .transpose()?
        .unwrap_or(PlainMode::Coap);
    let coap_target_mode = arg_value(&args, "--coap-target")
        .map(|s| parse_coap_target_mode(&s))
        .transpose()?
        .unwrap_or_else(|| {
            if matches!(position, Position::Core) && matches!(plain_mode, PlainMode::Coap) {
                CoapTargetMode::Packet
            } else {
                CoapTargetMode::PlainPeer
            }
        });
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");

    let rx_default = match position {
        Position::Core => DirectionMode::Up,
        Position::Device => DirectionMode::Down,
    };
    let tx_default = match position {
        Position::Core => Direction::Down,
        Position::Device => Direction::Up,
    };

    let rx_mode = arg_value(&args, "--rx-direction")
        .map(|s| parse_direction_mode(&s))
        .transpose()?
        .unwrap_or(rx_default);
    let tx_direction = arg_value(&args, "--tx-direction")
        .map(|s| parse_direction(&s))
        .transpose()?
        .unwrap_or(tx_default);

    println!("============================================================");
    println!("                SCHC Endpoint Bridge");
    println!("============================================================");
    println!("Position: {:?}", position);
    println!("SCHC listen: {}", schc_listen);
    if let Some(peer) = &schc_peer {
        println!("SCHC peer: {}", peer);
    } else {
        println!("SCHC peer: <auto reply to last SCHC sender>");
    }
    println!("Plain listen: {}", plain_listen);
    println!("Plain peer: {}", plain_peer);
    println!("Plain mode: {:?}", plain_mode);
    println!("CoAP target mode: {:?}", coap_target_mode);
    println!("RX direction mode: {:?}", rx_mode);
    println!("TX direction: {:?}", tx_direction);
    println!("Rules: {}", rules_path);
    println!("Verbose: {}", verbose);
    println!();

    let rules = load_rules(&rules_path)?;
    println!("Loaded {} rule(s)", rules.len());
    for rule in &rules {
        println!("  Rule {}/{}: {} fields", rule.rule_id, rule.rule_id_length, rule.compression.len());
    }
    println!();

    let ruleset = Arc::new(RuleSet { rules: rules.clone() });
    let tree = Arc::new(build_tree(&ruleset.rules));
    let stats = Arc::new(Stats::default());
    let running = Arc::new(AtomicBool::new(true));

    {
        let running = running.clone();
        let stats = stats.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
            stats.print();
            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler");
    }

    let schc_listen_addr = resolve_socket_addr(&schc_listen, "--schc-listen")?;
    let schc_peer_addr = match schc_peer {
        Some(s) => Some(resolve_socket_addr(&s, "--schc-peer")?),
        None => None,
    };
    let plain_listen_addr = resolve_socket_addr(&plain_listen, "--plain-listen")?;
    let plain_peer_addr = resolve_socket_addr(&plain_peer, "--plain-peer")?;

    run_bridge(
        schc_listen_addr,
        schc_peer_addr,
        plain_listen_addr,
        plain_peer_addr,
        &ruleset,
        &tree,
        &stats,
        &running,
        rx_mode,
        tx_direction,
        plain_mode,
        coap_target_mode,
        verbose,
    )?;

    stats.print();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_bridge(
    schc_listen_addr: SocketAddr,
    fixed_schc_peer: Option<SocketAddr>,
    plain_listen_addr: SocketAddr,
    plain_peer_addr: SocketAddr,
    ruleset: &Arc<RuleSet>,
    tree: &Arc<TreeNode>,
    stats: &Arc<Stats>,
    running: &Arc<AtomicBool>,
    rx_mode: DirectionMode,
    tx_direction: Direction,
    plain_mode: PlainMode,
    coap_target_mode: CoapTargetMode,
    verbose: bool,
) -> io::Result<()> {
    let schc_socket = UdpSocket::bind(schc_listen_addr)?;
    let plain_socket = UdpSocket::bind(plain_listen_addr)?;
    schc_socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    plain_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    println!("Bridge running (Ctrl+C to stop)");
    println!("  SCHC RX/TX socket: {}", schc_listen_addr);
    println!("  Plain RX/TX socket: {}", plain_listen_addr);
    println!("  Plain peer target: {}", plain_peer_addr);
    println!("  Plain mode: {:?}", plain_mode);
    println!("  CoAP target mode: {:?}", coap_target_mode);
    if matches!(plain_mode, PlainMode::Coap)
        && matches!(coap_target_mode, CoapTargetMode::PlainPeer)
        && plain_peer_addr.ip().is_loopback()
    {
        println!("  Note: loopback plain-peer requires a local CoAP service on {}", plain_peer_addr);
    }
    println!();

    let mut last_schc_sender: Option<SocketAddr> = None;
    let mut last_plain_request_packet: Option<Vec<u8>> = None;
    let mut schc_buf = [0u8; 2048];
    let mut plain_buf = [0u8; 4096];

    while running.load(Ordering::Relaxed) {
        match schc_socket.recv_from(&mut schc_buf) {
            Ok((len, src)) => {
                last_schc_sender = Some(src);
                stats.schc_rx_packets.fetch_add(1, Ordering::Relaxed);
                let schc_data = &schc_buf[..len];
                println!("[SCHC RX] {} bytes from {}", len, src);

                match decompress_with_mode(schc_data, &ruleset.rules, rx_mode) {
                    Ok((used_direction, rule_id, rule_id_length, full_data)) => {
                        stats.schc_decompress_ok.fetch_add(1, Ordering::Relaxed);
                        println!(
                            "  Decompressed {} bytes (rule {}/{}, direction={:?})",
                            full_data.len(),
                            rule_id,
                            rule_id_length,
                            used_direction
                        );
                        display_packet_structure(&full_data, verbose);
                        match plain_mode {
                            PlainMode::Ipv6 => {
                                plain_socket.send_to(&full_data, plain_peer_addr)?;
                                stats.plain_tx_packets.fetch_add(1, Ordering::Relaxed);
                                println!(
                                    "  Forwarded plain IPv6 packet: {} bytes to {}",
                                    full_data.len(),
                                    plain_peer_addr
                                );
                            }
                            PlainMode::Coap => {
                                if full_data.len() < 48 {
                                    stats.schc_decompress_fail.fetch_add(1, Ordering::Relaxed);
                                    println!("  Packet too short for IPv6/UDP->CoAP extraction");
                                    println!();
                                    continue;
                                }
                                let coap = &full_data[48..];
                                last_plain_request_packet = Some(full_data.clone());
                                let coap_target = match coap_target_mode {
                                    CoapTargetMode::Packet => match extract_udp_destination_from_packet(&full_data) {
                                        Ok(target) => target,
                                        Err(e) => {
                                            stats.schc_decompress_fail.fetch_add(1, Ordering::Relaxed);
                                            println!("  Failed to determine CoAP target from packet: {}", e);
                                            println!();
                                            continue;
                                        }
                                    },
                                    CoapTargetMode::PlainPeer => plain_peer_addr,
                                };

                                println!(
                                    "  Forwarded CoAP payload: {} bytes to {} ({:?})",
                                    coap.len(),
                                    coap_target,
                                    coap_target_mode
                                );
                                if verbose {
                                    println!("  CoAP request hex: {}", hex::encode(coap));
                                }

                                match coap_target_mode {
                                    CoapTargetMode::PlainPeer => {
                                        plain_socket.send_to(coap, coap_target)?;
                                        stats.plain_tx_packets.fetch_add(1, Ordering::Relaxed);
                                    }
                                    CoapTargetMode::Packet => {
                                        stats.plain_tx_packets.fetch_add(1, Ordering::Relaxed);
                                        match send_coap_and_receive_response(coap, coap_target, Duration::from_secs(5)) {
                                            Ok(response_coap) => {
                                                stats.plain_rx_packets.fetch_add(1, Ordering::Relaxed);
                                                if verbose {
                                                    println!(
                                                        "  CoAP response hex: {}",
                                                        hex::encode(&response_coap)
                                                    );
                                                }
                                                let tx_packet = match build_ipv6_udp_response(&full_data, &response_coap) {
                                                    Ok(pkt) => pkt,
                                                    Err(e) => {
                                                        stats.schc_compress_fail.fetch_add(1, Ordering::Relaxed);
                                                        println!("  Failed to build IPv6/UDP response: {}", e);
                                                        println!();
                                                        continue;
                                                    }
                                                };

                                                match compress_packet_with_link_layer(
                                                    tree,
                                                    &tx_packet,
                                                    tx_direction,
                                                    &ruleset.rules,
                                                    verbose,
                                                    LinkLayer::None,
                                                ) {
                                                    Ok(compressed) => {
                                                        let schc_target = fixed_schc_peer.or(last_schc_sender);
                                                        let Some(target) = schc_target else {
                                                            stats.schc_compress_fail.fetch_add(1, Ordering::Relaxed);
                                                            println!("  No SCHC target available yet (set --schc-peer or wait for first SCHC RX)");
                                                            println!();
                                                            continue;
                                                        };

                                                        schc_socket.send_to(&compressed.data, target)?;
                                                        stats.schc_compress_ok.fetch_add(1, Ordering::Relaxed);
                                                        stats.schc_tx_packets.fetch_add(1, Ordering::Relaxed);
                                                        println!(
                                                            "  Sent SCHC: {} bytes to {} (rule {}/{}, tx-dir={:?})",
                                                            compressed.data.len(),
                                                            target,
                                                            compressed.rule_id,
                                                            compressed.rule_id_length,
                                                            tx_direction
                                                        );
                                                        if verbose {
                                                            println!("  SCHC bits: {}", compressed.bit_length);
                                                            println!("  SCHC hex: {}", hex::encode(&compressed.data));
                                                        }
                                                    }
                                                    Err(e) => {
                                                        stats.schc_compress_fail.fetch_add(1, Ordering::Relaxed);
                                                        println!("  Compress error: {:?}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("  CoAP target {} failed: {}", coap_target, e);
                                                if coap_target.ip().is_loopback() {
                                                    println!("  Hint: loopback target requires a local CoAP service listening on that host/port");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        stats.schc_decompress_fail.fetch_add(1, Ordering::Relaxed);
                        println!("  Decompress error: {}", e);
                    }
                }
                println!();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => eprintln!("SCHC receive error: {}", e),
        }

        if matches!(plain_mode, PlainMode::Coap) && matches!(coap_target_mode, CoapTargetMode::Packet) {
            continue;
        }

        match plain_socket.recv_from(&mut plain_buf) {
            Ok((len, src)) => {
                stats.plain_rx_packets.fetch_add(1, Ordering::Relaxed);
                let plain_data = &plain_buf[..len];
                println!("[PLAIN RX] {} bytes from {}", len, src);

                let tx_packet = match plain_mode {
                    PlainMode::Ipv6 => plain_data.to_vec(),
                    PlainMode::Coap => {
                        let Some(request_packet) = last_plain_request_packet.as_ref() else {
                            stats.schc_compress_fail.fetch_add(1, Ordering::Relaxed);
                            println!("  No request context available to wrap CoAP response");
                            println!();
                            continue;
                        };
                        if verbose {
                            println!("  CoAP response hex: {}", hex::encode(plain_data));
                        }
                        match build_ipv6_udp_response(request_packet, plain_data) {
                            Ok(pkt) => pkt,
                            Err(e) => {
                                stats.schc_compress_fail.fetch_add(1, Ordering::Relaxed);
                                println!("  Failed to build IPv6/UDP response: {}", e);
                                println!();
                                continue;
                            }
                        }
                    }
                };

                match compress_packet_with_link_layer(
                    tree,
                    &tx_packet,
                    tx_direction,
                    &ruleset.rules,
                    verbose,
                    LinkLayer::None,
                ) {
                    Ok(compressed) => {
                        let schc_target = fixed_schc_peer.or(last_schc_sender);
                        let Some(target) = schc_target else {
                            stats.schc_compress_fail.fetch_add(1, Ordering::Relaxed);
                            println!("  No SCHC target available yet (set --schc-peer or wait for first SCHC RX)");
                            println!();
                            continue;
                        };

                        schc_socket.send_to(&compressed.data, target)?;
                        stats.schc_compress_ok.fetch_add(1, Ordering::Relaxed);
                        stats.schc_tx_packets.fetch_add(1, Ordering::Relaxed);
                        println!(
                            "  Sent SCHC: {} bytes to {} (rule {}/{}, tx-dir={:?})",
                            compressed.data.len(),
                            target,
                            compressed.rule_id,
                            compressed.rule_id_length,
                            tx_direction
                        );
                        if verbose {
                            println!("  SCHC bits: {}", compressed.bit_length);
                            println!("  SCHC hex: {}", hex::encode(&compressed.data));
                        }
                    }
                    Err(e) => {
                        stats.schc_compress_fail.fetch_add(1, Ordering::Relaxed);
                        println!("  Compress error: {:?}", e);
                    }
                }
                println!();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => eprintln!("Plain receive error: {}", e),
        }
    }
    Ok(())
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn parse_position(value: &str) -> io::Result<Position> {
    match value.to_ascii_lowercase().as_str() {
        "device" => Ok(Position::Device),
        "core" => Ok(Position::Core),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid --position '{}'. Use device|core", value),
        )),
    }
}

fn parse_direction_mode(value: &str) -> io::Result<DirectionMode> {
    match value.to_ascii_lowercase().as_str() {
        "up" => Ok(DirectionMode::Up),
        "down" | "dw" => Ok(DirectionMode::Down),
        "auto" => Ok(DirectionMode::Auto),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid direction mode '{}'. Use up|down|auto", value),
        )),
    }
}

fn parse_direction(value: &str) -> io::Result<Direction> {
    match value.to_ascii_lowercase().as_str() {
        "up" => Ok(Direction::Up),
        "down" | "dw" => Ok(Direction::Down),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid direction '{}'. Use up|down", value),
        )),
    }
}

fn parse_plain_mode(value: &str) -> io::Result<PlainMode> {
    match value.to_ascii_lowercase().as_str() {
        "coap" => Ok(PlainMode::Coap),
        "ipv6" | "raw" => Ok(PlainMode::Ipv6),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid --plain-mode '{}'. Use coap|ipv6", value),
        )),
    }
}

fn parse_coap_target_mode(value: &str) -> io::Result<CoapTargetMode> {
    match value.to_ascii_lowercase().as_str() {
        "packet" => Ok(CoapTargetMode::Packet),
        "plain-peer" | "peer" => Ok(CoapTargetMode::PlainPeer),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid --coap-target '{}'. Use packet|plain-peer", value),
        )),
    }
}

fn resolve_socket_addr(addr: &str, arg_name: &str) -> io::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid {} '{}': {}", arg_name, addr, e)))?
        .collect();
    addrs.into_iter().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} '{}' resolved to no address", arg_name, addr),
        )
    })
}

fn load_rules(path: &str) -> io::Result<Vec<Rule>> {
    if path.ends_with(".sor") || path.ends_with(".cbor") {
        println!("Loading SOR rules with SID file: {}", SID_FILE_PATH);
        let sid_file = SidFile::from_file(SID_FILE_PATH)
            .map_err(|e| io::Error::other(format!("SID file error: {}", e)))?;
        load_sor_rules(path, &sid_file)
            .map_err(|e| io::Error::other(format!("SOR parse error: {}", e)))
    } else {
        println!("Loading JSON rules");
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("JSON parse error: {}", e)))
    }
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
    response.extend_from_slice(&request_packet[24..40]);
    response.extend_from_slice(&request_packet[8..24]);

    // Swap UDP ports.
    response.extend_from_slice(&request_packet[42..44]);
    response.extend_from_slice(&request_packet[40..42]);
    response.extend_from_slice(&payload_length.to_be_bytes());
    response.extend_from_slice(&[0x00, 0x00]); // checksum compute by rule behavior

    response.extend_from_slice(coap_response);
    Ok(response)
}

fn extract_udp_destination_from_packet(packet: &[u8]) -> io::Result<SocketAddr> {
    if packet.len() < 48 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Packet too short for IPv6/UDP: {} bytes", packet.len()),
        ));
    }
    if packet[6] != 17 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IPv6 next-header {} is not UDP", packet[6]),
        ));
    }
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "Invalid IPv6 destination slice")
    })?);
    let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
    Ok(SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0)))
}

fn send_coap_and_receive_response(
    coap_request: &[u8],
    target: SocketAddr,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let bind_addr = match target {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.send_to(coap_request, target)?;

    let mut buf = [0u8; 4096];
    let (len, src) = socket.recv_from(&mut buf)?;
    println!("  CoAP response: {} bytes from {}", len, src);
    Ok(buf[..len].to_vec())
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
                "AUTO failed: up_err={}, down_err={}",
                up.err().unwrap_or_else(|| "unknown".to_string()),
                down.err().unwrap_or_else(|| "unknown".to_string())
            ))
        }
    }
}

fn print_usage() {
    println!("SCHC Endpoint Bridge Example\n");
    println!("Required:");
    println!("  --position <device|core>");
    println!("  --schc-listen <ip:port>");
    println!("  --plain-listen <ip:port>");
    println!("  --plain-peer <ip:port>");
    println!();
    println!("Optional:");
    println!("  --schc-peer <ip:port>      Fixed SCHC target (otherwise auto-reply to last SCHC sender)");
    println!("  --plain-mode <coap|ipv6>   coap: plain side carries CoAP bytes; ipv6: carries full IPv6 packet");
    println!("  --coap-target <packet|plain-peer>  for plain-mode=coap: packet=decompressed IPv6 dst/UDP port, plain-peer=configured --plain-peer");
    println!("  --rules <path>             Rules file (.sor/.cbor/.json), default rules/base-ipv6-udp.sor");
    println!("  --rx-direction <up|down|auto>");
    println!("  --tx-direction <up|down>");
    println!("  -v, --verbose");
    println!();
    println!("Examples:");
    println!("  # Core role:");
    println!("  cargo run --example udp_tunnel_interop -- --position core --plain-mode coap --coap-target packet --schc-listen 0.0.0.0:23628 --plain-listen 0.0.0.0:23629 --plain-peer 127.0.0.1:5683 --rules rules/docker1.sor -v");
    println!();
    println!("  # Device role:");
    println!("  cargo run --example udp_tunnel_interop -- --position device --plain-mode coap --schc-listen 0.0.0.0:23628 --schc-peer 192.0.2.10:23628 --plain-listen 0.0.0.0:23629 --plain-peer 127.0.0.1:5683 --rules rules/docker1.sor -v");
}

fn display_packet_structure(data: &[u8], verbose: bool) {
    if data.len() < 40 {
        println!("  [Not IPv6 packet, {} bytes]", data.len());
        if verbose {
            println!("  Raw bytes: {}", hex::encode(data));
        }
        return;
    }

    let version = (data[0] >> 4) & 0x0F;
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let src_addr: [u8; 16] = data[8..24].try_into().unwrap_or([0; 16]);
    let dst_addr: [u8; 16] = data[24..40].try_into().unwrap_or([0; 16]);

    println!(
        "  IPv6: ver={} len={} nxt={} hop={}",
        version, payload_len, next_header, hop_limit
    );
    println!(
        "    src: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        u16::from_be_bytes([src_addr[0], src_addr[1]]),
        u16::from_be_bytes([src_addr[2], src_addr[3]]),
        u16::from_be_bytes([src_addr[4], src_addr[5]]),
        u16::from_be_bytes([src_addr[6], src_addr[7]]),
        u16::from_be_bytes([src_addr[8], src_addr[9]]),
        u16::from_be_bytes([src_addr[10], src_addr[11]]),
        u16::from_be_bytes([src_addr[12], src_addr[13]]),
        u16::from_be_bytes([src_addr[14], src_addr[15]])
    );
    println!(
        "    dst: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        u16::from_be_bytes([dst_addr[0], dst_addr[1]]),
        u16::from_be_bytes([dst_addr[2], dst_addr[3]]),
        u16::from_be_bytes([dst_addr[4], dst_addr[5]]),
        u16::from_be_bytes([dst_addr[6], dst_addr[7]]),
        u16::from_be_bytes([dst_addr[8], dst_addr[9]]),
        u16::from_be_bytes([dst_addr[10], dst_addr[11]]),
        u16::from_be_bytes([dst_addr[12], dst_addr[13]]),
        u16::from_be_bytes([dst_addr[14], dst_addr[15]])
    );

    if next_header == 17 && data.len() >= 48 {
        let udp = &data[40..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]);
        println!("  UDP: {}:{}, len={}", src_port, dst_port, udp_len);
        if verbose {
            display_coap_structure(&data[48..]);
        }
    }

    if verbose {
        println!("  Full packet hex ({} bytes): {}", data.len(), hex::encode(data));
    }
}

fn display_coap_structure(coap: &[u8]) {
    if coap.len() < 4 {
        println!("  CoAP: short/none ({} bytes)", coap.len());
        return;
    }
    let ver = (coap[0] >> 6) & 0x03;
    let typ = (coap[0] >> 4) & 0x03;
    let tkl = (coap[0] & 0x0F) as usize;
    let code = coap[1];
    let mid = u16::from_be_bytes([coap[2], coap[3]]);
    println!(
        "  CoAP: ver={} type={} code={}.{} mid={} tkl={}",
        ver,
        typ,
        code >> 5,
        code & 0x1f,
        mid,
        tkl
    );
    if coap.len() >= 4 + tkl {
        println!("    token={}", hex::encode(&coap[4..4 + tkl]));
    }
}

#[cfg(test)]
mod tests {
    use super::{build_ipv6_udp_response, extract_udp_destination_from_packet};
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

    fn sample_request_packet() -> Vec<u8> {
        // IPv6(40) + UDP(8) + CoAP(41)
        let mut pkt = vec![
            0x60, 0x00, 0x00, 0x00, // ver/tc/fl
            0x00, 0x31, // payload len = 49
            0x11, // UDP
            0xff, // hop limit
        ];
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x06, 0x60, 0x73, 0x01, 0x5c, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0b,
        ]);
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x41, 0xd0, 0x03, 0x02, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x13, 0xb3,
        ]);
        pkt.extend_from_slice(&[
            0xdb, 0xec, // src port
            0x16, 0x33, // dst port 5683
            0x00, 0x31, // udp len
            0xc7, 0x27, // checksum
        ]);
        pkt.extend_from_slice(&[
            0x42, 0x01, 0x6f, 0x71, 0xa5, 0x1f, 0x3d, 0x0f, 0x37, 0x35, 0x37, 0x33, 0x36, 0x35,
            0x37, 0x32, 0x32, 0x65, 0x37, 0x30, 0x36, 0x63, 0x36, 0x39, 0x36, 0x34, 0x36, 0x66,
            0x32, 0x65, 0x36, 0x65, 0x36, 0x35, 0x37, 0x34, 0x84, 0x74, 0x69, 0x6d, 0x65,
        ]);
        pkt
    }

    #[test]
    fn extract_udp_destination_ipv6_works() {
        let pkt = sample_request_packet();
        let dst = extract_udp_destination_from_packet(&pkt).expect("destination should parse");
        let expected_ip = Ipv6Addr::new(0x2001, 0x41d0, 0x0302, 0x2200, 0, 0, 0, 0x13b3);
        assert_eq!(dst, SocketAddr::V6(SocketAddrV6::new(expected_ip, 5683, 0, 0)));
    }

    #[test]
    fn build_ipv6_udp_response_swaps_addrs_and_ports() {
        let req = sample_request_packet();
        let coap_response = [0x62, 0x45, 0x6f, 0x71, 0xa5, 0x1f, 0xff, 0x32, 0x30];
        let rsp = build_ipv6_udp_response(&req, &coap_response).expect("response packet build should work");

        assert_eq!(&rsp[0..4], &req[0..4]);
        assert_eq!(u16::from_be_bytes([rsp[4], rsp[5]]), (8 + coap_response.len()) as u16);
        assert_eq!(rsp[6], req[6]);
        assert_eq!(rsp[7], req[7]);
        assert_eq!(&rsp[8..24], &req[24..40]);
        assert_eq!(&rsp[24..40], &req[8..24]);
        assert_eq!(&rsp[40..42], &req[42..44]);
        assert_eq!(&rsp[42..44], &req[40..42]);
        assert_eq!(u16::from_be_bytes([rsp[44], rsp[45]]), (8 + coap_response.len()) as u16);
        assert_eq!(&rsp[48..], &coap_response);
    }
}
