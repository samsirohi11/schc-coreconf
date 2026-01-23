//! SCHC Device (IoT Endpoint) Example
//!
//! This example demonstrates the Device/IoT side of a SCHC-CORECONF deployment:
//! - Loads M-Rules and base application rules from SOR (CORECONF CBOR format)
//! - Generates synthetic IPv6/UDP packets
//! - Compresses packets using SCHC rules and sends them to Core
//! - After N packets, sends a duplicate-rule RPC to derive a more optimized rule
//! - Continues sending with the new derived rule
//!
//! Usage:
//!   cargo run --example schc_device -- [--core-mgmt 127.0.0.1:5683] [--core-data 127.0.0.1:5684]
//!
//! Run schc_core first in another terminal, then run this.

use std::net::UdpSocket;
use std::time::Duration;

use coap_lite::{
    MessageClass, MessageType, Packet, RequestType,
    ResponseType,
};
use rust_coreconf::SidFile;
use schc::{build_tree, compress_packet, Direction, Rule};
use schc_coreconf::{
    load_sor_rules, MRuleSet, SchcCoreconfManager,
    mgmt_compression::MgmtCompressor,
    rpc_builder::{build_duplicate_rule_rpc, EntryModification},
    sor_loader::{mo_to_sid, cda_to_sid},
};
use schc::{MatchingOperator, CompressionAction};

const M_RULES_PATH: &str = "samples/m-rules.sor";
const BASE_RULES_PATH: &str = "rules/base-ipv6-udp.sor";
const SID_FILE_PATH: &str = "samples/ietf-schc@2026-01-12.sid";
const PACKETS_BEFORE_DERIVATION: usize = 5;

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let core_mgmt = args
        .iter()
        .position(|a| a == "--core-mgmt")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1:5683");
    let core_data = args
        .iter()
        .position(|a| a == "--core-data")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1:5684");

    println!("============================================================");
    println!("            SCHC Device (IoT Endpoint)");
    println!("============================================================\n");

    // Load SID file for CORECONF parsing
    println!("Loading SID file: {}", SID_FILE_PATH);
    let sid_file = SidFile::from_file(SID_FILE_PATH).expect("Failed to load SID file");

    // Load M-Rules for CORECONF traffic compression (from SOR format)
    println!("Loading M-Rules from: {}", M_RULES_PATH);
    let m_rules = MRuleSet::from_sor(M_RULES_PATH, &sid_file).expect("Failed to load M-Rules");
    println!("  Loaded {} M-Rules", m_rules.rules().len());
    
    // Create management compressor (must be created before m_rules is moved to manager)
    let mgmt_compressor = MgmtCompressor::new(&m_rules);

    // Load base application rules from SOR (CORECONF CBOR format)
    println!("Loading base rules from: {}", BASE_RULES_PATH);
    let base_rules: Vec<Rule> = load_sor_rules(BASE_RULES_PATH, &sid_file)
        .expect("Failed to load base rules from SOR");
    println!("  Loaded {} application rule(s)", base_rules.len());

    let base_rule_id = base_rules[0].rule_id;
    let base_rule_id_length = base_rules[0].rule_id_length;
    println!(
        "  Base rule: {}/{} ({} fields)",
        base_rule_id,
        base_rule_id_length,
        base_rules[0].compression.len()
    );

    // Create SCHC-CORECONF manager
    let estimated_rtt = Duration::from_millis(100);
    let mut manager = SchcCoreconfManager::new(m_rules, base_rules, estimated_rtt);

    // Create UDP socket for CORECONF management (CoAP)
    let mgmt_socket = UdpSocket::bind("0.0.0.0:0")?;
    mgmt_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    mgmt_socket.connect(core_mgmt)?;

    // Create UDP socket for data channel
    let data_socket = UdpSocket::bind("0.0.0.0:0")?;
    data_socket.connect(core_data)?;

    println!("\n------------------------------------------------------------");
    println!("Core Management: {}", core_mgmt);
    println!("Core Data:       {}", core_data);
    println!("------------------------------------------------------------\n");

    // =========================================================================
    // Phase 1: Send packets with base rule
    // =========================================================================
    println!("=== Phase 1: Sending {} packets with base rule ===\n", PACKETS_BEFORE_DERIVATION);

    let mut packet_count = 0;
    let mut message_id: u16 = 1;

    // Synthetic packet parameters (constant for this demo)
    let src_prefix: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]; // 2001:db8::a0
    let src_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_prefix: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]; // 2001:db8::b0
    let dst_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    let src_port: u16 = 12345;
    let dst_port: u16 = 5683;
    let flow_label: u32 = 0x12345; // Constant flow label for the session

    for i in 0..PACKETS_BEFORE_DERIVATION {
        packet_count += 1;

        // Build synthetic IPv6/UDP packet
        let payload = format!("Hello from device! Packet #{}", packet_count);
        let packet = build_ipv6_udp_packet(
            &src_prefix,
            &src_iid,
            &dst_prefix,
            &dst_iid,
            src_port,
            dst_port,
            flow_label,
            payload.as_bytes(),
        );

        // Get current ruleset and compress
        let ruleset = manager.compression_ruleset().expect("Failed to get ruleset");
        let rules: Vec<Rule> = ruleset.rules.to_vec();
        let tree = build_tree(&rules);

        match compress_packet(&tree, &packet, Direction::Up, &rules, false) {
            Ok(compressed) => {
                println!(
                    "[Packet {}] Rule {}/{}: {} bytes -> {} bytes ({:.1}% compression)",
                    i + 1,
                    compressed.rule_id,
                    compressed.rule_id_length,
                    packet.len() - 14, // Ethernet header
                    compressed.data.len(),
                    (1.0 - compressed.data.len() as f64 / (packet.len() - 14) as f64) * 100.0
                );

                // Send compressed packet to Core
                data_socket.send(&compressed.data)?;
            }
            Err(e) => {
                println!("[Packet {}] Compression error: {:?}", i + 1, e);
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    // =========================================================================
    // Phase 2: Send duplicate-rule RPC to derive optimized rule
    // =========================================================================
    println!("\n=== Phase 2: Sending duplicate-rule RPC to Core ===\n");

    // Calculate derived rule ID using binary tree derivation
    // Rule 8/4 can derive to 8/5 (append 0) or 24/5 (append 1)
    let derivation_options = SchcCoreconfManager::get_derivation_options((base_rule_id, base_rule_id_length));
    let (derived_rule_id, derived_rule_id_length) = derivation_options[0]; // Use first option (append 0)

    println!(
        "Deriving rule {}/{} -> {}/{}",
        base_rule_id, base_rule_id_length, derived_rule_id, derived_rule_id_length
    );

    // Build modifications using entry-index addressing (more efficient)
    // Entry indices from base-ipv6-udp.sor:
    //   2 = IPV6.FL (flow label)
    //   7 = IPV6.DEV_IID
    //   9 = IPV6.APP_IID  
    //   10 = UDP.DEV_PORT
    //   11 = UDP.APP_PORT
    let modifications = vec![
        EntryModification::new(2)  // IPV6.FL
            .with_target_value_bytes(flow_label.to_be_bytes()[1..4].to_vec())
            .with_mo(mo_to_sid(&MatchingOperator::Equal))
            .with_cda(cda_to_sid(&CompressionAction::NotSent)),
        EntryModification::new(7)  // IPV6.DEV_IID
            .with_target_value_bytes(src_iid.to_vec())
            .with_mo(mo_to_sid(&MatchingOperator::Equal))
            .with_cda(cda_to_sid(&CompressionAction::NotSent)),
        EntryModification::new(9)  // IPV6.APP_IID
            .with_target_value_bytes(dst_iid.to_vec())
            .with_mo(mo_to_sid(&MatchingOperator::Equal))
            .with_cda(cda_to_sid(&CompressionAction::NotSent)),
        EntryModification::new(10)  // UDP.DEV_PORT
            .with_target_value_bytes(src_port.to_be_bytes().to_vec())
            .with_mo(mo_to_sid(&MatchingOperator::Equal))
            .with_cda(cda_to_sid(&CompressionAction::NotSent)),
        EntryModification::new(11)  // UDP.APP_PORT
            .with_target_value_bytes(dst_port.to_be_bytes().to_vec())
            .with_mo(mo_to_sid(&MatchingOperator::Equal))
            .with_cda(cda_to_sid(&CompressionAction::NotSent)),
    ];

    // Build SID-encoded duplicate-rule RPC (compact encoding)
    let rpc_cbor = build_duplicate_rule_rpc(
        (base_rule_id, base_rule_id_length),
        (derived_rule_id, derived_rule_id_length),
        Some(&modifications),
    );

    println!("RPC payload size: {} bytes (SID-encoded)", rpc_cbor.len());

    // Send POST request to Core (compressed with M-Rules)
    let response = send_coap_post(&mgmt_socket, &mut message_id, &rpc_cbor, &mgmt_compressor)?;

    match response.header.code {
        MessageClass::Response(ResponseType::Changed) => {
            println!("duplicate-rule RPC successful!");

            // Build JSON modifications for local manager (same format expected by manager)
            let local_mods = serde_json::json!({
                "entry": modifications.iter().map(|m| {
                    let mut entry = serde_json::Map::new();
                    entry.insert("entry-index".to_string(), serde_json::Value::Number(m.entry_index.into()));
                    if let Some(mo) = m.matching_operator {
                        entry.insert("matching-operator-sid".to_string(), serde_json::Value::Number(mo.into()));
                    }
                    if let Some(cda) = m.comp_decomp_action {
                        entry.insert("comp-decomp-action-sid".to_string(), serde_json::Value::Number(cda.into()));
                    }
                    if let Some(ref tv) = m.target_value {
                        entry.insert("target-value-bytes".to_string(), 
                            serde_json::Value::String(base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD, tv)));
                    }
                    serde_json::Value::Object(entry)
                }).collect::<Vec<_>>()
            });

            // Apply the same derivation with modifications locally
            manager
                .duplicate_rule(
                    (base_rule_id, base_rule_id_length),
                    (derived_rule_id, derived_rule_id_length),
                    Some(&local_mods),
                )
                .expect("Failed to duplicate rule locally");

            println!(
                "Derived rule {}/{} provisioned locally",
                derived_rule_id, derived_rule_id_length
            );
        }
        code => {
            println!("duplicate-rule RPC failed: {:?}", code);
            println!("Payload: {:02x?}", response.payload);
            return Ok(());
        }
    }

    // Wait for guard period
    let guard_period = manager.guard_period();
    println!("\nWaiting for guard period ({:?})...", guard_period);
    std::thread::sleep(guard_period);
    manager.tick();

    // =========================================================================
    // Phase 3: Send packets with derived rule
    // =========================================================================
    println!("\n=== Phase 3: Sending packets with derived rule ===\n");

    for _ in 0..PACKETS_BEFORE_DERIVATION {
        packet_count += 1;

        // Build synthetic IPv6/UDP packet (same parameters)
        let payload = format!("Hello from device! Packet #{}", packet_count);
        let packet = build_ipv6_udp_packet(
            &src_prefix,
            &src_iid,
            &dst_prefix,
            &dst_iid,
            src_port,
            dst_port,
            flow_label,
            payload.as_bytes(),
        );

        // Get current ruleset and compress
        let ruleset = manager.compression_ruleset().expect("Failed to get ruleset");
        let rules: Vec<Rule> = ruleset.rules.to_vec();
        let tree = build_tree(&rules);

        match compress_packet(&tree, &packet, Direction::Up, &rules, false) {
            Ok(compressed) => {
                let improvement = if compressed.rule_id == derived_rule_id {
                    " (DERIVED RULE)"
                } else {
                    ""
                };

                println!(
                    "[Packet {}] Rule {}/{}{}: {} bytes -> {} bytes ({:.1}% compression)",
                    packet_count,
                    compressed.rule_id,
                    compressed.rule_id_length,
                    improvement,
                    packet.len() - 14, // Ethernet header
                    compressed.data.len(),
                    (1.0 - compressed.data.len() as f64 / (packet.len() - 14) as f64) * 100.0
                );

                // Send compressed packet to Core
                data_socket.send(&compressed.data)?;
            }
            Err(e) => {
                println!("[Packet {}] Compression error: {:?}", packet_count, e);
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    println!("\n------------------------------------------------------------");
    println!("Device finished. Total packets sent: {}", packet_count);
    println!("------------------------------------------------------------");

    Ok(())
}

/// Build an IPv6/UDP packet with the given parameters
#[allow(clippy::too_many_arguments)]
fn build_ipv6_udp_packet(
    src_prefix: &[u8; 8],
    src_iid: &[u8; 8],
    dst_prefix: &[u8; 8],
    dst_iid: &[u8; 8],
    _src_port: u16,
    dst_port: u16,
    _flow_label: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + 40 + 8 + payload.len());

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Source MAC
        0x86, 0xDD,                          // EtherType: IPv6
    ]);

    // IPv6 Header (40 bytes)
    // Version 6, TC 1 (as per M-Rules), FL 0x23456 (144470)
    let version_tc_fl = (6u32 << 28) | (1u32 << 20) | 0x23456;
    packet.extend_from_slice(&version_tc_fl.to_be_bytes());

    // Payload Length (UDP header + payload)
    let payload_length = (8 + payload.len()) as u16;
    packet.extend_from_slice(&payload_length.to_be_bytes());

    // Next Header (17 = UDP)
    packet.push(17);

    // Hop Limit
    packet.push(64);

    // Source Address (prefix + IID)
    packet.extend_from_slice(src_prefix);
    packet.extend_from_slice(src_iid);

    // Destination Address (prefix + IID)
    packet.extend_from_slice(dst_prefix);
    packet.extend_from_slice(dst_iid);

    // UDP Header (8 bytes)
    // Use fixed source port 3865 as per M-Rules
    packet.extend_from_slice(&3865u16.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&payload_length.to_be_bytes());

    // UDP Checksum (0 for now - would need proper calculation)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Payload
    packet.extend_from_slice(payload);

    packet
}

/// Build an IPv6/UDP/CoAP packet for management traffic
fn build_mgmt_packet(coap_payload: &[u8]) -> Vec<u8> {
    // Fixed M-Rule addressing per draft:
    // - Device: fe80::1
    // - Core: fe80::2
    // - Port: 5683 (CoAP default)
    let src_prefix: [u8; 8] = [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let src_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]; // ::1
    let dst_prefix: [u8; 8] = [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let dst_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]; // ::2
    
    let mut packet = Vec::with_capacity(14 + 40 + 8 + coap_payload.len());

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Source MAC
        0x86, 0xDD,                          // EtherType: IPv6
    ]);

    // IPv6 Header (40 bytes)
    let version_tc_fl = (6u32 << 28) | 0; // Version 6, TC 0, FL 0
    packet.extend_from_slice(&version_tc_fl.to_be_bytes());

    // Payload Length (UDP header + CoAP)
    let payload_length = (8 + coap_payload.len()) as u16;
    packet.extend_from_slice(&payload_length.to_be_bytes());

    // Next Header (17 = UDP), Hop Limit (64)
    packet.push(17);
    packet.push(64);

    // Source Address (prefix + IID)
    packet.extend_from_slice(&src_prefix);
    packet.extend_from_slice(&src_iid);

    // Destination Address (prefix + IID)
    packet.extend_from_slice(&dst_prefix);
    packet.extend_from_slice(&dst_iid);

    // UDP Header (8 bytes)
    packet.extend_from_slice(&3865u16.to_be_bytes()); // src port (per M-Rule)
    packet.extend_from_slice(&5683u16.to_be_bytes()); // dst port
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // checksum (0 for now)

    // CoAP payload
    packet.extend_from_slice(coap_payload);

    packet
}

/// Send a CoAP POST request compressed with M-Rules and wait for response
fn send_coap_post(
    socket: &UdpSocket,
    message_id: &mut u16,
    payload: &[u8],
    mgmt_compressor: &MgmtCompressor,
) -> std::io::Result<Packet> {
    let mut coap_packet = Packet::new();
    coap_packet.header.message_id = *message_id;
    *message_id = message_id.wrapping_add(1);
    coap_packet.header.code = MessageClass::Request(RequestType::Post);
    coap_packet.header.set_type(MessageType::Confirmable);
    coap_packet.set_token(vec![]); // Empty token per M-Rule
    coap_packet.add_option(coap_lite::CoapOption::UriPath, b"c".to_vec());
    // Use Content-Format 313 (application/yang-instances+cbor-seq) for CORECONF POST
    coap_packet.add_option(coap_lite::CoapOption::ContentFormat, vec![0x01, 0x39]);
    coap_packet.payload = payload.to_vec();

    let coap_bytes = coap_packet.to_bytes().map_err(|e| {
        std::io::Error::other(e.to_string())
    })?;

    // Build full IPv6/UDP/CoAP packet
    let full_packet = build_mgmt_packet(&coap_bytes);
    
    // Compress with M-Rules
    let compressed = mgmt_compressor.compress(&full_packet, Direction::Up)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    
    println!("  MGMT compressed: {} bytes -> {} bytes ({:.1}% compression)",
        full_packet.len() - 14, // exclude Ethernet header
        compressed.len(),
        (1.0 - compressed.len() as f64 / (full_packet.len() - 14) as f64) * 100.0
    );

    socket.send(&compressed)?;

    // Wait for response (also compressed)
    let mut buf = [0u8; 1500];
    let len = socket.recv(&mut buf)?;

    // Decompress response with M-Rules
    let decompressed = mgmt_compressor.decompress(&buf[..len], Direction::Down)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    
    // Extract CoAP packet from decompressed IPv6/UDP packet
    // Skip: Ethernet (14) + IPv6 (40) + UDP (8) = 62 bytes
    if decompressed.len() < 62 {
        return Err(std::io::Error::other("Decompressed packet too small"));
    }
    let coap_response_bytes = &decompressed[62..];

    Packet::from_bytes(coap_response_bytes).map_err(|e| {
        std::io::Error::other(e.to_string())
    })
}
