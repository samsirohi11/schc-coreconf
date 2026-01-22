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
use schc_coreconf::{load_sor_rules, MRuleSet, SchcCoreconfManager};
use serde_json::json;

const M_RULES_PATH: &str = "samples/m-rules.json";
const BASE_RULES_PATH: &str = "rules/base-ipv6-udp.sor";
const SID_FILE_PATH: &str = "samples/ietf-schc.sid";
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

    // Load M-Rules for CORECONF traffic compression
    println!("Loading M-Rules from: {}", M_RULES_PATH);
    let m_rules = MRuleSet::from_file(M_RULES_PATH).expect("Failed to load M-Rules");
    println!("  Loaded {} M-Rules", m_rules.rules().len());

    // Load SID file for CORECONF parsing
    println!("Loading SID file: {}", SID_FILE_PATH);
    let sid_file = SidFile::from_file(SID_FILE_PATH).expect("Failed to load SID file");

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
                    packet.len(),
                    compressed.data.len(),
                    (1.0 - compressed.data.len() as f64 / packet.len() as f64) * 100.0
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

    // Build modifications to make more fields "not-sent" based on constant values
    // We'll set flow_label and source IID as not-sent since they're constant
    let modifications = json!({
        "entry": [
            {
                "field-id": "fid-ipv6-flowlabel",
                "target-value": [{"index": 0, "value": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &flow_label.to_be_bytes()[1..4])}],
                "matching-operator": "mo-equal",
                "comp-decomp-action": "cda-not-sent"
            },
            {
                "field-id": "fid-ipv6-deviid",
                "target-value": [{"index": 0, "value": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, src_iid)}],
                "matching-operator": "mo-equal",
                "comp-decomp-action": "cda-not-sent"
            },
            {
                "field-id": "fid-ipv6-appiid",
                "target-value": [{"index": 0, "value": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, dst_iid)}],
                "matching-operator": "mo-equal",
                "comp-decomp-action": "cda-not-sent"
            },
            {
                "field-id": "fid-udp-dev-port",
                "target-value": [{"index": 0, "value": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, src_port.to_be_bytes())}],
                "matching-operator": "mo-equal",
                "comp-decomp-action": "cda-not-sent"
            },
            {
                "field-id": "fid-udp-app-port",
                "target-value": [{"index": 0, "value": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, dst_port.to_be_bytes())}],
                "matching-operator": "mo-equal",
                "comp-decomp-action": "cda-not-sent"
            }
        ]
    });

    // Build duplicate-rule RPC request
    let rpc_input = json!({
        "input": {
            "source-rule-id-value": base_rule_id,
            "source-rule-id-length": base_rule_id_length,
            "target-rule-id-value": derived_rule_id,
            "target-rule-id-length": derived_rule_id_length,
            "modifications": modifications
        }
    });

    // Serialize to CBOR
    let mut rpc_cbor = Vec::new();
    ciborium::into_writer(&rpc_input, &mut rpc_cbor).expect("Failed to serialize RPC");

    // Send POST request to Core
    let response = send_coap_post(&mgmt_socket, &mut message_id, &rpc_cbor)?;

    match response.header.code {
        MessageClass::Response(ResponseType::Changed) => {
            println!("duplicate-rule RPC successful!");

            // Apply the same derivation locally
            manager
                .duplicate_rule(
                    (base_rule_id, base_rule_id_length),
                    (derived_rule_id, derived_rule_id_length),
                    Some(&modifications),
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
                    packet.len(),
                    compressed.data.len(),
                    (1.0 - compressed.data.len() as f64 / packet.len() as f64) * 100.0
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
    src_port: u16,
    dst_port: u16,
    flow_label: u32,
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
    // Version (4 bits) = 6, Traffic Class (8 bits) = 0, Flow Label (20 bits)
    let version_tc_fl = (6u32 << 28) | (flow_label & 0xFFFFF);
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
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&payload_length.to_be_bytes());

    // UDP Checksum (0 for now - would need proper calculation)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Payload
    packet.extend_from_slice(payload);

    packet
}

/// Send a CoAP POST request and wait for response
fn send_coap_post(socket: &UdpSocket, message_id: &mut u16, payload: &[u8]) -> std::io::Result<Packet> {
    let mut packet = Packet::new();
    packet.header.message_id = *message_id;
    *message_id = message_id.wrapping_add(1);
    packet.header.code = MessageClass::Request(RequestType::Post);
    packet.header.set_type(MessageType::Confirmable);
    packet.set_token(vec![0x01]);
    packet.add_option(coap_lite::CoapOption::UriPath, b"c".to_vec());
    // Use Content-Format 313 (application/yang-instances+cbor-seq) for CORECONF POST
    // coap_lite's ContentFormat enum doesn't have this, so we set it manually
    packet.add_option(coap_lite::CoapOption::ContentFormat, vec![0x01, 0x39]); // 313 in big-endian
    packet.payload = payload.to_vec();

    let bytes = packet.to_bytes().map_err(|e| {
        std::io::Error::other(e.to_string())
    })?;
    socket.send(&bytes)?;

    // Wait for response
    let mut buf = [0u8; 1500];
    let len = socket.recv(&mut buf)?;

    Packet::from_bytes(&buf[..len]).map_err(|e| {
        std::io::Error::other(e.to_string())
    })
}
