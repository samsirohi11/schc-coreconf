//! SCHC Device (IoT Endpoint) Example - Interactive Mode
//!
//! This example demonstrates the Device/IoT side of a SCHC-CORECONF deployment:
//! - Loads M-Rules and base application rules from SOR (CORECONF CBOR format)
//! - Runs interactively, maintaining state across operations
//! - Derives optimized rules on demand with smart rule ID allocation
//! - Compresses packets using the best available rule
//!
//! Commands:
//!   send [N]     - Send N packets (default 5)
//!   derive       - Derive a new optimized rule for current flow
//!   rules        - Show current rules
//!   help         - Show commands
//!   quit         - Exit
//!
//! Usage:
//!   cargo run --example schc_device -- [--core-mgmt 127.0.0.1:5683] [--core-data 127.0.0.1:5684]
//!
//! Run schc_core first in another terminal, then run this.

use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::net::UdpSocket;
use std::time::Duration;

use coap_lite::{MessageClass, MessageType, Packet, RequestType, ResponseType};
use rust_coreconf::SidFile;
use schc::{build_tree, compress_packet, Direction, MatchingOperator, CompressionAction, Rule};
use schc_coreconf::{
    load_sor_rules, MRuleSet, SchcCoreconfManager,
    mgmt_compression::MgmtCompressor,
    rpc_builder::{build_duplicate_rule_rpc, analyze_rpc_overhead, EntryModification},
    sor_loader::{mo_to_sid, cda_to_sid},
};

const M_RULES_PATH: &str = "samples/m-rules.sor";
const BASE_RULES_PATH: &str = "rules/base-ipv6-udp.sor";
const SID_FILE_PATH: &str = "samples/ietf-schc@2026-01-12.sid";

/// Device state that persists across commands
struct DeviceState {
    manager: SchcCoreconfManager,
    mgmt_compressor: MgmtCompressor,
    mgmt_socket: UdpSocket,
    data_socket: UdpSocket,
    message_id: u16,
    packet_count: u64,

    // Flow parameters (fixed for this session)
    base_rule: (u32, u8),
    src_prefix: [u8; 8],
    src_iid: [u8; 8],
    dst_prefix: [u8; 8],
    dst_iid: [u8; 8],
    src_port: u16,
    dst_port: u16,
    flow_label: u32,

    // Track locally known rule IDs to avoid unnecessary RPC conflicts
    known_rule_ids: HashSet<(u32, u8)>,

    // Current derived rule (if any)
    derived_rule: Option<(u32, u8)>,

    show_overhead: bool,
}

impl DeviceState {
    fn new(
        manager: SchcCoreconfManager,
        mgmt_compressor: MgmtCompressor,
        mgmt_socket: UdpSocket,
        data_socket: UdpSocket,
        base_rule: (u32, u8),
        show_overhead: bool,
    ) -> Self {
        let mut known_rule_ids = HashSet::new();
        known_rule_ids.insert(base_rule); // Base rule is always known

        Self {
            manager,
            mgmt_compressor,
            mgmt_socket,
            data_socket,
            message_id: 1,
            packet_count: 0,
            base_rule,
            src_prefix: [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00],
            src_iid: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            dst_prefix: [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00],
            dst_iid: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
            src_port: 12345,
            dst_port: 5683,
            flow_label: 0x12345,
            known_rule_ids,
            derived_rule: None,
            show_overhead,
        }
    }

    /// Find the next available rule ID using BFS across the binary tree
    /// This gives a more balanced allocation: 8/5, 24/5, 8/6, 24/6, 40/6, 56/6, etc.
    fn find_next_available_rule_id(&self) -> Option<(u32, u8)> {
        use std::collections::VecDeque;

        const MAX_RULE_ID_LENGTH: u8 = 12; // Don't go beyond 12 bits

        let mut queue: VecDeque<(u32, u8)> = VecDeque::new();
        let mut visited: HashSet<(u32, u8)> = HashSet::new();

        // Start with direct children of base rule
        let [child0, child1] = SchcCoreconfManager::get_derivation_options(self.base_rule);
        queue.push_back(child0); // append 0 first
        queue.push_back(child1); // then append 1

        // BFS to find first available slot
        while let Some(candidate) = queue.pop_front() {
            let (_rule_id, rule_id_length) = candidate;

            // Skip if too long
            if rule_id_length > MAX_RULE_ID_LENGTH {
                continue;
            }

            // Skip if already visited
            if visited.contains(&candidate) {
                continue;
            }
            visited.insert(candidate);

            // Check if this rule ID is available (not in our known set)
            if !self.known_rule_ids.contains(&candidate) {
                return Some(candidate);
            }

            // Add children to queue for BFS exploration
            let [child0, child1] = SchcCoreconfManager::get_derivation_options(candidate);
            queue.push_back(child0);
            queue.push_back(child1);
        }

        None // No available rule ID found within limits
    }

    /// Send packets using the best available rule
    fn send_packets(&mut self, count: usize) -> io::Result<()> {
        println!("\n--- Sending {} packets ---\n", count);

        for i in 0..count {
            self.packet_count += 1;

            let payload = format!("Hello from device! Packet #{}", self.packet_count);
            let packet = build_ipv6_udp_packet(
                &self.src_prefix, &self.src_iid,
                &self.dst_prefix, &self.dst_iid,
                self.src_port, self.dst_port,
                self.flow_label,
                payload.as_bytes(),
            );

            let ruleset = self.manager.compression_ruleset().expect("Failed to get ruleset");
            let rules: Vec<Rule> = ruleset.rules.to_vec();
            let tree = build_tree(&rules);

            match compress_packet(&tree, &packet, Direction::Up, &rules, false) {
                Ok(compressed) => {
                    let is_derived = self.derived_rule
                        .map(|(id, _)| id == compressed.rule_id)
                        .unwrap_or(false);
                    let marker = if is_derived { " (DERIVED)" } else { "" };

                    println!(
                        "[Packet {}] Rule {}/{}{}: {} bytes -> {} bytes ({:.1}% compression)",
                        i + 1,
                        compressed.rule_id,
                        compressed.rule_id_length,
                        marker,
                        packet.len() - 14 - payload.len(),
                        compressed.data.len() - payload.len(),
                        (1.0 - (compressed.data.len() - payload.len()) as f64
                            / (packet.len() - 14 - payload.len()) as f64) * 100.0
                    );

                    self.data_socket.send(&compressed.data)?;
                }
                Err(e) => {
                    println!("[Packet {}] Compression error: {:?}", i + 1, e);
                }
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }

    /// Derive a new optimized rule
    fn derive_rule(&mut self) -> io::Result<()> {
        println!("\n--- Deriving optimized rule ---\n");

        // Find next available rule ID using BFS (checks local state first)
        let candidate = match self.find_next_available_rule_id() {
            Some(c) => c,
            None => {
                println!("Error: No available rule IDs within limits");
                return Ok(());
            }
        };

        let (derived_rule_id, derived_rule_id_length) = candidate;
        println!(
            "Selected rule ID {}/{} (locally available)",
            derived_rule_id, derived_rule_id_length
        );

        // Build modifications for the flow
        let modifications = vec![
            EntryModification::new(2)  // IPV6.FL
                .with_target_value_bytes(self.flow_label.to_be_bytes()[1..4].to_vec())
                .with_mo(mo_to_sid(&MatchingOperator::Equal))
                .with_cda(cda_to_sid(&CompressionAction::NotSent)),
            EntryModification::new(7)  // IPV6.DEV_IID
                .with_target_value_bytes(self.src_iid.to_vec())
                .with_mo(mo_to_sid(&MatchingOperator::Equal))
                .with_cda(cda_to_sid(&CompressionAction::NotSent)),
            EntryModification::new(9)  // IPV6.APP_IID
                .with_target_value_bytes(self.dst_iid.to_vec())
                .with_mo(mo_to_sid(&MatchingOperator::Equal))
                .with_cda(cda_to_sid(&CompressionAction::NotSent)),
            EntryModification::new(10)  // UDP.DEV_PORT
                .with_target_value_bytes(self.src_port.to_be_bytes().to_vec())
                .with_mo(mo_to_sid(&MatchingOperator::Equal))
                .with_cda(cda_to_sid(&CompressionAction::NotSent)),
            EntryModification::new(11)  // UDP.APP_PORT
                .with_target_value_bytes(self.dst_port.to_be_bytes().to_vec())
                .with_mo(mo_to_sid(&MatchingOperator::Equal))
                .with_cda(cda_to_sid(&CompressionAction::NotSent)),
        ];

        // Build and send RPC
        let rpc_cbor = build_duplicate_rule_rpc(
            self.base_rule,
            (derived_rule_id, derived_rule_id_length),
            Some(&modifications),
        );

        // Analyze and print CORECONF overhead breakdown
        if self.show_overhead {
            let analysis = analyze_rpc_overhead(
                self.base_rule,
                (derived_rule_id, derived_rule_id_length),
                Some(&modifications),
            );
            analysis.print_breakdown();
            // Print M-Rule compression overhead analysis
            print_mrule_compression_overhead(&self.mgmt_compressor, &rpc_cbor);
        }

        println!("RPC payload: {} bytes", rpc_cbor.len());

        let response = send_coap_post(
            &self.mgmt_socket,
            &mut self.message_id,
            &rpc_cbor,
            &self.mgmt_compressor,
        )?;

        match response.header.code {
            MessageClass::Response(ResponseType::Changed) => {
                println!("RPC successful!");

                // Apply locally
                let local_mods = build_local_mods(&modifications);
                self.manager
                    .duplicate_rule(self.base_rule, (derived_rule_id, derived_rule_id_length), Some(&local_mods))
                    .expect("Failed to duplicate rule locally");

                // Update local state
                self.known_rule_ids.insert((derived_rule_id, derived_rule_id_length));
                self.derived_rule = Some((derived_rule_id, derived_rule_id_length));

                // Wait for guard period
                let guard = self.manager.guard_period();
                println!("Waiting for guard period ({:?})...", guard);
                std::thread::sleep(guard);
                self.manager.tick();

                println!("Rule {}/{} is now active!", derived_rule_id, derived_rule_id_length);
            }
            MessageClass::Response(ResponseType::Conflict) => {
                // This shouldn't happen if our local tracking is correct,
                // but handle it gracefully by adding to known set
                let msg = String::from_utf8_lossy(&response.payload);
                println!("Conflict (unexpected): {}", msg);
                println!("Adding {}/{} to known rules and retrying...", derived_rule_id, derived_rule_id_length);
                self.known_rule_ids.insert((derived_rule_id, derived_rule_id_length));
                // Recursive retry
                return self.derive_rule();
            }
            code => {
                let msg = String::from_utf8_lossy(&response.payload);
                println!("RPC failed: {:?} - {}", code, msg);
            }
        }

        Ok(())
    }

    /// Show current rules
    fn show_rules(&self) {
        println!("\n--- Current Rules ---\n");
        println!("Base rule: {}/{}", self.base_rule.0, self.base_rule.1);

        if let Some((id, len)) = self.derived_rule {
            println!("Active derived rule: {}/{}", id, len);
        } else {
            println!("No derived rule active");
        }

        println!("\nKnown rule IDs (local tracking):");
        let mut known: Vec<_> = self.known_rule_ids.iter().collect();
        known.sort_by_key(|(id, len)| (*len, *id));
        for (id, len) in known {
            let marker = if (*id, *len) == self.base_rule {
                " (base)"
            } else if self.derived_rule == Some((*id, *len)) {
                " (active)"
            } else {
                ""
            };
            println!("  {}/{}{}", id, len, marker);
        }

        // Show what the manager has
        println!("\nManager active rules: {}", self.manager.active_rules().len());
        for rule in self.manager.active_rules() {
            println!("  {}/{}: {} fields", rule.rule_id, rule.rule_id_length, rule.compression.len());
        }
    }
}

fn main() -> io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let core_mgmt = args.iter().position(|a| a == "--core-mgmt")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1:5683");
    let core_data = args.iter().position(|a| a == "--core-data")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1:5684");
    let show_overhead = args.iter().any(|a| a == "--show-overhead");

    println!("============================================================");
    println!("       SCHC Device (IoT Endpoint) - Interactive Mode");
    println!("============================================================\n");

    // Load SID file
    println!("Loading SID file: {}", SID_FILE_PATH);
    let sid_file = SidFile::from_file(SID_FILE_PATH).expect("Failed to load SID file");

    // Load M-Rules
    println!("Loading M-Rules from: {}", M_RULES_PATH);
    let m_rules = MRuleSet::from_sor(M_RULES_PATH, &sid_file).expect("Failed to load M-Rules");
    println!("  Loaded {} M-Rules", m_rules.rules().len());

    let mgmt_compressor = MgmtCompressor::new(&m_rules);

    // Load base rules
    println!("Loading base rules from: {}", BASE_RULES_PATH);
    let base_rules: Vec<Rule> = load_sor_rules(BASE_RULES_PATH, &sid_file)
        .expect("Failed to load base rules");

    let base_rule_id = base_rules[0].rule_id;
    let base_rule_id_length = base_rules[0].rule_id_length;
    println!("  Base rule: {}/{} ({} fields)", base_rule_id, base_rule_id_length, base_rules[0].compression.len());

    // Create manager
    let estimated_rtt = Duration::from_millis(100);
    let manager = SchcCoreconfManager::new(m_rules, base_rules, estimated_rtt);

    // Create sockets
    let mgmt_socket = UdpSocket::bind("0.0.0.0:0")?;
    mgmt_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    mgmt_socket.connect(core_mgmt)?;

    let data_socket = UdpSocket::bind("0.0.0.0:0")?;
    data_socket.connect(core_data)?;

    println!("\n------------------------------------------------------------");
    println!("Core Management: {}", core_mgmt);
    println!("Core Data:       {}", core_data);
    println!("------------------------------------------------------------");
    println!("\nCommands: send [N], derive, rules, help, quit\n");

    // Create device state
    let mut state = DeviceState::new(
        manager,
        mgmt_compressor,
        mgmt_socket,
        data_socket,
        (base_rule_id, base_rule_id_length),
        show_overhead,
    );

    // Interactive loop
    let stdin = io::stdin();
    loop {
        print!("device> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break; // EOF
        }

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "send" => {
                let count = parts.get(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5);
                state.send_packets(count)?;
            }
            "derive" => {
                state.derive_rule()?;
            }
            "rules" => {
                state.show_rules();
            }
            "help" => {
                println!("\nCommands:");
                println!("  send [N]  - Send N packets (default 5)");
                println!("  derive    - Derive a new optimized rule for current flow");
                println!("  rules     - Show current rules");
                println!("  help      - Show this help");
                println!("  quit      - Exit");
            }
            "quit" | "exit" | "q" => {
                println!("Goodbye!");
                break;
            }
            cmd => {
                println!("Unknown command: {}. Type 'help' for available commands.", cmd);
            }
        }
    }

    println!("\n------------------------------------------------------------");
    println!("Device finished. Total packets sent: {}", state.packet_count);
    println!("------------------------------------------------------------");

    Ok(())
}

/// Build JSON modifications for local manager
fn build_local_mods(modifications: &[EntryModification]) -> serde_json::Value {
    serde_json::json!({
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
    })
}

/// Build an IPv6/UDP packet
fn build_ipv6_udp_packet(
    src_prefix: &[u8; 8], src_iid: &[u8; 8],
    dst_prefix: &[u8; 8], dst_iid: &[u8; 8],
    src_port: u16, dst_port: u16,
    flow_label: u32, payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + 40 + 8 + payload.len());

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x86, 0xDD,
    ]);

    // IPv6 Header
    let version_tc_fl = (6u32 << 28) | (flow_label & 0xFFFFF);
    packet.extend_from_slice(&version_tc_fl.to_be_bytes());
    let payload_length = (8 + payload.len()) as u16;
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.push(17); // UDP
    packet.push(64); // Hop limit
    packet.extend_from_slice(src_prefix);
    packet.extend_from_slice(src_iid);
    packet.extend_from_slice(dst_prefix);
    packet.extend_from_slice(dst_iid);

    // UDP Header
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum

    packet.extend_from_slice(payload);
    packet
}

/// Build management packet for CORECONF
fn build_mgmt_packet(coap_payload: &[u8]) -> Vec<u8> {
    let src_prefix: [u8; 8] = [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let src_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_prefix: [u8; 8] = [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let dst_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

    const TRAFFIC_CLASS: u32 = 1;
    const FLOW_LABEL: u32 = 0x23456;
    const DEV_PORT: u16 = 3865;
    const APP_PORT: u16 = 5683;

    let mut packet = Vec::with_capacity(14 + 40 + 8 + coap_payload.len());

    // Ethernet
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x86, 0xDD,
    ]);

    // IPv6
    let version_tc_fl = (6u32 << 28) | (TRAFFIC_CLASS << 20) | (FLOW_LABEL & 0xFFFFF);
    packet.extend_from_slice(&version_tc_fl.to_be_bytes());
    let payload_length = (8 + coap_payload.len()) as u16;
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.push(17);
    packet.push(64);
    packet.extend_from_slice(&src_prefix);
    packet.extend_from_slice(&src_iid);
    packet.extend_from_slice(&dst_prefix);
    packet.extend_from_slice(&dst_iid);

    // UDP
    packet.extend_from_slice(&DEV_PORT.to_be_bytes());
    packet.extend_from_slice(&APP_PORT.to_be_bytes());
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);

    packet.extend_from_slice(coap_payload);
    packet
}

/// Send CoAP POST with M-Rule compression
fn send_coap_post(
    socket: &UdpSocket,
    message_id: &mut u16,
    payload: &[u8],
    mgmt_compressor: &MgmtCompressor,
) -> io::Result<Packet> {
    let mut coap_packet = Packet::new();
    coap_packet.header.message_id = *message_id;
    *message_id = message_id.wrapping_add(1);
    coap_packet.header.code = MessageClass::Request(RequestType::Post);
    coap_packet.header.set_type(MessageType::Confirmable);
    coap_packet.set_token(vec![]);
    coap_packet.add_option(coap_lite::CoapOption::UriPath, b"c".to_vec());
    coap_packet.add_option(coap_lite::CoapOption::ContentFormat, vec![0x01, 0x39]);
    coap_packet.payload = payload.to_vec();

    let coap_bytes = coap_packet.to_bytes().map_err(|e| io::Error::other(e.to_string()))?;
    let full_packet = build_mgmt_packet(&coap_bytes);

    let compressed = mgmt_compressor.compress(&full_packet, Direction::Up)
        .map_err(|e| io::Error::other(e.to_string()))?;

    println!("  MGMT: {} -> {} bytes ({:.1}% compression)",
        full_packet.len() - 14, compressed.len(),
        (1.0 - compressed.len() as f64 / (full_packet.len() - 14) as f64) * 100.0);

    socket.send(&compressed)?;

    let mut buf = [0u8; 1500];
    let len = socket.recv(&mut buf)?;

    let decompressed = mgmt_compressor.decompress(&buf[..len], Direction::Down)
        .map_err(|e| io::Error::other(e.to_string()))?;

    if decompressed.len() < 48 {
        return Err(io::Error::other("Decompressed packet too small"));
    }

    Packet::from_bytes(&decompressed[48..]).map_err(|e| io::Error::other(e.to_string()))
}

/// Print M-Rule compression overhead analysis for CORECONF traffic
fn print_mrule_compression_overhead(mgmt_compressor: &MgmtCompressor, rpc_payload: &[u8]) {
    // Build a sample CoAP POST request with the RPC payload
    let mut coap_packet = coap_lite::Packet::new();
    coap_packet.header.message_id = 1;
    coap_packet.header.code = coap_lite::MessageClass::Request(coap_lite::RequestType::Post);
    coap_packet.header.set_type(coap_lite::MessageType::Confirmable);
    coap_packet.set_token(vec![]);
    coap_packet.add_option(coap_lite::CoapOption::UriPath, b"c".to_vec());
    coap_packet.add_option(coap_lite::CoapOption::ContentFormat, vec![0x01, 0x39]); // 313
    coap_packet.payload = rpc_payload.to_vec();

    let coap_bytes = coap_packet.to_bytes().unwrap_or_default();

    // Build full IPv6/UDP/CoAP packet
    let full_packet = build_mgmt_packet(&coap_bytes);

    // Compress with M-Rules
    let compressed = mgmt_compressor.compress(&full_packet, Direction::Up)
        .unwrap_or_default();

    // Calculate overhead components
    let ethernet_header = 14;
    let ipv6_header = 40;
    let udp_header = 8;
    let coap_header = coap_bytes.len() - rpc_payload.len();

    let original_headers = ipv6_header + udp_header + coap_header;
    let original_total = full_packet.len() - ethernet_header;

    // SCHC Rule ID is embedded in the compressed data
    // For M-Rules with RuleIDLength=4, it's 4 bits = 0.5 bytes (rounded to 1 byte in practice)
    let schc_rule_id_bits = 4; // M-Rules use 4-bit rule IDs
    let schc_residue = compressed.len() - rpc_payload.len();

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       M-RULE COMPRESSION OVERHEAD ANALYSIS                    ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║ ORIGINAL PACKET (before SCHC compression)                     ║");
    println!("╠───────────────────────────────────────────────────────────────╣");
    println!("║  IPv6 header:                         {:>3} bytes               ║", ipv6_header);
    println!("║  UDP header:                          {:>3} bytes               ║", udp_header);
    println!("║  CoAP header (incl. options):         {:>3} bytes               ║", coap_header);
    println!("║  CBOR RPC payload:                    {:>3} bytes               ║", rpc_payload.len());
    println!("║                                      ─────────                 ║");
    println!("║  Total (excl. Ethernet):              {:>3} bytes               ║", original_total);
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║ COMPRESSED PACKET (after M-Rule compression)                  ║");
    println!("╠───────────────────────────────────────────────────────────────╣");
    println!("║  SCHC Rule ID:                        {:>3} bits ({:.1} bytes)    ║",
        schc_rule_id_bits, schc_rule_id_bits as f64 / 8.0);
    println!("║  SCHC residue (compressed headers):   {:>3} bytes               ║", schc_residue);
    println!("║  CBOR RPC payload (unchanged):        {:>3} bytes               ║", rpc_payload.len());
    println!("║                                      ─────────                 ║");
    println!("║  Total compressed:                    {:>3} bytes               ║", compressed.len());
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║ COMPRESSION SUMMARY                                           ║");
    println!("╠───────────────────────────────────────────────────────────────╣");
    println!("║  Original headers:                    {:>3} bytes               ║", original_headers);
    println!("║  Compressed headers (Rule ID+residue):{:>3} bytes               ║", schc_residue);
    println!("║  Header compression ratio:           {:>4.1}%                    ║",
        (1.0 - schc_residue as f64 / original_headers as f64) * 100.0);
    println!("║  Overall compression ratio:          {:>4.1}%                    ║",
        (1.0 - compressed.len() as f64 / original_total as f64) * 100.0);
    println!("╚═══════════════════════════════════════════════════════════════╝\n");
}