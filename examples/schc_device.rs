//! SCHC Device (IoT Endpoint) Example - Interactive Mode
//!
//! This example demonstrates the Device/IoT side of a SCHC-CORECONF deployment:
//! - Loads M-Rules and base application rules from SOR (CORECONF CBOR format)
//! - Runs interactively, maintaining state across operations
//! - Derives optimized rules on demand with smart rule ID allocation (BFS)
//! - Supports learning mode using RuleLearner to observe traffic patterns
//! - Compresses packets using the best available rule
//!
//! Learning Mode:
//!   The `learn` command enables the RuleLearner which observes field values
//!   across packets. After the specified minimum packets are observed, it
//!   detects fields with constant values and suggests converting them from
//!   `value-sent` to `not-sent` compression action, reducing overhead.
//!
//! Commands:
//!   send [N]     - Send N packets (default 5)
//!   derive       - Derive a new optimized rule (manual/hardcoded)
//!   learn [N]    - Enable learning mode (RuleLearner suggests after N packets)
//!   learn off    - Disable learning mode
//!   rules        - Show current rules and learning status
//!   help         - Show commands
//!   quit         - Exit
//!
//! Usage:
//!   cargo run --example schc_device -- [--core-mgmt 127.0.0.1:5683] [--core-data 127.0.0.1:5684]
//!
//! Run schc_core first in another terminal, then run this.

use std::io::{self, BufRead, Write};
use std::net::UdpSocket;
use std::time::Duration;

use coap_lite::{MessageClass, MessageType, Packet, RequestType, ResponseType};
use rust_coreconf::SidFile;
use schc::{build_tree, compress_packet, Direction, MatchingOperator, CompressionAction, Rule};
use schc::field_id::FieldId;
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

    // Current derived rule (if any)
    derived_rule: Option<(u32, u8)>,

    // Learning mode: uses the manager's RuleLearner to observe packets
    // and dynamically suggest optimized rules based on observed patterns
    learning_enabled: bool,

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
            derived_rule: None,
            learning_enabled: false,
            show_overhead,
        }
    }

    /// Extract field values from an IPv6/UDP packet for learning
    ///
    /// Note: Excludes computed fields (lengths, checksums) since they vary per packet
    /// and should never be learned as constants.
    fn extract_fields(&self, packet: &[u8]) -> Vec<(FieldId, Vec<u8>)> {
        // Skip 14-byte Ethernet header
        if packet.len() < 14 + 40 + 8 {
            return vec![];
        }
        let ipv6 = &packet[14..];

        let mut fields = Vec::new();

        // IPv6 Version (4 bits) - offset 0, upper nibble
        fields.push((FieldId::Ipv6Ver, vec![(ipv6[0] >> 4) & 0x0F]));

        // Traffic Class (8 bits) - offset 0-1
        let tc = ((ipv6[0] & 0x0F) << 4) | ((ipv6[1] >> 4) & 0x0F);
        fields.push((FieldId::Ipv6Tc, vec![tc]));

        // Flow Label (20 bits) - offset 1-3
        let fl = ((ipv6[1] as u32 & 0x0F) << 16) | ((ipv6[2] as u32) << 8) | (ipv6[3] as u32);
        fields.push((FieldId::Ipv6Fl, fl.to_be_bytes()[1..4].to_vec()));

        // SKIP: Payload Length - computed field (varies with payload size)

        // Next Header (8 bits) - offset 6
        fields.push((FieldId::Ipv6Nxt, vec![ipv6[6]]));

        // Hop Limit (8 bits) - offset 7
        fields.push((FieldId::Ipv6HopLmt, vec![ipv6[7]]));

        // Source Prefix (64 bits) - offset 8-15
        fields.push((FieldId::Ipv6DevPrefix, ipv6[8..16].to_vec()));

        // Source IID (64 bits) - offset 16-23
        fields.push((FieldId::Ipv6DevIid, ipv6[16..24].to_vec()));

        // Destination Prefix (64 bits) - offset 24-31
        fields.push((FieldId::Ipv6AppPrefix, ipv6[24..32].to_vec()));

        // Destination IID (64 bits) - offset 32-39
        fields.push((FieldId::Ipv6AppIid, ipv6[32..40].to_vec()));

        // UDP fields (if present)
        if ipv6[6] == 17 && ipv6.len() >= 48 {
            let udp = &ipv6[40..];
            // Source Port (16 bits)
            fields.push((FieldId::UdpDevPort, udp[0..2].to_vec()));
            // Destination Port (16 bits)
            fields.push((FieldId::UdpAppPort, udp[2..4].to_vec()));
            // SKIP: UDP Length - computed field (varies with payload size)
            // SKIP: UDP Checksum - computed field
        }

        fields
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

            // If learning is enabled, observe the packet fields
            if self.learning_enabled {
                let fields = self.extract_fields(&packet);
                self.manager.observe_packet(&fields);
            }

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

            // Check if learning mode has a suggestion ready (based on RuleLearner's min_packets)
            if self.learning_enabled && self.manager.has_suggestion() {
                println!("\n[Learning] RuleLearner ready to suggest (observed {} packets)",
                    self.manager.learning_stats().map(|s| {
                        // Extract packet count from stats
                        s.lines().next().unwrap_or("").to_string()
                    }).unwrap_or_default());
                self.derive_from_learning()?;
                self.learning_enabled = false;
                self.manager.reset_learning();
                println!("[Learning] Disabled (rule derived)");
                if i + 1 < count {
                    println!("\n--- Continuing with remaining {} packets ---\n", count - i - 1);
                }
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }

    /// Derive a new rule based on patterns learned by the RuleLearner
    fn derive_from_learning(&mut self) -> io::Result<()> {
        println!("\n--- Deriving rule from learned patterns ---\n");

        // Print what the learner observed
        if let Some(stats) = self.manager.learning_stats() {
            println!("Observed patterns:\n{}\n", stats);
        }

        // Get the suggested rule from the learner
        let suggested = match self.manager.suggest_rule() {
            Some(r) => r,
            None => {
                println!("No rule improvements suggested (fields may already be optimized)");
                return Ok(());
            }
        };

        // Allocate a proper rule ID using BFS (instead of learner's offset-based ID)
        let (derived_rule_id, derived_rule_id_length) = match self.manager.find_next_available_rule_id(self.base_rule) {
            Some(c) => c,
            None => {
                println!("Error: No available rule IDs within limits");
                return Ok(());
            }
        };
        println!(
            "Selected rule ID {}/{} (locally available)",
            derived_rule_id, derived_rule_id_length
        );

        // Get the base rule to compare against
        let base_rule = self.manager.active_rules()
            .into_iter()
            .find(|r| r.rule_id == self.base_rule.0 && r.rule_id_length == self.base_rule.1)
            .cloned()
            .expect("Base rule not found");

        // Build modifications by comparing suggested rule to base rule
        let modifications = build_learned_modifications(&base_rule, &suggested);

        if modifications.is_empty() {
            println!("No field modifications learned");
            return Ok(());
        }

        println!("Learned {} field modifications:", modifications.len());
        for m in &modifications {
            println!("  Entry {}: MO={:?}, CDA={:?}, TV={} bytes",
                m.entry_index,
                m.matching_operator.map(|s| format!("SID {}", s)),
                m.comp_decomp_action.map(|s| format!("SID {}", s)),
                m.target_value.as_ref().map(|v| v.len()).unwrap_or(0));
        }

        self.send_derive_rpc(derived_rule_id, derived_rule_id_length, &modifications)
    }

    /// Derive a new optimized rule (manual/hardcoded mode)
    fn derive_rule(&mut self) -> io::Result<()> {
        println!("\n--- Deriving optimized rule (manual) ---\n");

        // Find next available rule ID using manager's BFS allocation
        let candidate = match self.manager.find_next_available_rule_id(self.base_rule) {
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

        // Build modifications for the flow (hardcoded based on device state)
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

        self.send_derive_rpc(derived_rule_id, derived_rule_id_length, &modifications)
    }

    /// Send the RPC to derive a rule and apply locally
    fn send_derive_rpc(&mut self, derived_rule_id: u32, derived_rule_id_length: u8, modifications: &[EntryModification]) -> io::Result<()> {

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

                // Update state (manager already tracks via duplicate_rule/provision_rule)
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
                // but handle it gracefully by adding to known set via manager
                let msg = String::from_utf8_lossy(&response.payload);
                println!("Conflict (unexpected): {}", msg);
                println!("Adding {}/{} to known rules and retrying...", derived_rule_id, derived_rule_id_length);
                self.manager.mark_rule_id_known(derived_rule_id, derived_rule_id_length);
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

        // Learning mode status
        if self.learning_enabled {
            if let Some(stats) = self.manager.learning_stats() {
                println!("Learning mode: ENABLED");
                println!("{}", stats);
            } else {
                println!("Learning mode: ENABLED (learner not initialized)");
            }
        } else {
            println!("Learning mode: disabled");
        }

        println!("\nKnown rule IDs (manager tracking):");
        let mut known: Vec<_> = self.manager.known_rule_ids().iter().collect();
        known.sort_by_key(|(id, len)| (*len, *id));
        for (id, len) in known {
            let marker = if (*id, *len) == self.base_rule {
                " (base)"
            } else if self.derived_rule == Some((*id, *len)) {
                " (derived)"
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
    println!("\nCommands: send [N], derive, learn [N], rules, help, quit\n");

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
            "learn" => {
                // Enable/disable learning mode using the RuleLearner
                if let Some(arg) = parts.get(1) {
                    if arg.to_lowercase() == "off" {
                        state.learning_enabled = false;
                        state.manager.reset_learning();
                        println!("Learning mode disabled.");
                    } else if let Ok(min_packets) = arg.parse::<usize>() {
                        // Enable learning with specified min_packets threshold
                        state.manager.enable_learning(min_packets);
                        state.learning_enabled = true;
                        println!("Learning mode enabled. RuleLearner will suggest after {} packets.", min_packets);
                        println!("Fields with constant values will be converted to not-sent.");
                    } else {
                        println!("Invalid argument. Use: learn <N> or learn off");
                    }
                } else {
                    // Toggle with default min_packets (5)
                    if state.learning_enabled {
                        state.learning_enabled = false;
                        state.manager.reset_learning();
                        println!("Learning mode disabled.");
                    } else {
                        state.manager.enable_learning(5);
                        state.learning_enabled = true;
                        println!("Learning mode enabled (default: 5 packets min).");
                        println!("Fields with constant values will be converted to not-sent.");
                    }
                }
            }
            "rules" => {
                state.show_rules();
            }
            "help" => {
                println!("\nCommands:");
                println!("  send [N]    - Send N packets (default 5)");
                println!("  derive      - Derive a new optimized rule (manual/hardcoded)");
                println!("  learn [N]   - Enable learning mode (observe N packets, then suggest)");
                println!("  learn off   - Disable learning mode and reset observations");
                println!("  rules       - Show current rules and learning status");
                println!("  help        - Show this help");
                println!("  quit        - Exit");
                println!("\nLearning mode observes packet fields and detects constant patterns.");
                println!("After N packets, fields that were constant are converted from");
                println!("value-sent to not-sent, reducing transmission overhead.");
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

/// Build modifications by comparing learned rule to base rule
///
/// The RuleLearner produces a suggested rule with fields modified based on
/// observed patterns. This function compares the suggested rule to the base
/// and builds EntryModification structures for fields that changed.
fn build_learned_modifications(base_rule: &Rule, suggested_rule: &Rule) -> Vec<EntryModification> {
    let mut modifications = Vec::new();

    for (idx, (base_field, suggested_field)) in base_rule.compression.iter()
        .zip(suggested_rule.compression.iter())
        .enumerate()
    {
        // Check if this field was modified by the learner
        // The learner converts value-sent fields with constant values to not-sent
        if base_field.cda != suggested_field.cda || base_field.mo != suggested_field.mo {
            let mut entry_mod = EntryModification::new(idx as u16);

            // Set matching operator
            entry_mod = entry_mod.with_mo(mo_to_sid(&suggested_field.mo));

            // Set compression action
            entry_mod = entry_mod.with_cda(cda_to_sid(&suggested_field.cda));

            // Extract target value bytes from the suggested field's tv
            // Use field-aware conversion to get proper byte lengths
            if let Some(ref tv) = suggested_field.tv {
                if let Some(bytes) = json_value_to_bytes_for_field(tv, suggested_field.fid) {
                    entry_mod = entry_mod.with_target_value_bytes(bytes);
                }
            }

            modifications.push(entry_mod);
        }
    }

    modifications
}

/// Convert a JSON target value to bytes for RPC transmission, field-aware
///
/// Uses the field ID to determine the expected byte length:
/// - IID fields: 8 bytes
/// - Prefix fields: 8 bytes
/// - Port fields: 2 bytes
/// - Flow label: 3 bytes
fn json_value_to_bytes_for_field(tv: &serde_json::Value, fid: FieldId) -> Option<Vec<u8>> {
    // Determine expected byte length based on field type
    let expected_len = match fid {
        FieldId::Ipv6DevIid | FieldId::Ipv6AppIid
        | FieldId::Ipv6SrcIid | FieldId::Ipv6DstIid => Some(8),
        FieldId::Ipv6DevPrefix | FieldId::Ipv6AppPrefix
        | FieldId::Ipv6SrcPrefix | FieldId::Ipv6DstPrefix => Some(8),
        FieldId::UdpDevPort | FieldId::UdpAppPort
        | FieldId::UdpSrcPort | FieldId::UdpDstPort => Some(2),
        FieldId::Ipv6Fl => Some(3),
        _ => None, // Use minimal representation
    };

    let bytes = json_value_to_bytes(tv)?;

    // Pad to expected length if needed
    if let Some(len) = expected_len {
        if bytes.len() < len {
            let mut padded = vec![0u8; len];
            padded[len - bytes.len()..].copy_from_slice(&bytes);
            return Some(padded);
        }
    }

    Some(bytes)
}

/// Convert a JSON target value to bytes for RPC transmission
///
/// Handles formats produced by the RuleLearner:
/// - Numbers: Convert to minimal byte representation
/// - IPv6 prefix strings: "2001:0db8:0000:0000::/64" -> 8 bytes
/// - Hex strings: "0x..." -> decoded bytes
fn json_value_to_bytes(tv: &serde_json::Value) -> Option<Vec<u8>> {
    match tv {
        serde_json::Value::Number(n) => {
            // Convert number to minimal byte representation
            if let Some(val) = n.as_u64() {
                if val == 0 {
                    Some(vec![0])
                } else {
                    // Find minimal byte representation
                    let bytes = val.to_be_bytes();
                    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
                    Some(bytes[first_nonzero..].to_vec())
                }
            } else {
                None
            }
        }
        serde_json::Value::String(s) => {
            // Handle hex strings like "0x2001..."
            if let Some(hex_str) = s.strip_prefix("0x") {
                return hex::decode(hex_str).ok();
            }

            // Handle IPv6 prefix format like "2001:0db8:0000:0000::/64"
            if let Some(prefix_str) = s.strip_suffix("::/64") {
                return parse_ipv6_prefix(prefix_str);
            }

            // Shouldn't reach here with properly formatted values
            log::warn!("Unexpected string format in target value: {}", s);
            None
        }
        serde_json::Value::Array(arr) => {
            // Array of bytes
            arr.iter()
                .map(|v| v.as_u64().map(|n| n as u8))
                .collect::<Option<Vec<u8>>>()
        }
        _ => None,
    }
}

/// Parse IPv6 prefix like "2001:0db8:0000:0000" to 8 bytes
fn parse_ipv6_prefix(s: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut bytes = Vec::with_capacity(8);
    for part in parts {
        let val = u16::from_str_radix(part, 16).ok()?;
        bytes.extend_from_slice(&val.to_be_bytes());
    }
    Some(bytes)
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