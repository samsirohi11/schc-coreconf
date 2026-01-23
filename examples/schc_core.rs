//! SCHC Core (Network Endpoint) Example
//!
//! This example demonstrates the Core/Network side of a SCHC-CORECONF deployment:
//! - Loads M-Rules for CORECONF management traffic compression
//! - Loads base application rules from SOR (CORECONF CBOR format)
//! - Starts a CoAP server for CORECONF management (rule provisioning)
//! - Receives compressed SCHC packets and decompresses them
//! - Handles duplicate-rule RPC for dynamic rule derivation
//!
//! Usage:
//!   cargo run --example schc_core -- [--port 5683] [--data-port 5684]
//!
//! Run this in one terminal, then run schc_device in another terminal.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use coap_lite::{
    CoapRequest, ContentFormat as CoapContentFormat, MessageClass, Packet, RequestType,
    ResponseType,
};
use rust_coreconf::SidFile;
use schc::{decompress_packet, Direction, RuleSet};
use schc_coreconf::{
    load_sor_rules, MRuleSet, SchcCoreconfHandler, SchcCoreconfManager,
    mgmt_compression::MgmtCompressor,
};

const M_RULES_PATH: &str = "samples/m-rules.sor";
const BASE_RULES_PATH: &str = "rules/base-ipv6-udp.sor";
const SID_FILE_PATH: &str = "samples/ietf-schc@2026-01-12.sid";

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let mgmt_port = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(5683u16);
    let data_port = args
        .iter()
        .position(|a| a == "--data-port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(5684u16);

    println!("============================================================");
    println!("            SCHC Core (Network Endpoint)");
    println!("============================================================\n");

    // Load SID file for CORECONF parsing
    println!("Loading SID file: {}", SID_FILE_PATH);
    let sid_file = SidFile::from_file(SID_FILE_PATH).expect("Failed to load SID file");

    // Load M-Rules for CORECONF traffic compression (from SOR format)
    println!("Loading M-Rules from: {}", M_RULES_PATH);
    let m_rules = MRuleSet::from_sor(M_RULES_PATH, &sid_file).expect("Failed to load M-Rules");
    println!("  Loaded {} M-Rules (IDs {}-{})", m_rules.rules().len(), m_rules.reserved_range().0, m_rules.reserved_range().1);

    // Load base application rules from SOR (CORECONF CBOR format)
    println!("Loading base rules from: {}", BASE_RULES_PATH);
    let base_rules = load_sor_rules(BASE_RULES_PATH, &sid_file)
        .expect("Failed to load base rules from SOR");
    println!("  Loaded {} application rule(s)", base_rules.len());
    for rule in &base_rules {
        println!("    - Rule {}/{}: {} fields", rule.rule_id, rule.rule_id_length, rule.compression.len());
    }

    // Create SCHC-CORECONF manager with estimated RTT
    // Using 100ms RTT for local testing (increase for satellite/lunar links)
    let estimated_rtt = Duration::from_millis(100);
    
    // Create management compressor for M-rule based compression
    let mgmt_compressor = MgmtCompressor::new(&m_rules);
    
    let manager = SchcCoreconfManager::new(m_rules.clone(), base_rules, estimated_rtt);
    println!("\nGuard period: {:?}", manager.guard_period());

    // Create CORECONF handler (reuses the SID file path)
    let mut coreconf_handler = SchcCoreconfHandler::new(SID_FILE_PATH, manager)
        .expect("Failed to create CORECONF handler");

    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n\nReceived Ctrl+C, shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    // Bind management socket (CORECONF/CoAP)
    let mgmt_addr = format!("0.0.0.0:{}", mgmt_port);
    let mgmt_socket = UdpSocket::bind(&mgmt_addr)?;
    mgmt_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    // Bind data socket (compressed SCHC packets)
    let data_addr = format!("0.0.0.0:{}", data_port);
    let data_socket = UdpSocket::bind(&data_addr)?;
    data_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    println!("\n------------------------------------------------------------");
    println!("CORECONF Management: coap://0.0.0.0:{}/c", mgmt_port);
    println!("SCHC Data Channel:   udp://0.0.0.0:{}", data_port);
    println!("------------------------------------------------------------");
    println!("\nWaiting for connections... (Ctrl+C to stop)\n");

    let mut mgmt_buf = [0u8; 1500];
    let mut data_buf = [0u8; 1500];
    let mut packet_count = 0u64;
    let mut last_rule_id = 0u32;

    while running.load(Ordering::SeqCst) {
        // Tick guard period manager
        coreconf_handler.tick();

        // Handle CORECONF management requests (compressed with M-Rules)
        if let Ok((len, src)) = mgmt_socket.recv_from(&mut mgmt_buf) {
            // Decompress incoming SCHC packet with M-Rules
            match mgmt_compressor.decompress(&mgmt_buf[..len], Direction::Up) {
                Ok(decompressed) => {
                    // Extract CoAP from decompressed IPv6/UDP packet
                    // Skip: Ethernet (14) + IPv6 (40) + UDP (8) = 62 bytes
                    if decompressed.len() < 62 {
                        println!("\n[CORECONF] Error: Decompressed packet too small ({} bytes)", decompressed.len());
                        continue;
                    }
                    let coap_bytes = &decompressed[62..];
                    
                    println!("\n[CORECONF] MGMT decompressed: {} bytes -> {} bytes",
                        len, decompressed.len() - 14);
                    
                    if let Ok(packet) = Packet::from_bytes(coap_bytes) {
                        if matches!(packet.header.code, MessageClass::Empty) {
                            continue;
                        }

                        let request = CoapRequest::from_packet(packet, src);
                        let path = request.get_path();

                        println!("  {} {} /{} from {}",
                            format_method(&request.message.header.code),
                            request.message.payload.len(),
                            path,
                            src);

                        let response = if path == "c" {
                            handle_coreconf_request(&mut coreconf_handler, &request)
                        } else {
                            create_not_found(&request.message)
                        };

                        // Build response into IPv6/UDP/CoAP packet and compress
                        let response_coap_bytes = response.to_bytes().unwrap_or_default();
                        let response_packet = build_mgmt_response_packet(&response_coap_bytes);
                        
                        match mgmt_compressor.compress(&response_packet, Direction::Down) {
                            Ok(compressed_response) => {
                                println!("  Response: {:?} (compressed {} -> {} bytes)",
                                    response.header.code,
                                    response_packet.len() - 14,
                                    compressed_response.len());
                                mgmt_socket.send_to(&compressed_response, src)?;
                            }
                            Err(e) => {
                                println!("  Response compression failed: {}, sending raw", e);
                                mgmt_socket.send_to(&response_coap_bytes, src)?;
                            }
                        }

                        // Show current rules after management operation
                        let mgr = coreconf_handler.manager().read().unwrap();
                        println!("  Active rules: {} M-Rules + {} app rules",
                            mgr.m_rules().rules().len(),
                            mgr.active_rules().len());
                    }
                }
                Err(e) => {
                    // Fallback: try to parse as raw CoAP (for compatibility)
                    println!("\n[CORECONF] M-Rule decompression failed: {}, trying raw CoAP", e);
                    if let Ok(packet) = Packet::from_bytes(&mgmt_buf[..len]) {
                        if !matches!(packet.header.code, MessageClass::Empty) {
                            let request = CoapRequest::from_packet(packet, src);
                            let response = handle_coreconf_request(&mut coreconf_handler, &request);
                            let response_bytes = response.to_bytes().unwrap_or_default();
                            mgmt_socket.send_to(&response_bytes, src)?;
                        }
                    }
                }
            }
        }

        // Handle compressed SCHC data packets
        if let Ok((len, src)) = data_socket.recv_from(&mut data_buf) {
            packet_count += 1;

            // Get current ruleset for decompression
            let mgr = coreconf_handler.manager().read().unwrap();
            let ruleset = mgr.compression_ruleset()
                .expect("Failed to get compression ruleset");
            drop(mgr);

            println!("\n[DATA #{}] Received {} bytes from {}", packet_count, len, src);
            // println!("  Compressed: {:02x?}", &data_buf[..len.min(32)]);

            // Try to decompress
            match decompress_schc_packet(&data_buf[..len], &ruleset) {
                Ok((rule_id, rule_id_length, decompressed)) => {
                    if rule_id != last_rule_id {
                        println!("  ** Rule changed: {} -> {} **", last_rule_id, rule_id);
                        last_rule_id = rule_id;
                    }
                    
                    println!("  Rule ID: {}/{}", rule_id, rule_id_length);
                    println!("  Decompressed: {} bytes", decompressed.len());

                    // Parse and display IPv6/UDP headers
                    if decompressed.len() >= 48 {
                        display_ipv6_udp_headers(&decompressed);
                        
                        // Extract and display payload (after Ethernet + IPv6 + UDP headers)
                        if decompressed.len() > 62 {
                            
                        }
                    }
                }
                Err(e) => {
                    println!("  Decompression error: {}", e);
                }
            }
        }
    }

    println!("\n------------------------------------------------------------");
    println!("Core shutdown. Processed {} packets.", packet_count);
    println!("------------------------------------------------------------");

    Ok(())
}

fn decompress_schc_packet(compressed: &[u8], ruleset: &RuleSet) -> Result<(u32, u8, Vec<u8>), String> {
    let rules: Vec<schc::Rule> = ruleset.rules.to_vec();

    match decompress_packet(compressed, &rules, Direction::Up, None) {
        Ok(result) => Ok((result.rule_id, result.rule_id_length, result.full_data)),
        Err(e) => Err(format!("{:?}", e)),
    }
}

fn display_ipv6_udp_headers(data: &[u8]) {
    if data.len() < 48 {
        return;
    }

    // IPv6 header (40 bytes)
    let version = (data[0] >> 4) & 0x0F;
    let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
    let flow_label = ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);
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

    // UDP header (8 bytes starting at offset 40)
    if data.len() >= 48 {
        let src_port = u16::from_be_bytes([data[40], data[41]]);
        let dst_port = u16::from_be_bytes([data[42], data[43]]);
        let udp_len = u16::from_be_bytes([data[44], data[45]]);
        println!("  UDP: src_port={} dst_port={} len={}", src_port, dst_port, udp_len);
    }

    let payload_bytes = &data[48..];
    if let Ok(payload_str) = std::str::from_utf8(payload_bytes) {
        println!("  Payload: \"{}\"", payload_str);
    } else {
        println!("  Payload: {:02x?} (non-UTF8)", payload_bytes);
    }

}

fn handle_coreconf_request(
    handler: &mut SchcCoreconfHandler,
    coap_request: &CoapRequest<std::net::SocketAddr>,
) -> Packet {
    let packet = &coap_request.message;

    let method = match packet.header.code {
        MessageClass::Request(RequestType::Get) => rust_coreconf::coap_types::Method::Get,
        MessageClass::Request(RequestType::Fetch) => rust_coreconf::coap_types::Method::Fetch,
        MessageClass::Request(RequestType::Post) => rust_coreconf::coap_types::Method::Post,
        MessageClass::Request(RequestType::Patch) | MessageClass::Request(RequestType::IPatch) => {
            rust_coreconf::coap_types::Method::IPatch
        }
        _ => return create_method_not_allowed(packet),
    };

    let mut request = rust_coreconf::coap_types::Request::new(method);
    request.payload = packet.payload.clone();

    if let Some(cf) = packet.get_content_format() {
        request.content_format = content_format_from_coap(cf);
    }

    let coreconf_response = handler.handle(&request);

    let mut response = Packet::new();
    response.header.message_id = packet.header.message_id;
    response.set_token(packet.get_token().to_vec());

    let (class, detail) = coreconf_response.code.to_code_pair();
    response.header.code = match (class, detail) {
        (2, 1) => MessageClass::Response(ResponseType::Created),
        (2, 4) => MessageClass::Response(ResponseType::Changed),
        (2, 5) => MessageClass::Response(ResponseType::Content),
        (4, 0) => MessageClass::Response(ResponseType::BadRequest),
        (4, 1) => MessageClass::Response(ResponseType::Unauthorized),
        (4, 4) => MessageClass::Response(ResponseType::NotFound),
        (4, 5) => MessageClass::Response(ResponseType::MethodNotAllowed),
        (4, 9) => MessageClass::Response(ResponseType::Conflict),
        _ => MessageClass::Response(ResponseType::InternalServerError),
    };

    if !coreconf_response.payload.is_empty() {
        response.payload = coreconf_response.payload;
        if let Some(format) = coreconf_response.content_format {
            response.set_content_format(content_format_to_coap(format));
        }
    }

    response
}

fn create_not_found(request: &Packet) -> Packet {
    let mut response = Packet::new();
    response.header.message_id = request.header.message_id;
    response.header.code = MessageClass::Response(ResponseType::NotFound);
    response.set_token(request.get_token().to_vec());
    response
}

fn create_method_not_allowed(request: &Packet) -> Packet {
    let mut response = Packet::new();
    response.header.message_id = request.header.message_id;
    response.header.code = MessageClass::Response(ResponseType::MethodNotAllowed);
    response.set_token(request.get_token().to_vec());
    response
}

fn format_method(code: &MessageClass) -> &'static str {
    match code {
        MessageClass::Request(RequestType::Get) => "GET",
        MessageClass::Request(RequestType::Post) => "POST",
        MessageClass::Request(RequestType::Fetch) => "FETCH",
        MessageClass::Request(RequestType::Patch) => "PATCH",
        MessageClass::Request(RequestType::IPatch) => "iPATCH",
        _ => "???",
    }
}

fn content_format_from_coap(cf: CoapContentFormat) -> Option<rust_coreconf::coap_types::ContentFormat> {
    match cf {
        CoapContentFormat::ApplicationCBOR => Some(rust_coreconf::coap_types::ContentFormat::YangDataCbor),
        _ => None,
    }
}

fn content_format_to_coap(format: rust_coreconf::coap_types::ContentFormat) -> CoapContentFormat {
    match format {
        rust_coreconf::coap_types::ContentFormat::YangDataCbor => CoapContentFormat::ApplicationCBOR,
        rust_coreconf::coap_types::ContentFormat::YangInstancesCborSeq => CoapContentFormat::ApplicationCBOR,
        rust_coreconf::coap_types::ContentFormat::YangIdentifiersCbor => CoapContentFormat::ApplicationCBOR,
    }
}

/// Build an IPv6/UDP/CoAP packet for management response (Core -> Device)
fn build_mgmt_response_packet(coap_payload: &[u8]) -> Vec<u8> {
    // Fixed M-Rule addressing per draft (reversed for response):
    // - Core (source): fe80::2
    // - Device (dest): fe80::1
    // - Port: 5683 (CoAP default)
    let src_prefix: [u8; 8] = [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let src_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]; // ::2 (Core)
    let dst_prefix: [u8; 8] = [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let dst_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]; // ::1 (Device)
    
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
    packet.extend_from_slice(&5683u16.to_be_bytes()); // src port
    packet.extend_from_slice(&5683u16.to_be_bytes()); // dst port
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // checksum (0 for now)

    // CoAP payload
    packet.extend_from_slice(coap_payload);

    packet
}
