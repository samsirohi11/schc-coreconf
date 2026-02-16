//! Derive-Implicit RPC Example
//!
//! Demonstrates a proposed "derive-implicit" RPC mechanism where compressed SCHC
//! packets serve as both data AND rule derivation requests.
//!
//! The key insight: when a device compresses a packet with a base rule, the residue
//! already contains the exact field values that would become target values in a
//! derived rule. Instead of sending those values explicitly (as in duplicate-rule),
//! we piggyback the derivation on the compressed packet itself.
//!
//! This example is self-contained — it runs device+core logic in-process with no
//! network sockets. All derive-implicit RPC logic lives here.
//!
//! Usage:
//!   cargo run --example derive_implicit
//!   cargo run --example derive_implicit -- --rules rules/base-ipv6-udp.json
//!   cargo run --example derive_implicit -- --rules rules/base-ipv6-udp.sor

use std::time::Duration;

use ciborium::Value as CborValue;
use rust_coreconf::SidFile;
use schc::{
    build_tree, compress_packet,
    CompressionAction, Direction, MatchingOperator, Rule,
};
use schc_coreconf::{
    load_sor_rules,
    rpc_builder::{analyze_rpc_overhead, build_duplicate_rule_rpc, EntryModification},
    sor_loader::{cda_to_sid, mo_to_sid},
    MRuleSet, SchcCoreconfManager,
};

const DEFAULT_RULES_PATH: &str = "rules/base-ipv6-udp.json";
const SID_FILE_PATH: &str = "samples/ietf-schc@2026-01-12.sid";

// =============================================================================
// Derive-Implicit RPC: Data Structures
// =============================================================================

/// CBOR SID for the derive-implicit RPC input container
/// (Using a SID value beyond the duplicate-rule range for illustration)
const SID_DERIVE_IMPLICIT_INPUT: i64 = 5210;

/// Deltas within the derive-implicit input container
const DELTA_DI_TARGET_RULE_ID_VALUE: i64 = 1;
const DELTA_DI_TARGET_RULE_ID_LENGTH: i64 = 2;
const DELTA_DI_COMPRESSED_PACKET: i64 = 3;
const DELTA_DI_LOCK_ENTRIES: i64 = 4;
const DELTA_DI_OVERRIDES: i64 = 5; // Optional per-entry overrides

/// Delta keys within an override entry
const DELTA_OVERRIDE_ENTRY_INDEX: i64 = 1;
const DELTA_OVERRIDE_MO: i64 = 2;
const DELTA_OVERRIDE_CDA: i64 = 3;

/// Per-entry override for when the default equal/not-sent isn't desired
#[derive(Debug, Clone)]
struct EntryOverride {
    entry_index: u16,
    matching_operator: Option<i64>, // SID
    comp_decomp_action: Option<i64>, // SID
}

/// Parsed derive-implicit RPC request
#[derive(Debug)]
struct DeriveImplicitRequest {
    target_rule_id: (u32, u8),
    compressed_packet: Vec<u8>,
    lock_entries: Vec<u16>,
    overrides: Vec<EntryOverride>,
}

/// Result of the derive-implicit RPC processing (returned as ACK)
#[derive(Debug)]
struct DeriveImplicitResult {
    derived_rule_id: (u32, u8),
    status: String,
    derived_rule: Rule,
}

// =============================================================================
// Derive-Implicit RPC: Build (Device Side)
// =============================================================================

/// Build the derive-implicit RPC payload
///
/// The compressed packet's Rule ID implicitly identifies the source rule —
/// we don't need to send it separately.
///
/// CBOR structure:
/// ```text
/// { 5210: {
///     1: target_id,        // proposed new Rule ID value
///     2: target_len,       // proposed new Rule ID length
///     3: h'...',           // compressed SCHC packet bytes
///     4: [2, 7, 9, 10, 11], // entry indices to lock (equal/not-sent)
///     5: [{ 1: idx, 2: mo_sid, 3: cda_sid }, ...] // optional overrides
/// }}
/// ```
fn build_derive_implicit_rpc(
    target: (u32, u8),
    compressed_packet: &[u8],
    lock_entries: &[u16],
    overrides: Option<&[EntryOverride]>,
) -> Vec<u8> {
    let mut input_entries = vec![
        (
            CborValue::Integer(DELTA_DI_TARGET_RULE_ID_VALUE.into()),
            CborValue::Integer((target.0 as i64).into()),
        ),
        (
            CborValue::Integer(DELTA_DI_TARGET_RULE_ID_LENGTH.into()),
            CborValue::Integer((target.1 as i64).into()),
        ),
        (
            CborValue::Integer(DELTA_DI_COMPRESSED_PACKET.into()),
            CborValue::Bytes(compressed_packet.to_vec()),
        ),
        (
            CborValue::Integer(DELTA_DI_LOCK_ENTRIES.into()),
            CborValue::Array(
                lock_entries
                    .iter()
                    .map(|&idx| CborValue::Integer((idx as i64).into()))
                    .collect(),
            ),
        ),
    ];

    // Optional per-entry overrides for non-default MO/CDA
    if let Some(ovrs) = overrides {
        if !ovrs.is_empty() {
            let ovr_array: Vec<CborValue> = ovrs
                .iter()
                .map(|o| {
                    let mut entries = vec![(
                        CborValue::Integer(DELTA_OVERRIDE_ENTRY_INDEX.into()),
                        CborValue::Integer((o.entry_index as i64).into()),
                    )];
                    if let Some(mo) = o.matching_operator {
                        entries.push((
                            CborValue::Integer(DELTA_OVERRIDE_MO.into()),
                            CborValue::Integer(mo.into()),
                        ));
                    }
                    if let Some(cda) = o.comp_decomp_action {
                        entries.push((
                            CborValue::Integer(DELTA_OVERRIDE_CDA.into()),
                            CborValue::Integer(cda.into()),
                        ));
                    }
                    CborValue::Map(entries)
                })
                .collect();
            input_entries.push((
                CborValue::Integer(DELTA_DI_OVERRIDES.into()),
                CborValue::Array(ovr_array),
            ));
        }
    }

    let input = CborValue::Map(input_entries);
    let root = CborValue::Map(vec![(
        CborValue::Integer(SID_DERIVE_IMPLICIT_INPUT.into()),
        input,
    )]);

    let mut output = Vec::new();
    ciborium::into_writer(&root, &mut output).expect("CBOR serialization failed");
    output
}

// =============================================================================
// Derive-Implicit RPC: Parse (Core Side)
// =============================================================================

/// Parse a derive-implicit RPC from CBOR bytes
fn parse_derive_implicit_rpc(payload: &[u8]) -> Result<DeriveImplicitRequest, String> {
    let value: CborValue =
        ciborium::from_reader(payload).map_err(|e| format!("CBOR decode error: {}", e))?;

    let root_map = value.as_map().ok_or("Root is not a map")?;

    // Find input container
    let input = find_cbor_key(root_map, SID_DERIVE_IMPLICIT_INPUT)
        .ok_or("derive-implicit input not found")?;
    let input_map = input.as_map().ok_or("Input is not a map")?;

    // Parse target rule ID
    let target_value = find_cbor_key(input_map, DELTA_DI_TARGET_RULE_ID_VALUE)
        .and_then(cbor_to_u32)
        .ok_or("target-rule-id-value missing")?;
    let target_length = find_cbor_key(input_map, DELTA_DI_TARGET_RULE_ID_LENGTH)
        .and_then(cbor_to_u8)
        .ok_or("target-rule-id-length missing")?;

    // Parse compressed packet
    let compressed_packet = find_cbor_key(input_map, DELTA_DI_COMPRESSED_PACKET)
        .and_then(|v| v.as_bytes().cloned())
        .ok_or("compressed-packet missing")?;

    // Parse lock entries
    let lock_entries = find_cbor_key(input_map, DELTA_DI_LOCK_ENTRIES)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| cbor_to_u16(v))
                .collect::<Vec<u16>>()
        })
        .unwrap_or_default();

    // Parse optional overrides
    let overrides = find_cbor_key(input_map, DELTA_DI_OVERRIDES)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let map = v.as_map()?;
                    let entry_index = find_cbor_key(map, DELTA_OVERRIDE_ENTRY_INDEX)
                        .and_then(cbor_to_u16)?;
                    let matching_operator =
                        find_cbor_key(map, DELTA_OVERRIDE_MO).and_then(cbor_to_i64);
                    let comp_decomp_action =
                        find_cbor_key(map, DELTA_OVERRIDE_CDA).and_then(cbor_to_i64);
                    Some(EntryOverride {
                        entry_index,
                        matching_operator,
                        comp_decomp_action,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(DeriveImplicitRequest {
        target_rule_id: (target_value, target_length),
        compressed_packet,
        lock_entries,
        overrides,
    })
}

// =============================================================================
// Derive-Implicit RPC: Process (Core Side)
// =============================================================================

/// Core processes the derive-implicit RPC:
///  1. Identifies source rule from the compressed packet's Rule ID
///  2. Extracts field values from the residue for each lock-entry
///  3. Creates a derived rule with those fields set to equal/not-sent
///  4. Returns the derived rule
///
/// We use rule entry indices, and go through the
/// rule's field list to map each index to its residue bit offset.
///
/// The core creates the rule and returns it.
/// The device must NOT use the derived rule until it receives this ACK.
fn process_derive_implicit(
    rpc: &DeriveImplicitRequest,
    rules: &[Rule],
) -> Result<DeriveImplicitResult, String> {
    // Step 1: Match the Rule ID from the compressed packet to find the source rule
    let source_rule = schc::decompressor::match_rule_id(&rpc.compressed_packet, rules)
        .map_err(|e| format!("Cannot identify source rule: {:?}", e))?;

    println!(
        "  [Core] Source rule: {}/{} ({} entries)",
        source_rule.rule_id,
        source_rule.rule_id_length,
        source_rule.compression.len()
    );

    // Step 2: Extract field values from the residue
    // Go through the rule's compression entries, tracking the bit position in the residue.
    // Fields with CDA not-sent/compute produce 0 residue bits — they are skipped.
    let extracted = extract_residue_values(source_rule, &rpc.compressed_packet)?;

    println!("  [Core] Extracted {} residue field values:", extracted.len());
    for (idx, (value, bits)) in &extracted {
        println!("    Entry[{}]: {} bits ({} bytes) = {:02x?}", idx, bits, value.len(), value);
    }

    // Step 3: Create derived rule
    let mut derived = source_rule.clone();
    derived.rule_id = rpc.target_rule_id.0;
    derived.rule_id_length = rpc.target_rule_id.1;

    for &lock_idx in &rpc.lock_entries {
        let idx = lock_idx as usize;
        if idx >= derived.compression.len() {
            return Err(format!(
                "Lock entry index {} out of bounds (rule has {} entries)",
                idx,
                derived.compression.len()
            ));
        }

        let field = &mut derived.compression[idx];

        // Get the value from the residue for this entry
        if let Some((value_bytes, field_bits)) = extracted.get(&lock_idx) {
            // Default: lock to equal/not-sent (the common case)
            let mut target_mo = MatchingOperator::Equal;
            let mut target_cda = CompressionAction::NotSent;

            //: Check for overrides on this entry
            if let Some(ovr) = rpc.overrides.iter().find(|o| o.entry_index == lock_idx) {
                if let Some(mo_sid) = ovr.matching_operator {
                    target_mo = sid_to_mo(mo_sid);
                }
                if let Some(cda_sid) = ovr.comp_decomp_action {
                    target_cda = sid_to_cda(cda_sid);
                }
            }

            // Set the target value from the residue
            field.tv = Some(bytes_to_json_value(value_bytes, field.fid, *field_bits));
            field.mo = target_mo;
            field.cda = target_cda;

            // Re-parse the TV so the compressor/decompressor can use it
            let _ = field.parse_tv();

            println!(
                "  [Core] Locked entry[{}] ({:?}): MO={:?}, CDA={:?}, TV={} bytes",
                idx,
                field.fid,
                field.mo,
                field.cda,
                value_bytes.len()
            );
        } else {
            // Field doesn't produce residue bits (e.g., not-sent / compute)
            // — nothing to lock, it's already optimized
            println!(
                "  [Core] Entry[{}] ({:?}) has no residue (already {:?}) — skipping",
                idx, field.fid, field.cda
            );
        }
    }

    Ok(DeriveImplicitResult {
        derived_rule_id: rpc.target_rule_id,
        status: "Created".to_string(),
        derived_rule: derived,
    })
}

/// Extract field values from the SCHC residue using the rule's field metadata
///
/// Go through the rule's field list sequentially. For each field with
/// a CDA that produces residue bits (value-sent, mapping-sent, lsb), read the
/// appropriate number of bits. For not-sent/compute, skip (0 residue bits).
/// Returns a map of entry_index → extracted bytes.
fn extract_residue_values(
    rule: &Rule,
    compressed_data: &[u8],
) -> Result<std::collections::HashMap<u16, (Vec<u8>, u16)>, String> {
    let mut result = std::collections::HashMap::new();

    // Start reading after the Rule ID bits
    let mut bit_offset = rule.rule_id_length as usize;
    let total_bits = compressed_data.len() * 8;

    for (idx, field) in rule.compression.iter().enumerate() {
        match field.cda {
            CompressionAction::NotSent | CompressionAction::Compute => {
                // No residue bits produced — skip
            }
            CompressionAction::ValueSent => {
                let field_bits = field
                    .fl
                    .or_else(|| field.fid.default_size_bits())
                    .unwrap_or(8) as usize;

                if bit_offset + field_bits > total_bits {
                    return Err(format!(
                        "Residue overflow at entry[{}]: need {} bits at offset {}, have {}",
                        idx, field_bits, bit_offset, total_bits
                    ));
                }

                // Extract bits from the compressed data
                let value = extract_bits(compressed_data, bit_offset, field_bits);
                result.insert(idx as u16, (value, field_bits as u16));
                bit_offset += field_bits;
            }
            CompressionAction::MappingSent => {
                // Mapping-sent sends an index, not the full value
                // For derive-implicit, we'd need to resolve the mapping
                // For now, skip mapping-sent fields in lock_entries
                if let Some(ref tv) = field.tv {
                    if let serde_json::Value::Array(arr) = tv {
                        let num_items = arr.len();
                        let index_bits = if num_items <= 1 {
                            0
                        } else {
                            (usize::BITS - (num_items - 1).leading_zeros()) as usize
                        };
                        bit_offset += index_bits;
                    }
                }
            }
            CompressionAction::Lsb => {
                // LSB sends only lower bits
                let msb_bits = field.mo_val.unwrap_or(0) as usize;
                let field_bits = field
                    .fl
                    .or_else(|| field.fid.default_size_bits())
                    .unwrap_or(8) as usize;
                let lsb_bits = field_bits.saturating_sub(msb_bits);
                bit_offset += lsb_bits;
            }
        }
    }

    Ok(result)
}

/// Extract `num_bits` from a byte slice starting at `bit_offset`
fn extract_bits(data: &[u8], bit_offset: usize, num_bits: usize) -> Vec<u8> {
    let num_bytes = num_bits.div_ceil(8);
    let mut result = vec![0u8; num_bytes];

    for i in 0..num_bits {
        let src_byte = (bit_offset + i) / 8;
        let src_bit = 7 - ((bit_offset + i) % 8); // MSB first
        let dst_byte = i / 8;
        let dst_bit = 7 - (i % 8); // MSB first

        if src_byte < data.len() && (data[src_byte] >> src_bit) & 1 == 1 {
            result[dst_byte] |= 1 << dst_bit;
        }
    }

    result
}

// =============================================================================
// Overhead Comparison
// =============================================================================

/// Build the equivalent duplicate-rule RPC for the same derivation,
/// then compare sizes with derive-implicit
fn compare_overhead(
    source: (u32, u8),
    target: (u32, u8),
    lock_entries: &[u16],
    residue_values: &std::collections::HashMap<u16, (Vec<u8>, u16)>,
    base_rule: &Rule,
    di_rpc_bytes: &[u8],
    compressed_packet: &[u8],
) {
    // Build equivalent duplicate-rule modifications
    let modifications: Vec<EntryModification> = lock_entries
        .iter()
        .filter_map(|&idx| {
            let _field = base_rule.compression.get(idx as usize)?;
            let (tv_bytes, _bits) = residue_values.get(&idx)?;
            Some(
                EntryModification::new(idx)
                    .with_target_value_bytes(tv_bytes.clone())
                    .with_mo(mo_to_sid(&MatchingOperator::Equal))
                    .with_cda(cda_to_sid(&CompressionAction::NotSent)),
            )
        })
        .collect();

    let dup_rpc_bytes = build_duplicate_rule_rpc(source, target, Some(&modifications));
    let analysis = analyze_rpc_overhead(source, target, Some(&modifications));

    // Print comparison
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║           OVERHEAD COMPARISON: TWO APPROACHES                 ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║                                                               ║");
    println!("║  APPROACH 1: duplicate-rule RPC (index-based)                 ║");
    println!("╠───────────────────────────────────────────────────────────────╣");
    println!(
        "║  Fixed overhead (CBOR+SIDs+RuleIDs):  {:>3} bytes               ║",
        analysis.total_fixed_overhead
    );
    println!(
        "║  Per-field modifications ({} fields):  {:>3} bytes               ║",
        modifications.len(),
        analysis.total_per_field_overhead
    );
    println!(
        "║  Total RPC CBOR payload:              {:>3} bytes               ║",
        dup_rpc_bytes.len()
    );
    println!("║                                                               ║");
    println!(
        "║  Breakdown per field (avg):          {:>4.1} bytes               ║",
        analysis.avg_per_field_overhead
    );
    for m in &analysis.modification_overheads {
        let field_name = base_rule
            .compression
            .get(m.entry_index as usize)
            .map(|f| format!("{:?}", f.fid))
            .unwrap_or_else(|| "???".to_string());
        println!(
            "║    [{:>2}] {:<20} {:>3} B (data: {} B)                ║",
            m.entry_index,
            field_name,
            m.total_bytes,
            m.total_bytes - m.overhead_bytes,
        );
    }
    println!("║                                                               ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║  APPROACH 2: derive-implicit RPC (proposed)                   ║");
    println!("╠───────────────────────────────────────────────────────────────╣");

    // Decompose the derive-implicit RPC
    let di_rpc_only = di_rpc_bytes.len();
    let di_compressed_packet_len = compressed_packet.len();
    let di_rpc_overhead = di_rpc_only - di_compressed_packet_len;

    println!(
        "║  RPC overhead (target ID + indices):  {:>3} bytes               ║",
        di_rpc_overhead
    );
    println!(
        "║  Compressed packet (bundled data):    {:>3} bytes               ║",
        di_compressed_packet_len
    );
    println!(
        "║  Total RPC CBOR payload:              {:>3} bytes               ║",
        di_rpc_only
    );
    println!("║                                                               ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║  SAVINGS                                                      ║");
    println!("╠───────────────────────────────────────────────────────────────╣");
    println!("║                                                               ║");

    let net_savings = dup_rpc_bytes.len() as i64 - di_rpc_only as i64;
    let net_savings_pct = if dup_rpc_bytes.len() > 0 {
        net_savings as f64 / dup_rpc_bytes.len() as f64 * 100.0
    } else {
        0.0
    };

    println!(
        "║  Net derivation savings:    {:>+4} bytes ({:>5.1}%)               ║",
        net_savings, net_savings_pct
    );
    println!("║                                                               ║");

    // Assertions
    assert!(
        di_rpc_overhead < dup_rpc_bytes.len(),
        "derive-implicit net overhead ({}) should be less than duplicate-rule overhead ({})",
        di_rpc_overhead,
        dup_rpc_bytes.len()
    );
    println!("║  ✓ derive-implicit overhead < duplicate-rule overhead         ║");

    println!("╚═══════════════════════════════════════════════════════════════╝");
}

// =============================================================================
// Helper Functions
// =============================================================================

fn find_cbor_key<'a>(
    map: &'a [(CborValue, CborValue)],
    key: i64,
) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| {
        if let CborValue::Integer(i) = k {
            if i128::from(*i) == key as i128 {
                return Some(v);
            }
        }
        None
    })
}

fn cbor_to_u32(v: &CborValue) -> Option<u32> {
    if let CborValue::Integer(i) = v {
        Some(i128::from(*i) as u32)
    } else {
        None
    }
}

fn cbor_to_u16(v: &CborValue) -> Option<u16> {
    if let CborValue::Integer(i) = v {
        Some(i128::from(*i) as u16)
    } else {
        None
    }
}

fn cbor_to_u8(v: &CborValue) -> Option<u8> {
    if let CborValue::Integer(i) = v {
        Some(i128::from(*i) as u8)
    } else {
        None
    }
}

fn cbor_to_i64(v: &CborValue) -> Option<i64> {
    if let CborValue::Integer(i) = v {
        Some(i128::from(*i) as i64)
    } else {
        None
    }
}

/// Convert SID to MatchingOperator
fn sid_to_mo(sid: i64) -> MatchingOperator {
    // SID values from ietf-schc identities
    match sid {
        5035 => MatchingOperator::Equal,
        5037 => MatchingOperator::Ignore,
        5039 => MatchingOperator::Msb(0), // MSB length comes from mo_val
        5041 => MatchingOperator::MatchMapping,
        _ => MatchingOperator::Equal,
    }
}

/// Convert SID to CompressionAction
fn sid_to_cda(sid: i64) -> CompressionAction {
    match sid {
        5003 => CompressionAction::NotSent,
        5005 => CompressionAction::ValueSent,
        5007 => CompressionAction::MappingSent,
        5009 => CompressionAction::Lsb,
        5011 => CompressionAction::Compute,
        _ => CompressionAction::NotSent,
    }
}

/// Convert extracted bytes + field ID into a JSON target value
fn bytes_to_json_value(bytes: &[u8], fid: schc::field_id::FieldId, field_bits: u16) -> serde_json::Value {
    use schc::field_id::FieldId;

    match fid {
        // Address-like fields → hex string
        FieldId::Ipv6DevPrefix
        | FieldId::Ipv6AppPrefix
        | FieldId::Ipv6SrcPrefix
        | FieldId::Ipv6DstPrefix => {
            // Format as "2001:0db8:0000:0000::/64"
            if bytes.len() >= 8 {
                serde_json::json!(format!(
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7]
                ))
            } else {
                serde_json::json!(format!("0x{}", hex::encode(bytes)))
            }
        }
        FieldId::Ipv6DevIid
        | FieldId::Ipv6AppIid
        | FieldId::Ipv6SrcIid
        | FieldId::Ipv6DstIid => {
            // IID as hex string
            serde_json::json!(format!("0x{}", hex::encode(bytes)))
        }
        // Numeric fields — strip byte-alignment padding
        // e.g. 20-bit flow label stored in 3 bytes has 4 padding bits at LSB
        _ => {
            let mut val: u64 = 0;
            for &b in bytes {
                val = (val << 8) | b as u64;
            }
            // Right-shift to remove padding bits
            let total_bits_in_bytes = (bytes.len() as u16) * 8;
            let padding_bits = total_bits_in_bytes.saturating_sub(field_bits);
            val >>= padding_bits;
            serde_json::json!(val)
        }
    }
}

/// Build an IPv6/UDP packet for testing
fn build_test_packet(
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

    // Ethernet header
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x86, 0xDD,
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

/// Load rules from either .json or .sor file
fn load_rules(path: &str) -> Vec<Rule> {
    if path.ends_with(".sor") {
        let sid_file = SidFile::from_file(SID_FILE_PATH).expect("Failed to load SID file");
        load_sor_rules(path, &sid_file).expect("Failed to load SOR rules")
    } else {
        // JSON format
        let json = std::fs::read_to_string(path).expect("Failed to read rules file");
        let ruleset = schc::RuleSet::from_json(&json).expect("Failed to parse JSON rules");
        ruleset.rules
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let rules_path = args
        .iter()
        .position(|a| a == "--rules")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_RULES_PATH);

    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║         DERIVE-IMPLICIT RPC DEMONSTRATION                    ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // =========================================================================
    // Setup
    // =========================================================================

    println!("Loading rules from: {}", rules_path);
    let base_rules = load_rules(rules_path);

    let base_rule = &base_rules[0];
    println!(
        "Base rule: {}/{} ({} entries)",
        base_rule.rule_id,
        base_rule.rule_id_length,
        base_rule.compression.len()
    );

    // Show which fields produce residue (value-sent)
    println!("\nRule entry map:");
    for (idx, field) in base_rule.compression.iter().enumerate() {
        let residue = match field.cda {
            CompressionAction::ValueSent => "-> RESIDUE (value-sent)",
            CompressionAction::NotSent => "   (not-sent)",
            CompressionAction::Compute => "   (compute)",
            CompressionAction::MappingSent => "-> RESIDUE (mapping-sent)",
            CompressionAction::Lsb => "-> RESIDUE (lsb)",
        };
        let fid_str = format!("{:?}", field.fid);
        println!(
            "  [{:>2}] {:<25} FL={:<5} {}",
            idx,
            fid_str,
            field.fl.map(|f| f.to_string()).unwrap_or("-".into()),
            residue
        );
    }

    // Create managers for both device and core
    let m_rules = MRuleSet::default_ipv6_coap();
    let estimated_rtt = Duration::from_millis(100);

    let mut device_manager =
        SchcCoreconfManager::new(m_rules.clone(), base_rules.clone(), estimated_rtt);
    let mut core_manager = SchcCoreconfManager::new(m_rules, base_rules.clone(), estimated_rtt);

    // Flow parameters
    let src_prefix: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];
    let src_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_prefix: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];
    let dst_iid: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    let src_port: u16 = 12345;
    let dst_port: u16 = 5683;
    let flow_label: u32 = 0x12345;

    let base_rule_id = (base_rule.rule_id, base_rule.rule_id_length);

    // =========================================================================
    // Phase 1: Send packets with base rule
    // =========================================================================

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  PHASE 1: Compress packets with base rule {}/{}",
        base_rule_id.0, base_rule_id.1);
    println!("═══════════════════════════════════════════════════════════════\n");

    let ruleset = device_manager
        .compression_ruleset()
        .expect("Failed to get ruleset");
    let rules: Vec<Rule> = ruleset.rules.to_vec();
    let tree = build_tree(&rules);

    for i in 0..3 {
        let payload = format!("Hello #{}", i + 1);
        let packet = build_test_packet(
            &src_prefix, &src_iid, &dst_prefix, &dst_iid,
            src_port, dst_port, flow_label, payload.as_bytes(),
        );

        match compress_packet(&tree, &packet, Direction::Up, &rules, false) {
            Ok(compressed) => {
                let header_bytes = packet.len() - 14 - payload.len();
                println!(
                    "  Packet {}: Rule {}/{}, headers {} → {} bytes ({:.1}% compression)",
                    i + 1,
                    compressed.rule_id,
                    compressed.rule_id_length,
                    header_bytes,
                    compressed.data.len() - payload.len(),
                    (1.0 - (compressed.data.len() - payload.len()) as f64 / header_bytes as f64)
                        * 100.0
                );
            }
            Err(e) => println!("  Packet {}: Error: {:?}", i + 1, e),
        }
    }

    // =========================================================================
    // Phase 2: Device builds derive-implicit RPC
    // =========================================================================

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  PHASE 2: Device builds derive-implicit RPC");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Issue #4: Use BFS allocation for the target Rule ID
    let target_rule_id = device_manager
        .find_next_available_rule_id(base_rule_id)
        .expect("No available rule IDs");

    println!(
        "  Target Rule ID: {}/{} (BFS-allocated)",
        target_rule_id.0, target_rule_id.1
    );

    // Compress the "derivation packet" — this is the packet that doubles as the RPC
    let derivation_payload = b"Derive me!";
    let derivation_packet = build_test_packet(
        &src_prefix, &src_iid, &dst_prefix, &dst_iid,
        src_port, dst_port, flow_label, derivation_payload,
    );

    let compressed = compress_packet(&tree, &derivation_packet, Direction::Up, &rules, false)
        .expect("Compression failed for derivation packet");

    println!(
        "  Compressed derivation packet: {} bytes (Rule {}/{})",
        compressed.data.len(),
        compressed.rule_id,
        compressed.rule_id_length
    );

    // Entry indices to lock: all value-sent fields
    // From base-ipv6-udp.json:
    //   [2] IPV6.FL      (value-sent, 20 bits)
    //   [7] IPV6.DEV_IID (value-sent, 64 bits)
    //   [8] IPV6.APP_PREFIX (value-sent, 64 bits)
    //   [9] IPV6.APP_IID (value-sent, 64 bits)
    //  [10] UDP.DEV_PORT (value-sent, 16 bits)
    //  [11] UDP.APP_PORT (value-sent, 16 bits)
    let lock_entries: Vec<u16> = vec![2, 7, 8, 9, 10, 11];

    //: Demonstrate an override — lock APP_PREFIX with MSB matching instead
    // (This shows extensibility; most fields use default equal/not-sent)
    let overrides = vec![
        // No overrides for now — all default to equal/not-sent
        // Uncomment to test:
        // EntryOverride {
        //     entry_index: 8, // IPV6.APP_PREFIX
        //     matching_operator: Some(mo_to_sid(&MatchingOperator::Msb(0))),
        //     comp_decomp_action: Some(cda_to_sid(&CompressionAction::Lsb)),
        // },
    ];

    let di_rpc = build_derive_implicit_rpc(
        target_rule_id,
        &compressed.data,
        &lock_entries,
        if overrides.is_empty() { None } else { Some(&overrides) },
    );

    println!("  Derive-implicit RPC payload: {} bytes", di_rpc.len());
    println!(
        "    - Target Rule ID:          {} bytes",
        4 // approximately: 1 delta + 1-2 value + 1 delta + 1 value
    );
    println!(
        "    - Compressed packet:       {} bytes",
        compressed.data.len()
    );
    println!(
        "    - Lock entries ({} indices): {} bytes",
        lock_entries.len(),
        lock_entries.len() + 1 // ~1 byte per index + array header
    );
    println!(
        "    - CBOR framing:            {} bytes",
        di_rpc.len() - compressed.data.len() - lock_entries.len() - 4
    );

    // =========================================================================
    // Phase 3: Core processes the RPC
    // =========================================================================

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  PHASE 3: Core processes derive-implicit RPC");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Parse the RPC
    let parsed_rpc = parse_derive_implicit_rpc(&di_rpc).expect("Failed to parse RPC");

    println!(
        "  Parsed RPC: target={}/{}, {} lock entries, {} overrides",
        parsed_rpc.target_rule_id.0,
        parsed_rpc.target_rule_id.1,
        parsed_rpc.lock_entries.len(),
        parsed_rpc.overrides.len(),
    );

    // Process the RPC using the core's rules
    let core_rules = core_manager
        .compression_ruleset()
        .expect("Failed to get core ruleset");
    let core_rules_list: Vec<Rule> = core_rules.rules.to_vec();

    let result =
        process_derive_implicit(&parsed_rpc, &core_rules_list).expect("RPC processing failed");

    println!(
        "\n  [Core] Derived rule {}/{}: status={}",
        result.derived_rule_id.0, result.derived_rule_id.1, result.status
    );

    // Issue #5: Core provisions the rule and sends ACK
    core_manager
        .provision_rule(result.derived_rule.clone())
        .expect("Core: failed to provision derived rule");
    println!("  [Core] Rule provisioned. Sending ACK...");

    // =========================================================================
    // Phase 4: Device receives ACK, applies rule locally
    // =========================================================================

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  PHASE 4: Device receives ACK, applies derived rule");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Issue #5: Device ONLY applies the rule AFTER receiving the ACK
    println!("  [Device] ACK received. Applying derived rule locally...");

    device_manager
        .provision_rule(result.derived_rule.clone())
        .expect("Device: failed to provision derived rule");

    println!(
        "  [Device] Rule {}/{} is now active!",
        target_rule_id.0, target_rule_id.1
    );

    // Show the derived rule's fields
    println!("\n  Derived rule entry map:");
    for (idx, field) in result.derived_rule.compression.iter().enumerate() {
        let changed = match field.cda {
            CompressionAction::NotSent
                if base_rules[0].compression[idx].cda == CompressionAction::ValueSent =>
            {
                " ← LOCKED"
            }
            _ => "",
        };
        let fid_str = format!("{:?}", field.fid);
        let mo_str = format!("{:?}", field.mo);
        let cda_str = format!("{:?}", field.cda);
        println!(
            "    [{:>2}] {:<25} MO={:<10} CDA={:<12} {}",
            idx, fid_str, mo_str, cda_str, changed
        );
    }

    // =========================================================================
    // Phase 5: Send packets with derived rule
    // =========================================================================

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  PHASE 5: Compress packets with derived rule {}/{}",
        target_rule_id.0, target_rule_id.1);
    println!("═══════════════════════════════════════════════════════════════\n");

    let new_ruleset = device_manager
        .compression_ruleset()
        .expect("Failed to get updated ruleset");
    let new_rules: Vec<Rule> = new_ruleset.rules.to_vec();
    let new_tree = build_tree(&new_rules);

    let mut base_sizes = vec![];
    let mut derived_sizes = vec![];

    for i in 0..3 {
        let payload = format!("Post-derive #{}", i + 1);
        let packet = build_test_packet(
            &src_prefix, &src_iid, &dst_prefix, &dst_iid,
            src_port, dst_port, flow_label, payload.as_bytes(),
        );

        let header_bytes = packet.len() - 14 - payload.len();

        // Compress with old tree (base rule only) for comparison
        let base_compressed =
            compress_packet(&tree, &packet, Direction::Up, &rules, false).ok();

        // Compress with new tree (includes derived rule)
        match compress_packet(&new_tree, &packet, Direction::Up, &new_rules, false) {
            Ok(new_compressed) => {
                let is_derived = new_compressed.rule_id == target_rule_id.0
                    && new_compressed.rule_id_length == target_rule_id.1;
                let marker = if is_derived { " (DERIVED)" } else { "" };

                let base_size = base_compressed
                    .as_ref()
                    .map(|c| c.data.len() - payload.len())
                    .unwrap_or(0);
                let new_size = new_compressed.data.len() - payload.len();

                base_sizes.push(base_size);
                derived_sizes.push(new_size);

                println!(
                    "  Packet {}: Rule {}/{}{}, headers: {} → {} bytes (was {} with base rule)",
                    i + 1,
                    new_compressed.rule_id,
                    new_compressed.rule_id_length,
                    marker,
                    header_bytes,
                    new_size,
                    base_size,
                );
            }
            Err(e) => println!("  Packet {}: Error: {:?}", i + 1, e),
        }
    }

    // Summary
    if !base_sizes.is_empty() && !derived_sizes.is_empty() {
        let avg_base: f64 = base_sizes.iter().sum::<usize>() as f64 / base_sizes.len() as f64;
        let avg_derived: f64 =
            derived_sizes.iter().sum::<usize>() as f64 / derived_sizes.len() as f64;
        println!(
            "\n  Average compressed header: {:.1} bytes (base) → {:.1} bytes (derived) = {:.1}% improvement",
            avg_base,
            avg_derived,
            (1.0 - avg_derived / avg_base) * 100.0
        );

        // Assert improvement
        assert!(
            avg_derived < avg_base,
            "Derived rule should produce smaller compressed headers"
        );
        println!("  ✓ Derived rule produces smaller compressed headers");
    }

    // =========================================================================
    // Phase 6: Overhead comparison
    // =========================================================================

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  PHASE 6: Overhead comparison");
    println!("═══════════════════════════════════════════════════════════════");

    let residue_values =
        extract_residue_values(base_rule, &compressed.data).expect("Failed to extract residue");

    compare_overhead(
        base_rule_id,
        target_rule_id,
        &lock_entries,
        &residue_values,
        base_rule,
        &di_rpc,
        &compressed.data,
    );

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  DONE — All assertions passed ✓");
    println!("═══════════════════════════════════════════════════════════════\n");
}
