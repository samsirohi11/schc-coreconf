//! RPC Builder with SID-based encoding
//!
//! Builds CORECONF RPC requests using SID delta encoding for compact messages.
//! This replaces the verbose JSON string format with efficient CBOR encoding.

use ciborium::Value as CborValue;

// =============================================================================
// SID Constants for duplicate-rule RPC
// =============================================================================

/// SID for duplicate-rule RPC input container
pub const SID_DUPLICATE_RULE_INPUT: i64 = 5201;

// Deltas from input container (5201)
const DELTA_SOURCE_RULE_ID_VALUE: i64 = 1; // 5202
const DELTA_SOURCE_RULE_ID_LENGTH: i64 = 2; // 5203
const DELTA_TARGET_RULE_ID_VALUE: i64 = 3; // 5204
const DELTA_TARGET_RULE_ID_LENGTH: i64 = 4; // 5205
const DELTA_MODIFICATIONS: i64 = 5; // 5206

// Deltas for entry modifications (from entry container)
const DELTA_ENTRY_INDEX: i64 = 1;
const DELTA_TARGET_VALUE: i64 = 2;
const DELTA_MATCHING_OPERATOR: i64 = 3;
const DELTA_COMP_DECOMP_ACTION: i64 = 4;

// =============================================================================
// Entry Modification
// =============================================================================

#[derive(Debug, Clone)]
pub struct DuplicateRuleRequest {
    pub source: (u32, u8),
    pub target: (u32, u8),
    pub modifications: Vec<EntryModification>,
}

/// Entry modification using index-based addressing
///
/// Since both endpoints share the same base rule structure, modifications
/// reference entries by index only - no need to send FID/POS/DI.
#[derive(Debug, Clone)]
pub struct EntryModification {
    /// Entry index within the rule (0-based)
    pub entry_index: u16,
    /// Optional new target value (as CBOR bytes)
    pub target_value: Option<Vec<u8>>,
    /// Optional new matching operator (SID)
    pub matching_operator: Option<i64>,
    /// Optional new compression action (SID)
    pub comp_decomp_action: Option<i64>,
}

impl EntryModification {
    /// Create a new entry modification for the given index
    pub fn new(entry_index: u16) -> Self {
        Self {
            entry_index,
            target_value: None,
            matching_operator: None,
            comp_decomp_action: None,
        }
    }

    /// Set the target value as raw bytes
    pub fn with_target_value_bytes(mut self, value: Vec<u8>) -> Self {
        self.target_value = Some(value);
        self
    }

    /// Set the target value from an integer
    pub fn with_target_value_int(mut self, value: i64) -> Self {
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Integer(value.into()), &mut bytes).ok();
        self.target_value = Some(bytes);
        self
    }

    /// Set the matching operator (SID)
    pub fn with_mo(mut self, mo_sid: i64) -> Self {
        self.matching_operator = Some(mo_sid);
        self
    }

    /// Set the compression action (SID)
    pub fn with_cda(mut self, cda_sid: i64) -> Self {
        self.comp_decomp_action = Some(cda_sid);
        self
    }

    /// Convert to CBOR value
    fn to_cbor(&self) -> CborValue {
        let mut entries = vec![(
            CborValue::Integer(DELTA_ENTRY_INDEX.into()),
            CborValue::Integer((self.entry_index as i64).into()),
        )];

        if let Some(ref tv) = self.target_value {
            entries.push((
                CborValue::Integer(DELTA_TARGET_VALUE.into()),
                CborValue::Bytes(tv.clone()),
            ));
        }

        if let Some(mo) = self.matching_operator {
            entries.push((
                CborValue::Integer(DELTA_MATCHING_OPERATOR.into()),
                CborValue::Integer(mo.into()),
            ));
        }

        if let Some(cda) = self.comp_decomp_action {
            entries.push((
                CborValue::Integer(DELTA_COMP_DECOMP_ACTION.into()),
                CborValue::Integer(cda.into()),
            ));
        }

        CborValue::Map(entries)
    }
}

// =============================================================================
// RPC Builder Functions
// =============================================================================

/// Build duplicate-rule RPC using SID delta encoding
///
/// Output CBOR structure:
/// ```text
/// { 5201: { 1: src_id, 2: src_len, 3: tgt_id, 4: tgt_len, 5: [...mods...] } }
/// ```
///
/// This is significantly more compact than the JSON string format.
pub fn build_duplicate_rule_rpc(
    source: (u32, u8),
    target: (u32, u8),
    modifications: Option<&[EntryModification]>,
) -> Vec<u8> {
    let mut input_entries = vec![
        (
            CborValue::Integer(DELTA_SOURCE_RULE_ID_VALUE.into()),
            CborValue::Integer((source.0 as i64).into()),
        ),
        (
            CborValue::Integer(DELTA_SOURCE_RULE_ID_LENGTH.into()),
            CborValue::Integer((source.1 as i64).into()),
        ),
        (
            CborValue::Integer(DELTA_TARGET_RULE_ID_VALUE.into()),
            CborValue::Integer((target.0 as i64).into()),
        ),
        (
            CborValue::Integer(DELTA_TARGET_RULE_ID_LENGTH.into()),
            CborValue::Integer((target.1 as i64).into()),
        ),
    ];

    if let Some(mods) = modifications {
        let mods_array: Vec<CborValue> = mods.iter().map(|m| m.to_cbor()).collect();
        input_entries.push((
            CborValue::Integer(DELTA_MODIFICATIONS.into()),
            CborValue::Array(mods_array),
        ));
    }

    let input = CborValue::Map(input_entries);
    let root = CborValue::Map(vec![(
        CborValue::Integer(SID_DUPLICATE_RULE_INPUT.into()),
        input,
    )]);

    let mut output = Vec::new();
    if let Err(e) = ciborium::into_writer(&root, &mut output) {
        log::error!(
            "CBOR serialization failed: {:?}. This should never happen for valid input.",
            e
        );
        // Return empty vec on error - caller should check for empty result
        return Vec::new();
    }
    output
}

/// Parse a SID-encoded duplicate-rule RPC request
///
/// Returns DuplicateRuleRequest if successful.
pub fn parse_duplicate_rule_rpc(payload: &[u8]) -> Result<DuplicateRuleRequest, String> {
    let value: CborValue =
        ciborium::from_reader(payload).map_err(|e| format!("CBOR decode error: {}", e))?;

    let root_map = value.as_map().ok_or("Root is not a map")?;

    // Find input container (SID 5201)
    let input =
        find_by_key(root_map, SID_DUPLICATE_RULE_INPUT).ok_or("Input container not found")?;

    let input_map = input.as_map().ok_or("Input is not a map")?;

    // Extract source rule ID with validation
    let src_id_raw = find_integer(input_map, DELTA_SOURCE_RULE_ID_VALUE)
        .ok_or("source-rule-id-value not found")?;
    let src_id =
        u32::try_from(src_id_raw).map_err(|_| "source-rule-id-value out of range for u32")?;

    let src_len_raw = find_integer(input_map, DELTA_SOURCE_RULE_ID_LENGTH)
        .ok_or("source-rule-id-length not found")?;
    let src_len =
        u8::try_from(src_len_raw).map_err(|_| "source-rule-id-length out of range for u8")?;

    // Extract target rule ID with validation
    let tgt_id_raw = find_integer(input_map, DELTA_TARGET_RULE_ID_VALUE)
        .ok_or("target-rule-id-value not found")?;
    let tgt_id =
        u32::try_from(tgt_id_raw).map_err(|_| "target-rule-id-value out of range for u32")?;

    let tgt_len_raw = find_integer(input_map, DELTA_TARGET_RULE_ID_LENGTH)
        .ok_or("target-rule-id-length not found")?;
    let tgt_len =
        u8::try_from(tgt_len_raw).map_err(|_| "target-rule-id-length out of range for u8")?;

    // Parse modifications if present
    let mut modifications = Vec::new();
    if let Some(mods_value) = find_by_key(input_map, DELTA_MODIFICATIONS) {
        if let Some(mods_array) = mods_value.as_array() {
            for mod_value in mods_array {
                if let Some(m) = parse_entry_modification(mod_value) {
                    modifications.push(m);
                }
            }
        }
    }

    Ok(DuplicateRuleRequest {
        source: (src_id, src_len),
        target: (tgt_id, tgt_len),
        modifications,
    })
}

fn parse_entry_modification(value: &CborValue) -> Option<EntryModification> {
    let map = value.as_map()?;

    let entry_index_raw = find_integer(map, DELTA_ENTRY_INDEX)?;
    let entry_index = u16::try_from(entry_index_raw).ok()?;

    let mut modification = EntryModification::new(entry_index);

    if let Some(tv) = find_by_key(map, DELTA_TARGET_VALUE) {
        if let Some(bytes) = tv.as_bytes() {
            modification.target_value = Some(bytes.clone());
        }
    }

    if let Some(mo) = find_integer(map, DELTA_MATCHING_OPERATOR) {
        modification.matching_operator = Some(mo);
    }

    if let Some(cda) = find_integer(map, DELTA_COMP_DECOMP_ACTION) {
        modification.comp_decomp_action = Some(cda);
    }

    Some(modification)
}

// =============================================================================
// Helper Functions
// =============================================================================

fn find_by_key(map: &[(CborValue, CborValue)], key: i64) -> Option<&CborValue> {
    for (k, v) in map {
        if let CborValue::Integer(i) = k {
            if i128::from(*i) == key as i128 {
                return Some(v);
            }
        }
    }
    None
}

fn find_integer(map: &[(CborValue, CborValue)], key: i64) -> Option<i64> {
    let value = find_by_key(map, key)?;
    if let CborValue::Integer(i) = value {
        Some(i128::from(*i) as i64)
    } else {
        None
    }
}

// =============================================================================
// Overhead Analysis
// =============================================================================

/// Overhead breakdown for CORECONF duplicate-rule RPC
#[derive(Debug, Clone)]
pub struct RpcOverheadAnalysis {
    /// Total RPC payload size (CBOR bytes)
    pub total_rpc_bytes: usize,
    /// Fixed overhead: CBOR root map + RPC SID
    pub cbor_root_overhead: usize,
    /// Fixed overhead: source/target rule ID fields
    pub rule_id_overhead: usize,
    /// Fixed overhead: modifications array wrapper (if present)
    pub mods_array_overhead: usize,
    /// Per-modification overhead details
    pub modification_overheads: Vec<ModificationOverhead>,
    /// Total fixed overhead (cbor_root + rule_id + mods_array)
    pub total_fixed_overhead: usize,
    /// Total per-field overhead (sum of all modifications)
    pub total_per_field_overhead: usize,
    /// Average per-field overhead
    pub avg_per_field_overhead: f64,
}

/// Overhead breakdown for a single entry modification
#[derive(Debug, Clone)]
pub struct ModificationOverhead {
    /// Entry index being modified
    pub entry_index: u16,
    /// Overhead for entry-index field (delta + value)
    pub entry_index_bytes: usize,
    /// Overhead for target-value field (delta + CBOR header + data)
    pub target_value_bytes: Option<usize>,
    /// Size of actual target value data (without CBOR overhead)
    pub target_value_data_bytes: Option<usize>,
    /// Overhead for matching-operator field (delta + SID)
    pub mo_bytes: Option<usize>,
    /// Overhead for comp-decomp-action field (delta + SID)
    pub cda_bytes: Option<usize>,
    /// Total bytes for this modification
    pub total_bytes: usize,
    /// Overhead bytes (total - data)
    pub overhead_bytes: usize,
}

impl RpcOverheadAnalysis {
    /// Print a detailed breakdown of the overhead
    pub fn print_breakdown(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║          CORECONF RPC OVERHEAD ANALYSIS                       ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║ FIXED OVERHEAD (CoAP/CBOR RPC wrapper)                        ║");
        println!("╠───────────────────────────────────────────────────────────────╣");
        println!(
            "║  CBOR root map + RPC SID (5201):     {:>3} bytes                ║",
            self.cbor_root_overhead
        );
        println!(
            "║  Source/Target Rule IDs (4 fields):  {:>3} bytes                ║",
            self.rule_id_overhead
        );
        println!(
            "║  Modifications array wrapper:        {:>3} bytes                ║",
            self.mods_array_overhead
        );
        println!("║                                     ─────────                 ║");
        println!(
            "║  Total Fixed Overhead:               {:>3} bytes                ║",
            self.total_fixed_overhead
        );
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║ PER-FIELD OVERHEAD (Entry Modifications)                      ║");
        println!("╠───────────────────────────────────────────────────────────────╣");

        for (i, m) in self.modification_overheads.iter().enumerate() {
            println!(
                "║  Entry[{}] (index={}):                                          ║",
                i, m.entry_index
            );
            println!(
                "║    - entry-index (delta+val):        {:>3} bytes                ║",
                m.entry_index_bytes
            );
            if let Some(tv) = m.target_value_bytes {
                let data = m.target_value_data_bytes.unwrap_or(0);
                println!(
                    "║    - target-value (delta+hdr+data):  {:>3} bytes (data: {} B)    ║",
                    tv, data
                );
            }
            if let Some(mo) = m.mo_bytes {
                println!(
                    "║    - matching-operator (delta+SID):  {:>3} bytes                ║",
                    mo
                );
            }
            if let Some(cda) = m.cda_bytes {
                println!(
                    "║    - comp-decomp-action (delta+SID): {:>3} bytes                ║",
                    cda
                );
            }
            println!(
                "║    Subtotal: {} bytes (overhead: {} B, data: {} B)             ║",
                m.total_bytes,
                m.overhead_bytes,
                m.total_bytes - m.overhead_bytes
            );
            println!("║                                                               ║");
        }

        println!("╠───────────────────────────────────────────────────────────────╣");
        println!(
            "║  Total Per-Field Overhead:           {:>3} bytes                ║",
            self.total_per_field_overhead
        );
        println!(
            "║  Average Per-Field Overhead:        {:>4.1} bytes                ║",
            self.avg_per_field_overhead
        );
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║ SUMMARY                                                       ║");
        println!("╠───────────────────────────────────────────────────────────────╣");
        println!(
            "║  Total RPC Payload:                  {:>3} bytes                ║",
            self.total_rpc_bytes
        );
        println!(
            "║  Fixed Overhead:                     {:>3} bytes ({:>4.1}%)        ║",
            self.total_fixed_overhead,
            self.total_fixed_overhead as f64 / self.total_rpc_bytes as f64 * 100.0
        );
        println!(
            "║  Total Per-Field Overhead:           {:>3} bytes ({:>4.1}%)        ║",
            self.total_per_field_overhead,
            self.total_per_field_overhead as f64 / self.total_rpc_bytes as f64 * 100.0
        );
        println!("╚═══════════════════════════════════════════════════════════════╝\n");
    }
}

/// Analyze the overhead of a duplicate-rule RPC
pub fn analyze_rpc_overhead(
    source: (u32, u8),
    target: (u32, u8),
    modifications: Option<&[EntryModification]>,
) -> RpcOverheadAnalysis {
    // Build the actual RPC to get total size
    let rpc_bytes = build_duplicate_rule_rpc(source, target, modifications);
    let total_rpc_bytes = rpc_bytes.len();

    // Calculate CBOR root overhead: { SID_5201: { ... } }
    // - 1 byte: outer map header (0xa1 = map with 1 element)
    // - N bytes: integer key 5201 (0x19 0x14 0x51 = 3 bytes for uint16)
    // - 1 byte: inner map header (0xa4/0xa5 = map with 4-5 elements)
    let cbor_root_overhead = 1 + cbor_integer_size(SID_DUPLICATE_RULE_INPUT) + 1;

    // Calculate rule ID overhead (4 fields with small integer values)
    // Each field: 1 byte delta + 1-2 bytes value
    // source-rule-id-value: delta 1 + value (1-5 bytes depending on size)
    // source-rule-id-length: delta 2 + value 1 byte
    // target-rule-id-value: delta 3 + value (1-5 bytes)
    // target-rule-id-length: delta 4 + value 1 byte
    let rule_id_overhead = measure_rule_id_fields(source, target);

    // Calculate modifications array overhead
    let mods_array_overhead = if modifications.is_some() && !modifications.unwrap().is_empty() {
        // delta 5 (1 byte) + array header (1-2 bytes depending on count)
        // let count = modifications.unwrap().len();
        if let Some(mods) = modifications {
            let count = mods.len();
            if count < 24 {
                2
            } else {
                3
            }
        } else {
            0
        }
    } else {
        0
    };

    // Calculate per-modification overhead
    let modification_overheads: Vec<ModificationOverhead> = modifications
        .map(|mods| mods.iter().map(analyze_modification_overhead).collect())
        .unwrap_or_default();

    let total_per_field_overhead: usize =
        modification_overheads.iter().map(|m| m.total_bytes).sum();
    let avg_per_field_overhead = if modification_overheads.is_empty() {
        0.0
    } else {
        total_per_field_overhead as f64 / modification_overheads.len() as f64
    };

    let total_fixed_overhead = cbor_root_overhead + rule_id_overhead + mods_array_overhead;

    RpcOverheadAnalysis {
        total_rpc_bytes,
        cbor_root_overhead,
        rule_id_overhead,
        mods_array_overhead,
        modification_overheads,
        total_fixed_overhead,
        total_per_field_overhead,
        avg_per_field_overhead,
    }
}

fn measure_rule_id_fields(source: (u32, u8), target: (u32, u8)) -> usize {
    let mut size = 0;

    // source-rule-id-value: delta 1 (1 byte) + value
    size += 1 + cbor_integer_size(source.0 as i64);
    // source-rule-id-length: delta 2 (1 byte) + value
    size += 1 + cbor_integer_size(source.1 as i64);
    // target-rule-id-value: delta 3 (1 byte) + value
    size += 1 + cbor_integer_size(target.0 as i64);
    // target-rule-id-length: delta 4 (1 byte) + value
    size += 1 + cbor_integer_size(target.1 as i64);

    size
}

fn analyze_modification_overhead(m: &EntryModification) -> ModificationOverhead {
    // Entry index: delta (1 byte) + value (1-2 bytes)
    let entry_index_bytes = 1 + cbor_integer_size(m.entry_index as i64);

    // Target value: delta (1 byte) + CBOR bytes header (2-3 bytes) + data
    let (target_value_bytes, target_value_data_bytes) = if let Some(ref tv) = m.target_value {
        let data_len = tv.len();
        let header_len = if data_len < 24 {
            1
        } else if data_len < 256 {
            2
        } else {
            3
        };
        (Some(1 + header_len + data_len), Some(data_len))
    } else {
        (None, None)
    };

    // Matching operator: delta (1 byte) + SID (2-3 bytes)
    let mo_bytes = m.matching_operator.map(|sid| 1 + cbor_integer_size(sid));

    // Comp-decomp-action: delta (1 byte) + SID (2-3 bytes)
    let cda_bytes = m.comp_decomp_action.map(|sid| 1 + cbor_integer_size(sid));

    // Map wrapper overhead: 1 byte for small maps
    let map_overhead = 1;

    let total_bytes = map_overhead
        + entry_index_bytes
        + target_value_bytes.unwrap_or(0)
        + mo_bytes.unwrap_or(0)
        + cda_bytes.unwrap_or(0);

    // Overhead = total - actual data
    let data_bytes = target_value_data_bytes.unwrap_or(0);
    let overhead_bytes = total_bytes - data_bytes;

    ModificationOverhead {
        entry_index: m.entry_index,
        entry_index_bytes,
        target_value_bytes,
        target_value_data_bytes,
        mo_bytes,
        cda_bytes,
        total_bytes,
        overhead_bytes,
    }
}

/// Calculate CBOR encoding size for an integer
fn cbor_integer_size(value: i64) -> usize {
    if value >= 0 {
        if value < 24 {
            1
        } else if value < 256 {
            2
        } else if value < 65536 {
            3
        } else if value < 4294967296 {
            5
        } else {
            9
        }
    } else {
        let abs_val = (-1 - value) as u64;
        if abs_val < 24 {
            1
        } else if abs_val < 256 {
            2
        } else if abs_val < 65536 {
            3
        } else if abs_val < 4294967296 {
            5
        } else {
            9
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_duplicate_rule_rpc_no_mods() {
        let payload = build_duplicate_rule_rpc((8, 4), (8, 5), None);
        assert!(!payload.is_empty());

        // Verify we can parse it back
        let request = parse_duplicate_rule_rpc(&payload).unwrap();

        assert_eq!(request.source.0, 8);
        assert_eq!(request.source.1, 4);
        assert_eq!(request.target.0, 8);
        assert_eq!(request.target.1, 5);
        assert!(request.modifications.is_empty());
    }

    #[test]
    fn test_build_duplicate_rule_rpc_with_mods() {
        let mods = vec![
            EntryModification::new(3)
                .with_mo(2900) // SID_MO_EQUAL
                .with_cda(2920), // SID_CDA_NOT_SENT
            EntryModification::new(5).with_target_value_int(12345),
        ];

        let payload = build_duplicate_rule_rpc((8, 4), (16, 5), Some(&mods));

        // Parse and verify
        let request = parse_duplicate_rule_rpc(&payload).unwrap();

        assert_eq!(request.source.0, 8);
        assert_eq!(request.source.1, 4);
        assert_eq!(request.target.0, 16);
        assert_eq!(request.target.1, 5);
        assert_eq!(request.modifications.len(), 2);
        assert_eq!(request.modifications[0].entry_index, 3);
        assert_eq!(request.modifications[0].matching_operator, Some(2900));
        assert_eq!(request.modifications[1].entry_index, 5);
    }

    #[test]
    fn test_rpc_size_comparison() {
        // Build the SID-encoded version
        let sid_payload = build_duplicate_rule_rpc((8, 4), (8, 5), None);

        // Build the equivalent JSON string version
        let json_value = serde_json::json!({
            "input": {
                "source-rule-id-value": 8,
                "source-rule-id-length": 4,
                "target-rule-id-value": 8,
                "target-rule-id-length": 5
            }
        });
        let mut json_cbor = Vec::new();
        ciborium::into_writer(&json_value, &mut json_cbor).unwrap();

        // SID-encoded should be smaller
        println!(
            "SID-encoded: {} bytes, JSON-string: {} bytes, savings: {:.1}%",
            sid_payload.len(),
            json_cbor.len(),
            (1.0 - sid_payload.len() as f64 / json_cbor.len() as f64) * 100.0
        );

        // Verify SID encoding is more compact
        assert!(
            sid_payload.len() < json_cbor.len(),
            "SID encoding should be more compact"
        );
    }
}
