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
const DELTA_SOURCE_RULE_ID_VALUE: i64 = 1;  // 5202
const DELTA_SOURCE_RULE_ID_LENGTH: i64 = 2; // 5203
const DELTA_TARGET_RULE_ID_VALUE: i64 = 3;  // 5204
const DELTA_TARGET_RULE_ID_LENGTH: i64 = 4; // 5205
const DELTA_MODIFICATIONS: i64 = 5;         // 5206

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
    ciborium::into_writer(&root, &mut output).expect("CBOR serialization should succeed");
    output
}

/// Parse a SID-encoded duplicate-rule RPC request
///
/// Returns DuplicateRuleRequest if successful.
pub fn parse_duplicate_rule_rpc(
    payload: &[u8],
) -> Result<DuplicateRuleRequest, String> {
    let value: CborValue =
        ciborium::from_reader(payload).map_err(|e| format!("CBOR decode error: {}", e))?;

    let root_map = value
        .as_map()
        .ok_or("Root is not a map")?;

    // Find input container (SID 5201)
    let input = find_by_key(root_map, SID_DUPLICATE_RULE_INPUT)
        .ok_or("Input container not found")?;

    let input_map = input
        .as_map()
        .ok_or("Input is not a map")?;

    // Extract source rule ID with validation
    let src_id_raw = find_integer(input_map, DELTA_SOURCE_RULE_ID_VALUE)
        .ok_or("source-rule-id-value not found")?;
    let src_id = u32::try_from(src_id_raw)
        .map_err(|_| "source-rule-id-value out of range for u32")?;

    let src_len_raw = find_integer(input_map, DELTA_SOURCE_RULE_ID_LENGTH)
        .ok_or("source-rule-id-length not found")?;
    let src_len = u8::try_from(src_len_raw)
        .map_err(|_| "source-rule-id-length out of range for u8")?;

    // Extract target rule ID with validation
    let tgt_id_raw = find_integer(input_map, DELTA_TARGET_RULE_ID_VALUE)
        .ok_or("target-rule-id-value not found")?;
    let tgt_id = u32::try_from(tgt_id_raw)
        .map_err(|_| "target-rule-id-value out of range for u32")?;

    let tgt_len_raw = find_integer(input_map, DELTA_TARGET_RULE_ID_LENGTH)
        .ok_or("target-rule-id-length not found")?;
    let tgt_len = u8::try_from(tgt_len_raw)
        .map_err(|_| "target-rule-id-length out of range for u8")?;

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
