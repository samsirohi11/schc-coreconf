//! SOR (CORECONF CBOR) Rule Loader
//!
//! Parse SCHC rules from .sor files (CBOR-encoded CORECONF format) using SID mapping.
//! This enables loading rules in the IETF standard YANG-based format.

use std::fs;
use std::path::Path;

use ciborium::Value as CborValue;
use rust_coreconf::SidFile;
use schc::{CompressionAction, Field, FieldId, FieldLength, MatchingOperator, Rule};

use crate::error::{Error, Result};

// =============================================================================
// SID Constants (from ietf-schc@2026-01-12.sid)
// =============================================================================

/// Root SID for ietf-schc:schc
const SID_SCHC_ROOT: i64 = 2574;

/// Rule list (delta from root)
const DELTA_RULE: i64 = 23; // 2597

/// Rule metadata deltas (from rule SID 2597)
const DELTA_RULE_ID_LENGTH: i64 = 1; // 2598
const DELTA_RULE_ID_VALUE: i64 = 2; // 2599
#[allow(dead_code)]
const DELTA_RULE_NATURE: i64 = 3; // 2600

/// Entry list delta (from rule)
const DELTA_ENTRY: i64 = 23; // 2620

/// Entry field deltas (from entry SID 2620)
#[allow(dead_code)]
const DELTA_ENTRY_INDEX: i64 = 1; // 2621
#[allow(dead_code)]
const DELTA_SPACE_ID: i64 = 2; // 2622
const DELTA_FIELD_ID: i64 = 3; // 2623
const DELTA_FIELD_LENGTH: i64 = 4; // 2624
#[allow(dead_code)]
const DELTA_FIELD_LENGTH_VALUE: i64 = 5; // 2625
const DELTA_DIRECTION: i64 = 6; // 2626
#[allow(dead_code)]
const DELTA_FIELD_POSITION: i64 = 7; // 2627
const DELTA_TARGET_VALUE: i64 = 8; // 2628

// Identity SIDs for Direction Indicator
const SID_DI_BIDIRECTIONAL: i64 = 2880;
const SID_DI_DOWN: i64 = 2881;
const SID_DI_UP: i64 = 2882;
const DELTA_MO: i64 = 11; // 2631
const DELTA_MO_VALUE: i64 = 12; // 2632
const DELTA_CDA: i64 = 15; // 2635

// Identity SIDs for Matching Operators
const SID_MO_EQUAL: i64 = 2900;
const SID_MO_IGNORE: i64 = 2901;
const SID_MO_MATCH_MAPPING: i64 = 2902;
const SID_MO_MSB: i64 = 2903;

// Identity SIDs for Compression Actions
const SID_CDA_NOT_SENT: i64 = 2920;
const SID_CDA_VALUE_SENT: i64 = 2921;
const SID_CDA_MAPPING_SENT: i64 = 2922;
const SID_CDA_LSB: i64 = 2923;
const SID_CDA_COMPUTE: i64 = 2924;

// Identity SIDs for Field Length functions
const SID_FL_LENGTH_BITS: i64 = 2890;
const SID_FL_LENGTH_BYTES: i64 = 2891;
const SID_FL_TOKEN_LENGTH: i64 = 2892;
const SID_FL_VARIABLE: i64 = 2893;

// Identity SID for CoAP Space ID (universal options)
const SID_SPACE_ID_COAP: i64 = 2930;

// Negative deltas for universal option entries (CoAP options, etc.)
// These are used instead of positive deltas when encoding CoAP options
const NEG_DELTA_SPACE_ID: i64 = -4;
const NEG_DELTA_OPTION_NUM: i64 = -5;
const NEG_DELTA_FIELD_LENGTH: i64 = -11;
const NEG_DELTA_DIRECTION: i64 = -12;
const NEG_DELTA_TARGET_VALUE: i64 = -3;
const NEG_DELTA_MO: i64 = -9;
const NEG_DELTA_MO_VALUE: i64 = -8;
const NEG_DELTA_CDA: i64 = -16;

// =============================================================================
// Public API
// =============================================================================

/// Load SCHC rules from a .sor (CORECONF CBOR) file
///
/// # Arguments
/// * `sor_path` - Path to the .sor file
/// * `sid_file` - Parsed SID file for identifier resolution
///
/// # Returns
/// Vector of parsed SCHC Rules
pub fn load_sor_rules(sor_path: impl AsRef<Path>, sid_file: &SidFile) -> Result<Vec<Rule>> {
    let cbor_bytes = fs::read(sor_path.as_ref())
        .map_err(|e| Error::Coreconf(format!("Failed to read .sor file: {}", e)))?;

    parse_cbor_rules(&cbor_bytes, sid_file)
}

/// Parse SCHC rules from CBOR bytes
pub fn parse_cbor_rules(cbor_bytes: &[u8], sid_file: &SidFile) -> Result<Vec<Rule>> {
    let cbor_value: CborValue = ciborium::from_reader(cbor_bytes)
        .map_err(|e| Error::Coreconf(format!("Failed to parse CBOR: {}", e)))?;

    parse_cbor_value(&cbor_value, sid_file)
}

/// Parse SCHC rules from a CBOR Value
fn parse_cbor_value(cbor_value: &CborValue, sid_file: &SidFile) -> Result<Vec<Rule>> {
    // Root structure: { 2574: { 23: [...rules...] } }
    let root_map = cbor_value
        .as_map()
        .ok_or_else(|| Error::Coreconf("CBOR root is not a map".to_string()))?;

    // Find the schc container (SID 2574 or delta from context)
    let schc_container = find_value_by_sid(root_map, SID_SCHC_ROOT)
        .ok_or_else(|| Error::Coreconf(format!("SCHC root (SID {}) not found", SID_SCHC_ROOT)))?;

    let schc_map = schc_container
        .as_map()
        .ok_or_else(|| Error::Coreconf("SCHC container is not a map".to_string()))?;

    // Find rule list (delta 23 from root)
    let rules_array = find_value_by_delta(schc_map, DELTA_RULE)
        .ok_or_else(|| Error::Coreconf("Rule list not found".to_string()))?;

    let rules_list = rules_array
        .as_array()
        .ok_or_else(|| Error::Coreconf("Rules is not an array".to_string()))?;

    let mut rules = Vec::new();

    for rule_value in rules_list {
        match parse_rule(rule_value, sid_file) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                log::warn!("Failed to parse rule: {}", e);
                // Continue parsing other rules
            }
        }
    }

    Ok(rules)
}

// =============================================================================
// Rule Parsing
// =============================================================================

fn parse_rule(rule_value: &CborValue, sid_file: &SidFile) -> Result<Rule> {
    let rule_map = rule_value
        .as_map()
        .ok_or_else(|| Error::Coreconf("Rule is not a map".to_string()))?;

    // Extract rule metadata - these are required fields, not optional
    let rule_id_length_raw = find_integer_by_delta(rule_map, DELTA_RULE_ID_LENGTH)
        .ok_or_else(|| Error::Coreconf("Missing required field: rule-id-length".to_string()))?;
    let rule_id_length = u8::try_from(rule_id_length_raw).map_err(|_| {
        Error::Coreconf(format!(
            "rule-id-length out of range: {}",
            rule_id_length_raw
        ))
    })?;

    let rule_id_value_raw = find_integer_by_delta(rule_map, DELTA_RULE_ID_VALUE)
        .ok_or_else(|| Error::Coreconf("Missing required field: rule-id-value".to_string()))?;
    let rule_id_value = u32::try_from(rule_id_value_raw).map_err(|_| {
        Error::Coreconf(format!("rule-id-value out of range: {}", rule_id_value_raw))
    })?;

    // Parse entries (fields)
    let entries = find_value_by_delta(rule_map, DELTA_ENTRY);

    let mut compression = Vec::new();
    if let Some(entries_value) = entries {
        if let Some(entries_array) = entries_value.as_array() {
            for entry in entries_array {
                match parse_field_entry(entry, sid_file) {
                    Ok(mut field) => {
                        // Parse the target value to populate parsed_tv
                        // This is needed for the tree builder and compressor
                        if let Err(e) = field.parse_tv() {
                            log::warn!("Failed to parse TV for field {:?}: {}", field.fid, e);
                        }
                        compression.push(field);
                    }
                    Err(e) => {
                        log::debug!("Skipping field: {}", e);
                    }
                }
            }
        }
    }

    Ok(Rule {
        rule_id: rule_id_value,
        rule_id_length,
        comment: None,
        compression,
    })
}

fn parse_field_entry(entry_value: &CborValue, sid_file: &SidFile) -> Result<Field> {
    let entry_map = entry_value
        .as_map()
        .ok_or_else(|| Error::Coreconf("Entry is not a map".to_string()))?;

    // Check for negative keys (universal options) vs positive keys (normal fields)
    let has_negative_keys = entry_map
        .iter()
        .any(|(k, _)| k.as_integer().map(|i| i128::from(i) < 0).unwrap_or(false));

    if has_negative_keys {
        parse_universal_option_entry(entry_map, sid_file)
    } else {
        parse_normal_field_entry(entry_map, sid_file)
    }
}

fn parse_normal_field_entry(
    entry_map: &[(CborValue, CborValue)],
    sid_file: &SidFile,
) -> Result<Field> {
    let space_id = find_integer_by_delta(entry_map, DELTA_SPACE_ID);

    // Field ID (delta +3 = 2623)
    let (fid, coap_option_number) = if space_id == Some(SID_SPACE_ID_COAP) {
        // In CoAP option space, field-id is the CoAP option number itself.
        let option_num_raw = find_integer_by_delta(entry_map, DELTA_FIELD_ID)
            .ok_or_else(|| Error::Coreconf("Field ID not found".to_string()))?;
        let option_num = u16::try_from(option_num_raw).map_err(|_| {
            Error::Coreconf(format!(
                "CoAP option number out of range for field-id: {}",
                option_num_raw
            ))
        })?;
        (coap_option_to_field_id(option_num), Some(option_num))
    } else {
        let fid_sid = find_integer_by_delta(entry_map, DELTA_FIELD_ID)
            .ok_or_else(|| Error::Coreconf("Field ID not found".to_string()))?;
        let fid = sid_to_field_id(fid_sid, sid_file)?;
        (fid, field_id_to_coap_option_num(fid))
    };

    // Field Length (delta +4 = 2624) — union of uint8 (fixed) or identity SID (function)
    // Field Length Value (delta +5 = 2625) — argument for some fl functions
    let (fl, fl_func) = parse_field_length(entry_map);

    // Direction Indicator (delta +6 = 2626, identityref)
    let di = find_integer_by_delta(entry_map, DELTA_DIRECTION).and_then(sid_to_direction);

    // Target Value (delta +8 = 2628)
    let tv = parse_target_value(entry_map, DELTA_TARGET_VALUE);

    // Matching Operator (delta +11 = 2631, identityref)
    let mo_sid = find_integer_by_delta(entry_map, DELTA_MO)
        .ok_or_else(|| Error::Coreconf("MO not found".to_string()))?;

    // MO Value (delta +12 = 2632)
    let mo_val = parse_mo_value(entry_map);

    let mo = sid_to_mo(mo_sid, mo_val)?;

    // Compression Action (delta +15 = 2635, identityref)
    let cda_sid = find_integer_by_delta(entry_map, DELTA_CDA)
        .ok_or_else(|| Error::Coreconf("CDA not found".to_string()))?;

    let cda = sid_to_cda(cda_sid, mo_val)?;

    Ok(Field {
        fid,
        fl,
        fp: None,
        coap_option_number,
        di,
        tv,
        mo,
        mo_val,
        cda,
        parsed_tv: None,
        fl_func,
    })
}

fn parse_universal_option_entry(
    entry_map: &[(CborValue, CborValue)],
    _sid_file: &SidFile,
) -> Result<Field> {
    // Universal options use negative deltas
    // space-id: -4, option-num: -5, FL: -11, DI: -12, MO: -9, CDA: -16

    let option_num = find_integer_by_neg_delta(entry_map, 5);

    // For universal options, create a CoAP option field ID based on option number
    let fid = if let Some(opt_num) = option_num {
        coap_option_to_field_id(opt_num as u16)
    } else {
        return Err(Error::Coreconf(
            "Universal option without option number".to_string(),
        ));
    };

    // Field Length (negative delta -11) — union of uint8 or identity SID
    let (fl, fl_func) = parse_field_length_neg(entry_map);

    // Direction Indicator (negative delta -12)
    let di = find_integer_by_neg_delta(entry_map, 12).and_then(sid_to_direction);

    // Target Value (negative delta -3)
    let tv = parse_target_value_neg(entry_map, 3);

    // MO (negative delta -9)
    let mo_sid = find_integer_by_neg_delta(entry_map, 9)
        .ok_or_else(|| Error::Coreconf("MO not found in universal option".to_string()))?;

    // MO Value (negative delta -8)
    let mo_val = parse_mo_value_neg(entry_map);

    let mo = sid_to_mo(mo_sid, mo_val)?;

    // CDA (negative delta -16)
    let cda_sid = find_integer_by_neg_delta(entry_map, 16)
        .ok_or_else(|| Error::Coreconf("CDA not found in universal option".to_string()))?;

    let cda = sid_to_cda(cda_sid, mo_val)?;

    Ok(Field {
        fid,
        fl,
        fp: None,
        coap_option_number: option_num.map(|n| n as u16),
        di,
        tv,
        mo,
        mo_val,
        cda,
        parsed_tv: None,
        fl_func,
    })
}

// =============================================================================
// Value Parsing Helpers
// =============================================================================

/// Parse field-length from a normal entry (positive deltas)
/// Returns (fl as fixed u16 if integer, fl_func if identity SID)
fn parse_field_length(entry_map: &[(CborValue, CborValue)]) -> (Option<u16>, Option<FieldLength>) {
    let fl_value = find_value_by_delta(entry_map, DELTA_FIELD_LENGTH);
    let fl_arg = find_integer_by_delta(entry_map, DELTA_FIELD_LENGTH_VALUE).map(|v| v as usize);
    parse_fl_value(fl_value, fl_arg)
}

/// Parse field-length from a universal option entry (negative deltas)
fn parse_field_length_neg(
    entry_map: &[(CborValue, CborValue)],
) -> (Option<u16>, Option<FieldLength>) {
    let fl_value = find_value_by_neg_delta(entry_map, 11);
    // field-length-value uses negative delta -10 (2625 relative encoding)
    let fl_arg = find_integer_by_neg_delta(entry_map, 10).map(|v| v as usize);
    parse_fl_value(fl_value, fl_arg)
}

/// Shared logic: interpret FL CBOR value as fixed integer or identity SID
fn parse_fl_value(
    fl_value: Option<&CborValue>,
    fl_arg: Option<usize>,
) -> (Option<u16>, Option<FieldLength>) {
    match fl_value.and_then(cbor_integer_value) {
        Some(val) => {
            // Distinguish between a small fixed length (uint8) and an identity SID (>= 2890)
            match val {
                SID_FL_TOKEN_LENGTH => (None, Some(FieldLength::TokenLength)),
                SID_FL_LENGTH_BYTES => (None, Some(FieldLength::LengthBytes(fl_arg.unwrap_or(0)))),
                SID_FL_LENGTH_BITS => (None, Some(FieldLength::LengthBits(fl_arg.unwrap_or(0)))),
                SID_FL_VARIABLE => (None, Some(FieldLength::Variable)),
                v if (0..=255).contains(&v) => (Some(v as u16), None), // uint8 fixed length
                _ => (None, None),                                     // Unknown
            }
        }
        None => (None, None),
    }
}

fn parse_target_value(
    entry_map: &[(CborValue, CborValue)],
    delta: i64,
) -> Option<serde_json::Value> {
    let tv_value = find_value_by_delta(entry_map, delta)?;
    cbor_to_json_tv(tv_value)
}

fn parse_target_value_neg(
    entry_map: &[(CborValue, CborValue)],
    neg_delta: i64,
) -> Option<serde_json::Value> {
    let tv_value = find_value_by_neg_delta(entry_map, neg_delta)?;
    cbor_to_json_tv(tv_value)
}

fn cbor_to_json_tv(tv_value: &CborValue) -> Option<serde_json::Value> {
    match tv_value {
        CborValue::Integer(i) => {
            let val: i128 = (*i).into();
            Some(serde_json::Value::Number(serde_json::Number::from(
                val as i64,
            )))
        }
        CborValue::Bytes(b) => {
            // Convert small byte values to integer, larger ones to hex string
            // Use 4-byte threshold to keep IPv6 prefixes (8 bytes) as hex strings
            if b.len() <= 4 {
                let mut val: u64 = 0;
                for byte in b.iter() {
                    val = (val << 8) | (*byte as u64);
                }
                Some(serde_json::Value::Number(serde_json::Number::from(val)))
            } else {
                Some(serde_json::Value::String(hex::encode(b)))
            }
        }
        CborValue::Text(s) => Some(serde_json::Value::String(s.clone())),
        CborValue::Array(arr) => {
            // Handle TV list (match-mapping)
            let values: Vec<serde_json::Value> = arr
                .iter()
                .filter_map(|v| {
                    // Each item may be {index: i, value: v} structure
                    if let Some(map) = v.as_map() {
                        // Extract value from {2: value} (delta +2 is "value" field)
                        find_value_by_delta(map, 2).and_then(cbor_to_json_tv)
                    } else {
                        cbor_to_json_tv(v)
                    }
                })
                .collect();
            if values.is_empty() {
                None
            } else if values.len() == 1 {
                values.into_iter().next()
            } else {
                Some(serde_json::Value::Array(values))
            }
        }
        _ => None,
    }
}

fn parse_mo_value(entry_map: &[(CborValue, CborValue)]) -> Option<u8> {
    let mo_value_array = find_value_by_delta(entry_map, DELTA_MO_VALUE)?;
    extract_first_mo_value(mo_value_array)
}

fn parse_mo_value_neg(entry_map: &[(CborValue, CborValue)]) -> Option<u8> {
    let mo_value_array = find_value_by_neg_delta(entry_map, 8)?;
    extract_first_mo_value(mo_value_array)
}

fn extract_first_mo_value(mo_value_array: &CborValue) -> Option<u8> {
    let arr = mo_value_array.as_array()?;
    let first = arr.first()?;

    if let Some(map) = first.as_map() {
        // Structure: {index: 0, value: <bytes or int>}
        // value is at delta +2
        let value = find_value_by_delta(map, 2)?;
        match value {
            CborValue::Integer(i) => {
                let val: i128 = (*i).into();
                if (0..=255).contains(&val) {
                    Some(val as u8)
                } else {
                    None // Value out of u8 range
                }
            }
            CborValue::Bytes(b) if !b.is_empty() => Some(b[0]),
            _ => None,
        }
    } else {
        None
    }
}

// =============================================================================
// Map Navigation Helpers
// =============================================================================

fn find_value_by_sid(map: &[(CborValue, CborValue)], sid: i64) -> Option<&CborValue> {
    for (key, value) in map {
        if let CborValue::Integer(i) = key {
            if i128::from(*i) == sid as i128 {
                return Some(value);
            }
        }
    }
    None
}

fn find_value_by_delta(map: &[(CborValue, CborValue)], delta: i64) -> Option<&CborValue> {
    for (key, value) in map {
        if let CborValue::Integer(i) = key {
            if i128::from(*i) == delta as i128 {
                return Some(value);
            }
        }
    }
    None
}

fn find_value_by_neg_delta(map: &[(CborValue, CborValue)], neg_delta: i64) -> Option<&CborValue> {
    let target = -(neg_delta as i128);
    for (key, value) in map {
        if let CborValue::Integer(i) = key {
            if i128::from(*i) == target {
                return Some(value);
            }
        }
    }
    None
}

fn find_integer_by_delta(map: &[(CborValue, CborValue)], delta: i64) -> Option<i64> {
    let value = find_value_by_delta(map, delta)?;
    cbor_integer_value(value)
}

fn find_integer_by_neg_delta(map: &[(CborValue, CborValue)], neg_delta: i64) -> Option<i64> {
    let value = find_value_by_neg_delta(map, neg_delta)?;
    cbor_integer_value(value)
}

fn cbor_integer_value(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Integer(i) => Some(i128::from(*i) as i64),
        CborValue::Tag(_, inner) => cbor_integer_value(inner),
        _ => None,
    }
}

// =============================================================================
// SID to Type Conversions
// =============================================================================

fn sid_to_field_id(sid: i64, _sid_file: &SidFile) -> Result<FieldId> {
    // Map field SIDs to FieldId enum
    match sid {
        // IPv6 fields
        2860 => Ok(FieldId::Ipv6Ver),
        2861 => Ok(FieldId::Ipv6Tc),
        2864 => Ok(FieldId::Ipv6Fl),
        2865 => Ok(FieldId::Ipv6Len),
        2866 => Ok(FieldId::Ipv6Nxt),
        2867 => Ok(FieldId::Ipv6HopLmt),
        2868 => Ok(FieldId::Ipv6DevIid),
        2869 => Ok(FieldId::Ipv6DevPrefix),
        2870 => Ok(FieldId::Ipv6AppIid),
        2871 => Ok(FieldId::Ipv6AppPrefix),

        // UDP fields
        2850 => Ok(FieldId::UdpDevPort),
        2851 => Ok(FieldId::UdpAppPort),
        2852 => Ok(FieldId::UdpLen),
        2853 => Ok(FieldId::UdpCksum),

        // CoAP fields
        2840 => Ok(FieldId::CoapVer),
        2841 => Ok(FieldId::CoapType),
        2842 => Ok(FieldId::CoapTkl),
        2843 => Ok(FieldId::CoapCode),
        2846 => Ok(FieldId::CoapMid),
        2847 => Ok(FieldId::CoapToken),

        // ICMPv6 fields
        2810 => Ok(FieldId::Icmpv6Type),
        2811 => Ok(FieldId::Icmpv6Code),
        2812 => Ok(FieldId::Icmpv6Checksum),
        2813 => Ok(FieldId::Icmpv6Identifier),
        2814 => Ok(FieldId::Icmpv6Mtu),
        2815 => Ok(FieldId::Icmpv6Pointer),
        2816 => Ok(FieldId::Icmpv6Sequence),
        2817 => Ok(FieldId::Icmpv6Payload),

        _ => Err(Error::Coreconf(format!("Unknown field SID: {}", sid))),
    }
}

fn coap_option_to_field_id(option_num: u16) -> FieldId {
    // Map CoAP option numbers to FieldId
    match option_num {
        1 => FieldId::CoapIfMatch,
        3 => FieldId::CoapUriHost,
        4 => FieldId::CoapEtag,
        5 => FieldId::CoapIfNoneMatch,
        6 => FieldId::CoapObserve,
        7 => FieldId::CoapUriPort,
        8 => FieldId::CoapLocationPath,
        11 => FieldId::CoapUriPath,
        12 => FieldId::CoapContentFormat,
        14 => FieldId::CoapMaxAge,
        15 => FieldId::CoapUriQuery,
        17 => FieldId::CoapAccept,
        20 => FieldId::CoapLocationQuery,
        23 => FieldId::CoapBlock2,
        27 => FieldId::CoapBlock1,
        28 => FieldId::CoapSize2,
        35 => FieldId::CoapProxyUri,
        39 => FieldId::CoapProxyScheme,
        60 => FieldId::CoapSize1,
        258 => FieldId::CoapNoResponse,
        // Default to generic option for unknown
        _ => FieldId::CoapOption,
    }
}

/// Check if a FieldId represents a CoAP option (that requires universal option encoding)
fn is_coap_option(fid: FieldId) -> bool {
    matches!(
        fid,
        FieldId::CoapIfMatch
            | FieldId::CoapUriHost
            | FieldId::CoapEtag
            | FieldId::CoapIfNoneMatch
            | FieldId::CoapObserve
            | FieldId::CoapUriPort
            | FieldId::CoapLocationPath
            | FieldId::CoapUriPath
            | FieldId::CoapContentFormat
            | FieldId::CoapMaxAge
            | FieldId::CoapUriQuery
            | FieldId::CoapAccept
            | FieldId::CoapLocationQuery
            | FieldId::CoapBlock2
            | FieldId::CoapBlock1
            | FieldId::CoapSize2
            | FieldId::CoapProxyUri
            | FieldId::CoapProxyScheme
            | FieldId::CoapSize1
            | FieldId::CoapNoResponse
            | FieldId::CoapOption
    )
}

/// Map FieldId to CoAP option number (reverse of coap_option_to_field_id)
fn field_id_to_coap_option_num(fid: FieldId) -> Option<u16> {
    match fid {
        FieldId::CoapIfMatch => Some(1),
        FieldId::CoapUriHost => Some(3),
        FieldId::CoapEtag => Some(4),
        FieldId::CoapIfNoneMatch => Some(5),
        FieldId::CoapObserve => Some(6),
        FieldId::CoapUriPort => Some(7),
        FieldId::CoapLocationPath => Some(8),
        FieldId::CoapUriPath => Some(11),
        FieldId::CoapContentFormat => Some(12),
        FieldId::CoapMaxAge => Some(14),
        FieldId::CoapUriQuery => Some(15),
        FieldId::CoapAccept => Some(17),
        FieldId::CoapLocationQuery => Some(20),
        FieldId::CoapBlock2 => Some(23),
        FieldId::CoapBlock1 => Some(27),
        FieldId::CoapSize2 => Some(28),
        FieldId::CoapProxyUri => Some(35),
        FieldId::CoapProxyScheme => Some(39),
        FieldId::CoapSize1 => Some(60),
        FieldId::CoapNoResponse => Some(258),
        // Generic CoAP option doesn't have a fixed number
        FieldId::CoapOption => None,
        _ => None,
    }
}

fn sid_to_mo(sid: i64, mo_val: Option<u8>) -> Result<MatchingOperator> {
    match sid {
        SID_MO_EQUAL => Ok(MatchingOperator::Equal),
        SID_MO_IGNORE => Ok(MatchingOperator::Ignore),
        SID_MO_MATCH_MAPPING => Ok(MatchingOperator::MatchMapping),
        SID_MO_MSB => Ok(MatchingOperator::Msb(mo_val.unwrap_or(0))),
        _ => Err(Error::Coreconf(format!("Unknown MO SID: {}", sid))),
    }
}

fn sid_to_cda(sid: i64, _mo_val: Option<u8>) -> Result<CompressionAction> {
    match sid {
        SID_CDA_NOT_SENT => Ok(CompressionAction::NotSent),
        SID_CDA_VALUE_SENT => Ok(CompressionAction::ValueSent),
        SID_CDA_MAPPING_SENT => Ok(CompressionAction::MappingSent),
        SID_CDA_LSB => Ok(CompressionAction::Lsb),
        SID_CDA_COMPUTE => Ok(CompressionAction::Compute),
        _ => Err(Error::Coreconf(format!("Unknown CDA SID: {}", sid))),
    }
}

fn sid_to_direction(sid: i64) -> Option<schc::Direction> {
    match sid {
        SID_DI_UP => Some(schc::Direction::Up),
        SID_DI_DOWN => Some(schc::Direction::Down),
        SID_DI_BIDIRECTIONAL => None, // Bidirectional means applies to both directions
        _ => None,                    // Unknown direction, treat as bidirectional
    }
}

// =============================================================================
// Reverse Mappings (FieldId/MO/CDA -> SID)
// =============================================================================

/// Get the SID for a FieldId
pub fn field_id_to_sid(fid: FieldId) -> Option<i64> {
    match fid {
        // IPv6 fields
        FieldId::Ipv6Ver => Some(2860),
        FieldId::Ipv6Tc => Some(2861),
        FieldId::Ipv6Fl => Some(2864),
        FieldId::Ipv6Len => Some(2865),
        FieldId::Ipv6Nxt => Some(2866),
        FieldId::Ipv6HopLmt => Some(2867),
        FieldId::Ipv6DevIid => Some(2868),
        FieldId::Ipv6DevPrefix => Some(2869),
        FieldId::Ipv6AppIid => Some(2870),
        FieldId::Ipv6AppPrefix => Some(2871),

        // UDP fields
        FieldId::UdpDevPort => Some(2850),
        FieldId::UdpAppPort => Some(2851),
        FieldId::UdpLen => Some(2852),
        FieldId::UdpCksum => Some(2853),

        // CoAP fields
        FieldId::CoapVer => Some(2840),
        FieldId::CoapType => Some(2841),
        FieldId::CoapTkl => Some(2842),
        FieldId::CoapCode => Some(2843),
        FieldId::CoapMid => Some(2846),
        FieldId::CoapToken => Some(2847),

        // ICMPv6 fields
        FieldId::Icmpv6Type => Some(2810),
        FieldId::Icmpv6Code => Some(2811),
        FieldId::Icmpv6Checksum => Some(2812),
        FieldId::Icmpv6Identifier => Some(2813),
        FieldId::Icmpv6Mtu => Some(2814),
        FieldId::Icmpv6Pointer => Some(2815),
        FieldId::Icmpv6Sequence => Some(2816),
        FieldId::Icmpv6Payload => Some(2817),

        // CoAP options do not have dedicated field-id SIDs in ietf-schc.
        FieldId::CoapIfMatch
        | FieldId::CoapUriHost
        | FieldId::CoapEtag
        | FieldId::CoapIfNoneMatch
        | FieldId::CoapObserve
        | FieldId::CoapUriPort
        | FieldId::CoapLocationPath
        | FieldId::CoapUriPath
        | FieldId::CoapContentFormat
        | FieldId::CoapMaxAge
        | FieldId::CoapUriQuery
        | FieldId::CoapAccept
        | FieldId::CoapLocationQuery
        | FieldId::CoapBlock2
        | FieldId::CoapBlock1
        | FieldId::CoapSize2
        | FieldId::CoapProxyUri
        | FieldId::CoapProxyScheme
        | FieldId::CoapSize1
        | FieldId::CoapNoResponse
        | FieldId::CoapOption => None,

        _ => None, // Not all fields have SIDs
    }
}

/// Get the SID for a MatchingOperator
pub fn mo_to_sid(mo: &MatchingOperator) -> i64 {
    match mo {
        MatchingOperator::Equal => SID_MO_EQUAL,
        MatchingOperator::Ignore => SID_MO_IGNORE,
        MatchingOperator::MatchMapping => SID_MO_MATCH_MAPPING,
        MatchingOperator::Msb(_) => SID_MO_MSB,
    }
}

/// Get the SID for a CompressionAction
pub fn cda_to_sid(cda: &CompressionAction) -> i64 {
    match cda {
        CompressionAction::NotSent => SID_CDA_NOT_SENT,
        CompressionAction::ValueSent => SID_CDA_VALUE_SENT,
        CompressionAction::MappingSent => SID_CDA_MAPPING_SENT,
        CompressionAction::Lsb => SID_CDA_LSB,
        CompressionAction::Compute => SID_CDA_COMPUTE,
    }
}

/// Get the SID for a Direction
pub fn direction_to_sid(di: &schc::Direction) -> i64 {
    match di {
        schc::Direction::Up => SID_DI_UP,
        schc::Direction::Down => SID_DI_DOWN,
    }
}

// =============================================================================
// JSON to CBOR Conversion
// =============================================================================

/// Convert JSON rules to CORECONF CBOR format (.sor)
///
/// # Arguments
/// * `rules` - Vector of SCHC Rules
///
/// # Returns
/// CBOR bytes suitable for writing to .sor file
pub fn rules_to_cbor(rules: &[Rule]) -> Result<Vec<u8>> {
    let cbor_value = rules_to_cbor_value(rules);

    let mut output = Vec::new();
    ciborium::into_writer(&cbor_value, &mut output)
        .map_err(|e| Error::Coreconf(format!("Failed to serialize CBOR: {}", e)))?;

    Ok(output)
}

/// Convert rules to CBOR Value structure (for inspection or further processing)
pub fn rules_to_cbor_value(rules: &[Rule]) -> CborValue {
    // Build structure: { 2574: { 23: [...rules...] } }
    let rule_array: Vec<CborValue> = rules.iter().map(rule_to_cbor_value).collect();

    let schc_map = CborValue::Map(vec![(
        CborValue::Integer(DELTA_RULE.into()),
        CborValue::Array(rule_array),
    )]);

    CborValue::Map(vec![(CborValue::Integer(SID_SCHC_ROOT.into()), schc_map)])
}

fn rule_to_cbor_value(rule: &Rule) -> CborValue {
    let mut entries: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Integer(DELTA_RULE_ID_LENGTH.into()),
            CborValue::Integer((rule.rule_id_length as i64).into()),
        ),
        (
            CborValue::Integer(DELTA_RULE_ID_VALUE.into()),
            CborValue::Integer((rule.rule_id as i64).into()),
        ),
    ];

    // Add compression entries
    let entry_array: Vec<CborValue> = rule
        .compression
        .iter()
        .enumerate()
        .map(|(idx, field)| field_to_cbor_value(field, idx))
        .collect();

    entries.push((
        CborValue::Integer(DELTA_ENTRY.into()),
        CborValue::Array(entry_array),
    ));

    CborValue::Map(entries)
}

fn field_to_cbor_value(field: &Field, index: usize) -> CborValue {
    // Check if this is a CoAP option that needs universal option encoding
    if is_coap_option(field.fid) {
        return coap_option_to_cbor_value(field, index);
    }

    let mut entries: Vec<(CborValue, CborValue)> = vec![(
        CborValue::Integer(DELTA_ENTRY_INDEX.into()),
        CborValue::Integer((index as i64).into()),
    )];

    // Field ID (if we have a SID for it)
    if let Some(fid_sid) = field_id_to_sid(field.fid) {
        entries.push((
            CborValue::Integer(DELTA_FIELD_ID.into()),
            CborValue::Integer(fid_sid.into()),
        ));
    }

    // Field Length
    if let Some(fl) = field.fl {
        entries.push((
            CborValue::Integer(DELTA_FIELD_LENGTH.into()),
            CborValue::Integer((fl as i64).into()),
        ));
    }

    // Direction Indicator
    if let Some(ref di) = field.di {
        let di_sid = direction_to_sid(di);
        entries.push((
            CborValue::Integer(DELTA_DIRECTION.into()),
            CborValue::Integer(di_sid.into()),
        ));
    }

    // Target Value
    if let Some(ref tv) = field.tv {
        if let Some(tv_cbor) = json_tv_to_cbor(tv) {
            entries.push((CborValue::Integer(DELTA_TARGET_VALUE.into()), tv_cbor));
        }
    }

    // Matching Operator
    entries.push((
        CborValue::Integer(DELTA_MO.into()),
        CborValue::Integer(mo_to_sid(&field.mo).into()),
    ));

    // MO Value (for MSB)
    if let Some(mo_val) = field.mo_val {
        let mo_value_entry = CborValue::Array(vec![CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(0.into())), // index
            (
                CborValue::Integer(2.into()),
                CborValue::Integer((mo_val as i64).into()),
            ), // value
        ])]);
        entries.push((CborValue::Integer(DELTA_MO_VALUE.into()), mo_value_entry));
    }

    // Compression Action
    entries.push((
        CborValue::Integer(DELTA_CDA.into()),
        CborValue::Integer(cda_to_sid(&field.cda).into()),
    ));

    CborValue::Map(entries)
}

/// Encode a CoAP option field using the universal option format (negative deltas)
fn coap_option_to_cbor_value(field: &Field, index: usize) -> CborValue {
    let mut entries: Vec<(CborValue, CborValue)> = vec![(
        CborValue::Integer(DELTA_ENTRY_INDEX.into()),
        CborValue::Integer((index as i64).into()),
    )];

    // Space ID (negative delta -4) - set to CoAP space
    entries.push((
        CborValue::Integer(NEG_DELTA_SPACE_ID.into()),
        CborValue::Integer(SID_SPACE_ID_COAP.into()),
    ));

    // Option Number (negative delta -5)
    if let Some(opt_num) = field_id_to_coap_option_num(field.fid) {
        entries.push((
            CborValue::Integer(NEG_DELTA_OPTION_NUM.into()),
            CborValue::Integer((opt_num as i64).into()),
        ));
    }

    // Field Length (negative delta -11)
    if let Some(fl) = field.fl {
        entries.push((
            CborValue::Integer(NEG_DELTA_FIELD_LENGTH.into()),
            CborValue::Integer((fl as i64).into()),
        ));
    }

    // Direction Indicator (negative delta -12)
    if let Some(ref di) = field.di {
        let di_sid = direction_to_sid(di);
        entries.push((
            CborValue::Integer(NEG_DELTA_DIRECTION.into()),
            CborValue::Integer(di_sid.into()),
        ));
    }

    // Target Value (negative delta -3)
    if let Some(ref tv) = field.tv {
        if let Some(tv_cbor) = json_tv_to_cbor(tv) {
            entries.push((CborValue::Integer(NEG_DELTA_TARGET_VALUE.into()), tv_cbor));
        }
    }

    // Matching Operator (negative delta -9)
    entries.push((
        CborValue::Integer(NEG_DELTA_MO.into()),
        CborValue::Integer(mo_to_sid(&field.mo).into()),
    ));

    // MO Value (negative delta -8)
    if let Some(mo_val) = field.mo_val {
        let mo_value_entry = CborValue::Array(vec![CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(0.into())), // index
            (
                CborValue::Integer(2.into()),
                CborValue::Integer((mo_val as i64).into()),
            ), // value
        ])]);
        entries.push((
            CborValue::Integer(NEG_DELTA_MO_VALUE.into()),
            mo_value_entry,
        ));
    }

    // Compression Action (negative delta -16)
    entries.push((
        CborValue::Integer(NEG_DELTA_CDA.into()),
        CborValue::Integer(cda_to_sid(&field.cda).into()),
    ));

    CborValue::Map(entries)
}

fn json_tv_to_cbor(tv: &serde_json::Value) -> Option<CborValue> {
    match tv {
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|i| CborValue::Integer(i.into()))
            .or_else(|| n.as_u64().map(|u| CborValue::Integer((u as i64).into()))),
        serde_json::Value::String(s) => {
            // Try to parse as hex if it looks like hex
            if let Some(hex_str) = s.strip_prefix("0x") {
                if let Ok(bytes) = hex::decode(hex_str) {
                    return Some(CborValue::Bytes(bytes));
                }
            }
            Some(CborValue::Text(s.clone()))
        }
        serde_json::Value::Array(arr) => {
            let values: Vec<CborValue> = arr
                .iter()
                .enumerate()
                .filter_map(|(idx, v)| {
                    json_tv_to_cbor(v).map(|cbor_val| {
                        CborValue::Map(vec![
                            (
                                CborValue::Integer(1.into()),
                                CborValue::Integer((idx as i64).into()),
                            ),
                            (CborValue::Integer(2.into()), cbor_val),
                        ])
                    })
                })
                .collect();
            Some(CborValue::Array(values))
        }
        _ => None,
    }
}

// =============================================================================
// Display Helpers
// =============================================================================

/// Format a field with its SID information
pub fn format_field_with_sid(field: &Field) -> String {
    let fid_sid = field_id_to_sid(field.fid)
        .map(|s| format!(" (SID {})", s))
        .unwrap_or_default();

    let mo_sid = mo_to_sid(&field.mo);
    let cda_sid = cda_to_sid(&field.cda);

    let fl_str = field
        .fl
        .map(|l| format!("{}", l))
        .unwrap_or_else(|| "var".to_string());

    let tv_str = field
        .tv
        .as_ref()
        .map(|v| format!("{}", v))
        .unwrap_or_else(|| "-".to_string());

    format!(
        "{}{}: FL={}, TV={}, MO={:?} (SID {}), CDA={:?} (SID {})",
        field.fid, fid_sid, fl_str, tv_str, field.mo, mo_sid, field.cda, cda_sid
    )
}

/// Display all rules with SID information
pub fn display_rules_with_sids(rules: &[Rule]) {
    for rule in rules {
        println!(
            "Rule {}/{} ({} fields):",
            rule.rule_id,
            rule.rule_id_length,
            rule.compression.len()
        );
        for (idx, field) in rule.compression.iter().enumerate() {
            println!("  [{}] {}", idx, format_field_with_sid(field));
        }
        println!();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mo_sid_conversion() {
        assert!(matches!(
            sid_to_mo(SID_MO_EQUAL, None),
            Ok(MatchingOperator::Equal)
        ));
        assert!(matches!(
            sid_to_mo(SID_MO_IGNORE, None),
            Ok(MatchingOperator::Ignore)
        ));
        assert!(matches!(
            sid_to_mo(SID_MO_MSB, Some(8)),
            Ok(MatchingOperator::Msb(8))
        ));
    }

    #[test]
    fn test_cda_sid_conversion() {
        assert!(matches!(
            sid_to_cda(SID_CDA_NOT_SENT, None),
            Ok(CompressionAction::NotSent)
        ));
        assert!(matches!(
            sid_to_cda(SID_CDA_VALUE_SENT, None),
            Ok(CompressionAction::ValueSent)
        ));
        assert!(matches!(
            sid_to_cda(SID_CDA_LSB, Some(8)),
            Ok(CompressionAction::Lsb)
        ));
    }

    #[test]
    fn test_field_sid_conversion() {
        let sid_file = create_test_sid_file();
        assert!(matches!(
            sid_to_field_id(2860, &sid_file),
            Ok(FieldId::Ipv6Ver)
        ));
        assert!(matches!(
            sid_to_field_id(2850, &sid_file),
            Ok(FieldId::UdpDevPort)
        ));
    }

    #[test]
    fn test_coap_option_mapping() {
        assert_eq!(coap_option_to_field_id(11), FieldId::CoapUriPath);
        assert_eq!(coap_option_to_field_id(12), FieldId::CoapContentFormat);
    }

    #[test]
    fn test_coap_option_reverse_mapping() {
        // Test round-trip: option_num -> FieldId -> option_num
        let test_cases = vec![
            (1, FieldId::CoapIfMatch),
            (3, FieldId::CoapUriHost),
            (4, FieldId::CoapEtag),
            (7, FieldId::CoapUriPort),
            (11, FieldId::CoapUriPath),
            (12, FieldId::CoapContentFormat),
            (15, FieldId::CoapUriQuery),
            (17, FieldId::CoapAccept),
        ];

        for (option_num, expected_fid) in test_cases {
            let fid = coap_option_to_field_id(option_num);
            assert_eq!(
                fid, expected_fid,
                "option_num {} should map to {:?}",
                option_num, expected_fid
            );

            let back = field_id_to_coap_option_num(fid);
            assert_eq!(
                back,
                Some(option_num),
                "{:?} should map back to option_num {}",
                fid,
                option_num
            );
        }
    }

    #[test]
    fn test_is_coap_option() {
        // CoAP options should be detected
        assert!(is_coap_option(FieldId::CoapUriPath));
        assert!(is_coap_option(FieldId::CoapContentFormat));
        assert!(is_coap_option(FieldId::CoapUriHost));
        assert!(is_coap_option(FieldId::CoapOption));

        // Non-option CoAP fields should NOT be detected as options
        assert!(!is_coap_option(FieldId::CoapVer));
        assert!(!is_coap_option(FieldId::CoapType));
        assert!(!is_coap_option(FieldId::CoapCode));
        assert!(!is_coap_option(FieldId::CoapMid));
        assert!(!is_coap_option(FieldId::CoapToken));

        // Other protocol fields should not be options
        assert!(!is_coap_option(FieldId::Ipv6Ver));
        assert!(!is_coap_option(FieldId::UdpDevPort));
    }

    #[test]
    fn test_coap_option_cbor_encoding() {
        // Create a field with CoAP Uri-Path option
        let field = Field {
            fid: FieldId::CoapUriPath,
            fl: Some(8),
            fp: None,
            coap_option_number: Some(11),
            di: None,
            tv: Some(serde_json::Value::String("c".to_string())),
            mo: MatchingOperator::Equal,
            mo_val: None,
            cda: CompressionAction::NotSent,
            parsed_tv: None,
            fl_func: None,
        };

        let cbor = field_to_cbor_value(&field, 0);
        let map = cbor.as_map().expect("Should be a map");

        // Check that we have negative deltas (universal option format)
        let keys: Vec<i64> = map
            .iter()
            .filter_map(|(k, _)| k.as_integer().map(|i| i128::from(i) as i64))
            .collect();

        // Should have entry index (positive) and negative deltas for universal options
        assert!(keys.contains(&1), "Should have entry index delta 1");
        assert!(keys.contains(&-4), "Should have space-id delta -4");
        assert!(keys.contains(&-5), "Should have option-num delta -5");
        assert!(keys.contains(&-3), "Should have target-value delta -3");
        assert!(keys.contains(&-9), "Should have MO delta -9");
        assert!(keys.contains(&-16), "Should have CDA delta -16");

        // Check space-id is CoAP
        let space_id = map
            .iter()
            .find(|(k, _)| k.as_integer().map(|i| i128::from(i) == -4).unwrap_or(false))
            .map(|(_, v)| v.as_integer().map(|i| i128::from(i) as i64))
            .flatten();
        assert_eq!(space_id, Some(SID_SPACE_ID_COAP), "Space ID should be CoAP");

        // Check option number is Uri-Path (11)
        let opt_num = map
            .iter()
            .find(|(k, _)| k.as_integer().map(|i| i128::from(i) == -5).unwrap_or(false))
            .map(|(_, v)| v.as_integer().map(|i| i128::from(i) as i64))
            .flatten();
        assert_eq!(opt_num, Some(11), "Option number should be 11 (Uri-Path)");
    }

    #[test]
    fn test_parse_normal_coap_option_space_entry() {
        let sid_file = create_test_sid_file();
        let entry = CborValue::Map(vec![
            (
                CborValue::Integer(DELTA_SPACE_ID.into()),
                CborValue::Integer(SID_SPACE_ID_COAP.into()),
            ),
            (
                CborValue::Integer(DELTA_FIELD_ID.into()),
                CborValue::Integer(11.into()),
            ),
            (
                CborValue::Integer(DELTA_FIELD_LENGTH.into()),
                CborValue::Tag(45, Box::new(CborValue::Integer(SID_FL_VARIABLE.into()))),
            ),
            (
                CborValue::Integer(DELTA_DIRECTION.into()),
                CborValue::Integer(SID_DI_UP.into()),
            ),
            (
                CborValue::Integer(DELTA_MO.into()),
                CborValue::Integer(SID_MO_IGNORE.into()),
            ),
            (
                CborValue::Integer(DELTA_CDA.into()),
                CborValue::Integer(SID_CDA_NOT_SENT.into()),
            ),
        ]);

        let field = parse_field_entry(&entry, &sid_file).expect("entry should parse");
        assert_eq!(field.fid, FieldId::CoapUriPath);
        assert_eq!(field.coap_option_number, Some(11));
        assert_eq!(field.fl_func, Some(FieldLength::Variable));
        assert_eq!(field.di, Some(schc::Direction::Up));
    }

    #[test]
    fn test_parse_fl_value_from_tagged_identityref() {
        let tagged = CborValue::Tag(45, Box::new(CborValue::Integer(SID_FL_VARIABLE.into())));
        let (fl, fl_func) = parse_fl_value(Some(&tagged), None);
        assert_eq!(fl, None);
        assert_eq!(fl_func, Some(FieldLength::Variable));
    }

    #[test]
    fn test_direction_to_sid() {
        assert_eq!(direction_to_sid(&schc::Direction::Up), SID_DI_UP);
        assert_eq!(direction_to_sid(&schc::Direction::Down), SID_DI_DOWN);
    }

    fn create_test_sid_file() -> SidFile {
        SidFile::from_json_str(
            r#"{
            "module-name": "ietf-schc",
            "module-revision": "2026-01-12",
            "item": [],
            "key-mapping": {}
        }"#,
        )
        .unwrap()
    }
}
