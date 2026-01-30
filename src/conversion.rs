//! Conversion between YANG/JSON and SCHC Rule structures
//!
//! Handles bidirectional conversion following RFC 9363 YANG model
//! with extensions from draft-toutain-schc-coreconf-management.

use schc::field_id::FieldId;
use schc::parser::Direction;
use schc::rule::{Field, MatchingOperator, Rule};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::identities::{
    schc_cda_to_yang, schc_fid_to_yang, schc_mo_to_yang, yang_cda_to_schc, yang_fid_to_schc,
    yang_mo_to_schc,
};

/// Rule status per draft-toutain-schc-coreconf-management
///
/// A rule can be either active (usable for compression) or candidate
/// (pending activation during guard period).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleStatus {
    #[default]
    Active,
    Candidate,
}

impl RuleStatus {
    /// Convert from YANG identity string
    pub fn from_yang(s: &str) -> Self {
        let status = s
            .strip_prefix("schc:")
            .or_else(|| s.strip_prefix("ietf-schc:"))
            .unwrap_or(s);
        match status {
            "status-candidate" => RuleStatus::Candidate,
            _ => RuleStatus::Active,
        }
    }

    /// Convert to YANG identity string
    pub fn to_yang(self) -> &'static str {
        match self {
            RuleStatus::Active => "status-active",
            RuleStatus::Candidate => "status-candidate",
        }
    }
}

/// Rule nature per draft-toutain-schc-coreconf-management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleNature {
    #[default]
    Compression,
    /// Management rules (M-Rules) for CORECONF traffic
    Management,
    Fragmentation,
}

impl RuleNature {
    /// Convert from YANG identity string
    pub fn from_yang(s: &str) -> Self {
        let nature = s
            .strip_prefix("schc:")
            .or_else(|| s.strip_prefix("ietf-schc:"))
            .unwrap_or(s);
        match nature {
            "nature-management" => RuleNature::Management,
            "nature-fragmentation" => RuleNature::Fragmentation,
            _ => RuleNature::Compression,
        }
    }

    /// Convert to YANG identity string
    pub fn to_yang(self) -> &'static str {
        match self {
            RuleNature::Compression => "nature-compression",
            RuleNature::Management => "nature-management",
            RuleNature::Fragmentation => "nature-fragmentation",
        }
    }
}

/// Convert YANG JSON representation to SCHC Rule
///
/// The YANG format follows RFC 9363 structure:
/// ```json
/// {
///   "rule-id-value": 100,
///   "rule-id-length": 8,
///   "rule-nature": "nature-compression",
///   "entry": [
///     {
///       "field-id": "fid-ipv6-version",
///       "field-length": 4,
///       "field-position": 1,
///       "direction-indicator": "di-bidirectional",
///       "matching-operator": "mo-equal",
///       "comp-decomp-action": "cda-not-sent",
///       "target-value": [{"index": 0, "value": "Bg=="}]
///     }
///   ]
/// }
/// ```
/// Extended rule metadata per draft-toutain-schc-coreconf-management
#[derive(Debug, Clone, Default)]
pub struct RuleMetadata {
    pub status: RuleStatus,
    pub nature: RuleNature,
}

/// Convert YANG JSON representation to SCHC Rule
pub fn yang_to_schc_rule(yang_json: &Value) -> Result<Rule> {
    let (rule, _) = yang_to_schc_rule_with_metadata(yang_json)?;
    Ok(rule)
}

/// Convert YANG JSON to SCHC Rule with extended metadata
pub fn yang_to_schc_rule_with_metadata(yang_json: &Value) -> Result<(Rule, RuleMetadata)> {
    let rule_id = yang_json["rule-id-value"]
        .as_u64()
        .ok_or_else(|| Error::Conversion("Missing rule-id-value".into()))? as u32;

    let rule_id_length = yang_json["rule-id-length"]
        .as_u64()
        .ok_or_else(|| Error::Conversion("Missing rule-id-length".into()))?
        as u8;

    let comment = yang_json["comment"].as_str().map(String::from);

    // Parse rule-status (draft-toutain extension)
    let status = yang_json["rule-status"]
        .as_str()
        .map(RuleStatus::from_yang)
        .unwrap_or_default();

    // Parse rule-nature (draft-toutain extension)
    let nature = yang_json["rule-nature"]
        .as_str()
        .map(RuleNature::from_yang)
        .unwrap_or_default();

    let entries = yang_json["entry"]
        .as_array()
        .ok_or_else(|| Error::Conversion("Missing entry array".into()))?;

    let mut compression = Vec::new();
    for entry in entries {
        let field = yang_entry_to_field(entry)?;
        compression.push(field);
    }

    let rule = Rule {
        rule_id,
        rule_id_length,
        comment,
        compression,
    };

    let metadata = RuleMetadata { status, nature };

    Ok((rule, metadata))
}

/// Convert a YANG entry to SCHC Field
fn yang_entry_to_field(entry: &Value) -> Result<Field> {
    let fid_str = entry["field-id"]
        .as_str()
        .ok_or_else(|| Error::Conversion("Missing field-id".into()))?;
    let fid = yang_fid_to_schc(fid_str)?;

    let fl = entry["field-length"].as_u64().map(|v| v as u16);

    let mo_str = entry["matching-operator"]
        .as_str()
        .ok_or_else(|| Error::Conversion("Missing matching-operator".into()))?;
    let mut mo = yang_mo_to_schc(mo_str)?;

    // Apply MSB value if present
    let mo_val = if let Some(mo_values) = entry["matching-operator-value"].as_array() {
        if let Some(first) = mo_values.first() {
            first["value"].as_str().and_then(base64_decode_u8)
        } else {
            None
        }
    } else {
        None
    };

    if let MatchingOperator::Msb(_) = mo {
        mo = MatchingOperator::Msb(mo_val.unwrap_or(0));
    }

    let cda_str = entry["comp-decomp-action"]
        .as_str()
        .ok_or_else(|| Error::Conversion("Missing comp-decomp-action".into()))?;
    let cda = yang_cda_to_schc(cda_str)?;

    // Parse target value
    let tv = parse_yang_target_value(&entry["target-value"], fid)?;

    // Parse direction indicator
    let di_str = entry["direction-indicator"]
        .as_str()
        .unwrap_or("di-bidirectional");
    
    let di = match di_str {
        "di-up" => Some(Direction::Up),
        "di-down" => Some(Direction::Down),
        _ => None, // Bidirectional
    };

    Ok(Field {
        fid,
        fl,
        di,
        tv,
        mo,
        cda,
        mo_val,
        parsed_tv: None,
        fl_func: None,
    })
}

/// Parse YANG target-value list to JSON Value
fn parse_yang_target_value(tv_list: &Value, _fid: FieldId) -> Result<Option<Value>> {
    let arr = match tv_list.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return Ok(None),
    };

    if arr.len() == 1 {
        // Single value
        if let Some(value_b64) = arr[0]["value"].as_str() {
            if let Some(bytes) = base64_decode(value_b64) {
                // Try to interpret as number if small enough
                if bytes.len() <= 8 {
                    let mut padded = [0u8; 8];
                    padded[8 - bytes.len()..].copy_from_slice(&bytes);
                    let num = u64::from_be_bytes(padded);
                    return Ok(Some(json!(num)));
                }
                // Otherwise keep as hex string
                return Ok(Some(json!(format!("0x{}", hex::encode(&bytes)))));
            }
        }
    } else {
        // Mapping list
        let values: Vec<Value> = arr
            .iter()
            .filter_map(|entry| {
                entry["value"]
                    .as_str()
                    .and_then(base64_decode)
                    .map(|bytes| {
                        if bytes.len() <= 8 {
                            let mut padded = [0u8; 8];
                            padded[8 - bytes.len()..].copy_from_slice(&bytes);
                            json!(u64::from_be_bytes(padded))
                        } else {
                            json!(format!("0x{}", hex::encode(&bytes)))
                        }
                    })
            })
            .collect();

        if !values.is_empty() {
            return Ok(Some(json!(values)));
        }
    }

    Ok(None)
}

/// Convert SCHC Rule to YANG JSON representation
pub fn schc_rule_to_yang(rule: &Rule) -> Result<Value> {
    schc_rule_to_yang_with_metadata(rule, &RuleMetadata::default())
}

/// Convert SCHC Rule to YANG JSON with extended metadata
pub fn schc_rule_to_yang_with_metadata(rule: &Rule, metadata: &RuleMetadata) -> Result<Value> {
    let entries: Vec<Value> = rule
        .compression
        .iter()
        .map(field_to_yang_entry)
        .collect::<Result<Vec<_>>>()?;

    let mut result = json!({
        "rule-id-value": rule.rule_id,
        "rule-id-length": rule.rule_id_length,
        "rule-status": metadata.status.to_yang(),
        "rule-nature": metadata.nature.to_yang(),
        "entry": entries,
    });

    if let Some(ref comment) = rule.comment {
        result["comment"] = json!(comment);
    }

    Ok(result)
}

/// Convert SCHC Field to YANG entry
fn field_to_yang_entry(field: &Field) -> Result<Value> {
    let mut entry = json!({
        "field-id": schc_fid_to_yang(field.fid),
        "field-position": 1,
        "direction-indicator": match field.di {
            Some(Direction::Up) => "di-up",
            Some(Direction::Down) => "di-down",
            None => "di-bidirectional",
        },
        "matching-operator": schc_mo_to_yang(&field.mo),
        "comp-decomp-action": schc_cda_to_yang(&field.cda),
    });

    if let Some(fl) = field.fl {
        entry["field-length"] = json!(fl);
    }

    // Add MSB value if applicable
    if let MatchingOperator::Msb(val) = field.mo {
        if val > 0 {
            entry["matching-operator-value"] = json!([{
                "index": 0,
                "value": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [val]
                )
            }]);
        }
    }

    // Add target value if present
    if let Some(ref tv) = field.tv {
        entry["target-value"] = schc_tv_to_yang(tv)?;
    }

    Ok(entry)
}

/// Convert SCHC target value to YANG format
fn schc_tv_to_yang(tv: &Value) -> Result<Value> {
    match tv {
        Value::Number(n) => {
            let bytes = n
                .as_u64()
                .map(|v| v.to_be_bytes().to_vec())
                .unwrap_or_default();
            // Remove leading zeros
            let trimmed: Vec<u8> = bytes.into_iter().skip_while(|&b| b == 0).collect();
            let final_bytes = if trimmed.is_empty() { vec![0] } else { trimmed };

            Ok(json!([{
                "index": 0,
                "value": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &final_bytes
                )
            }]))
        }
        Value::String(s) => {
            let bytes = if let Some(hex_str) = s.strip_prefix("0x") {
                hex::decode(hex_str).map_err(|e| Error::Conversion(e.to_string()))?
            } else {
                s.as_bytes().to_vec()
            };

            Ok(json!([{
                "index": 0,
                "value": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &bytes
                )
            }]))
        }
        Value::Array(arr) => {
            let entries: Vec<Value> = arr
                .iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    let bytes = match v {
                        Value::Number(n) => {
                            let b = n.as_u64()?.to_be_bytes().to_vec();
                            let trimmed: Vec<u8> = b.into_iter().skip_while(|&x| x == 0).collect();
                            if trimmed.is_empty() {
                                vec![0]
                            } else {
                                trimmed
                            }
                        }
                        Value::String(s) => {
                            if let Some(hex) = s.strip_prefix("0x") {
                                hex::decode(hex).ok()?
                            } else {
                                s.as_bytes().to_vec()
                            }
                        }
                        _ => return None,
                    };
                    Some(json!({
                        "index": i,
                        "value": base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &bytes
                        )
                    }))
                })
                .collect();

            Ok(json!(entries))
        }
        _ => Ok(json!([])),
    }
}

/// Decode base64 string to bytes
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Decode base64 string to single u8
fn base64_decode_u8(s: &str) -> Option<u8> {
    base64_decode(s).and_then(|v| v.first().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use schc::rule::CompressionAction;

    #[test]
    fn test_yang_to_schc_basic() {
        let yang = json!({
            "rule-id-value": 100,
            "rule-id-length": 8,
            "rule-nature": "nature-compression",
            "entry": [
                {
                    "field-id": "fid-ipv6-version",
                    "field-length": 4,
                    "field-position": 1,
                    "direction-indicator": "di-bidirectional",
                    "matching-operator": "mo-equal",
                    "comp-decomp-action": "cda-not-sent",
                    "target-value": [{"index": 0, "value": "Bg=="}]  // 6 in base64
                }
            ]
        });

        let rule = yang_to_schc_rule(&yang).unwrap();
        assert_eq!(rule.rule_id, 100);
        assert_eq!(rule.rule_id_length, 8);
        assert_eq!(rule.compression.len(), 1);
        assert_eq!(rule.compression[0].fid, FieldId::Ipv6Ver);
    }

    #[test]
    fn test_schc_to_yang_roundtrip() {
        let original = Rule {
            rule_id: 42,
            rule_id_length: 6,
            comment: Some("Test rule".to_string()),
            compression: vec![Field {
                fid: FieldId::Ipv6Ver,
                fl: Some(4),
                tv: Some(json!(6)),
                mo: MatchingOperator::Equal,
                cda: CompressionAction::NotSent,
                mo_val: None,
                di: None,
                parsed_tv: None,
                fl_func: None,
            }],
        };

        let yang = schc_rule_to_yang(&original).unwrap();
        let back = yang_to_schc_rule(&yang).unwrap();

        assert_eq!(original.rule_id, back.rule_id);
        assert_eq!(original.rule_id_length, back.rule_id_length);
        assert_eq!(original.compression.len(), back.compression.len());
    }
}
