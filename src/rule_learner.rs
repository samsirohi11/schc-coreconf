//! Dynamic rule learning from traffic patterns
//!
//! Observes packet fields and suggests more specific compression rules
//! when constant patterns are detected. This enables progressive rule
//! refinement: start with a basic rule, then add fields as patterns emerge.

use schc::field_id::FieldId;
use schc::rule::{CompressionAction, MatchingOperator, Rule};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Observed pattern for a single field
#[derive(Debug, Default, Clone)]
struct FieldPattern {
    /// Values seen and their occurrence counts
    values_seen: HashMap<Vec<u8>, usize>,
    /// Total number of observations
    total_observations: usize,
}

impl FieldPattern {
    /// Record an observed value
    fn observe(&mut self, value: &[u8]) {
        self.total_observations += 1;
        *self.values_seen.entry(value.to_vec()).or_insert(0) += 1;
    }

    /// Get the most common value and its frequency (0.0 - 1.0)
    fn most_common(&self) -> Option<(&Vec<u8>, f64)> {
        if self.total_observations == 0 {
            return None;
        }
        self.values_seen
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(value, count)| (value, *count as f64 / self.total_observations as f64))
    }

    /// Check if a single value dominates (above threshold)
    fn is_constant(&self, threshold: f64) -> bool {
        self.most_common()
            .map(|(_, freq)| freq >= threshold)
            .unwrap_or(false)
    }
}

/// Rule learner that observes traffic and suggests optimized rules
///
/// The learner tracks field values across packets and identifies fields
/// that consistently have the same value. These fields can be converted
/// from `value-sent` to `not-sent` in a more specific rule.
#[derive(Debug)]
pub struct RuleLearner {
    /// Observed patterns per field ID
    patterns: HashMap<FieldId, FieldPattern>,
    /// Threshold for considering a value "constant" (e.g., 1.0 = 100%)
    constant_threshold: f64,
    /// Minimum packets before suggesting rules
    min_packets: usize,
    /// Total packets observed
    packet_count: usize,
    /// Rule ID offset for learned rules
    learned_rule_id_offset: u32,
    /// Counter for learned rules
    learned_rule_count: u32,
}

impl RuleLearner {
    /// Create a new rule learner
    ///
    /// # Arguments
    /// * `min_packets` - Minimum packets to observe before suggesting rules
    pub fn new(min_packets: usize) -> Self {
        Self {
            patterns: HashMap::new(),
            constant_threshold: 1.0, // Require 100% constant by default
            min_packets,
            packet_count: 0,
            learned_rule_id_offset: 1000,
            learned_rule_count: 0,
        }
    }

    /// Create with custom threshold
    ///
    /// # Arguments  
    /// * `min_packets` - Minimum packets to observe
    /// * `threshold` - Frequency threshold for constant detection (0.0 - 1.0)
    pub fn with_threshold(min_packets: usize, threshold: f64) -> Self {
        Self {
            constant_threshold: threshold.clamp(0.0, 1.0),
            ..Self::new(min_packets)
        }
    }

    /// Get the number of packets observed so far
    pub fn packet_count(&self) -> usize {
        self.packet_count
    }

    /// Check if enough packets have been observed to suggest rules
    pub fn ready_to_suggest(&self) -> bool {
        self.packet_count >= self.min_packets
    }

    /// Observe a packet's field values
    ///
    /// # Arguments
    /// * `fields` - List of (field_id, value) pairs from the packet
    pub fn observe_packet(&mut self, fields: &[(FieldId, Vec<u8>)]) {
        self.packet_count += 1;

        for (field_id, value) in fields {
            self.patterns.entry(*field_id).or_default().observe(value);
        }
    }

    /// Get fields that have constant values (above threshold)
    pub fn constant_fields(&self) -> Vec<(FieldId, &Vec<u8>, f64)> {
        if !self.ready_to_suggest() {
            return Vec::new();
        }

        self.patterns
            .iter()
            .filter_map(|(fid, pattern)| {
                if pattern.is_constant(self.constant_threshold) {
                    pattern
                        .most_common()
                        .map(|(value, freq)| (*fid, value, freq))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Suggest a more specific rule based on observed patterns
    ///
    /// Takes a base rule and optimizes fields that were observed to be constant.
    /// Fields with `value-sent` CDA that have constant values are converted to
    /// `not-sent` with the observed value as the target value.
    ///
    /// Returns `None` if:
    /// - Not enough packets observed
    /// - No optimizations possible
    pub fn suggest_rule(&mut self, base_rule: &Rule) -> Option<Rule> {
        if !self.ready_to_suggest() {
            return None;
        }

        let mut new_rule = base_rule.clone();
        let mut improvements = 0;

        for field in &mut new_rule.compression {
            // Only optimize fields currently using value-sent
            if !matches!(field.cda, CompressionAction::ValueSent) {
                continue;
            }

            if let Some(pattern) = self.patterns.get(&field.fid) {
                if let Some((value, freq)) = pattern.most_common() {
                    if freq >= self.constant_threshold {
                        // Convert to not-sent with the constant value
                        log::info!(
                            "Field {:?}: value-sent → not-sent ({}% constant: 0x{})",
                            field.fid,
                            (freq * 100.0) as u32,
                            hex::encode(value)
                        );

                        field.mo = MatchingOperator::Equal;
                        field.cda = CompressionAction::NotSent;
                        field.tv = Some(bytes_to_json_value(value, field.fid));
                        // Parse the target value to populate parsed_tv for matching
                        if let Err(e) = field.parse_tv() {
                            log::warn!("Failed to parse learned TV for {:?}: {}", field.fid, e);
                        }
                        improvements += 1;
                    }
                }
            }
        }

        if improvements > 0 {
            // Assign unique rule ID for learned rule
            self.learned_rule_count += 1;
            new_rule.rule_id =
                base_rule.rule_id + self.learned_rule_id_offset + self.learned_rule_count - 1;
            new_rule.comment = Some(format!(
                "Learned rule (from {}, {} improvements)",
                base_rule.rule_id, improvements
            ));

            log::info!(
                "Suggested rule {} with {} improvements over rule {}",
                new_rule.rule_id,
                improvements,
                base_rule.rule_id
            );

            Some(new_rule)
        } else {
            None
        }
    }

    /// Reset the learner, clearing all observed patterns
    pub fn reset(&mut self) {
        self.patterns.clear();
        self.packet_count = 0;
    }

    /// Get a summary of observed patterns for logging
    pub fn pattern_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Observed {} packets", self.packet_count));

        for (fid, pattern) in &self.patterns {
            if let Some((value, freq)) = pattern.most_common() {
                let constancy = if pattern.is_constant(self.constant_threshold) {
                    "CONSTANT"
                } else {
                    "variable"
                };
                lines.push(format!(
                    "  {:?}: 0x{} ({:.1}%, {})",
                    fid,
                    hex::encode(value),
                    freq * 100.0,
                    constancy
                ));
            }
        }

        lines.join("\n")
    }
}

/// Convert bytes to appropriate JSON value based on field type
///
/// Uses formats that the SCHC library's parse_tv() can understand:
/// - Prefixes: Full IPv6 address format "2001:0db8::/64" (parseable by Ipv6Addr)
/// - IIDs: numeric (fits in u64)
/// - Ports/small values: numeric
/// - Other: hex string with 0x prefix
fn bytes_to_json_value(bytes: &[u8], fid: FieldId) -> Value {
    // For IPv6 prefix fields, format as full IPv6 address with /64 notation
    // The parse_single_value function expects a string parseable by Ipv6Addr::parse()
    if matches!(fid, FieldId::Ipv6DevPrefix | FieldId::Ipv6AppPrefix
                   | FieldId::Ipv6SrcPrefix | FieldId::Ipv6DstPrefix) 
        && bytes.len() == 8 {
            // Format as full IPv6 address with trailing zeros: xxxx:xxxx:xxxx:xxxx::/64
            // Using :: notation for the zero suffix to make it parse correctly
            let prefix = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7]
            );
            return json!(prefix);
        }

    // For IID fields and small values, use numeric representation (fits in u64)
    // This works well for both parse_tv() and for RPC byte conversion
    if bytes.len() <= 8 {
        let mut padded = [0u8; 8];
        padded[8 - bytes.len()..].copy_from_slice(bytes);
        let num = u64::from_be_bytes(padded);
        return json!(num);
    }

    // For larger values, use hex string
    json!(format!("0x{}", hex::encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use schc::rule::Field;

    fn create_test_field(fid: FieldId, cda: CompressionAction) -> Field {
        Field {
            fid,
            fl: None,
            fp: None,
            coap_option_number: None,
            di: None,
            tv: None,
            mo: MatchingOperator::Ignore,
            cda,
            mo_val: None,
            parsed_tv: None,
            fl_func: None,
        }
    }

    #[test]
    fn test_constant_detection() {
        let mut learner = RuleLearner::new(3);

        // Observe same value 3 times
        for _ in 0..3 {
            learner.observe_packet(&[(FieldId::Ipv6Ver, vec![6])]);
        }

        assert!(learner.ready_to_suggest());

        let constants = learner.constant_fields();
        assert_eq!(constants.len(), 1);
        assert_eq!(constants[0].0, FieldId::Ipv6Ver);
        assert_eq!(constants[0].1, &vec![6]);
        assert_eq!(constants[0].2, 1.0); // 100% constant
    }

    #[test]
    fn test_variable_detection() {
        let mut learner = RuleLearner::new(3);

        // Observe different values
        learner.observe_packet(&[(FieldId::UdpDevPort, vec![0, 80])]);
        learner.observe_packet(&[(FieldId::UdpDevPort, vec![0, 81])]);
        learner.observe_packet(&[(FieldId::UdpDevPort, vec![0, 82])]);

        let constants = learner.constant_fields();
        assert!(constants.is_empty()); // Not constant
    }

    #[test]
    fn test_suggest_rule_improvements() {
        let mut learner = RuleLearner::new(3);

        // Observe constant destination
        for _ in 0..3 {
            learner.observe_packet(&[(
                FieldId::Ipv6AppPrefix,
                vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
            )]);
        }

        let base_rule = Rule {
            rule_id: 100,
            rule_id_length: 8,
            comment: None,
            compression: vec![create_test_field(
                FieldId::Ipv6AppPrefix,
                CompressionAction::ValueSent,
            )],
        };

        let suggested = learner.suggest_rule(&base_rule).unwrap();

        assert_eq!(suggested.rule_id, 1100); // 100 + 1000 offset
        assert_eq!(suggested.compression[0].cda, CompressionAction::NotSent);
        assert_eq!(suggested.compression[0].mo, MatchingOperator::Equal);
    }

    #[test]
    fn test_not_ready_returns_none() {
        let mut learner = RuleLearner::new(10);

        // Only observe 3 packets
        for _ in 0..3 {
            learner.observe_packet(&[(FieldId::Ipv6Ver, vec![6])]);
        }

        let base_rule = Rule {
            rule_id: 1,
            rule_id_length: 8,
            comment: None,
            compression: vec![],
        };

        assert!(!learner.ready_to_suggest());
        assert!(learner.suggest_rule(&base_rule).is_none());
    }
}
