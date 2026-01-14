//! M-Rules: Management Rules for CORECONF traffic
//!
//! M-Rules are pre-provisioned SCHC compression rules used exclusively for
//! compressing CORECONF management traffic. Only M-Rules can modify the Set
//! of Rules (SoR), and M-Rules themselves cannot be modified via CORECONF.

use crate::error::{Error, Result};
use schc::rule::{Rule, RuleSet};
use std::fs;

/// M-Rule set for CORECONF management traffic
#[derive(Debug, Clone)]
pub struct MRuleSet {
    /// Rule ID range reserved for M-Rules (inclusive)
    reserved_range: (u32, u32),
    /// Pre-defined M-Rules for CORECONF traffic
    rules: Vec<Rule>,
}

impl MRuleSet {
    /// Create M-Rules from a JSON file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    /// Create M-Rules from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        let rules: Vec<Rule> = serde_json::from_str(json)?;

        // Determine reserved range from loaded rules
        let min_id = rules.iter().map(|r| r.rule_id).min().unwrap_or(0);
        let max_id = rules.iter().map(|r| r.rule_id).max().unwrap_or(15);

        Ok(Self {
            reserved_range: (min_id, max_id),
            rules,
        })
    }

    /// Create default M-Rules for IPv6/UDP/CoAP CORECONF traffic
    ///
    /// These rules compress standard CORECONF operations:
    /// - Rule 0: GET/FETCH requests
    /// - Rule 1: iPATCH requests/responses
    /// - Rule 2: Error responses
    pub fn default_ipv6_coap() -> Self {
        // Minimal M-Rule set - actual rules would be more comprehensive
        let json = r#"[
            {
                "RuleID": 0,
                "RuleIDLength": 4,
                "Comment": "M-Rule: CORECONF over IPv6/UDP/CoAP",
                "Compression": [
                    { "FID": "IPV6.VER", "TV": 6, "MO": "equal", "CDA": "not-sent" },
                    { "FID": "IPV6.TC", "TV": 0, "MO": "equal", "CDA": "not-sent" },
                    { "FID": "IPV6.NXT", "TV": 17, "MO": "equal", "CDA": "not-sent" },
                    { "FID": "IPV6.LEN", "MO": "ignore", "CDA": "compute" },
                    { "FID": "UDP.APP_PORT", "TV": 5683, "MO": "equal", "CDA": "not-sent" },
                    { "FID": "UDP.LEN", "MO": "ignore", "CDA": "compute" },
                    { "FID": "UDP.CKSUM", "MO": "ignore", "CDA": "compute" }
                ]
            }
        ]"#;

        Self::from_json(json).expect("Default M-Rules should parse")
    }

    /// Get the reserved Rule ID range for M-Rules
    pub fn reserved_range(&self) -> (u32, u32) {
        self.reserved_range
    }

    /// Get the M-Rules as a slice
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Check if a rule ID is in the M-Rule reserved range
    pub fn is_m_rule(&self, rule_id: u32) -> bool {
        rule_id >= self.reserved_range.0 && rule_id <= self.reserved_range.1
    }

    /// Validate that a modification doesn't target an M-Rule
    ///
    /// Returns an error if the target rule ID is in the M-Rule range.
    pub fn validate_modification(&self, target_rule_id: u32) -> Result<()> {
        if self.is_m_rule(target_rule_id) {
            Err(Error::MRuleModificationForbidden(target_rule_id))
        } else {
            Ok(())
        }
    }

    /// Convert M-Rules to a RuleSet for use with SCHC compressor
    pub fn to_ruleset(&self) -> Result<RuleSet> {
        let json = serde_json::to_string(&self.rules)?;
        RuleSet::from_json(&json).map_err(|e| Error::Schc(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_m_rules() {
        let m_rules = MRuleSet::default_ipv6_coap();
        assert!(!m_rules.rules().is_empty());
        assert!(m_rules.is_m_rule(0));
    }

    #[test]
    fn test_m_rule_range() {
        let m_rules = MRuleSet::default_ipv6_coap();
        let (min, max) = m_rules.reserved_range();

        // Rule IDs in range should be M-Rules
        assert!(m_rules.is_m_rule(min));
        assert!(m_rules.is_m_rule(max));

        // Rule IDs outside range should not be M-Rules
        assert!(!m_rules.is_m_rule(max + 1));
        assert!(!m_rules.is_m_rule(100));
    }

    #[test]
    fn test_modification_validation() {
        let m_rules = MRuleSet::default_ipv6_coap();

        // Modifying an M-Rule should fail
        assert!(m_rules.validate_modification(0).is_err());

        // Modifying a non-M-Rule should succeed
        assert!(m_rules.validate_modification(100).is_ok());
    }
}
