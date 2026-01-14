//! Unified SCHC-CoRECONF Manager
//!
//! Combines M-Rules, guard period management, and rule learning into
//! a single manager that handles both SCHC compression and CoRECONF
//! rule provisioning.

use schc::field_id::FieldId;
use schc::rule::{Rule, RuleSet};
use serde_json::Value;
use std::fs;
use std::time::Duration;

use crate::conversion::{schc_rule_to_yang, yang_to_schc_rule};
use crate::error::{Error, Result};
use crate::guard_period::GuardPeriodManager;
use crate::m_rules::MRuleSet;
use crate::rule_learner::RuleLearner;

/// Unified SCHC-CoRECONF Manager
///
/// This manager:
/// - Maintains M-Rules for compressing CORECONF traffic
/// - Manages application rules with guard period synchronization
/// - Optionally learns traffic patterns to suggest optimized rules
#[derive(Debug)]
pub struct SchcCoreconfManager {
    /// M-Rules for CORECONF traffic (immutable via remote APIs)
    m_rules: MRuleSet,
    /// Application rules (mutable via CORECONF)
    app_rules: Vec<Rule>,
    /// Guard period manager for rule synchronization
    guard_period: GuardPeriodManager,
    /// Rule learner (optional, for progressive optimization)
    learner: Option<RuleLearner>,
}

impl SchcCoreconfManager {
    /// Create a new manager with M-Rules and initial application rules
    ///
    /// # Arguments
    /// * `m_rules` - Pre-loaded M-Rules set
    /// * `initial_rules` - Initial application rules
    /// * `estimated_rtt` - Estimated RTT to peer for guard period calculation
    pub fn new(m_rules: MRuleSet, initial_rules: Vec<Rule>, estimated_rtt: Duration) -> Self {
        let mut guard_period = GuardPeriodManager::new(estimated_rtt);

        // Mark initial rules as immediately active
        for rule in &initial_rules {
            guard_period.mark_active(rule.rule_id, rule.rule_id_length);
        }

        Self {
            m_rules,
            app_rules: initial_rules,
            guard_period,
            learner: None,
        }
    }

    /// Create manager from file paths
    ///
    /// # Arguments
    /// * `m_rules_path` - Path to M-Rules JSON file
    /// * `initial_rules_path` - Optional path to initial rules JSON file
    /// * `estimated_rtt` - Estimated RTT to peer
    pub fn from_files(
        m_rules_path: &str,
        initial_rules_path: Option<&str>,
        estimated_rtt: Duration,
    ) -> Result<Self> {
        let m_rules = MRuleSet::from_file(m_rules_path)?;

        let initial_rules = if let Some(path) = initial_rules_path {
            let content = fs::read_to_string(path)?;
            let rules: Vec<Rule> = serde_json::from_str(&content)?;
            rules
        } else {
            Vec::new()
        };

        Ok(Self::new(m_rules, initial_rules, estimated_rtt))
    }

    /// Enable progressive rule learning
    ///
    /// # Arguments
    /// * `min_packets` - Minimum packets to observe before suggesting rules
    pub fn enable_learning(&mut self, min_packets: usize) {
        self.learner = Some(RuleLearner::new(min_packets));
        log::info!("Rule learning enabled (min {} packets)", min_packets);
    }

    /// Enable learning with custom threshold
    pub fn enable_learning_with_threshold(&mut self, min_packets: usize, threshold: f64) {
        self.learner = Some(RuleLearner::with_threshold(min_packets, threshold));
        log::info!(
            "Rule learning enabled (min {} packets, {:.0}% threshold)",
            min_packets,
            threshold * 100.0
        );
    }

    /// Get M-Rules for compressing CORECONF traffic
    pub fn m_rules(&self) -> &MRuleSet {
        &self.m_rules
    }

    /// Get all application rules (including pending ones)
    pub fn all_rules(&self) -> &[Rule] {
        &self.app_rules
    }

    /// Get only active application rules (past guard period)
    pub fn active_rules(&self) -> Vec<&Rule> {
        self.app_rules
            .iter()
            .filter(|r| {
                self.guard_period
                    .is_rule_active(r.rule_id, r.rule_id_length)
            })
            .collect()
    }

    /// Get the combined RuleSet (M-Rules + active app rules) for compression
    pub fn compression_ruleset(&self) -> Result<RuleSet> {
        let mut all_rules: Vec<Rule> = self.m_rules.rules().to_vec();
        all_rules.extend(self.active_rules().iter().cloned().cloned());

        let json = serde_json::to_string(&all_rules)?;
        RuleSet::from_json(&json).map_err(|e| Error::Schc(e.to_string()))
    }

    /// Get the guard period duration
    pub fn guard_period(&self) -> Duration {
        self.guard_period.guard_period()
    }

    /// Update the estimated RTT
    pub fn set_estimated_rtt(&mut self, rtt: Duration) {
        self.guard_period.set_estimated_rtt(rtt);
    }

    /// Provision a new rule (schedules activation after guard period)
    ///
    /// Returns an error if attempting to modify an M-Rule.
    pub fn provision_rule(&mut self, rule: Rule) -> Result<()> {
        // Validate not an M-Rule
        self.m_rules.validate_modification(rule.rule_id)?;

        log::info!(
            "Provisioning rule {}/{} (guard period: {:?})",
            rule.rule_id,
            rule.rule_id_length,
            self.guard_period.guard_period()
        );

        // Schedule activation
        self.guard_period
            .schedule_activation(rule.rule_id, rule.rule_id_length);

        // Add to rules (or replace existing)
        let existing_idx = self
            .app_rules
            .iter()
            .position(|r| r.rule_id == rule.rule_id && r.rule_id_length == rule.rule_id_length);

        if let Some(idx) = existing_idx {
            self.app_rules[idx] = rule;
        } else {
            self.app_rules.push(rule);
        }

        Ok(())
    }

    /// Provision a rule from YANG JSON format
    pub fn provision_rule_from_yang(&mut self, yang_json: &Value) -> Result<()> {
        let rule = yang_to_schc_rule(yang_json)?;
        self.provision_rule(rule)
    }

    /// Delete a rule by ID
    pub fn delete_rule(&mut self, rule_id: u32, rule_id_length: u8) -> Result<bool> {
        self.m_rules.validate_modification(rule_id)?;

        let len_before = self.app_rules.len();
        self.app_rules
            .retain(|r| !(r.rule_id == rule_id && r.rule_id_length == rule_id_length));

        if self.app_rules.len() < len_before {
            self.guard_period
                .schedule_deprecation(rule_id, rule_id_length);
            log::info!("Deleted rule {}/{}", rule_id, rule_id_length);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Observe a packet for rule learning
    ///
    /// Call this during compression to record field values.
    /// After enough observations, call `suggest_rule()` to get optimizations.
    pub fn observe_packet(&mut self, fields: &[(FieldId, Vec<u8>)]) {
        if let Some(learner) = &mut self.learner {
            learner.observe_packet(fields);
        }
    }

    /// Check if rule learning has suggestions ready
    pub fn has_suggestion(&self) -> bool {
        self.learner
            .as_ref()
            .map_or(false, |l| l.ready_to_suggest())
    }

    /// Get suggested rule improvement based on observed traffic
    ///
    /// Returns a new rule if patterns were detected that can improve
    /// compression. The returned rule should be provisioned to both
    /// endpoints via CORECONF.
    pub fn suggest_rule(&mut self) -> Option<Rule> {
        // Get the base rule first (before mutable borrow of learner)
        let base_rule = self.active_rules().first()?.clone().clone();

        // Now we can borrow learner mutably
        let learner = self.learner.as_mut()?;
        learner.suggest_rule(&base_rule)
    }

    /// Get suggested rule and automatically provision it locally
    ///
    /// Returns the rule that should be sent to the peer via CORECONF.
    pub fn suggest_and_provision(&mut self) -> Option<Rule> {
        let rule = self.suggest_rule()?;

        // Provision locally
        if let Err(e) = self.provision_rule(rule.clone()) {
            log::error!("Failed to provision suggested rule: {}", e);
            return None;
        }

        Some(rule)
    }

    /// Export a rule as YANG JSON for CORECONF transmission
    pub fn rule_to_yang(&self, rule_id: u32, rule_id_length: u8) -> Result<Value> {
        let rule = self
            .app_rules
            .iter()
            .find(|r| r.rule_id == rule_id && r.rule_id_length == rule_id_length)
            .ok_or_else(|| Error::RuleNotFound(rule_id, rule_id_length))?;

        schc_rule_to_yang(rule)
    }

    /// Tick - call periodically to update guard period states
    pub fn tick(&mut self) {
        let changes = self.guard_period.tick();
        for (rule_id, rule_id_length, action) in changes {
            log::debug!("Rule {}/{} {}", rule_id, rule_id_length, action);
        }
    }

    /// Reset the rule learner
    pub fn reset_learning(&mut self) {
        if let Some(learner) = &mut self.learner {
            learner.reset();
        }
    }

    /// Get learning statistics
    pub fn learning_stats(&self) -> Option<String> {
        self.learner.as_ref().map(|l| l.pattern_summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schc::rule::{CompressionAction, Field, MatchingOperator};

    fn create_test_rule(id: u32) -> Rule {
        Rule {
            rule_id: id,
            rule_id_length: 8,
            comment: Some(format!("Test rule {}", id)),
            compression: vec![Field {
                fid: FieldId::Ipv6Ver,
                fl: Some(4),
                tv: Some(serde_json::json!(6)),
                mo: MatchingOperator::Equal,
                cda: CompressionAction::NotSent,
                mo_val: None,
                parsed_tv: None,
            }],
        }
    }

    #[test]
    fn test_manager_creation() {
        let m_rules = MRuleSet::default_ipv6_coap();
        let initial = vec![create_test_rule(100)];
        let manager = SchcCoreconfManager::new(m_rules, initial, Duration::from_millis(100));

        assert_eq!(manager.all_rules().len(), 1);
        assert_eq!(manager.active_rules().len(), 1); // Initial rules are active
    }

    #[test]
    fn test_provision_rule() {
        let m_rules = MRuleSet::default_ipv6_coap();
        let mut manager = SchcCoreconfManager::new(m_rules, vec![], Duration::from_millis(10));

        let rule = create_test_rule(100);
        manager.provision_rule(rule).unwrap();

        assert_eq!(manager.all_rules().len(), 1);

        // Wait for guard period
        std::thread::sleep(Duration::from_millis(25));
        manager.tick();

        assert_eq!(manager.active_rules().len(), 1);
    }

    #[test]
    fn test_m_rule_protection() {
        let m_rules = MRuleSet::default_ipv6_coap();
        let mut manager = SchcCoreconfManager::new(m_rules, vec![], Duration::from_secs(1));

        // Should fail - rule 0 is an M-Rule
        let result = manager.provision_rule(create_test_rule(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_learning_integration() {
        let m_rules = MRuleSet::default_ipv6_coap();
        let initial = vec![Rule {
            rule_id: 100,
            rule_id_length: 8,
            comment: None,
            compression: vec![Field {
                fid: FieldId::Ipv6AppPrefix,
                fl: Some(64),
                tv: None,
                mo: MatchingOperator::Ignore,
                cda: CompressionAction::ValueSent,
                mo_val: None,
                parsed_tv: None,
            }],
        }];

        let mut manager = SchcCoreconfManager::new(m_rules, initial, Duration::from_millis(10));

        manager.enable_learning(3);

        // Observe constant pattern
        let addr = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0];
        for _ in 0..3 {
            manager.observe_packet(&[(FieldId::Ipv6AppPrefix, addr.clone())]);
        }

        assert!(manager.has_suggestion());
        let suggested = manager.suggest_rule();
        assert!(suggested.is_some());
    }
}
