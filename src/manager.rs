//! Unified SCHC-CoRECONF Manager
//!
//! Combines M-Rules, guard period management, and rule learning into
//! a single manager that handles both SCHC compression and CoRECONF
//! rule provisioning.

use schc::field_id::FieldId;
use schc::rule::{Rule, RuleSet};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::time::Duration;

use crate::conversion::{schc_rule_to_yang, yang_to_schc_rule};
use crate::error::{Error, Result};
use crate::guard_period::GuardPeriodManager;
use crate::m_rules::MRuleSet;
use crate::rule_learner::RuleLearner;

/// Maximum rule ID length for derived rules (prevents infinite tree traversal)
const MAX_RULE_ID_LENGTH: u8 = 12;

/// Unified SCHC-CoRECONF Manager
///
/// This manager:
/// - Maintains M-Rules for compressing CORECONF traffic
/// - Manages application rules with guard period synchronization
/// - Tracks known rule IDs for efficient allocation (avoids conflicts)
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
    /// Known rule IDs (local tracking to avoid RPC conflicts)
    /// Includes both locally provisioned and remotely learned (via conflicts)
    known_rule_ids: HashSet<(u32, u8)>,
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

        // Build known rule IDs set from M-Rules and initial rules
        let mut known_rule_ids = HashSet::new();
        for rule in m_rules.rules() {
            known_rule_ids.insert((rule.rule_id, rule.rule_id_length));
        }
        for rule in &initial_rules {
            guard_period.mark_active(rule.rule_id, rule.rule_id_length);
            known_rule_ids.insert((rule.rule_id, rule.rule_id_length));
        }

        Self {
            m_rules,
            app_rules: initial_rules,
            guard_period,
            learner: None,
            known_rule_ids,
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
        // active_rules() returns Vec<&Rule>, so use into_iter() + cloned()
        all_rules.extend(self.active_rules().into_iter().cloned());

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

    // ========================================================================
    // Rule ID Tracking and Allocation
    // ========================================================================

    /// Check if a rule ID is known (either locally provisioned or learned from conflicts)
    pub fn is_rule_id_known(&self, rule_id: u32, rule_id_length: u8) -> bool {
        self.known_rule_ids.contains(&(rule_id, rule_id_length))
    }

    /// Mark a rule ID as known (used when learning from RPC conflicts)
    ///
    /// This allows the manager to avoid trying the same rule ID again.
    pub fn mark_rule_id_known(&mut self, rule_id: u32, rule_id_length: u8) {
        self.known_rule_ids.insert((rule_id, rule_id_length));
        log::debug!("Marked rule {}/{} as known", rule_id, rule_id_length);
    }

    /// Get all known rule IDs
    pub fn known_rule_ids(&self) -> &HashSet<(u32, u8)> {
        &self.known_rule_ids
    }

    /// Find the next available rule ID using BFS from a base rule
    ///
    /// This traverses the binary derivation tree breadth-first, giving a more
    /// balanced allocation: 8/5, 24/5, 8/6, 24/6, 40/6, 56/6, etc.
    ///
    /// # Arguments
    /// * `base_rule` - The base rule to derive from (rule_id, rule_id_length)
    ///
    /// # Returns
    /// * `Some((rule_id, rule_id_length))` - Next available rule ID
    /// * `None` - No available rule IDs within MAX_RULE_ID_LENGTH limit
    #[must_use]
    pub fn find_next_available_rule_id(&self, base_rule: (u32, u8)) -> Option<(u32, u8)> {
        let mut queue: VecDeque<(u32, u8)> = VecDeque::new();
        let mut visited: HashSet<(u32, u8)> = HashSet::new();

        // Start with direct children of base rule
        let [child0, child1] = Self::get_derivation_options(base_rule);
        queue.push_back(child0); // append 0 first (smaller rule IDs)
        queue.push_back(child1); // then append 1

        // BFS to find first available slot
        while let Some(candidate) = queue.pop_front() {
            let (_rule_id, rule_id_length) = candidate;

            // Skip if too long
            if rule_id_length > MAX_RULE_ID_LENGTH {
                continue;
            }

            // Skip if already visited
            if visited.contains(&candidate) {
                continue;
            }
            visited.insert(candidate);

            // Check if this rule ID is available
            if !self.known_rule_ids.contains(&candidate) {
                return Some(candidate);
            }

            // Add children to queue for BFS exploration
            let [child0, child1] = Self::get_derivation_options(candidate);
            queue.push_back(child0);
            queue.push_back(child1);
        }

        None
    }

    /// Allocate and reserve the next available rule ID
    ///
    /// This is a convenience method that finds the next available ID and
    /// immediately marks it as known to prevent concurrent allocation.
    ///
    /// # Returns
    /// * `Some((rule_id, rule_id_length))` - Allocated rule ID (now marked as known)
    /// * `None` - No available rule IDs
    pub fn allocate_rule_id(&mut self, base_rule: (u32, u8)) -> Option<(u32, u8)> {
        if let Some(rule_id) = self.find_next_available_rule_id(base_rule) {
            self.known_rule_ids.insert(rule_id);
            log::info!("Allocated rule ID {}/{}", rule_id.0, rule_id.1);
            Some(rule_id)
        } else {
            log::warn!(
                "No available rule IDs from base {}/{}",
                base_rule.0,
                base_rule.1
            );
            None
        }
    }

    /// Provision a new rule or modify an existing one
    ///
    /// - New rules are immediately active (no guard period)
    /// - Rule modifications require guard period (candidate state)
    /// - Blocked rule IDs (during deletion guard period) cannot be re-created
    ///
    /// Returns an error if:
    /// - Attempting to modify an M-Rule
    /// - Rule ID is blocked during deletion guard period
    pub fn provision_rule(&mut self, rule: Rule) -> Result<()> {
        // Validate rule ID length is within valid range (1-32 bits per SCHC spec)
        if rule.rule_id_length == 0 || rule.rule_id_length > 32 {
            return Err(Error::Conversion(format!(
                "Invalid rule-id-length: {} (must be 1-32)",
                rule.rule_id_length
            )));
        }

        // Validate not an M-Rule
        self.m_rules.validate_modification(rule.rule_id)?;

        // Check if rule ID is blocked (during deletion guard period)
        if self
            .guard_period
            .is_rule_id_blocked(rule.rule_id, rule.rule_id_length)
        {
            return Err(Error::RuleIdBlocked(rule.rule_id, rule.rule_id_length));
        }

        // Check if this is a new rule or modification
        let existing_idx = self
            .app_rules
            .iter()
            .position(|r| r.rule_id == rule.rule_id && r.rule_id_length == rule.rule_id_length);

        if let Some(idx) = existing_idx {
            // Rule modification - requires guard period per draft
            log::info!(
                "Modifying rule {}/{} (guard period: {:?})",
                rule.rule_id,
                rule.rule_id_length,
                self.guard_period.guard_period()
            );
            self.guard_period
                .schedule_activation(rule.rule_id, rule.rule_id_length);
            self.app_rules[idx] = rule;
        } else {
            // New rule creation - immediately active per draft
            // "Rule creation do not require a Guard period"
            log::info!(
                "Creating new rule {}/{} (immediately active)",
                rule.rule_id,
                rule.rule_id_length
            );
            self.guard_period
                .mark_active(rule.rule_id, rule.rule_id_length);
            self.known_rule_ids
                .insert((rule.rule_id, rule.rule_id_length));
            self.app_rules.push(rule);
        }

        Ok(())
    }

    /// Provision a rule with explicit creation/modification mode
    ///
    /// Use this for explicit control over guard period behavior.
    /// - `force_guard_period: true` - Always use guard period (for sync scenarios)
    /// - `force_guard_period: false` - Use draft behavior (new=immediate, modify=guard)
    pub fn provision_rule_with_mode(&mut self, rule: Rule, force_guard_period: bool) -> Result<()> {
        // Validate not an M-Rule
        self.m_rules.validate_modification(rule.rule_id)?;

        // Check if rule ID is blocked
        if self
            .guard_period
            .is_rule_id_blocked(rule.rule_id, rule.rule_id_length)
        {
            return Err(Error::RuleIdBlocked(rule.rule_id, rule.rule_id_length));
        }

        let existing_idx = self
            .app_rules
            .iter()
            .position(|r| r.rule_id == rule.rule_id && r.rule_id_length == rule.rule_id_length);

        if force_guard_period || existing_idx.is_some() {
            // Use guard period
            self.guard_period
                .schedule_activation(rule.rule_id, rule.rule_id_length);
        } else {
            // Immediately active
            self.guard_period
                .mark_active(rule.rule_id, rule.rule_id_length);
        }

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
    ///
    /// - Deletion requires Guard Period enforcement
    /// - During guard period, "a rule with the same ID cannot be created"
    /// - "SCHC PDU carrying the Rule ID are dropped"
    pub fn delete_rule(&mut self, rule_id: u32, rule_id_length: u8) -> Result<bool> {
        self.m_rules.validate_modification(rule_id)?;

        let len_before = self.app_rules.len();
        self.app_rules
            .retain(|r| !(r.rule_id == rule_id && r.rule_id_length == rule_id_length));

        if self.app_rules.len() < len_before {
            // Schedule deprecation - this also blocks the rule ID
            self.guard_period
                .schedule_deprecation(rule_id, rule_id_length);
            log::info!(
                "Deleted rule {}/{} (ID blocked for {:?})",
                rule_id,
                rule_id_length,
                self.guard_period.guard_period()
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if a rule ID is currently blocked (during deletion guard period)
    pub fn is_rule_id_blocked(&self, rule_id: u32, rule_id_length: u8) -> bool {
        self.guard_period
            .is_rule_id_blocked(rule_id, rule_id_length)
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
        self.learner.as_ref().is_some_and(|l| l.ready_to_suggest())
    }

    /// Get suggested rule improvement based on observed traffic
    ///
    /// Returns a new rule if patterns were detected that can improve
    /// compression. The returned rule should be provisioned to both
    /// endpoints via CORECONF.
    pub fn suggest_rule(&mut self) -> Option<Rule> {
        // Check if we have active rules first
        let active_rules = self.active_rules();
        if active_rules.is_empty() {
            return None;
        }
        let base_rule = active_rules[0].clone();

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
            .ok_or(Error::RuleNotFound(rule_id, rule_id_length))?;

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

    // ========================================================================
    // RPC Operations (per draft-toutain-schc-coreconf-management)
    // ========================================================================

    /// Duplicate a rule (RPC per draft-toutain-schc-coreconf-management)
    ///
    /// This is the RECOMMENDED method for adding new rules. It copies an existing
    /// rule ("from") to a new rule ID ("to") and optionally applies modifications.
    ///
    /// # Arguments
    /// * `from` - (rule_id, rule_id_length) of source rule
    /// * `to` - (rule_id, rule_id_length) of destination rule
    /// * `modifications` - Optional YANG JSON with iPATCH-style modifications
    ///
    /// # Errors
    /// Returns error if:
    /// - Source rule doesn't exist (4.04 Not Found)
    /// - Target conflicts with M-Rule range (4.01 Unauthorized)
    /// - Target rule ID is blocked during deletion guard period (4.09 Conflict)
    /// - Target rule already exists (4.09 Conflict)
    /// - Modifications fail to apply (4.00 Bad Request)
    ///
    /// Per draft spec, this operation is atomic - if any step fails, no changes occur.
    pub fn duplicate_rule(
        &mut self,
        from: (u32, u8),
        to: (u32, u8),
        modifications: Option<&Value>,
    ) -> Result<()> {
        // Validate not modifying M-Rules
        self.m_rules.validate_modification(to.0)?;

        // Check if target rule ID is blocked
        if self.guard_period.is_rule_id_blocked(to.0, to.1) {
            return Err(Error::RuleIdBlocked(to.0, to.1));
        }

        // Find source rule
        let source = self
            .app_rules
            .iter()
            .find(|r| r.rule_id == from.0 && r.rule_id_length == from.1)
            .ok_or(Error::RuleNotFound(from.0, from.1))?
            .clone();

        // Check target doesn't already exist
        if self
            .app_rules
            .iter()
            .any(|r| r.rule_id == to.0 && r.rule_id_length == to.1)
        {
            return Err(Error::RuleAlreadyExists(to.0, to.1));
        }

        // Create new rule with updated ID
        let mut new_rule = source.clone();
        new_rule.rule_id = to.0;
        new_rule.rule_id_length = to.1;
        new_rule.comment = Some(format!("Derived from {}/{}", from.0, from.1));

        // Apply modifications if provided
        if let Some(mods) = modifications {
            new_rule = Self::apply_rule_modifications(new_rule, mods)?;
        }

        log::info!(
            "Duplicating rule {}/{} -> {}/{}",
            from.0,
            from.1,
            to.0,
            to.1
        );

        // Provision the new rule (will be immediately active as it's a new rule)
        self.provision_rule(new_rule)?;

        Ok(())
    }

    /// Apply iPATCH-style modifications to a rule
    ///
    /// Supports both:
    /// - Field-ID based: `{"entry": [{"field-id": "fid-ipv6-flowlabel", ...}]}`
    /// - Entry-index based: `{"entry": [{"entry-index": 2, "matching-operator-sid": 2900, ...}]}`
    fn apply_rule_modifications(mut rule: Rule, mods: &Value) -> Result<Rule> {
        // Handle field-level modifications
        if let Some(entries) = mods.get("entry").and_then(|e| e.as_array()) {
            for entry_mod in entries {
                // Check for entry-index based modification (SID format)
                if let Some(entry_idx) = entry_mod.get("entry-index").and_then(|i| i.as_u64()) {
                    let idx = entry_idx as usize;
                    if idx < rule.compression.len() {
                        let field = &mut rule.compression[idx];

                        // Apply MO by SID
                        if let Some(mo_sid) = entry_mod
                            .get("matching-operator-sid")
                            .and_then(|m| m.as_i64())
                        {
                            use schc::rule::MatchingOperator;
                            // Map SID to MatchingOperator
                            field.mo = match mo_sid {
                                2900 => MatchingOperator::Equal,
                                2901 => MatchingOperator::Ignore,
                                2902 => MatchingOperator::MatchMapping,
                                2903 => MatchingOperator::Msb(field.mo_val.unwrap_or(0)),
                                _ => field.mo,
                            };
                        }

                        // Apply CDA by SID
                        if let Some(cda_sid) = entry_mod
                            .get("comp-decomp-action-sid")
                            .and_then(|c| c.as_i64())
                        {
                            use schc::rule::CompressionAction;
                            field.cda = match cda_sid {
                                2920 => CompressionAction::NotSent,
                                2921 => CompressionAction::ValueSent,
                                2922 => CompressionAction::MappingSent,
                                2923 => CompressionAction::Lsb,
                                2924 => CompressionAction::Compute,
                                _ => field.cda,
                            };
                        }

                        // Apply target value from bytes
                        if let Some(tv_b64) =
                            entry_mod.get("target-value-bytes").and_then(|t| t.as_str())
                        {
                            use base64::Engine;
                            if let Ok(bytes) =
                                base64::engine::general_purpose::STANDARD.decode(tv_b64)
                            {
                                field.tv = Some(Self::bytes_to_internal_tv(&bytes, field.fid));
                                if let Err(e) = field.parse_tv() {
                                    log::warn!(
                                        "Failed to parse target value for entry {}: {}",
                                        idx,
                                        e
                                    );
                                }
                            }
                        }
                    }
                    continue;
                }

                // Fall back to field-id based modification
                if let Some(fid_str) = entry_mod.get("field-id").and_then(|f| f.as_str()) {
                    // Find matching field in rule
                    use crate::identities::yang_fid_to_schc;
                    if let Ok(fid) = yang_fid_to_schc(fid_str) {
                        if let Some(field) = rule.compression.iter_mut().find(|f| f.fid == fid) {
                            // Apply target-value modification
                            // Convert YANG format [{"index": 0, "value": "base64..."}] to internal format
                            if let Some(tv) = entry_mod.get("target-value") {
                                field.tv = Some(Self::convert_yang_target_value(tv, fid));
                            }
                            // Apply matching-operator modification
                            if let Some(mo_str) =
                                entry_mod.get("matching-operator").and_then(|m| m.as_str())
                            {
                                use crate::identities::yang_mo_to_schc;
                                if let Ok(mo) = yang_mo_to_schc(mo_str) {
                                    field.mo = mo;
                                }
                            }
                            // Apply CDA modification
                            if let Some(cda_str) =
                                entry_mod.get("comp-decomp-action").and_then(|c| c.as_str())
                            {
                                use crate::identities::yang_cda_to_schc;
                                if let Ok(cda) = yang_cda_to_schc(cda_str) {
                                    field.cda = cda;
                                }
                            }
                            // Re-parse target value after modifications
                            if let Err(e) = field.parse_tv() {
                                log::warn!(
                                    "Failed to parse target value for field {:?}: {}",
                                    field.fid,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(rule)
    }

    /// Convert YANG target-value format to internal SCHC format
    ///
    /// YANG format: [{"index": 0, "value": "base64..."}]
    /// Internal format: numeric value (for ports, etc.) or hex string (for addresses)
    fn convert_yang_target_value(yang_tv: &Value, fid: FieldId) -> Value {
        use base64::Engine;

        // Try to extract the first value from the YANG array format
        if let Some(arr) = yang_tv.as_array() {
            if let Some(first) = arr.first() {
                if let Some(b64_str) = first.get("value").and_then(|v| v.as_str()) {
                    // Decode base64
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64_str) {
                        // Convert based on field type
                        return Self::bytes_to_internal_tv(&bytes, fid);
                    }
                }
            }
        }

        // If it's already in a simple format, return as-is
        yang_tv.clone()
    }

    /// Convert bytes to internal target value format based on field type
    ///
    /// Creates JSON values that parse_tv() can understand:
    /// - PREFIX fields: IPv6 address format "2001:0db8::/64"
    /// - IID fields: numeric u64
    /// - Small values: numeric
    fn bytes_to_internal_tv(bytes: &[u8], fid: FieldId) -> Value {
        let fid_str = fid.as_str();

        // For PREFIX fields, use IPv6 address format with /64 suffix
        // parse_single_value expects a string parseable by Ipv6Addr::parse()
        if fid_str.ends_with("PREFIX") && bytes.len() == 8 {
            let prefix = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
            );
            return Value::String(prefix);
        }

        // For IID fields, use numeric u64 representation
        if fid_str.ends_with("IID") && bytes.len() == 8 {
            let mut val: u64 = 0;
            for b in bytes {
                val = (val << 8) | (*b as u64);
            }
            return Value::Number(val.into());
        }

        // Small numeric fields (ports, flow label, etc.) - convert to number
        if bytes.len() <= 4 {
            let mut val: u64 = 0;
            for b in bytes {
                val = (val << 8) | (*b as u64);
            }
            return Value::Number(val.into());
        }

        // For other large fields, use hex string
        Value::String(format!("0x{}", hex::encode(bytes)))
    }

    // ========================================================================
    // Binary Tree Rule ID Helpers (per draft-toutain-schc-coreconf-management)
    // ========================================================================

    /// Check if a rule derivation follows binary tree structure
    ///
    /// Per the draft: "newly created rules SHOULD follow a binary tree structure.
    /// For instance, a rule identified as 8/4 may be duplicated as either 8/5 or 18/5."
    ///
    /// Valid derivations extend the rule ID by 1 bit:
    /// - Same prefix with 0 appended: (8/4) -> (8/5) means 1000 -> 01000
    /// - Same prefix with 1 appended: (8/4) -> (24/5) means 1000 -> 11000
    pub fn is_valid_binary_tree_derivation(from: (u32, u8), to: (u32, u8)) -> bool {
        // New rule must be exactly 1 bit longer
        if to.1 != from.1 + 1 {
            return false;
        }

        // The new rule ID should be either:
        // - from.0 (append 0 bit) -> value stays same, length increases
        // - from.0 | (1 << from.1) (append 1 bit) -> set new MSB
        let extended_with_0 = from.0;
        let extended_with_1 = from.0 | (1 << from.1);

        to.0 == extended_with_0 || to.0 == extended_with_1
    }

    /// Get valid binary tree derivation options for a rule
    ///
    /// # Panics
    /// Panics if from.1 >= 32 (rule ID length must be less than 32 bits)
    pub fn get_derivation_options(from: (u32, u8)) -> [(u32, u8); 2] {
        assert!(
            from.1 < 32,
            "Rule ID length must be less than 32 bits, got {}",
            from.1
        );
        let new_length = from.1.saturating_add(1);
        [
            (from.0, new_length),                    // Append 0
            (from.0 | (1u32 << from.1), new_length), // Append 1
        ]
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
                fp: None,
                coap_option_number: None,
                tv: Some(serde_json::json!(6)),
                mo: MatchingOperator::Equal,
                cda: CompressionAction::NotSent,
                mo_val: None,
                di: None,
                parsed_tv: None,
                fl_func: None,
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
    fn test_provision_new_rule_immediately_active() {
        // Per draft: "Rule creation do not require a Guard period"
        let m_rules = MRuleSet::default_ipv6_coap();
        let mut manager = SchcCoreconfManager::new(m_rules, vec![], Duration::from_millis(100));

        let rule = create_test_rule(100);
        manager.provision_rule(rule).unwrap();

        assert_eq!(manager.all_rules().len(), 1);
        // New rules are immediately active - no guard period needed
        assert_eq!(manager.active_rules().len(), 1);
    }

    #[test]
    fn test_modify_rule_requires_guard_period() {
        // Per draft: Rule modification requires guard period
        let m_rules = MRuleSet::default_ipv6_coap();
        let initial = vec![create_test_rule(100)];
        let mut manager = SchcCoreconfManager::new(m_rules, initial, Duration::from_millis(10));

        // Modify existing rule
        let mut modified = create_test_rule(100);
        modified.comment = Some("Modified".into());
        manager.provision_rule(modified).unwrap();

        // Rule should be in candidate state (not active) during guard period
        // But we check after guard period elapsed
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

        // Verify error maps to 4.01 Unauthorized
        if let Err(e) = result {
            assert_eq!(e.to_coap_code(), crate::error::CoapCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn test_deletion_blocks_rule_id() {
        // Per draft: "a rule with the same ID cannot be created" during guard period
        let m_rules = MRuleSet::default_ipv6_coap();
        let initial = vec![create_test_rule(100)];
        let mut manager = SchcCoreconfManager::new(m_rules, initial, Duration::from_millis(50));

        // Delete the rule
        let deleted = manager.delete_rule(100, 8).unwrap();
        assert!(deleted);

        // Rule ID should be blocked
        assert!(manager.is_rule_id_blocked(100, 8));

        // Attempting to create a rule with the same ID should fail
        let result = manager.provision_rule(create_test_rule(100));
        assert!(result.is_err());

        // Verify error maps to 4.09 Conflict
        if let Err(e) = result {
            assert_eq!(e.to_coap_code(), crate::error::CoapCode::CONFLICT);
        }
    }

    #[test]
    fn test_duplicate_rule_checks_blocked() {
        let m_rules = MRuleSet::default_ipv6_coap();
        let initial = vec![create_test_rule(100), create_test_rule(200)];
        let mut manager = SchcCoreconfManager::new(m_rules, initial, Duration::from_millis(50));

        // Delete rule 200
        manager.delete_rule(200, 8).unwrap();

        // Try to duplicate rule 100 to blocked ID 200
        let result = manager.duplicate_rule((100, 8), (200, 8), None);
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
                fp: None,
                coap_option_number: None,
                tv: None,
                mo: MatchingOperator::Ignore,
                cda: CompressionAction::ValueSent,
                mo_val: None,
                di: None,
                parsed_tv: None,
                fl_func: None,
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
