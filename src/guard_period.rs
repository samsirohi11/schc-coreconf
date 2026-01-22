//! Guard period management for rule synchronization
//!
//! Ensures that both endpoints wait for a guard period (based on RTT)
//! before using newly provisioned rules, enabling synchronization
//! across high-latency links like Earth-Moon communication.
//!
//! - Rule creation does NOT require a guard period (immediately active)
//! - Rule modification requires a guard period (candidate state)
//! - Rule deletion requires a guard period during which the rule ID is blocked

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rule activation state
#[derive(Debug, Clone, PartialEq)]
pub enum RuleState {
    /// Rule is active and can be used for compression
    Active,
    /// Rule is candidate (pending activation, in guard period)
    /// Per draft-toutain-schc-coreconf-management terminology
    Candidate {
        /// When the rule will become active
        activation_time: Instant,
    },
    /// Rule is deprecated and being phased out
    Deprecated {
        /// When the rule should be removed
        expiry_time: Instant,
    },
}

/// Guard period manager for rule activation synchronization
///
/// The guard period ensures that newly provisioned rules are not used
/// until both endpoints have had time to receive and process the update.
/// The guard period is calculated as a multiple of the estimated RTT.
///
/// - New rules are immediately active (no guard period)
/// - Modified rules enter candidate state for guard period
/// - Deleted rules block their ID for guard period (no re-creation allowed)
#[derive(Debug)]
pub struct GuardPeriodManager {
    /// Estimated RTT to peer (e.g., 2.5s for Earth-Moon)
    estimated_rtt: Duration,
    /// Safety margin multiplier (default: 2x RTT)
    safety_multiplier: f64,
    /// Rule states by (rule_id, rule_id_length)
    rule_states: HashMap<(u32, u8), RuleState>,
    /// Blocked rule IDs during deletion guard period
    /// Per draft: "a rule with the same ID cannot be created" during guard period
    blocked_ids: HashMap<(u32, u8), Instant>,
}

impl GuardPeriodManager {
    /// Create a new guard period manager with the given RTT estimate
    ///
    /// # Arguments
    /// * `estimated_rtt` - Estimated round-trip time to the peer
    pub fn new(estimated_rtt: Duration) -> Self {
        Self {
            estimated_rtt,
            safety_multiplier: 2.0,
            rule_states: HashMap::new(),
            blocked_ids: HashMap::new(),
        }
    }

    /// Create with custom safety multiplier
    pub fn with_multiplier(estimated_rtt: Duration, multiplier: f64) -> Self {
        Self {
            estimated_rtt,
            safety_multiplier: multiplier,
            rule_states: HashMap::new(),
            blocked_ids: HashMap::new(),
        }
    }

    /// Get the current estimated RTT
    pub fn estimated_rtt(&self) -> Duration {
        self.estimated_rtt
    }

    /// Update the estimated RTT (e.g., after RTT measurement)
    pub fn set_estimated_rtt(&mut self, rtt: Duration) {
        self.estimated_rtt = rtt;
    }

    /// Calculate the guard period based on RTT and safety multiplier
    pub fn guard_period(&self) -> Duration {
        Duration::from_secs_f64(self.estimated_rtt.as_secs_f64() * self.safety_multiplier)
    }

    /// Schedule a new rule for activation after the guard period
    ///
    /// The rule will transition to Active state after the guard period elapses.
    /// During the guard period, the rule is in Candidate state per the draft.
    pub fn schedule_activation(&mut self, rule_id: u32, rule_id_length: u8) {
        let activation_time = Instant::now() + self.guard_period();
        log::info!(
            "Scheduling rule {}/{} for activation in {:?} (candidate)",
            rule_id,
            rule_id_length,
            self.guard_period()
        );
        self.rule_states.insert(
            (rule_id, rule_id_length),
            RuleState::Candidate { activation_time },
        );
    }

    /// Mark a rule as immediately active (for pre-existing rules)
    pub fn mark_active(&mut self, rule_id: u32, rule_id_length: u8) {
        self.rule_states
            .insert((rule_id, rule_id_length), RuleState::Active);
    }

    /// Schedule a rule for deprecation
    ///
    /// The rule remains active until the expiry time, then is removed.
    /// Per draft-toutain: "a rule with the same ID cannot be created" during
    /// the guard period after deletion.
    pub fn schedule_deprecation(&mut self, rule_id: u32, rule_id_length: u8) {
        let expiry_time = Instant::now() + self.guard_period();
        log::info!(
            "Scheduling rule {}/{} for deprecation in {:?}",
            rule_id,
            rule_id_length,
            self.guard_period()
        );
        self.rule_states.insert(
            (rule_id, rule_id_length),
            RuleState::Deprecated { expiry_time },
        );
        // Block this rule ID from being re-created during guard period
        self.blocked_ids
            .insert((rule_id, rule_id_length), expiry_time);
    }

    /// Check if a rule ID is blocked (during deletion guard period)
    ///
    /// Per draft-toutain: During deletion guard period, "a rule with the same
    /// ID cannot be created, and SCHC PDU carrying the Rule ID are dropped."
    pub fn is_rule_id_blocked(&self, rule_id: u32, rule_id_length: u8) -> bool {
        if let Some(&expiry_time) = self.blocked_ids.get(&(rule_id, rule_id_length)) {
            Instant::now() < expiry_time
        } else {
            false
        }
    }

    /// Get time until a blocked rule ID becomes available
    pub fn time_until_unblocked(&self, rule_id: u32, rule_id_length: u8) -> Option<Duration> {
        if let Some(&expiry_time) = self.blocked_ids.get(&(rule_id, rule_id_length)) {
            let now = Instant::now();
            if now < expiry_time {
                Some(expiry_time - now)
            } else {
                Some(Duration::ZERO)
            }
        } else {
            None
        }
    }

    /// Check if a rule is currently active (can be used for compression)
    pub fn is_rule_active(&self, rule_id: u32, rule_id_length: u8) -> bool {
        match self.rule_states.get(&(rule_id, rule_id_length)) {
            Some(RuleState::Active) => true,
            Some(RuleState::Candidate { activation_time }) => Instant::now() >= *activation_time,
            Some(RuleState::Deprecated { .. }) => true, // Still usable until removed
            None => true, // Unknown rules are assumed active (for initial rules)
        }
    }

    /// Get the state of a specific rule
    pub fn get_state(&self, rule_id: u32, rule_id_length: u8) -> Option<&RuleState> {
        self.rule_states.get(&(rule_id, rule_id_length))
    }

    /// Get time until a candidate rule becomes active
    pub fn time_until_active(&self, rule_id: u32, rule_id_length: u8) -> Option<Duration> {
        match self.rule_states.get(&(rule_id, rule_id_length)) {
            Some(RuleState::Candidate { activation_time }) => {
                let now = Instant::now();
                if now < *activation_time {
                    Some(*activation_time - now)
                } else {
                    Some(Duration::ZERO)
                }
            }
            _ => None,
        }
    }

    /// Update rule states, transitioning pending rules to active
    ///
    /// Call this periodically to update rule states based on elapsed time.
    /// Returns a list of rules that were activated, removed, or unblocked.
    pub fn tick(&mut self) -> Vec<(u32, u8, &'static str)> {
        let now = Instant::now();
        let mut changes = Vec::new();
        let mut to_remove = Vec::new();
        let mut to_unblock = Vec::new();

        for (&(rule_id, rule_id_length), state) in self.rule_states.iter_mut() {
            match state {
                RuleState::Candidate { activation_time } if now >= *activation_time => {
                    *state = RuleState::Active;
                    log::info!(
                        "Rule {}/{} activated after guard period",
                        rule_id,
                        rule_id_length
                    );
                    changes.push((rule_id, rule_id_length, "activated"));
                }
                RuleState::Deprecated { expiry_time } if now >= *expiry_time => {
                    to_remove.push((rule_id, rule_id_length));
                    changes.push((rule_id, rule_id_length, "removed"));
                }
                _ => {}
            }
        }

        // Clean up expired blocked IDs
        for (&(rule_id, rule_id_length), &expiry_time) in self.blocked_ids.iter() {
            if now >= expiry_time {
                to_unblock.push((rule_id, rule_id_length));
                changes.push((rule_id, rule_id_length, "unblocked"));
            }
        }

        for key in to_remove {
            self.rule_states.remove(&key);
            log::info!("Rule {}/{} removed after deprecation", key.0, key.1);
        }

        for key in to_unblock {
            self.blocked_ids.remove(&key);
            log::info!("Rule ID {}/{} unblocked after guard period", key.0, key.1);
        }

        changes
    }

    /// Get all currently active rule IDs
    pub fn active_rule_ids(&self) -> Vec<(u32, u8)> {
        let now = Instant::now();
        self.rule_states
            .iter()
            .filter(|(_, state)| match state {
                RuleState::Active => true,
                RuleState::Candidate { activation_time } => now >= *activation_time,
                RuleState::Deprecated { expiry_time } => now < *expiry_time,
            })
            .map(|(&key, _)| key)
            .collect()
    }

    /// Clear all rule states and blocked IDs
    pub fn clear(&mut self) {
        self.rule_states.clear();
        self.blocked_ids.clear();
    }

    /// Get all currently blocked rule IDs
    pub fn blocked_rule_ids(&self) -> Vec<(u32, u8)> {
        let now = Instant::now();
        self.blocked_ids
            .iter()
            .filter(|(_, &expiry)| now < expiry)
            .map(|(&key, _)| key)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_guard_period_calculation() {
        let manager = GuardPeriodManager::new(Duration::from_millis(100));
        assert_eq!(manager.guard_period(), Duration::from_millis(200)); // 2x RTT
    }

    #[test]
    fn test_custom_multiplier() {
        let manager = GuardPeriodManager::with_multiplier(Duration::from_millis(100), 3.0);
        assert_eq!(manager.guard_period(), Duration::from_millis(300)); // 3x RTT
    }

    #[test]
    fn test_rule_activation_lifecycle() {
        let mut manager = GuardPeriodManager::new(Duration::from_millis(10));

        // Schedule a rule
        manager.schedule_activation(100, 8);

        // Should not be active immediately
        assert!(
            !manager.is_rule_active(100, 8)
                || manager
                    .time_until_active(100, 8)
                    .is_some_and(|d| d.is_zero())
        );

        // Wait for guard period
        sleep(Duration::from_millis(25));

        // Now should be active
        assert!(manager.is_rule_active(100, 8));
    }

    #[test]
    fn test_unknown_rules_assumed_active() {
        let manager = GuardPeriodManager::new(Duration::from_secs(1));

        // Unknown rules (e.g., pre-existing) should be considered active
        assert!(manager.is_rule_active(999, 8));
    }

    #[test]
    fn test_tick_activates_pending() {
        let mut manager = GuardPeriodManager::new(Duration::from_millis(1));
        manager.schedule_activation(42, 6);

        sleep(Duration::from_millis(5));

        let changes = manager.tick();
        assert!(!changes.is_empty());
        assert_eq!(changes[0], (42, 6, "activated"));
    }

    #[test]
    fn test_deletion_blocks_rule_id() {
        let mut manager = GuardPeriodManager::new(Duration::from_millis(10));

        // Mark rule as active first
        manager.mark_active(50, 6);

        // Schedule deprecation - should block the ID
        manager.schedule_deprecation(50, 6);

        // ID should be blocked immediately
        assert!(manager.is_rule_id_blocked(50, 6));

        // Other IDs should not be blocked
        assert!(!manager.is_rule_id_blocked(51, 6));
        assert!(!manager.is_rule_id_blocked(50, 7));

        // Wait for guard period to expire
        sleep(Duration::from_millis(25));
        manager.tick();

        // ID should no longer be blocked
        assert!(!manager.is_rule_id_blocked(50, 6));
    }

    #[test]
    fn test_blocked_rule_ids_list() {
        let mut manager = GuardPeriodManager::new(Duration::from_millis(50));

        manager.schedule_deprecation(10, 4);
        manager.schedule_deprecation(20, 4);

        let blocked = manager.blocked_rule_ids();
        assert_eq!(blocked.len(), 2);
        assert!(blocked.contains(&(10, 4)));
        assert!(blocked.contains(&(20, 4)));
    }
}
