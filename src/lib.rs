//! schc-coreconf: CoRECONF-based rule management for SCHC compression
//!
//! This crate provides integration between SCHC (Static Context Header Compression)
//! and CoRECONF (CoAP Management Interface), enabling remote management of SCHC
//! compression rules via CoAP/CBOR per draft-toutain-schc-coreconf-management.
//!
//! # Key Features
//!
//! - **M-Rules**: Pre-provisioned rules for compressing CORECONF management traffic
//!   - 4 predefined M-Rules (IDs 0-3) for IPv6/UDP/CoAP CORECONF traffic
//!   - M-Rules are immutable via CORECONF (protected from modification/deletion)
//!   - Management traffic uses fe80::1 (Device) and fe80::2 (Core) addresses
//!
//! - **Guard Period**: RTT-based synchronization for rule activation across endpoints
//!   - New rules are immediately active (no guard period per draft)
//!   - Rule modifications require guard period (candidate state)
//!   - Rule deletions block the ID for guard period duration
//!
//! - **Progressive Learning**: Learn traffic patterns and provision more specific rules
//!
//! - **RFC 9363 Compliance**: YANG data model for SCHC rules with extensions from
//!   draft-toutain-schc-coreconf-management (rule-status, rule-nature)
//!
//! - **CORECONF Protocol**: Full CoAP method support (GET, FETCH, iPATCH, POST)
//!   - SID-based CBOR encoding for compact messages
//!   - duplicate-rule RPC for atomic rule derivation
//!   - Proper CoAP error codes (4.01 Unauthorized, 4.04 Not Found, 4.09 Conflict)
//!
//! # Example
//!
//! ```no_run
//! use schc_coreconf::{SchcCoreconfManager, MRuleSet};
//! use std::time::Duration;
//!
//! // Load M-Rules and create manager
//! let m_rules = MRuleSet::from_file("samples/m-rules.json").unwrap();
//! let mut manager = SchcCoreconfManager::new(
//!     m_rules,
//!     vec![],  // No initial app rules
//!     Duration::from_millis(2500),  // Earth-Moon RTT
//! );
//!
//! // Enable progressive rule learning
//! manager.enable_learning(50);  // Learn after 50 packets
//!
//! // Get combined ruleset (M-Rules + active app rules) for compression
//! let ruleset = manager.compression_ruleset().unwrap();
//!
//! // Duplicate a rule using binary tree derivation
//! // Rule 8/4 can be derived to 8/5 (append 0) or 24/5 (append 1)
//! manager.duplicate_rule((8, 4), (8, 5), None).unwrap();
//! ```

mod conversion;
pub mod coreconf_adapter;
mod error;
mod guard_period;
mod identities;
mod m_rules;
mod manager;
pub mod mgmt_compression;
pub mod rpc_builder;
mod rule_learner;
pub mod sor_loader;

pub use conversion::{
    schc_rule_to_yang, schc_rule_to_yang_with_metadata, yang_to_schc_rule,
    yang_to_schc_rule_with_metadata, RuleMetadata, RuleNature, RuleStatus,
};
pub use coreconf_adapter::{SchcCoreconfHandler, sid};
pub use error::{CoapCode, Error, Result};
pub use guard_period::{GuardPeriodManager, RuleState};
pub use identities::{
    schc_cda_to_yang, schc_fid_to_yang, schc_mo_to_yang,
    yang_cda_to_schc, yang_fid_to_schc, yang_mo_to_schc,
};
pub use m_rules::MRuleSet;
pub use manager::SchcCoreconfManager;
pub use rule_learner::RuleLearner;
pub use sor_loader::{
    load_sor_rules, parse_cbor_rules,
    rules_to_cbor, rules_to_cbor_value,
    field_id_to_sid, mo_to_sid, cda_to_sid,
    format_field_with_sid, display_rules_with_sids,
};
