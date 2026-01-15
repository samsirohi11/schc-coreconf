//! schc-coreconf: CoRECONF-based rule management for SCHC compression
//!
//! This crate provides integration between SCHC (Static Context Header Compression)
//! and CoRECONF (CoAP Management Interface), enabling remote management of SCHC
//! compression rules via CoAP/CBOR.
//!
//! # Key Features
//!
//! - **M-Rules**: Pre-provisioned rules for compressing CORECONF management traffic
//! - **Guard Period**: RTT-based synchronization for rule activation across endpoints
//! - **Progressive Learning**: Learn traffic patterns and provision more specific rules
//! - **RFC 9363 Compliance**: YANG data model for SCHC rules
//!
//! # Example
//!
//! ```ignore
//! use schc_coreconf::SchcCoreconfManager;
//! use std::time::Duration;
//!
//! // Create manager with estimated RTT
//! let mut manager = SchcCoreconfManager::new(
//!     "samples/ietf-schc.sid",
//!     "samples/m-rules.json",
//!     Some("samples/initial-rules.json"),
//!     Duration::from_millis(2500),  // Earth-Moon RTT
//! ).unwrap();
//!
//! // Enable progressive rule learning
//! manager.enable_learning(50);  // Learn after 50 packets
//!
//! // Get active rules for compression
//! let rules = manager.active_rules();
//! ```

mod conversion;
mod error;
mod guard_period;
mod identities;
mod m_rules;
mod manager;
mod rule_learner;

pub use conversion::{
    schc_rule_to_yang, schc_rule_to_yang_with_metadata, yang_to_schc_rule,
    yang_to_schc_rule_with_metadata, RuleMetadata, RuleNature, RuleStatus,
};
pub use error::{Error, Result};
pub use guard_period::{GuardPeriodManager, RuleState};
pub use identities::{schc_fid_to_yang, yang_cda_to_schc, yang_fid_to_schc, yang_mo_to_schc};
pub use m_rules::MRuleSet;
pub use manager::SchcCoreconfManager;
pub use rule_learner::RuleLearner;
