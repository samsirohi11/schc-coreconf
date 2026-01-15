# schc-coreconf

CoRECONF-based rule management for SCHC (Static Context Header Compression).

This crate bridges SCHC compression with CoRECONF, enabling remote management of SCHC rules via CoAP/CBOR using YANG data models per [draft-toutain-schc-coreconf-management](https://datatracker.ietf.org/doc/draft-toutain-schc-coreconf-management/).

## Features

- **M-Rules (M1-M4)**: Pre-provisioned rules for compressing CORECONF management traffic with CoAP layer support
- **Guard Period**: RTT-based synchronization for rule activation across high-latency links
- **Rule Status**: Active/Candidate states per draft specification
- **Duplicate-Rule RPC**: Recommended method for deriving new rules from existing ones
- **Binary Tree Rule IDs**: Helper functions for proper rule derivation structure
- **Progressive Learning**: Observes traffic patterns and suggests optimized rules
- **RFC 9363 Compliance**: YANG identity mappings for SCHC field IDs, MOs, and CDAs

## Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/samsirohi11/schc-coreconf.git
cd schc-coreconf

# Run progressive learning demo
cargo run --example progressive_rule_demo
```

## Project Structure

```
schc-coreconf/
├── schc/           # Git submodule: SCHC compression engine
├── coreconf/       # Git submodule: rust-coreconf library
├── src/
│   ├── lib.rs          # Public API
│   ├── identities.rs   # YANG ↔ SCHC identity mappings
│   ├── conversion.rs   # YANG ↔ SCHC rule conversion
│   ├── m_rules.rs      # M-Rule management
│   ├── guard_period.rs # RTT-based synchronization
│   ├── rule_learner.rs # Progressive pattern learning
│   └── manager.rs      # Unified SCHC-CoRECONF manager
├── samples/
│   ├── m-rules.json        # M-Rules for CORECONF traffic
│   └── initial-rules.json  # Example initial rules
└── examples/
    ├── schc_coap_server.rs     # CoAP server demo
    ├── schc_coap_client.rs     # CoAP client CLI
    └── progressive_rule_demo.rs # Learning demo
```

## Usage

```rust
use schc_coreconf::{SchcCoreconfManager, MRuleSet};
use std::time::Duration;

// Create manager with 2.5s RTT (Earth-Moon)
let m_rules = MRuleSet::default_ipv6_coap();
let mut manager = SchcCoreconfManager::new(
    m_rules,
    vec![],  // initial rules
    Duration::from_millis(2500),
);

// Enable progressive learning
manager.enable_learning(50);  // After 50 packets

// Observe packets during compression
manager.observe_packet(&[(FieldId::Ipv6AppPrefix, dest_bytes)]);

// Check for rule suggestions
if manager.has_suggestion() {
    if let Some(new_rule) = manager.suggest_and_provision() {
        // Send to peer via CoRECONF iPATCH
    }
}
```

## References

- [draft-toutain-schc-coreconf-management](https://datatracker.ietf.org/doc/draft-toutain-schc-coreconf-management/) - CORECONF Rule management for SCHC
- [RFC 9363](https://datatracker.ietf.org/doc/rfc9363/) - YANG Data Model for SCHC
- [RFC 8724](https://datatracker.ietf.org/doc/rfc8724/) - SCHC Framework
- [draft-ietf-core-comi](https://datatracker.ietf.org/doc/draft-ietf-core-comi/) - CoRECONF

## License

MIT
