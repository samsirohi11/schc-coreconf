//! SCHC CoAP Server Example
//!
//! Demonstrates a CoAP server that hosts SCHC rules via CORECONF.
//!
//! Usage:
//! ```bash
//! cargo run --example schc_coap_server -- --m-rules samples/m-rules.json --rules samples/initial-rules.json
//! ```

use std::time::Duration;

fn main() {
    env_logger::init();

    println!("SCHC-CoRECONF Server Example");
    println!("============================");
    println!();
    println!("This example demonstrates hosting SCHC rules via CoAP/CORECONF.");
    println!();
    println!("Note: Full CoAP server implementation requires integration with");
    println!("      a CoAP stack like coap-rs. This is a placeholder for the");
    println!("      core functionality demonstration.");
    println!();

    // Create the SCHC-CoRECONF manager
    let m_rules = schc_coreconf::MRuleSet::default_ipv6_coap();
    let mut manager = schc_coreconf::SchcCoreconfManager::new(
        m_rules,
        vec![],
        Duration::from_millis(2500), // 2.5s RTT (Earth-Moon)
    );

    // Enable progressive rule learning
    manager.enable_learning(50);

    println!("Manager initialized:");
    println!(
        "  - M-Rules: {} rules (IDs 0-{})",
        manager.m_rules().rules().len(),
        manager.m_rules().reserved_range().1
    );
    println!("  - Guard period: {:?}", manager.guard_period());
    println!("  - Learning enabled: {} packets threshold", 50);
    println!();
    println!("Server would listen on coap://[::]:5683/c");
    println!();
    println!("Supported operations:");
    println!("  GET  /c        - Retrieve all rules");
    println!("  FETCH /c       - Retrieve specific rule(s)");
    println!("  iPATCH /c      - Add/modify/delete rules");
}
