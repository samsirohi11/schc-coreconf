//! SCHC CoAP Client Example
//!
//! Demonstrates a CLI client for managing SCHC rules via CORECONF.
//!
//! Usage:
//! ```bash
//! cargo run --example schc_coap_client -- --server coap://localhost:5683/c list
//! ```

fn main() {
    env_logger::init();

    println!("SCHC-CoRECONF Client Example");
    println!("============================");
    println!();
    println!("This example demonstrates a CLI for managing SCHC rules via CoAP.");
    println!();
    println!("Commands:");
    println!("  list              - List all rules (GET)");
    println!("  get <rule-id>     - Get a specific rule (FETCH)");
    println!("  add <rule-json>   - Add a new rule (iPATCH)");
    println!("  update <rule-json>- Update existing rule (iPATCH)");
    println!("  delete <rule-id>  - Delete a rule (iPATCH with null)");
    println!("  export <file>     - Export rules to JSON file");
    println!();
    println!("Note: Full CoAP client implementation requires integration with");
    println!("      a CoAP stack. This is a placeholder demonstration.");
}
