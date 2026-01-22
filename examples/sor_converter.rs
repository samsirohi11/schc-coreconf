//! SOR (SCHC Object Representation) File Converter
//!
//! Utility to convert between JSON and SOR (CBOR) rule formats.
//!
//! Usage:
//!   # Convert JSON to SOR
//!   cargo run --example sor_converter -- json2sor rules/base-ipv6-udp.json rules/base-ipv6-udp.sor
//!
//!   # Convert SOR to JSON (for inspection)
//!   cargo run --example sor_converter -- sor2json rules/base-ipv6-udp.sor --sid samples/ietf-schc.sid
//!
//!   # Display rules with SID mappings
//!   cargo run --example sor_converter -- display rules/base-ipv6-udp.json

use rust_coreconf::CoreconfModel;
use schc::Rule;
use schc_coreconf::sor_loader::{load_sor_rules, rules_to_cbor, display_rules_with_sids};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "json2sor" => {
            if args.len() < 4 {
                eprintln!("Usage: json2sor <input.json> <output.sor>");
                return;
            }
            json_to_sor(&args[2], &args[3]);
        }
        "sor2json" => {
            let sid_file_path = args.iter()
                .position(|a| a == "--sid")
                .and_then(|i| args.get(i + 1))
                .map(|s| s.as_str())
                .unwrap_or("samples/ietf-schc.sid");
            sor_to_json(&args[2], sid_file_path);
        }
        "display" => {
            display_json_rules(&args[2]);
        }
        _ => {
            print_usage();
        }
    }
}

fn print_usage() {
    println!("SOR (SCHC Object Representation) File Converter");
    println!();
    println!("Usage:");
    println!("  sor_converter json2sor <input.json> <output.sor>");
    println!("  sor_converter sor2json <input.sor> [--sid <sid-file>]");
    println!("  sor_converter display <rules.json>");
}

fn json_to_sor(json_path: &str, sor_path: &str) {
    println!("Converting {} -> {}", json_path, sor_path);

    // Load JSON rules
    let json_content = match std::fs::read_to_string(json_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Failed to read JSON file: {}", e);
            return;
        }
    };

    let rules: Vec<Rule> = match serde_json::from_str(&json_content) {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("Failed to parse JSON rules: {}", e);
            return;
        }
    };

    println!("Loaded {} rules from JSON", rules.len());

    // Convert to CBOR
    let cbor_bytes = match rules_to_cbor(&rules) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to convert to CBOR: {}", e);
            return;
        }
    };

    // Write SOR file
    match std::fs::write(sor_path, &cbor_bytes) {
        Ok(_) => {
            println!("Written {} bytes to {}", cbor_bytes.len(), sor_path);
            println!("CBOR hex: {}", hex::encode(&cbor_bytes[..cbor_bytes.len().min(100)]));
            if cbor_bytes.len() > 100 {
                println!("  ... ({} more bytes)", cbor_bytes.len() - 100);
            }
        }
        Err(e) => {
            eprintln!("Failed to write SOR file: {}", e);
        }
    }
}

fn sor_to_json(sor_path: &str, sid_file_path: &str) {
    println!("Converting {} -> JSON (using SID file: {})", sor_path, sid_file_path);

    // Load SID file
    let model = match CoreconfModel::new(sid_file_path) {
        Ok(model) => model,
        Err(e) => {
            eprintln!("Failed to load SID file: {}", e);
            return;
        }
    };

    // Load SOR rules
    let rules = match load_sor_rules(sor_path, &model.sid_file) {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("Failed to load SOR file: {}", e);
            return;
        }
    };

    println!("Loaded {} rules from SOR", rules.len());

    // Convert to JSON
    let json = serde_json::to_string_pretty(&rules).expect("Failed to serialize to JSON");
    println!("\nRules as JSON:\n{}", json);
}

fn display_json_rules(json_path: &str) {
    println!("Displaying rules from {}\n", json_path);

    // Load JSON rules
    let json_content = match std::fs::read_to_string(json_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Failed to read JSON file: {}", e);
            return;
        }
    };

    let rules: Vec<Rule> = match serde_json::from_str(&json_content) {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("Failed to parse JSON rules: {}", e);
            return;
        }
    };

    display_rules_with_sids(&rules);
}
