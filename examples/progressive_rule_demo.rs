//! Progressive Rule Learning Demo
//!
//! Demonstrates how the rule learner observes traffic patterns and
//! suggests more specific compression rules over time.
//!
//! This simulates the progressive learning scenario:
//! 1. Initial rule compresses source address (known from config)
//! 2. After N packets, learn destination address and provision Rule 101
//! 3. After M packets, learn UDP ports and provision Rule 102

use schc::field_id::FieldId;
use schc::rule::{CompressionAction, Field, MatchingOperator, Rule};
use schc_coreconf::{MRuleSet, SchcCoreconfManager};
use std::time::Duration;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("Progressive Rule Learning Demo");
    println!("===============================");
    println!();

    // Create initial rule: source prefix compressed, dest and ports sent
    let initial_rule = Rule {
        rule_id: 100,
        rule_id_length: 8,
        comment: Some("Initial: source prefix compressed".to_string()),
        compression: vec![
            Field {
                fid: FieldId::Ipv6Ver,
                fl: Some(4),
                tv: Some(serde_json::json!(6)),
                mo: MatchingOperator::Equal,
                cda: CompressionAction::NotSent,
                mo_val: None,
                parsed_tv: None,
            },
            Field {
                fid: FieldId::Ipv6DevPrefix,
                fl: Some(64),
                tv: Some(serde_json::json!("0x20010db8000000000000000000000000")),
                mo: MatchingOperator::Equal,
                cda: CompressionAction::NotSent,
                mo_val: None,
                parsed_tv: None,
            },
            Field {
                fid: FieldId::Ipv6AppPrefix,
                fl: Some(64),
                tv: None,
                mo: MatchingOperator::Ignore,
                cda: CompressionAction::ValueSent,
                mo_val: None,
                parsed_tv: None,
            },
            Field {
                fid: FieldId::UdpDevPort,
                fl: Some(16),
                tv: None,
                mo: MatchingOperator::Ignore,
                cda: CompressionAction::ValueSent,
                mo_val: None,
                parsed_tv: None,
            },
            Field {
                fid: FieldId::UdpAppPort,
                fl: Some(16),
                tv: None,
                mo: MatchingOperator::Ignore,
                cda: CompressionAction::ValueSent,
                mo_val: None,
                parsed_tv: None,
            },
        ],
    };

    // Create manager with 2.5s RTT (Earth-Moon scenario)
    let m_rules = MRuleSet::default_ipv6_coap();
    let mut manager =
        SchcCoreconfManager::new(m_rules, vec![initial_rule], Duration::from_millis(2500));

    println!("Configuration:");
    println!("  RTT: 2500ms (Earth-Moon)");
    println!("  Guard Period: {:?}", manager.guard_period());
    println!();

    // Enable learning after 10 packets (for demo purposes)
    let learning_threshold = 10;
    manager.enable_learning(learning_threshold);
    println!(
        "Learning enabled: threshold = {} packets",
        learning_threshold
    );
    println!();

    // Simulate observing packets with constant destination + ports
    let dest_prefix = vec![0x2a, 0x01, 0xcb, 0x08, 0x82, 0x98, 0x60, 0x00];
    let dev_port = vec![0x30, 0x39]; // 12345
    let app_port = vec![0x16, 0x33]; // 5683

    println!(
        "Simulating {} packets with constant patterns...",
        learning_threshold
    );
    println!("  Dest prefix: 0x{}", hex::encode(&dest_prefix));
    println!(
        "  Dev port: {} (0x{})",
        u16::from_be_bytes([dev_port[0], dev_port[1]]),
        hex::encode(&dev_port)
    );
    println!(
        "  App port: {} (0x{})",
        u16::from_be_bytes([app_port[0], app_port[1]]),
        hex::encode(&app_port)
    );
    println!();

    for i in 1..=learning_threshold {
        manager.observe_packet(&[
            (FieldId::Ipv6AppPrefix, dest_prefix.clone()),
            (FieldId::UdpDevPort, dev_port.clone()),
            (FieldId::UdpAppPort, app_port.clone()),
        ]);

        if i % 5 == 0 {
            println!("  Observed {} packets...", i);
        }
    }

    println!();
    println!("Learning complete. Checking for suggestions...");
    println!();

    // Print learning statistics
    if let Some(stats) = manager.learning_stats() {
        println!("Pattern Analysis:");
        for line in stats.lines() {
            println!("  {}", line);
        }
        println!();
    }

    // Check for suggested rule
    if manager.has_suggestion() {
        println!("✓ Learner has suggestions ready!");

        if let Some(new_rule) = manager.suggest_and_provision() {
            println!();
            println!("Suggested and provisioned Rule {}:", new_rule.rule_id);
            println!("  Comment: {:?}", new_rule.comment);
            println!("  Fields optimized:");
            for field in &new_rule.compression {
                if matches!(field.cda, CompressionAction::NotSent) && field.tv.is_some() {
                    println!("    - {:?}: not-sent (TV: {:?})", field.fid, field.tv);
                }
            }
            println!();
            println!(
                "Rule {} scheduled for activation after guard period ({:?})",
                new_rule.rule_id,
                manager.guard_period()
            );
            println!();
            println!("In a real deployment, this rule would be sent to the peer");
            println!("via CoRECONF iPATCH, compressed using M-Rules.");
        }
    } else {
        println!("✗ No suggestions available (patterns may not meet threshold)");
    }

    println!();
    println!("Current rules:");
    for rule in manager.all_rules() {
        let status = if manager
            .active_rules()
            .iter()
            .any(|r| r.rule_id == rule.rule_id)
        {
            "ACTIVE"
        } else {
            "PENDING"
        };
        println!(
            "  Rule {}: {} ({} fields) [{}]",
            rule.rule_id,
            rule.comment.as_deref().unwrap_or("no comment"),
            rule.compression.len(),
            status
        );
    }
}
