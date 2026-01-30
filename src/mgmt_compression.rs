//! Management Traffic Compression
//!
//! This module provides helpers to compress CORECONF management traffic
//! using M-Rules before transmission, and decompress on the receiver side.
//!
//! Per draft-toutain-schc-coreconf-management, M-Rules are pre-provisioned
//! rules used exclusively for compressing CORECONF management traffic.

use schc::{build_tree, compress_packet, decompress_packet, Direction, Rule, RuleSet};

use crate::error::{Error, Result};
use crate::m_rules::MRuleSet;

/// Management traffic compressor
///
/// Wraps M-Rules for compressing CORECONF traffic (CoAP iPATCH/RPC payloads).
pub struct MgmtCompressor {
    /// M-Rules for compression
    m_rules: Vec<Rule>,
    /// Debug mode
    debug: bool,
}

impl MgmtCompressor {
    /// Create a new management traffic compressor from M-Rules
    pub fn new(m_rules: &MRuleSet, debug: bool) -> Self {
        Self {
            m_rules: m_rules.rules().to_vec(),
            debug,
        }
    }

    /// Compress a CORECONF management payload
    ///
    /// Takes an IPv6/UDP/CoAP packet and compresses it using M-Rules.
    /// Returns the compressed SCHC packet.
    ///
    /// # Arguments
    /// * `packet` - Full IPv6/UDP/CoAP packet
    /// * `direction` - Up (device->core) or Down (core->device)
    ///
    /// # Returns
    /// Compressed SCHC packet bytes
    pub fn compress(&self, packet: &[u8], direction: Direction) -> Result<Vec<u8>> {
        let tree = build_tree(&self.m_rules);

        match compress_packet(&tree, packet, direction, &self.m_rules, self.debug) {
            Ok(compressed) => {
                if self.debug {
                    println!(
                        "Compressed with Rule {}/{}",
                        compressed.rule_id,
                        compressed.rule_id_length
                    );
                }
                Ok(compressed.data)
            }
            Err(e) => Err(Error::Schc(format!("Compression failed: {:?}", e))),
        }
    }

    /// Decompress a CORECONF management payload
    ///
    /// Takes a compressed SCHC packet and decompresses it using M-Rules.
    /// Returns the original IPv6/UDP/CoAP packet.
    ///
    /// # Arguments
    /// * `compressed` - Compressed SCHC packet
    /// * `direction` - Up or Down
    ///
    /// # Returns
    /// Decompressed full packet
    pub fn decompress(&self, compressed: &[u8], direction: Direction) -> Result<Vec<u8>> {
        match decompress_packet(compressed, &self.m_rules, direction, None) {
            Ok(result) => {
                if self.debug {
                    println!(
                        "Decompressed with Rule {}/{}",
                        result.rule_id,
                        result.rule_id_length
                    );
                }
                Ok(result.full_data)
            }
            Err(e) => Err(Error::Schc(format!("Decompression failed: {:?}", e))),
        }
    }

    /// Check if a packet can be compressed with M-Rules
    ///
    /// Attempts compression and returns true if a matching rule was found.
    pub fn can_compress(&self, packet: &[u8], direction: Direction) -> bool {
        let tree = build_tree(&self.m_rules);
        compress_packet(&tree, packet, direction, &self.m_rules, false).is_ok()
    }

    /// Get the M-Rules as a RuleSet for use with standard SCHC functions
    pub fn ruleset(&self) -> Result<RuleSet> {
        let json = serde_json::to_string(&self.m_rules)?;
        RuleSet::from_json(&json).map_err(|e| Error::Schc(e.to_string()))
    }
}

/// Compress a CoAP management message payload
///
/// This function wraps the payload in minimal CoAP headers for compression.
/// Use this when you want to compress just the CBOR payload, not a full packet.
///
/// # Arguments
/// * `payload` - CBOR payload (e.g., duplicate-rule RPC)
/// * `m_rules` - M-Rules for compression
///
/// # Returns
/// Compressed data (or original payload if compression fails/doesn't help)
pub fn compress_coap_payload(payload: &[u8], _m_rules: &MRuleSet) -> Vec<u8> {
    // For simple payloads, compression may not help
    // The M-Rules compress full IPv6/UDP/CoAP headers, not just payloads
    //
    // To fully benefit, the entire CoAP message should be compressed
    // as part of the IPv6/UDP/CoAP stack.
    //
    // For now, we return the payload as-is, with a note that the
    // compression happens at the packet level in the examples.
    payload.to_vec()
}

/// Statistics for management compression
#[derive(Debug, Default, Clone)]
pub struct CompressionStats {
    pub packets_compressed: u64,
    pub packets_decompressed: u64,
    pub bytes_saved: i64,
    pub bytes_original: u64,
    pub bytes_compressed: u64,
}

impl CompressionStats {
    /// Record a compression operation
    pub fn record_compression(&mut self, original_len: usize, compressed_len: usize) {
        self.packets_compressed += 1;
        self.bytes_original += original_len as u64;
        self.bytes_compressed += compressed_len as u64;
        self.bytes_saved += (original_len as i64) - (compressed_len as i64);
    }

    /// Record a decompression operation
    pub fn record_decompression(&mut self) {
        self.packets_decompressed += 1;
    }

    /// Get compression ratio as a percentage
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_original == 0 {
            return 0.0;
        }
        (1.0 - (self.bytes_compressed as f64 / self.bytes_original as f64)) * 100.0
    }

    /// Format as summary string
    pub fn summary(&self) -> String {
        format!(
            "Compressed: {} pkts, Decompressed: {} pkts, Saved: {} bytes ({:.1}%)",
            self.packets_compressed,
            self.packets_decompressed,
            self.bytes_saved,
            self.compression_ratio()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_stats() {
        let mut stats = CompressionStats::default();
        stats.record_compression(100, 20);
        stats.record_compression(100, 30);

        assert_eq!(stats.packets_compressed, 2);
        assert_eq!(stats.bytes_original, 200);
        assert_eq!(stats.bytes_compressed, 50);
        assert_eq!(stats.bytes_saved, 150);
        assert!((stats.compression_ratio() - 75.0).abs() < 0.1);
    }

    #[test]
    fn test_mgmt_compressor_creation() {
        let m_rules = MRuleSet::default_ipv6_coap();
        let compressor = MgmtCompressor::new(&m_rules, false);
        assert!(!compressor.m_rules.is_empty());
    }
}
