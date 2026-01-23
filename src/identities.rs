//! YANG identity mappings for SCHC
//!
//! Maps RFC 9363 YANG identities to SCHC implementation types and vice versa.

use schc::field_id::FieldId;
use schc::rule::{CompressionAction, MatchingOperator};

use crate::error::{Error, Result};

/// Map YANG field-id identity (RFC 9363) to SCHC FieldId
pub fn yang_fid_to_schc(yang_fid: &str) -> Result<FieldId> {
    // Strip the "schc:" or "ietf-schc:" prefix if present
    let fid = yang_fid
        .strip_prefix("schc:")
        .or_else(|| yang_fid.strip_prefix("ietf-schc:"))
        .unwrap_or(yang_fid);

    match fid {
        // IPv6 fields
        "fid-ipv6-version" => Ok(FieldId::Ipv6Ver),
        "fid-ipv6-trafficclass" => Ok(FieldId::Ipv6Tc),
        "fid-ipv6-trafficclass-ds" => Ok(FieldId::Ipv6Tc), // Map to TC
        "fid-ipv6-trafficclass-ecn" => Ok(FieldId::Ipv6Tc), // Map to TC
        "fid-ipv6-flowlabel" => Ok(FieldId::Ipv6Fl),
        "fid-ipv6-payload-length" => Ok(FieldId::Ipv6Len),
        "fid-ipv6-nextheader" => Ok(FieldId::Ipv6Nxt),
        "fid-ipv6-hoplimit" => Ok(FieldId::Ipv6HopLmt),
        "fid-ipv6-devprefix" => Ok(FieldId::Ipv6DevPrefix),
        "fid-ipv6-deviid" => Ok(FieldId::Ipv6DevIid),
        "fid-ipv6-appprefix" => Ok(FieldId::Ipv6AppPrefix),
        "fid-ipv6-appiid" => Ok(FieldId::Ipv6AppIid),

        // IPv4 fields
        "fid-ipv4-version" => Ok(FieldId::Ipv4Ver),
        "fid-ipv4-ihl" => Ok(FieldId::Ipv4Ihl),
        "fid-ipv4-dscp" => Ok(FieldId::Ipv4Dscp),
        "fid-ipv4-ecn" => Ok(FieldId::Ipv4Ecn),
        "fid-ipv4-length" => Ok(FieldId::Ipv4Len),
        "fid-ipv4-id" => Ok(FieldId::Ipv4Id),
        "fid-ipv4-flags" => Ok(FieldId::Ipv4Flags),
        "fid-ipv4-fragoffset" => Ok(FieldId::Ipv4FragOff),
        "fid-ipv4-ttl" => Ok(FieldId::Ipv4Ttl),
        "fid-ipv4-protocol" => Ok(FieldId::Ipv4Proto),
        "fid-ipv4-checksum" => Ok(FieldId::Ipv4Chksum),

        // UDP fields
        "fid-udp-dev-port" => Ok(FieldId::UdpDevPort),
        "fid-udp-app-port" => Ok(FieldId::UdpAppPort),
        "fid-udp-length" => Ok(FieldId::UdpLen),
        "fid-udp-checksum" => Ok(FieldId::UdpCksum),

        // CoAP fields
        "fid-coap-version" => Ok(FieldId::CoapVer),
        "fid-coap-type" => Ok(FieldId::CoapType),
        "fid-coap-tkl" => Ok(FieldId::CoapTkl),
        "fid-coap-code" => Ok(FieldId::CoapCode),
        "fid-coap-mid" => Ok(FieldId::CoapMid),
        "fid-coap-token" => Ok(FieldId::CoapToken),

        // CoAP Option fields
        // These are used in M-Rules for CORECONF traffic
        "fid-coap-option-if-match" => Ok(FieldId::CoapIfMatch),
        "fid-coap-option-uri-host" => Ok(FieldId::CoapUriHost),
        "fid-coap-option-etag" => Ok(FieldId::CoapEtag),
        "fid-coap-option-if-none-match" => Ok(FieldId::CoapIfNoneMatch),
        "fid-coap-option-observe" => Ok(FieldId::CoapObserve),
        "fid-coap-option-uri-port" => Ok(FieldId::CoapUriPort),
        "fid-coap-option-location-path" => Ok(FieldId::CoapLocationPath),
        "fid-coap-option-uri-path" => Ok(FieldId::CoapUriPath),
        "fid-coap-option-content-format" => Ok(FieldId::CoapContentFormat),
        "fid-coap-option-max-age" => Ok(FieldId::CoapMaxAge),
        "fid-coap-option-uri-query" => Ok(FieldId::CoapUriQuery),
        "fid-coap-option-accept" => Ok(FieldId::CoapAccept),
        "fid-coap-option-location-query" => Ok(FieldId::CoapLocationQuery),
        "fid-coap-option-block2" => Ok(FieldId::CoapBlock2),
        "fid-coap-option-block1" => Ok(FieldId::CoapBlock1),
        "fid-coap-option-size2" => Ok(FieldId::CoapSize2),
        "fid-coap-option-proxy-uri" => Ok(FieldId::CoapProxyUri),
        "fid-coap-option-proxy-scheme" => Ok(FieldId::CoapProxyScheme),
        "fid-coap-option-size1" => Ok(FieldId::CoapSize1),
        "fid-coap-option-no-response" => Ok(FieldId::CoapNoResponse),

        // QUIC fields
        "fid-quic-first-byte" => Ok(FieldId::QuicFirstByte),
        "fid-quic-version" => Ok(FieldId::QuicVersion),
        "fid-quic-dcid-len" => Ok(FieldId::QuicDcidLen),
        "fid-quic-dcid" => Ok(FieldId::QuicDcid),
        "fid-quic-scid-len" => Ok(FieldId::QuicScidLen),
        "fid-quic-scid" => Ok(FieldId::QuicScid),

        _ => Err(Error::UnknownIdentity(yang_fid.to_string())),
    }
}

/// Map SCHC FieldId to YANG identity string (RFC 9363)
pub fn schc_fid_to_yang(fid: FieldId) -> &'static str {
    match fid {
        // IPv6 fields
        FieldId::Ipv6Ver => "fid-ipv6-version",
        FieldId::Ipv6Tc => "fid-ipv6-trafficclass",
        FieldId::Ipv6Fl => "fid-ipv6-flowlabel",
        FieldId::Ipv6Len => "fid-ipv6-payload-length",
        FieldId::Ipv6Nxt => "fid-ipv6-nextheader",
        FieldId::Ipv6HopLmt => "fid-ipv6-hoplimit",
        FieldId::Ipv6DevPrefix => "fid-ipv6-devprefix",
        FieldId::Ipv6DevIid => "fid-ipv6-deviid",
        FieldId::Ipv6AppPrefix => "fid-ipv6-appprefix",
        FieldId::Ipv6AppIid => "fid-ipv6-appiid",
        FieldId::Ipv6Src => "fid-ipv6-devprefix", // Map to dev prefix
        FieldId::Ipv6Dst => "fid-ipv6-appprefix", // Map to app prefix
        FieldId::Ipv6SrcPrefix => "fid-ipv6-devprefix",
        FieldId::Ipv6SrcIid => "fid-ipv6-deviid",
        FieldId::Ipv6DstPrefix => "fid-ipv6-appprefix",
        FieldId::Ipv6DstIid => "fid-ipv6-appiid",

        // IPv4 fields
        FieldId::Ipv4Ver => "fid-ipv4-version",
        FieldId::Ipv4Ihl => "fid-ipv4-ihl",
        FieldId::Ipv4Dscp => "fid-ipv4-dscp",
        FieldId::Ipv4Ecn => "fid-ipv4-ecn",
        FieldId::Ipv4Len => "fid-ipv4-length",
        FieldId::Ipv4Id => "fid-ipv4-id",
        FieldId::Ipv4Flags => "fid-ipv4-flags",
        FieldId::Ipv4FragOff => "fid-ipv4-fragoffset",
        FieldId::Ipv4Ttl => "fid-ipv4-ttl",
        FieldId::Ipv4Proto => "fid-ipv4-protocol",
        FieldId::Ipv4Chksum => "fid-ipv4-checksum",
        FieldId::Ipv4Src => "fid-ipv4-src",
        FieldId::Ipv4Dst => "fid-ipv4-dst",
        FieldId::Ipv4Dev => "fid-ipv4-dev",
        FieldId::Ipv4App => "fid-ipv4-app",

        // UDP fields
        FieldId::UdpSrcPort => "fid-udp-dev-port",
        FieldId::UdpDstPort => "fid-udp-app-port",
        FieldId::UdpDevPort => "fid-udp-dev-port",
        FieldId::UdpAppPort => "fid-udp-app-port",
        FieldId::UdpLen => "fid-udp-length",
        FieldId::UdpCksum => "fid-udp-checksum",

        // CoAP fields
        FieldId::CoapVer => "fid-coap-version",
        FieldId::CoapType => "fid-coap-type",
        FieldId::CoapTkl => "fid-coap-tkl",
        FieldId::CoapCode => "fid-coap-code",
        FieldId::CoapMid => "fid-coap-mid",
        FieldId::CoapToken => "fid-coap-token",

        // CoAP Option fields
        FieldId::CoapIfMatch => "fid-coap-option-if-match",
        FieldId::CoapUriHost => "fid-coap-option-uri-host",
        FieldId::CoapEtag => "fid-coap-option-etag",
        FieldId::CoapIfNoneMatch => "fid-coap-option-if-none-match",
        FieldId::CoapObserve => "fid-coap-option-observe",
        FieldId::CoapUriPort => "fid-coap-option-uri-port",
        FieldId::CoapLocationPath => "fid-coap-option-location-path",
        FieldId::CoapUriPath => "fid-coap-option-uri-path",
        FieldId::CoapContentFormat => "fid-coap-option-content-format",
        FieldId::CoapMaxAge => "fid-coap-option-max-age",
        FieldId::CoapUriQuery => "fid-coap-option-uri-query",
        FieldId::CoapAccept => "fid-coap-option-accept",
        FieldId::CoapLocationQuery => "fid-coap-option-location-query",
        FieldId::CoapBlock2 => "fid-coap-option-block2",
        FieldId::CoapBlock1 => "fid-coap-option-block1",
        FieldId::CoapSize2 => "fid-coap-option-size2",
        FieldId::CoapProxyUri => "fid-coap-option-proxy-uri",
        FieldId::CoapProxyScheme => "fid-coap-option-proxy-scheme",
        FieldId::CoapSize1 => "fid-coap-option-size1",
        FieldId::CoapNoResponse => "fid-coap-option-no-response",

        // QUIC fields
        FieldId::QuicFirstByte => "fid-quic-first-byte",
        FieldId::QuicVersion => "fid-quic-version",
        FieldId::QuicDcidLen => "fid-quic-dcid-len",
        FieldId::QuicDcid => "fid-quic-dcid",
        FieldId::QuicScidLen => "fid-quic-scid-len",
        FieldId::QuicScid => "fid-quic-scid",

        // Fallback for any other fields
        _ => "fid-base-type",
    }
}

/// Map YANG matching-operator identity to SCHC MatchingOperator
pub fn yang_mo_to_schc(yang_mo: &str) -> Result<MatchingOperator> {
    let mo = yang_mo
        .strip_prefix("schc:")
        .or_else(|| yang_mo.strip_prefix("ietf-schc:"))
        .unwrap_or(yang_mo);

    match mo {
        "mo-equal" => Ok(MatchingOperator::Equal),
        "mo-ignore" => Ok(MatchingOperator::Ignore),
        "mo-msb" => Ok(MatchingOperator::Msb(0)), // MSB value set separately
        "mo-match-mapping" => Ok(MatchingOperator::MatchMapping),
        _ => Err(Error::UnknownIdentity(yang_mo.to_string())),
    }
}

/// Map SCHC MatchingOperator to YANG identity string
pub fn schc_mo_to_yang(mo: &MatchingOperator) -> &'static str {
    match mo {
        MatchingOperator::Equal => "mo-equal",
        MatchingOperator::Ignore => "mo-ignore",
        MatchingOperator::Msb(_) => "mo-msb",
        MatchingOperator::MatchMapping => "mo-match-mapping",
    }
}

/// Map YANG CDA identity to SCHC CompressionAction
pub fn yang_cda_to_schc(yang_cda: &str) -> Result<CompressionAction> {
    let cda = yang_cda
        .strip_prefix("schc:")
        .or_else(|| yang_cda.strip_prefix("ietf-schc:"))
        .unwrap_or(yang_cda);

    match cda {
        "cda-not-sent" => Ok(CompressionAction::NotSent),
        "cda-value-sent" => Ok(CompressionAction::ValueSent),
        "cda-lsb" => Ok(CompressionAction::Lsb), // LSB value set separately
        "cda-mapping-sent" => Ok(CompressionAction::MappingSent),
        "cda-compute" => Ok(CompressionAction::Compute),
        "cda-deviid" => Ok(CompressionAction::NotSent), // Device IID computed
        "cda-appiid" => Ok(CompressionAction::NotSent), // App IID computed
        _ => Err(Error::UnknownIdentity(yang_cda.to_string())),
    }
}

/// Map SCHC CompressionAction to YANG identity string
pub fn schc_cda_to_yang(cda: &CompressionAction) -> &'static str {
    match cda {
        CompressionAction::NotSent => "cda-not-sent",
        CompressionAction::ValueSent => "cda-value-sent",
        CompressionAction::Lsb => "cda-lsb",
        CompressionAction::MappingSent => "cda-mapping-sent",
        CompressionAction::Compute => "cda-compute",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yang_fid_roundtrip() {
        let fids = [
            FieldId::Ipv6Ver,
            FieldId::Ipv6Tc,
            FieldId::UdpDevPort,
            FieldId::CoapCode,
        ];

        for fid in fids {
            let yang = schc_fid_to_yang(fid);
            let back = yang_fid_to_schc(yang).unwrap();
            assert_eq!(fid, back, "Roundtrip failed for {:?}", fid);
        }
    }

    #[test]
    fn test_yang_mo_roundtrip() {
        assert_eq!(
            yang_mo_to_schc("mo-equal").unwrap(),
            MatchingOperator::Equal
        );
        assert_eq!(
            yang_mo_to_schc("mo-ignore").unwrap(),
            MatchingOperator::Ignore
        );
        assert!(matches!(
            yang_mo_to_schc("mo-msb").unwrap(),
            MatchingOperator::Msb(_)
        ));
    }

    #[test]
    fn test_yang_cda_roundtrip() {
        assert_eq!(
            yang_cda_to_schc("cda-not-sent").unwrap(),
            CompressionAction::NotSent
        );
        assert_eq!(
            yang_cda_to_schc("cda-value-sent").unwrap(),
            CompressionAction::ValueSent
        );
        assert_eq!(
            yang_cda_to_schc("cda-compute").unwrap(),
            CompressionAction::Compute
        );
    }

    #[test]
    fn test_prefixed_identities() {
        // Test with ietf-schc: prefix
        assert!(yang_fid_to_schc("ietf-schc:fid-ipv6-version").is_ok());
        assert!(yang_mo_to_schc("schc:mo-equal").is_ok());
    }
}
