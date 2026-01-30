//! CORECONF Integration Adapter
//!
//! Bridges the SchcCoreconfManager with the rust-coreconf library,
//! providing a complete CORECONF server for SCHC rule management.
//!
//! This module implements the protocol-level integration per
//! draft-toutain-schc-coreconf-management.

use rust_coreconf::coap_types::{ContentFormat, Method, Request, Response, ResponseCode};
use rust_coreconf::{CoreconfModel, Datastore, RequestHandler};
use serde_json::Value;
use std::io::Cursor;
use std::sync::{Arc, RwLock};

use crate::conversion::{
    schc_rule_to_yang_with_metadata, yang_to_schc_rule_with_metadata, RuleMetadata, RuleNature,
    RuleStatus,
};
use crate::error::{CoapCode, Error, Result};
use crate::manager::SchcCoreconfManager;

/// SID constants for SCHC YANG model
/// Per draft-toutain-schc-coreconf-management and ietf-schc.sid
pub mod sid {
    /// SID for /ietf-schc:schc container
    pub const SCHC: i64 = 5100;
    /// SID for /ietf-schc:schc/rule list
    pub const RULE: i64 = 5110;
    /// SID for rule-id-value
    pub const RULE_ID_VALUE: i64 = 5135;
    /// SID for rule-id-length
    pub const RULE_ID_LENGTH: i64 = 5136;
    /// SID for rule-status
    pub const RULE_STATUS: i64 = 5137;
    /// SID for rule-nature
    pub const RULE_NATURE: i64 = 5138;
    /// SID for duplicate-rule RPC
    pub const DUPLICATE_RULE: i64 = 5200;
    /// SID for duplicate-rule input
    pub const DUPLICATE_RULE_INPUT: i64 = 5201;
    /// SID for source-rule-id-value
    pub const SOURCE_RULE_ID_VALUE: i64 = 5202;
    /// SID for source-rule-id-length
    pub const SOURCE_RULE_ID_LENGTH: i64 = 5203;
    /// SID for target-rule-id-value
    pub const TARGET_RULE_ID_VALUE: i64 = 5204;
    /// SID for target-rule-id-length
    pub const TARGET_RULE_ID_LENGTH: i64 = 5205;
    /// SID for modifications
    pub const MODIFICATIONS: i64 = 5206;
}

/// SCHC CORECONF Handler
///
/// Integrates SchcCoreconfManager with CORECONF protocol handling.
/// Provides M-Rule protection, guard period enforcement, and
/// duplicate-rule RPC support.
pub struct SchcCoreconfHandler {
    /// The SCHC rule manager
    manager: Arc<RwLock<SchcCoreconfManager>>,
    /// The CORECONF model (SID mappings) - reserved for future SID-based operations
    _model: CoreconfModel,
    /// Datastore for YANG data
    datastore: Datastore,
}

impl SchcCoreconfHandler {
    /// Acquire a read lock on the manager, recovering from poison if necessary
    fn read_manager(&self) -> Result<std::sync::RwLockReadGuard<'_, SchcCoreconfManager>> {
        match self.manager.read() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                log::warn!("Manager lock was poisoned, recovering");
                Ok(poisoned.into_inner())
            }
        }
    }

    /// Acquire a write lock on the manager, recovering from poison if necessary
    fn write_manager(&self) -> Result<std::sync::RwLockWriteGuard<'_, SchcCoreconfManager>> {
        match self.manager.write() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                log::warn!("Manager lock was poisoned, recovering");
                Ok(poisoned.into_inner())
            }
        }
    }
    /// Create a new SCHC CORECONF handler
    ///
    /// # Arguments
    /// * `sid_file_path` - Path to the ietf-schc.sid file
    /// * `manager` - The SCHC rule manager
    pub fn new(sid_file_path: &str, manager: SchcCoreconfManager) -> Result<Self> {
        let model = CoreconfModel::new(sid_file_path).map_err(|e| Error::SidFile(e.to_string()))?;

        // Initialize datastore with current rules
        let mut datastore = Datastore::new(model.clone());

        // Sync rules to datastore
        let manager = Arc::new(RwLock::new(manager));
        {
            let manager_guard = match manager.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::warn!("Manager lock was poisoned during initialization, recovering");
                    poisoned.into_inner()
                }
            };
            Self::sync_rules_to_datastore(&manager_guard, &mut datastore)?;
        } // guard is dropped here

        Ok(Self {
            manager,
            _model: model,
            datastore,
        })
    }

    /// Create with default SID file path
    pub fn with_default_sid(manager: SchcCoreconfManager) -> Result<Self> {
        Self::new("samples/ietf-schc@2026-01-12.sid", manager)
    }

    /// Sync rules from manager to datastore
    fn sync_rules_to_datastore(
        manager: &SchcCoreconfManager,
        datastore: &mut Datastore,
    ) -> Result<()> {
        // Build YANG JSON structure for all rules
        let mut rules_json = Vec::new();

        // Add M-Rules with management nature
        for rule in manager.m_rules().rules() {
            let metadata = RuleMetadata {
                status: RuleStatus::Active,
                nature: RuleNature::Management,
            };
            let yang = schc_rule_to_yang_with_metadata(rule, &metadata)?;
            rules_json.push(yang);
        }

        // Add application rules
        for rule in manager.all_rules() {
            let metadata = RuleMetadata {
                status: RuleStatus::Active,
                nature: RuleNature::Compression,
            };
            let yang = schc_rule_to_yang_with_metadata(rule, &metadata)?;
            rules_json.push(yang);
        }

        // Set in datastore using set_by_path
        let schc_data = serde_json::json!({
            "rule": rules_json
        });

        datastore
            .set_by_path("/ietf-schc:schc", schc_data)
            .map_err(|e| Error::Coreconf(e.to_string()))?;

        Ok(())
    }

    /// Handle an incoming CORECONF request
    ///
    /// Implements GET, FETCH, iPATCH, and POST methods with
    /// M-Rule protection per draft-toutain-schc-coreconf-management.
    pub fn handle(&mut self, request: &Request) -> Response {
        match request.method {
            Method::Get => self.handle_get(request),
            Method::Fetch => self.handle_fetch(request),
            Method::IPatch => self.handle_ipatch(request),
            Method::Post => self.handle_post(request),
        }
    }

    /// Handle GET request - retrieve full datastore
    fn handle_get(&self, _request: &Request) -> Response {
        // Sync current rules to datastore first
        let manager = match self.read_manager() {
            Ok(guard) => guard,
            Err(e) => return Self::error_response(&e),
        };
        let mut datastore = self.datastore.clone();

        if let Err(e) = Self::sync_rules_to_datastore(&manager, &mut datastore) {
            return Self::error_response(&e);
        }

        match datastore.get_all_cbor() {
            Ok(cbor) => Response::content(cbor, ContentFormat::YangDataCbor),
            Err(e) => Response::error(ResponseCode::InternalServerError, &e.to_string()),
        }
    }

    /// Handle FETCH request - retrieve specific rules
    fn handle_fetch(&self, request: &Request) -> Response {
        // Validate content format
        if let Some(format) = request.content_format {
            if format != ContentFormat::YangIdentifiersCbor && format != ContentFormat::YangDataCbor
            {
                return Response::error(
                    ResponseCode::UnsupportedContentFormat,
                    "expected yang-identifiers+cbor",
                );
            }
        }

        // Empty payload = return all data
        if request.payload.is_empty() {
            return self.handle_get(request);
        }

        // Delegate to base handler
        let manager = match self.read_manager() {
            Ok(guard) => guard,
            Err(e) => return Self::error_response(&e),
        };
        let mut datastore = self.datastore.clone();

        if let Err(e) = Self::sync_rules_to_datastore(&manager, &mut datastore) {
            return Self::error_response(&e);
        }

        let mut handler = RequestHandler::new(datastore);
        handler.handle(request)
    }

    /// Handle iPATCH request - modify rules
    ///
    /// Implements M-Rule protection per draft:
    /// "M Rules MUST NOT be modified, duplicated, or deleted through CORECONF operations"
    fn handle_ipatch(&mut self, request: &Request) -> Response {
        // Validate content format
        if let Some(format) = request.content_format {
            if format != ContentFormat::YangInstancesCborSeq
                && format != ContentFormat::YangDataCbor
            {
                return Response::error(
                    ResponseCode::UnsupportedContentFormat,
                    "expected yang-instances+cbor-seq",
                );
            }
        }

        // Parse the request to check for M-Rule modifications
        match self.parse_and_validate_ipatch(&request.payload) {
            Ok(operations) => {
                let mut manager = match self.write_manager() {
                    Ok(guard) => guard,
                    Err(e) => return Self::error_response(&e),
                };

                for op in operations {
                    match op {
                        PatchOperation::Create(yang_json) => {
                            if let Err(e) = self.apply_create_rule(&mut manager, &yang_json) {
                                return Self::error_response(&e);
                            }
                        }
                        PatchOperation::Modify(rule_id, rule_id_length, yang_json) => {
                            if let Err(e) = self.apply_modify_rule(
                                &mut manager,
                                rule_id,
                                rule_id_length,
                                &yang_json,
                            ) {
                                return Self::error_response(&e);
                            }
                        }
                        PatchOperation::Delete(rule_id, rule_id_length) => {
                            if let Err(e) =
                                self.apply_delete_rule(&mut manager, rule_id, rule_id_length)
                            {
                                return Self::error_response(&e);
                            }
                        }
                    }
                }

                Response::changed()
            }
            Err(e) => Self::error_response(&e),
        }
    }

    /// Handle POST request - invoke RPC (duplicate-rule)
    fn handle_post(&mut self, request: &Request) -> Response {
        // Validate content format
        if let Some(format) = request.content_format {
            if format != ContentFormat::YangInstancesCborSeq {
                return Response::error(
                    ResponseCode::UnsupportedContentFormat,
                    "expected yang-instances+cbor-seq",
                );
            }
        }

        // Parse RPC invocation
        match self.parse_rpc_request(&request.payload) {
            Ok(rpc) => {
                match rpc {
                    RpcRequest::DuplicateRule {
                        from,
                        to,
                        modifications,
                    } => {
                        let mut manager = match self.write_manager() {
                            Ok(guard) => guard,
                            Err(e) => return Self::error_response(&e),
                        };

                        match manager.duplicate_rule(from, to, modifications.as_ref()) {
                            Ok(()) => {
                                // Return success with status
                                let output = serde_json::json!({
                                    "status": "success"
                                });
                                let mut cbor = Vec::new();
                                if let Err(e) = ciborium::into_writer(&output, &mut cbor) {
                                    log::error!("CBOR serialization failed: {:?}", e);
                                    return Self::error_response(&Error::Coreconf(format!(
                                        "CBOR serialization failed: {}",
                                        e
                                    )));
                                }
                                Response {
                                    code: ResponseCode::Changed,
                                    payload: cbor,
                                    content_format: Some(ContentFormat::YangInstancesCborSeq),
                                }
                            }
                            Err(e) => Self::error_response(&e),
                        }
                    }
                }
            }
            Err(e) => Self::error_response(&e),
        }
    }

    /// Parse and validate iPATCH operations
    ///
    /// iPATCH payload is application/yang-instances+cbor-seq format:
    /// A sequence of CBOR maps where each map is {SID: value}
    /// - Create/Modify: {SID: data} where data contains the rule information
    /// - Delete: {SID: null}
    fn parse_and_validate_ipatch(&self, payload: &[u8]) -> Result<Vec<PatchOperation>> {
        let mut operations = Vec::new();
        let mut cursor = Cursor::new(payload);

        // Parse CBOR sequence
        while (cursor.position() as usize) < payload.len() {
            let value: Value = ciborium::from_reader(&mut cursor)
                .map_err(|e| Error::Coreconf(format!("CBOR decode error: {}", e)))?;

            // Each item should be a map {SID: value}
            if let Value::Object(map) = value {
                for (key, val) in map {
                    // Key is the SID as string
                    let target_sid: i64 = key
                        .parse()
                        .map_err(|_| Error::Conversion("Invalid SID in iPATCH".into()))?;

                    // Determine operation type based on target SID and value
                    let op = self.parse_patch_operation(target_sid, val)?;
                    if let Some(operation) = op {
                        operations.push(operation);
                    }
                }
            }
        }

        Ok(operations)
    }

    /// Parse a single patch operation from SID + value
    fn parse_patch_operation(
        &self,
        target_sid: i64,
        value: Value,
    ) -> Result<Option<PatchOperation>> {
        // SID 5110 = /ietf-schc:schc/rule (rule list)
        // SID 5135 = rule-id-value
        // SID 5136 = rule-id-length

        match target_sid {
            // Rule list (5110) - creating a new rule entry
            5110 => {
                if value.is_null() {
                    // Delete all rules (not typically used)
                    log::warn!(
                        "iPATCH with null value for rule list SID - delete all not supported"
                    );
                    return Ok(None);
                }

                // Check if this is an array (instance identifier with keys for delete)
                if let Some(arr) = value.as_array() {
                    // Format: [rule-id-value, rule-id-length] means delete that specific rule
                    if arr.len() >= 2 {
                        let rule_id = arr.first().and_then(|v| v.as_u64()).ok_or_else(|| {
                            Error::Conversion("Invalid rule-id-value in array".into())
                        })? as u32;
                        let rule_id_length = arr.get(1).and_then(|v| v.as_u64()).unwrap_or(8) as u8;
                        return Ok(Some(PatchOperation::Delete(rule_id, rule_id_length)));
                    }
                }

                // Value should contain rule data with rule-id-value/length
                self.parse_rule_create_or_modify(&value)
            }
            // Direct rule-id-value modification (usually combined with rule context)
            5135 | 5136 => {
                // These are key fields, modifications come through rule (5110)
                log::debug!("Ignoring direct key field modification SID {}", target_sid);
                Ok(None)
            }
            // Field-level modifications (5140-5162)
            5140..=5162 => {
                if value.is_null() {
                    // Delete field entry
                    log::debug!(
                        "Field deletion via SID {} not directly supported",
                        target_sid
                    );
                    Ok(None)
                } else {
                    // Field modification - would need context of which rule
                    log::debug!(
                        "Field modification via SID {} - need rule context",
                        target_sid
                    );
                    Ok(None)
                }
            }
            // Handle rule with keys embedded in path
            _ => {
                // Check if this is a null value (delete operation)
                if value.is_null() {
                    log::debug!(
                        "Null value for SID {} - delete operation ignored without key context",
                        target_sid
                    );
                    return Ok(None);
                }

                // Check if this is a complete rule specification with nested data
                if let Some(obj) = value.as_object() {
                    // Check if it contains rule keys
                    let has_rule_id = obj.contains_key("rule-id-value")
                        || obj.contains_key(&sid::RULE_ID_VALUE.to_string());

                    if has_rule_id {
                        return self.parse_rule_create_or_modify(&value);
                    }
                }

                log::debug!("Unknown SID {} in iPATCH, skipping", target_sid);
                Ok(None)
            }
        }
    }

    /// Parse rule create/modify operation from YANG JSON
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn parse_rule_create_or_modify(&self, value: &Value) -> Result<Option<PatchOperation>> {
        // Extract rule-id-value and rule-id-length from the value
        // They might be keyed by SID or by name

        let rule_id_value = value
            .get("rule-id-value")
            .or_else(|| value.get(&sid::RULE_ID_VALUE.to_string()))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Conversion("Missing rule-id-value in rule data".into()))?
            as u32;

        let rule_id_length = value
            .get("rule-id-length")
            .or_else(|| value.get(&sid::RULE_ID_LENGTH.to_string()))
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as u8;

        // Check if the rule exists (modify) or is new (create)
        let manager = match self.read_manager() {
            Ok(guard) => guard,
            Err(e) => return Err(e),
        };
        let exists = manager
            .all_rules()
            .iter()
            .any(|r| r.rule_id == rule_id_value && r.rule_id_length == rule_id_length);
        drop(manager);

        if exists {
            // Modify existing rule
            Ok(Some(PatchOperation::Modify(
                rule_id_value,
                rule_id_length,
                value.clone(),
            )))
        } else {
            // Create new rule
            Ok(Some(PatchOperation::Create(value.clone())))
        }
    }

    /// Parse delete operation for a rule
    #[allow(dead_code)]
    fn parse_rule_delete(&self, path_value: &Value) -> Result<Option<PatchOperation>> {
        // Extract rule keys from the path
        if let Some(arr) = path_value.as_array() {
            // Array format: [sid_delta, key1, key2, ...]
            // For rules: [5110 delta, rule-id-value, rule-id-length]
            if arr.len() >= 3 {
                let rule_id = arr
                    .get(1)
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| Error::Conversion("Invalid rule-id in delete".into()))?
                    as u32;
                let rule_id_length = arr.get(2).and_then(|v| v.as_u64()).unwrap_or(8) as u8;

                return Ok(Some(PatchOperation::Delete(rule_id, rule_id_length)));
            }
        }

        Ok(None)
    }

    /// Parse RPC request from CBOR payload (SID-encoded format only)
    fn parse_rpc_request(&self, payload: &[u8]) -> Result<RpcRequest> {
        use crate::rpc_builder::parse_duplicate_rule_rpc;

        // Parse SID-encoded duplicate-rule RPC
        match parse_duplicate_rule_rpc(payload) {
            Ok(request) => {
                // Convert entry modifications to Value format for manager
                let mods_value = if request.modifications.is_empty() {
                    None
                } else {
                    // Build entry array from modifications
                    let entries: Vec<Value> = request
                        .modifications
                        .iter()
                        .map(|m| {
                            let mut entry = serde_json::Map::new();
                            entry.insert(
                                "entry-index".to_string(),
                                Value::Number(m.entry_index.into()),
                            );

                            if let Some(mo) = m.matching_operator {
                                entry.insert(
                                    "matching-operator-sid".to_string(),
                                    Value::Number(mo.into()),
                                );
                            }

                            if let Some(cda) = m.comp_decomp_action {
                                entry.insert(
                                    "comp-decomp-action-sid".to_string(),
                                    Value::Number(cda.into()),
                                );
                            }

                            if let Some(ref tv) = m.target_value {
                                // Encode as base64 for JSON transport
                                entry.insert(
                                    "target-value-bytes".to_string(),
                                    Value::String(base64::Engine::encode(
                                        &base64::engine::general_purpose::STANDARD,
                                        tv,
                                    )),
                                );
                            }

                            Value::Object(entry)
                        })
                        .collect();

                    Some(serde_json::json!({ "entry": entries }))
                };

                Ok(RpcRequest::DuplicateRule {
                    from: request.source,
                    to: request.target,
                    modifications: mods_value,
                })
            }
            Err(e) => Err(Error::Coreconf(format!("Failed to parse RPC: {}", e))),
        }
    }

    /// Apply a create rule operation
    fn apply_create_rule(
        &self,
        manager: &mut SchcCoreconfManager,
        yang_json: &Value,
    ) -> Result<()> {
        let (rule, _metadata) = yang_to_schc_rule_with_metadata(yang_json)?;
        manager.provision_rule(rule)
    }

    /// Apply a modify rule operation
    fn apply_modify_rule(
        &self,
        manager: &mut SchcCoreconfManager,
        rule_id: u32,
        rule_id_length: u8,
        yang_json: &Value,
    ) -> Result<()> {
        // Validate not an M-Rule
        manager.m_rules().validate_modification(rule_id)?;

        let (mut rule, _metadata) = yang_to_schc_rule_with_metadata(yang_json)?;
        rule.rule_id = rule_id;
        rule.rule_id_length = rule_id_length;

        manager.provision_rule(rule)
    }

    /// Apply a delete rule operation
    fn apply_delete_rule(
        &self,
        manager: &mut SchcCoreconfManager,
        rule_id: u32,
        rule_id_length: u8,
    ) -> Result<()> {
        manager.delete_rule(rule_id, rule_id_length)?;
        Ok(())
    }

    /// Convert error to CORECONF response
    fn error_response(err: &Error) -> Response {
        let code = match err.to_coap_code() {
            CoapCode::UNAUTHORIZED => ResponseCode::Unauthorized,
            CoapCode::NOT_FOUND => ResponseCode::NotFound,
            CoapCode::CONFLICT => ResponseCode::Conflict,
            CoapCode::BAD_REQUEST => ResponseCode::BadRequest,
            _ => ResponseCode::InternalServerError,
        };

        Response::error(code, &err.diagnostic())
    }

    /// Get a reference to the manager
    pub fn manager(&self) -> &Arc<RwLock<SchcCoreconfManager>> {
        &self.manager
    }

    /// Tick - update guard period states
    pub fn tick(&mut self) {
        let mut manager = match self.write_manager() {
            Ok(guard) => guard,
            Err(e) => {
                log::error!("Failed to acquire manager lock for tick: {:?}", e);
                return;
            }
        };
        manager.tick();
    }
}

/// Patch operation types for iPATCH
///
/// These represent the different CORECONF operations that can be
/// performed on SCHC rules via iPATCH requests.
enum PatchOperation {
    /// Create a new rule from YANG JSON data
    Create(Value),
    /// Modify an existing rule (rule_id, rule_id_length, YANG JSON data)
    Modify(u32, u8, Value),
    /// Delete a rule by ID (rule_id, rule_id_length)
    Delete(u32, u8),
}

/// RPC request types
enum RpcRequest {
    DuplicateRule {
        from: (u32, u8),
        to: (u32, u8),
        modifications: Option<Value>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sid_constants() {
        assert_eq!(sid::SCHC, 5100);
        assert_eq!(sid::RULE_ID_VALUE, 5135);
        assert_eq!(sid::DUPLICATE_RULE, 5200);
    }

    // Note: Full integration tests would require the SID file to exist
}
