//! IDL (Interface Definition Language) types for SPEL programs.
//!
//! The proc-macro generates an IDL JSON file at compile time that
//! describes the program's interface. This module defines the
//! serializable IDL format.
//!
//! ## LSSA-lang compatibility
//!
//! This IDL format is a superset of the lssa-lang IDL spec. Fields like
//! `discriminator`, `execution`, and `visibility` are included for
//! compatibility with lssa-lang tooling. All new fields are optional
//! and backward-compatible with existing SPEL programs.

use serde::{Deserialize, Serialize};

/// Top-level IDL for an SPEL program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpelIdl {
    pub version: String,
    pub name: String,
    pub instructions: Vec<IdlInstruction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<IdlAccountType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<IdlTypeDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<IdlError>,
    /// IDL spec identifier (lssa-lang compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    /// Program metadata (lssa-lang compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IdlMetadata>,
    /// Optional fully-qualified Rust path to the program's instruction enum.
    /// When set, generated FFI imports this type instead of generating a local enum.
    /// Example: "multisig_core::Instruction"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_type: Option<String>,
}

impl SpelIdl {
    /// Resolve the wire tag for the named instruction.
    ///
    /// Uses the recorded [`IdlInstruction::tag`] when present, and falls back
    /// to the instruction's position in the array for IDLs that predate the
    /// field. An unknown name is an error, never a silent tag 0.
    pub fn instruction_tag(&self, name: &str) -> Result<u32, String> {
        let (position, ix) = self
            .instructions
            .iter()
            .enumerate()
            .find(|(_, ix)| ix.name == name)
            .ok_or_else(|| format!("instruction '{name}' is not in the IDL"))?;
        match ix.tag {
            Some(tag) => Ok(tag),
            None => u32::try_from(position)
                .map_err(|_| format!("instruction '{name}' position exceeds u32")),
        }
    }
}

/// Program metadata (lssa-lang compat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlMetadata {
    pub name: String,
    pub version: String,
}

/// Execution mode for an instruction (lssa-lang compat).
///
/// Maps to lssa-lang's `Execution` type which has `public` and `private_owned` flags.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdlExecution {
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub private_owned: bool,
}

/// An instruction in the IDL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlInstruction {
    pub name: String,
    pub accounts: Vec<IdlAccountItem>,
    pub args: Vec<IdlArg>,
    /// SHA256("global:{name}")[..8] discriminator (lssa-lang compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<Vec<u8>>,
    /// Execution mode (lssa-lang compat). Defaults to public.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<IdlExecution>,
    /// Variant name in PascalCase (lssa-lang compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// The instruction enum's variant index: the tag the guest decodes.
    ///
    /// This is a wire-format fact, not an ordering convention. The guest
    /// decodes the leading tag from the declaration order of its
    /// `Instruction` enum, which need not match the order of `instructions`
    /// in this IDL. Absent in IDLs generated before this field existed;
    /// consumers then fall back to the array position (see
    /// [`SpelIdl::instruction_tag`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
}

/// An account expected by an instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountItem {
    pub name: String,
    #[serde(default)]
    pub writable: bool,
    #[serde(default)]
    pub signer: bool,
    #[serde(default)]
    pub init: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pda: Option<IdlPda>,
    /// If true, this account represents a variable-length trailing list.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rest: bool,
    /// Visibility tags (lssa-lang compat). e.g. ["public"].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visibility: Vec<String>,
}

fn is_false(v: &bool) -> bool {
    !v
}

/// PDA derivation specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlPda {
    pub seeds: Vec<IdlSeed>,
    /// If true, this is a private PDA — address includes the caller's NullifierPublicKey.
    /// Callers must supply `--npk <hex>` to derive the address.
    #[serde(default, skip_serializing_if = "is_false")]
    pub private: bool,
}

/// A seed component for PDA derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum IdlSeed {
    #[serde(rename = "const")]
    Const { value: String },
    #[serde(rename = "account")]
    Account { path: String },
    #[serde(rename = "arg")]
    Arg { path: String },
}

/// An instruction argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlArg {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: IdlType,
}

/// Type representation in the IDL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdlType {
    Primitive(String),
    Vec { vec: Box<IdlType> },
    Option { option: Box<IdlType> },
    Defined { defined: String },
    Array { array: (Box<IdlType>, usize) },
}

/// Account type definition in the IDL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountType {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: IdlTypeDef,
}

/// Type definition (struct or enum).
///
/// When stored in [`SpelIdl::types`] the `name` field identifies the type so
/// the decoder can resolve `Defined { name }` references. When embedded inside
/// [`IdlAccountType`] the name is redundant (already on the wrapper) and is
/// left empty / skipped during serialisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlTypeDef {
    /// Type name. Required when stored in `SpelIdl::types`; empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<IdlField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<IdlEnumVariant>,
}

/// A field in a struct type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlField {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: IdlType,
}

/// An enum variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlEnumVariant {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<IdlField>,
}

/// Error definition in the IDL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlError {
    pub code: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
}

/// Compute the lssa-lang discriminator for an instruction name.
///
/// This is SHA256("global:{name}")[..8], matching lssa-lang's convention.
pub fn compute_discriminator(name: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{name}").as_bytes());
    let result = hasher.finalize();
    result[..8].to_vec()
}

impl SpelIdl {
    /// Create a new IDL with the given program name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            version: "0.1.0".to_string(),
            name: name.into(),
            instructions: vec![],
            accounts: vec![],
            types: vec![],
            errors: vec![],
            spec: None,
            metadata: None,
            instruction_type: None,
        }
    }

    /// Serialize the IDL to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idl_from(instructions: serde_json::Value) -> SpelIdl {
        serde_json::from_value(serde_json::json!({
            "version": "0.1.0",
            "name": "p",
            "instructions": instructions,
        }))
        .expect("IDL deserializes")
    }

    #[test]
    fn old_idl_without_tag_falls_back_to_position() {
        let idl = idl_from(serde_json::json!([
            { "name": "a", "accounts": [], "args": [] },
            { "name": "b", "accounts": [], "args": [] },
        ]));
        assert_eq!(idl.instruction_tag("a"), Ok(0));
        assert_eq!(idl.instruction_tag("b"), Ok(1));
    }

    #[test]
    fn recorded_tag_wins_over_position() {
        let idl = idl_from(serde_json::json!([
            { "name": "a", "accounts": [], "args": [], "tag": 5 },
            { "name": "b", "accounts": [], "args": [], "tag": 2 },
        ]));
        assert_eq!(idl.instruction_tag("a"), Ok(5));
        assert_eq!(idl.instruction_tag("b"), Ok(2));
    }

    #[test]
    fn unknown_instruction_is_an_error() {
        let idl = idl_from(serde_json::json!([
            { "name": "a", "accounts": [], "args": [] },
        ]));
        assert!(idl.instruction_tag("missing").is_err());
    }

    #[test]
    fn tag_round_trips_and_is_omitted_when_absent() {
        let idl = idl_from(serde_json::json!([
            { "name": "a", "accounts": [], "args": [], "tag": 7 },
            { "name": "b", "accounts": [], "args": [] },
        ]));
        let json = serde_json::to_value(&idl).unwrap();
        assert_eq!(json["instructions"][0]["tag"], 7);
        assert!(json["instructions"][1].get("tag").is_none());
        let back: SpelIdl = serde_json::from_value(json).unwrap();
        assert_eq!(back.instructions[0].tag, Some(7));
        assert_eq!(back.instructions[1].tag, None);
    }
}
