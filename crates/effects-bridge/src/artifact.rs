//! The metadata custom section: how a component artifact carries its own
//! effect signatures.
//!
//! A package is content-addressed over its whole artifact, so putting the
//! metadata inside the artifact is what makes a method's declared effects
//! and an index into its event table unable to drift from the code they
//! describe: change either and the address changes.
//!
//! The walk is section framing and nothing more — the same framing core
//! modules and components share — so extraction needs no engine, no
//! compilation, and no instantiation. Runtimes ignore a custom section
//! they do not know, which is what lets the artifact the chain stores be
//! the artifact the engine compiles.

use std::collections::BTreeSet;

use hyperscale_types::VmStaticsError;
use hyperscale_vm_effects::PackageMetadata;
use wasmparser::{BinaryReaderError, ComponentExternalKind, Parser, Payload};

use crate::vm_metadata::{decode_metadata, encode_metadata};

/// The custom section a component artifact declares its effect metadata
/// in.
pub const METADATA_SECTION: &str = "hyperscale:effect-metadata";

/// The section id wasm reserves for custom sections.
const CUSTOM_SECTION_ID: u8 = 0;

/// The magic and version word every module and component opens with.
const WASM_MAGIC: [u8; 4] = *b"\0asm";
const PREAMBLE_LEN: usize = 8;

/// Attach `metadata` to a component artifact as its metadata section.
///
/// The result is the publishable artifact: same code, one section longer,
/// and a different content address.
///
/// # Errors
///
/// [`VmStaticsError`] if the artifact's section framing is malformed, if
/// it already declares a metadata section, or if the metadata is past a
/// bound the codec enforces.
pub fn attach_metadata(
    artifact: &[u8],
    metadata: &PackageMetadata,
) -> Result<Vec<u8>, VmStaticsError> {
    if find_section(artifact)?.is_some() {
        return Err(VmStaticsError(
            "artifact already declares an effect metadata section".into(),
        ));
    }
    let payload = encode_metadata(metadata)?;

    let mut content = Vec::with_capacity(METADATA_SECTION.len() + payload.len() + 8);
    write_uleb128(METADATA_SECTION.len(), &mut content);
    content.extend_from_slice(METADATA_SECTION.as_bytes());
    content.extend_from_slice(&payload);

    let mut out = Vec::with_capacity(artifact.len() + content.len() + 8);
    out.extend_from_slice(artifact);
    out.push(CUSTOM_SECTION_ID);
    write_uleb128(content.len(), &mut out);
    out.extend_from_slice(&content);
    Ok(out)
}

/// The effect metadata a component artifact declares, if it declares any.
///
/// # Errors
///
/// [`VmStaticsError`] if the artifact's section framing is malformed, if
/// it declares the metadata section more than once, or if the section's
/// payload is not canonical metadata.
pub fn extract_metadata(artifact: &[u8]) -> Result<Option<PackageMetadata>, VmStaticsError> {
    find_section(artifact)?.map(decode_metadata).transpose()
}

/// The metadata section's payload, walking the artifact's sections.
///
/// Every step is checked against the bytes that remain, so a truncated
/// length, a section running past the artifact, or a name running past
/// its own section is a refusal rather than a panic. Two sections under
/// the name are refused as well: which one meant the package's effects
/// would otherwise be a question the format does not answer.
fn find_section(artifact: &[u8]) -> Result<Option<&[u8]>, VmStaticsError> {
    if artifact.len() < PREAMBLE_LEN || artifact[..WASM_MAGIC.len()] != WASM_MAGIC {
        return Err(VmStaticsError(
            "artifact does not open with the wasm preamble".into(),
        ));
    }
    let mut found: Option<&[u8]> = None;
    let mut pos = PREAMBLE_LEN;
    while pos < artifact.len() {
        let id = artifact[pos];
        pos += 1;
        let size = read_uleb128(artifact, &mut pos)?;
        let end = pos
            .checked_add(size)
            .filter(|end| *end <= artifact.len())
            .ok_or_else(|| VmStaticsError("section runs past the artifact".into()))?;

        if id == CUSTOM_SECTION_ID {
            // Bounded by the section's own end, so a name length cannot
            // read into whatever follows.
            let section = &artifact[..end];
            let mut inner = pos;
            let name_len = read_uleb128(section, &mut inner)?;
            let name_end = inner
                .checked_add(name_len)
                .filter(|name_end| *name_end <= end)
                .ok_or_else(|| {
                    VmStaticsError("custom section name runs past its section".into())
                })?;
            if &artifact[inner..name_end] == METADATA_SECTION.as_bytes() {
                if found.is_some() {
                    return Err(VmStaticsError(
                        "artifact declares the effect metadata section twice".into(),
                    ));
                }
                found = Some(&artifact[name_end..end]);
            }
        }
        pos = end;
    }
    Ok(found)
}

/// The metadata a publish admits from an artifact, or why it does not.
///
/// Three things are checkable today, and they are checked: the artifact
/// declares a metadata section at all, the section decodes canonically
/// and within the bounds the vocabulary fixes, and every method it
/// describes is a function the component actually exports. Whether a
/// signature over-approximates the code it describes is a compiler's
/// judgement, and this is not one — an under-declaration is harmless
/// because the capability gate never materialises a handle the
/// declaration did not ask for, so a wrong signature costs its author a
/// trap rather than costing anyone else safety.
///
/// # Errors
///
/// [`VmStaticsError`] on an unparseable artifact, an absent or
/// non-canonical metadata section, or a declared method the component
/// does not export.
pub fn admit_package(artifact: &[u8]) -> Result<PackageMetadata, VmStaticsError> {
    let metadata = extract_metadata(artifact)?
        .ok_or_else(|| VmStaticsError("artifact declares no effect metadata section".into()))?;
    let exports = component_func_exports(artifact)?;
    for method in metadata.methods.keys() {
        if !exports.contains(method.as_str()) {
            return Err(VmStaticsError(format!(
                "metadata declares method {method:?}, which the component does not export"
            )));
        }
    }
    Ok(metadata)
}

/// The component's own function exports, by name.
///
/// Scoped to the outermost component: a nested component's exports are
/// its own, reachable through nothing a manifest can name.
fn component_func_exports(artifact: &[u8]) -> Result<BTreeSet<String>, VmStaticsError> {
    let parse =
        |error: BinaryReaderError| VmStaticsError(format!("artifact does not parse: {error}"));
    let mut exports = BTreeSet::new();
    let mut depth = 0usize;
    for payload in Parser::new(0).parse_all(artifact) {
        match payload.map_err(parse)? {
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => depth += 1,
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentExportSection(reader) if depth == 0 => {
                for export in reader {
                    let export = export.map_err(parse)?;
                    if export.kind == ComponentExternalKind::Func {
                        exports.insert(export.name.name.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(exports)
}

fn write_uleb128(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let byte = u8::try_from(value & 0x7F).expect("seven bits fit a byte");
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read one wasm `u32` length, capped at the five bytes the encoding
/// admits so a padded run cannot spin.
fn read_uleb128(bytes: &[u8], pos: &mut usize) -> Result<usize, VmStaticsError> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| VmStaticsError("section length is truncated".into()))?;
        *pos += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return Err(VmStaticsError(
                "section length is not a 32-bit value".into(),
            ));
        }
    }
    if value > u64::from(u32::MAX) {
        return Err(VmStaticsError(
            "section length is not a 32-bit value".into(),
        ));
    }
    usize::try_from(value)
        .map_err(|_| VmStaticsError("section length does not fit this platform".into()))
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::stdlib::{account_metadata, book_metadata};
    use hyperscale_vm_effects::{MethodSignature, PackageMetadata};
    use wat::parse_str;

    use super::*;

    /// A component exporting one no-argument function per name.
    fn component_exporting(names: &[&str]) -> Vec<u8> {
        use std::fmt::Write as _;

        let mut source = String::from("(component\n  (core module $m\n");
        for index in 0..names.len() {
            let _ = writeln!(source, "    (func (export \"f{index}\"))");
        }
        source.push_str("  )\n  (core instance $i (instantiate $m))\n");
        for (index, name) in names.iter().enumerate() {
            let _ = writeln!(
                source,
                "  (func (export \"{name}\") (canon lift (core func $i \"f{index}\")))"
            );
        }
        source.push(')');
        parse_str(&source).expect("the component assembles")
    }

    /// Metadata declaring one empty signature per method name.
    fn declaring(methods: &[&str]) -> PackageMetadata {
        let mut metadata = PackageMetadata::default();
        for method in methods {
            metadata
                .methods
                .insert((*method).into(), MethodSignature::default());
        }
        metadata
    }

    /// The smallest well-formed artifact shape the walk accepts: a
    /// preamble and nothing else.
    fn bare() -> Vec<u8> {
        let mut out = WASM_MAGIC.to_vec();
        out.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        out
    }

    /// A preamble followed by one non-custom section carrying `body`.
    fn with_section(id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = bare();
        out.push(id);
        write_uleb128(body.len(), &mut out);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn an_artifact_declares_the_metadata_it_was_attached() {
        for metadata in [account_metadata(), book_metadata()] {
            let plain = with_section(1, b"code goes here");
            assert_eq!(extract_metadata(&plain).expect("walks"), None);

            let artifact = attach_metadata(&plain, &metadata).expect("attaches");
            assert_eq!(
                extract_metadata(&artifact).expect("walks"),
                Some(metadata.clone())
            );
            // The code is untouched and the artifact is a different one.
            assert!(artifact.starts_with(&plain));
            assert_ne!(artifact, plain);
        }
    }

    #[test]
    fn different_metadata_makes_a_different_artifact() {
        // What content addressing over the whole artifact buys: the
        // declared effects cannot drift from the code under one address.
        let plain = with_section(1, b"code");
        let one = attach_metadata(&plain, &account_metadata()).expect("attaches");
        let other = attach_metadata(&plain, &book_metadata()).expect("attaches");
        assert_ne!(one, other);
    }

    #[test]
    fn the_section_is_found_past_other_custom_sections() {
        // A real component carries name and producers sections; the walk
        // has to skip custom sections it does not know, and must not
        // match on a prefix of the name either.
        let mut plain = with_section(1, b"code");
        for name in ["name", "producers", "hyperscale:effect-metadata-x"] {
            let mut content = Vec::new();
            write_uleb128(name.len(), &mut content);
            content.extend_from_slice(name.as_bytes());
            content.extend_from_slice(b"payload");
            plain.push(CUSTOM_SECTION_ID);
            write_uleb128(content.len(), &mut plain);
            plain.extend_from_slice(&content);
        }
        assert_eq!(extract_metadata(&plain).expect("walks"), None);

        let artifact = attach_metadata(&plain, &account_metadata()).expect("attaches");
        assert_eq!(
            extract_metadata(&artifact).expect("walks"),
            Some(account_metadata())
        );
    }

    #[test]
    fn a_second_metadata_section_is_refused() {
        let artifact =
            attach_metadata(&with_section(1, b"code"), &account_metadata()).expect("attaches");
        // Attaching again is refused rather than producing an artifact
        // whose metadata is ambiguous.
        assert!(attach_metadata(&artifact, &book_metadata()).is_err());

        // And an artifact assembled with two anyway does not extract.
        let mut doubled = artifact.clone();
        doubled.extend_from_slice(&artifact[with_section(1, b"code").len()..]);
        assert!(extract_metadata(&doubled).is_err());
    }

    #[test]
    fn malformed_framing_is_refused_rather_than_walked() {
        let artifact =
            attach_metadata(&with_section(1, b"code"), &account_metadata()).expect("attaches");

        // No preamble at all, and a preamble that is not wasm's.
        assert!(extract_metadata(b"").is_err());
        assert!(extract_metadata(&artifact[..4]).is_err());
        assert!(extract_metadata(&[0u8; 16]).is_err());

        // A section claiming more bytes than the artifact holds.
        let mut overrun = bare();
        overrun.push(1);
        write_uleb128(64, &mut overrun);
        overrun.extend_from_slice(b"short");
        assert!(extract_metadata(&overrun).is_err());

        // A length that never terminates, and one padded past 32 bits.
        let mut truncated = bare();
        truncated.extend_from_slice(&[1, 0x80]);
        assert!(extract_metadata(&truncated).is_err());
        let mut oversized = bare();
        oversized.extend_from_slice(&[1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);
        assert!(extract_metadata(&oversized).is_err());

        // A custom section with no room for its own name.
        let mut nameless = bare();
        nameless.push(CUSTOM_SECTION_ID);
        write_uleb128(0, &mut nameless);
        assert!(extract_metadata(&nameless).is_err());

        // A name longer than the section that carries it.
        let mut overlong = bare();
        let mut content = Vec::new();
        write_uleb128(64, &mut content);
        content.extend_from_slice(b"name");
        overlong.push(CUSTOM_SECTION_ID);
        write_uleb128(content.len(), &mut overlong);
        overlong.extend_from_slice(&content);
        assert!(extract_metadata(&overlong).is_err());

        // Truncating the payload leaves the framing intact and the
        // metadata undecodable, which is a refusal and not a None.
        let mut clipped = artifact.clone();
        clipped.truncate(artifact.len() - 1);
        assert!(extract_metadata(&clipped).is_err());
    }

    #[test]
    fn a_corrupt_payload_is_refused_rather_than_read() {
        let plain = with_section(1, b"code");
        let artifact = attach_metadata(&plain, &account_metadata()).expect("attaches");
        // Every byte the section's payload occupies: a change either
        // fails to decode or names different metadata, never silently
        // the same.
        for index in plain.len()..artifact.len() {
            let mut mutated = artifact.clone();
            mutated[index] ^= 0xFF;
            if let Ok(Some(metadata)) = extract_metadata(&mutated) {
                assert_ne!(metadata, account_metadata());
            }
        }
    }

    #[test]
    fn a_publish_admits_metadata_the_component_backs() {
        let component = component_exporting(&["deposit", "withdraw"]);
        let metadata = declaring(&["deposit", "withdraw"]);
        let artifact = attach_metadata(&component, &metadata).expect("attaches");
        assert_eq!(admit_package(&artifact).expect("admits"), metadata);

        // Declaring fewer methods than the component exports is fine:
        // an export nothing declares is an export nothing can call.
        let partial = attach_metadata(&component, &declaring(&["deposit"])).expect("attaches");
        assert!(admit_package(&partial).is_ok());
    }

    #[test]
    fn a_publish_refuses_a_method_the_component_does_not_export() {
        let component = component_exporting(&["deposit"]);
        let artifact =
            attach_metadata(&component, &declaring(&["deposit", "withdraw"])).expect("attaches");
        let refused = admit_package(&artifact).expect_err("refuses");
        assert!(refused.0.contains("withdraw"), "{}", refused.0);

        // The name has to match exactly — a component export is looked
        // up by the name a manifest node writes.
        let renamed = attach_metadata(
            &component_exporting(&["deposit2"]),
            &declaring(&["deposit"]),
        )
        .expect("attaches");
        assert!(admit_package(&renamed).is_err());
    }

    #[test]
    fn a_publish_refuses_an_artifact_that_declares_nothing() {
        // No signatures, no deploy: an artifact without the section is
        // refused rather than published with an empty table.
        let component = component_exporting(&["deposit"]);
        assert!(admit_package(&component).is_err());
        // And one whose section is not parseable as an artifact at all.
        assert!(admit_package(&with_section(1, b"code")).is_err());
    }

    #[test]
    fn only_the_outermost_components_exports_count() {
        // A nested component's exports are its own; nothing a manifest
        // names can reach them, so they cannot back a declaration.
        let inner = "(component (core module $m (func (export \"f\"))) \
             (core instance $i (instantiate $m)) \
             (func (export \"hidden\") (canon lift (core func $i \"f\"))))";
        let outer = parse_str(&*format!(
            "(component (core module $m (func (export \"f\"))) \
             (core instance $i (instantiate $m)) \
             (func (export \"shown\") (canon lift (core func $i \"f\"))) \
             {inner})"
        ))
        .expect("the component assembles");

        assert_eq!(
            component_func_exports(&outer).expect("parses"),
            BTreeSet::from(["shown".to_owned()])
        );
        let artifact = attach_metadata(&outer, &declaring(&["hidden"])).expect("attaches");
        assert!(admit_package(&artifact).is_err());
    }
}
