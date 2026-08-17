// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Software Bill of Materials (TODO.complete/62).
//!
//! Unlike `enprot manifest` (which describes the *content* being
//! protected), the SBOM describes the *software itself*: every Rust
//! crate baked in at build time (embedded from Cargo.lock by
//! build.rs), the C libraries actually linked at runtime (queried
//! from the libraries themselves — the Botan and librnp version
//! APIs, not build-time assumptions), and the enprot binary as the
//! top-level package.
//!
//! Two wire formats, both as typed serde models:
//! - SPDX 2.3 JSON (`enprot sbom --format spdx-json`)
//! - CycloneDX 1.5 JSON (`enprot sbom --format cyclonedx-json`)
//!
//! Determinism (ties into TODO.complete/45): the document namespace
//! (SPDX) and serial number (CycloneDX) derive from a SHA3-256 hash
//! of the component list — same inputs, same identifiers — and the
//! creation timestamp honors `SOURCE_DATE_EPOCH` when set, so CI can
//! generate byte-identical SBOMs for identical releases.

use serde::Serialize;

use crate::crypto;
use crate::error::{Error, Result};

/// One component of the software supply chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub download_location: String,
}

impl Component {
    fn spdx_id(&self) -> String {
        format!("SPDXRef-Package-{}", self.name)
    }
}

/// The runtime Botan version, straight from the linked library.
fn botan_component() -> Component {
    let version = botan::Version::current()
        .map(|v| v.string)
        .unwrap_or_else(|_| "unknown".to_string());
    Component {
        name: "botan".into(),
        version,
        download_location: "https://botan.randombit.net".into(),
    }
}

/// The runtime librnp version, straight from the linked library.
fn librnp_component() -> Component {
    Component {
        name: "librnp".into(),
        version: rnp::version_string(),
        download_location: "https://github.com/rnpgp/rnp".into(),
    }
}

/// Rust crate dependencies baked in at build time by build.rs, in
/// space-separated `name@version` records. Empty when the binary was built without a
/// lockfile — surfaced by [`components`] as an embedded marker.
fn embedded_rust_deps() -> Vec<Component> {
    env!("ENPROT_DEP_LIST")
        .split_whitespace()
        .filter_map(|line| {
            let (name, version) = line.split_once('@')?;
            Some(Component {
                name: name.to_string(),
                version: version.to_string(),
                download_location: format!("https://crates.io/crates/{name}/{version}"),
            })
        })
        .collect()
}

/// True when the build embedded a Cargo.lock dependency list.
pub fn has_embedded_deps() -> bool {
    !env!("ENPROT_DEP_LIST").is_empty()
}

/// The full component list: enprot itself, the linked C libraries,
/// and every embedded Rust dependency. Sorted by name for
/// deterministic ordering.
pub fn components() -> Vec<Component> {
    let mut list = vec![Component {
        name: "enprot".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        download_location: "https://github.com/engyon/enprot".into(),
    }];
    list.push(botan_component());
    list.push(librnp_component());
    list.extend(embedded_rust_deps());
    list.sort_by(|a, b| a.name.cmp(&b.name));
    list.dedup_by(|a, b| a.name == b.name);
    list
}

/// SHA3-256 hex of the sorted `name@version` list — the content
/// fingerprint both format identifiers derive from.
fn components_fingerprint(comps: &[Component]) -> Result<String> {
    let policy: Box<dyn crypto::CryptoPolicy> = Box::new(crypto::CryptoPolicyDefault {});
    let joined: String = comps
        .iter()
        .map(|c| format!("{}@{}\n", c.name, c.version))
        .collect();
    crypto::hexdigest("sha3-256", joined.as_bytes(), &*policy)
}

/// The document creation timestamp, RFC 3339. `SOURCE_DATE_EPOCH`
/// (seconds) wins when set, so release pipelines can produce
/// byte-identical SBOMs; otherwise the current time.
fn creation_timestamp() -> String {
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<i64>().ok());
    crate::utils::rfc3339(epoch)
}

// ---------------------------------------------------------------------
// SPDX 2.3 JSON model
// ---------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    pub spdx_version: &'static str,
    pub data_license: &'static str,
    /// SPDXID is all-caps in the spec; renamed explicitly.
    #[serde(rename = "SPDXID")]
    pub spdx_id: &'static str,
    pub name: String,
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
    pub packages: Vec<SpdxPackage>,
    pub relationships: Vec<SpdxRelationship>,
}

#[derive(Serialize)]
pub struct SpdxCreationInfo {
    pub created: String,
    pub creators: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    pub name: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub version_info: String,
    pub download_location: String,
    pub files_analyzed: bool,
    pub license_concluded: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationship {
    pub spdx_element_id: String,
    pub relationship_type: &'static str,
    pub related_spdx_element: String,
}

/// Build the SPDX 2.3 document for the running binary.
pub fn spdx_json() -> Result<String> {
    let comps = components();
    let fingerprint = components_fingerprint(&comps)?;
    let self_id = "SPDXRef-Package-enprot".to_string();

    let mut relationships = vec![SpdxRelationship {
        spdx_element_id: "SPDXRef-DOCUMENT".into(),
        relationship_type: "DESCRIBES",
        related_spdx_element: self_id.clone(),
    }];
    relationships.extend(
        comps
            .iter()
            .filter(|c| c.name != "enprot")
            .map(|c| SpdxRelationship {
                spdx_element_id: self_id.clone(),
                relationship_type: "DEPENDS_ON",
                related_spdx_element: c.spdx_id(),
            }),
    );

    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: "SPDXRef-DOCUMENT",
        name: "enprot".into(),
        document_namespace: format!(
            "https://engyon.com/spdx/enprot-{}-{fingerprint}",
            env!("CARGO_PKG_VERSION")
        ),
        creation_info: SpdxCreationInfo {
            created: creation_timestamp(),
            creators: vec![format!("Tool: enprot-sbom-{}", env!("CARGO_PKG_VERSION"))],
        },
        packages: comps
            .iter()
            .map(|c| SpdxPackage {
                name: c.name.clone(),
                spdx_id: c.spdx_id(),
                version_info: c.version.clone(),
                download_location: c.download_location.clone(),
                files_analyzed: false,
                // Cargo.lock carries no per-crate license metadata;
                // NOASSERTION is the SPDX-blessed value for that.
                license_concluded: "NOASSERTION",
            })
            .collect(),
        relationships,
    };
    serde_json::to_string_pretty(&doc).map_err(Error::json)
}

// ---------------------------------------------------------------------
// CycloneDX 1.5 JSON model
// ---------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CyclonedxDocument {
    pub bom_format: &'static str,
    pub spec_version: &'static str,
    pub serial_number: String,
    pub version: u32,
    pub metadata: CyclonedxMetadata,
    pub components: Vec<CyclonedxComponent>,
}

#[derive(Serialize)]
pub struct CyclonedxMetadata {
    pub timestamp: String,
    pub component: CyclonedxComponent,
}

#[derive(Serialize, Clone)]
pub struct CyclonedxComponent {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub name: String,
    pub version: String,
    pub purl: String,
}

/// Format a 32-hex fingerprint as a v5-shaped (name-based) UUID:
/// deterministic for the same component list, no uuid crate needed.
/// The version nibble is forced to 5 and the variant nibble to the
/// RFC 4122 form, per §4.3 of the RFC.
fn fingerprint_to_uuid(fp: &str) -> String {
    let hex: Vec<u32> = fp
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_digit(16).unwrap())
        .collect();
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (hex.get(i * 2).unwrap_or(&0) << 4 | hex.get(i * 2 + 1).unwrap_or(&0)) as u8;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    let s: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    )
}

fn to_cyclonedx(c: &Component) -> CyclonedxComponent {
    CyclonedxComponent {
        kind: "library",
        name: c.name.clone(),
        version: c.version.clone(),
        purl: format!("pkg:generic/{}@{}", c.name, c.version),
    }
}

/// Build the CycloneDX 1.5 document for the running binary.
pub fn cyclonedx_json() -> Result<String> {
    let comps = components();
    let fingerprint = components_fingerprint(&comps)?;

    let doc = CyclonedxDocument {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        serial_number: format!("urn:uuid:{}", fingerprint_to_uuid(&fingerprint)),
        version: 1,
        metadata: CyclonedxMetadata {
            timestamp: creation_timestamp(),
            component: to_cyclonedx(
                comps
                    .iter()
                    .find(|c| c.name == "enprot")
                    .expect("components() always includes enprot itself"),
            ),
        },
        components: comps
            .iter()
            .filter(|c| c.name != "enprot")
            .map(to_cyclonedx)
            .collect(),
    };
    serde_json::to_string_pretty(&doc).map_err(Error::json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_include_self_and_c_libraries() {
        let comps = components();
        let names: Vec<&str> = comps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"enprot"), "got: {names:?}");
        assert!(names.contains(&"botan"), "got: {names:?}");
        assert!(names.contains(&"librnp"), "got: {names:?}");
        // Sorted, deduplicated.
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted);
    }

    #[test]
    fn components_version_nonempty() {
        for c in components() {
            assert!(!c.version.is_empty(), "{:?} has no version", c.name);
        }
    }

    #[test]
    fn spdx_document_shape() {
        let s = spdx_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["dataLicense"], "CC0-1.0");
        assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(
            v["documentNamespace"]
                .as_str()
                .unwrap()
                .contains("https://engyon.com/spdx/enprot-")
        );
        // N packages + N-1 DEPENDS_ON + 1 DESCRIBES.
        let n = v["packages"].as_array().unwrap().len();
        let rels = v["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), n, "every package but self + DESCRIBES");
        assert!(rels.iter().any(|r| r["relationshipType"] == "DESCRIBES"));
        assert!(
            rels.iter()
                .filter(|r| r["relationshipType"] == "DEPENDS_ON")
                .all(|r| r["spdxElementId"] == "SPDXRef-Package-enprot")
        );
        // Every package uses NOASSERTION licenses (Cargo.lock carries none).
        assert!(
            v["packages"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["licenseConcluded"] == "NOASSERTION")
        );
    }

    #[test]
    fn cyclonedx_document_shape() {
        let s = cyclonedx_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        assert_eq!(v["version"], 1);
        let serial = v["serialNumber"].as_str().unwrap();
        assert!(serial.starts_with("urn:uuid:"), "got: {serial}");
        // v5-shaped UUID: version nibble in the third group.
        let uuid_part = serial.strip_prefix("urn:uuid:").unwrap();
        let groups: Vec<&str> = uuid_part.split('-').collect();
        assert!(groups[2].starts_with('5'), "got: {serial}");
        assert_eq!(v["metadata"]["component"]["name"], "enprot");
        // enprot itself is metadata.component, not in components.
        assert!(
            v["components"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["name"] != "enprot")
        );
    }

    #[test]
    fn identifiers_are_deterministic() {
        // Same component list => same fingerprint => same namespace/serial.
        let a = spdx_json().unwrap();
        let b = spdx_json().unwrap();
        let va: serde_json::Value = serde_json::from_str(&a).unwrap();
        let vb: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(va["documentNamespace"], vb["documentNamespace"]);
    }

    #[test]
    fn fingerprint_uuid_shape() {
        let u =
            fingerprint_to_uuid("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        assert_eq!(u.len(), 36);
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('5'), "version nibble: {u}");
    }
}
