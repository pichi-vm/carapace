// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Emit a carapace as an [OCI image layout][1] directory — the registry-native
//! distribution form, pushable verbatim with `skopeo copy oci:<dir>:<tag>
//! docker://…`. No pichi dependency: this is the producer half the standalone
//! `carapace` tooling (and `pichi import`) share.
//!
//! A **carapace artifact** is an OCI 1.1 image manifest whose layers are the
//! scute **cow** blobs (one per scute, base→top), each carrying its dm-verity
//! salt as an annotation. The verity trees are NOT shipped — they are a
//! deterministic function of `(cow, salt, chain params)`, so the consumer
//! reconstructs them at activation time (carapace `SPEC.md`, "Distribution
//! Without Verity Files"). That keeps the artifact registry-native: every byte
//! a registry stores is a manifest-referenced blob.
//!
//! [1]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md

use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};

/// OCI 1.1 image-manifest media type (the descriptor type registries expect).
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI image-index media type (`index.json`).
pub const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// OCI 1.1 empty-config media type (artifacts carry no real config blob).
pub const MEDIA_TYPE_OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
/// The pichi artifact wrapper type (top-level `artifactType`).
pub const MEDIA_TYPE_PICHI_ARTIFACT: &str = "application/vnd.pichi.artifact.v1+json";
/// A scute cow layer.
pub const MEDIA_TYPE_PICHI_SCUTE: &str = "application/vnd.pichi.scute.v1";

/// Per-scute salt annotation key (hex; the salt-chain binding).
pub const ANN_SCUTE_SALT: &str = "dev.pichi.scute.verity.salt";
/// Chain-wide verity parameter annotation keys.
pub const ANN_VERITY_ALGO: &str = "dev.pichi.carapace.verity.algo";
pub const ANN_VERITY_DATA_BLOCK: &str = "dev.pichi.carapace.verity.data-block-size";
pub const ANN_VERITY_HASH_BLOCK: &str = "dev.pichi.carapace.verity.hash-block-size";
/// OCI standard annotations.
pub const ANN_CREATED: &str = "org.opencontainers.image.created";
pub const ANN_REF_NAME: &str = "org.opencontainers.image.ref.name";

/// The OCI 1.1 empty-config blob bytes (`{}`), its digest, and size.
const EMPTY_CONFIG_BYTES: &[u8] = b"{}";

/// One scute to pack: its cow blob and full dm-verity salt (chain prefix +
/// optional suffix).
#[derive(Debug)]
pub struct ScuteLayer {
    pub cow: Vec<u8>,
    pub salt: Vec<u8>,
}

/// Write a carapace into the OCI image layout rooted at `dir`, tagged
/// `reference` (matched against `oci:<dir>:<reference>` by skopeo). `scutes`
/// are base→top. `created` is an RFC 3339 timestamp annotation (pass `None`
/// for a reproducible artifact with no timestamp). Returns the manifest
/// digest (`sha256:<hex>`).
///
/// Idempotent at the blob level (content-addressed); re-running overwrites the
/// `index.json` tag entry.
pub fn write_layout(
    dir: &Path,
    reference: &str,
    scutes: &[ScuteLayer],
    created: Option<&str>,
) -> Result<String> {
    let blobs = dir.join("blobs/sha256");
    fs::create_dir_all(&blobs).with_context(|| format!("creating {}", blobs.display()))?;

    // Empty config blob (referenced by the manifest's `config`).
    let empty_digest = put_blob(&blobs, EMPTY_CONFIG_BYTES)?;

    // Scute cow blobs + layer descriptors.
    let mut layers = Vec::with_capacity(scutes.len());
    for scute in scutes {
        let digest = put_blob(&blobs, &scute.cow)?;
        layers.push(serde_json::json!({
            "mediaType": MEDIA_TYPE_PICHI_SCUTE,
            "digest": digest,
            "size": scute.cow.len(),
            "annotations": { ANN_SCUTE_SALT: hex::encode(&scute.salt) },
        }));
    }

    let mut annotations = serde_json::Map::new();
    annotations.insert(ANN_VERITY_ALGO.into(), "sha256".into());
    annotations.insert(ANN_VERITY_DATA_BLOCK.into(), "4096".into());
    annotations.insert(ANN_VERITY_HASH_BLOCK.into(), "4096".into());
    if let Some(ts) = created {
        annotations.insert(ANN_CREATED.into(), ts.into());
    }

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_OCI_MANIFEST,
        "artifactType": MEDIA_TYPE_PICHI_ARTIFACT,
        "config": {
            "mediaType": MEDIA_TYPE_OCI_EMPTY,
            "digest": empty_digest,
            "size": EMPTY_CONFIG_BYTES.len(),
            "data": "e30=",
        },
        "layers": layers,
        "annotations": annotations,
    });
    // Canonical, stable bytes (sorted keys) so the digest is reproducible.
    let manifest_bytes = to_canonical_json(&manifest)?;
    let manifest_digest = put_blob(&blobs, &manifest_bytes)?;

    // `oci-layout` marker.
    fs::write(dir.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#)
        .with_context(|| format!("writing {}/oci-layout", dir.display()))?;

    // `index.json` — the manifest descriptor MUST carry the real byte size and
    // the image-manifest media type (skopeo/registries read both).
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_OCI_INDEX,
        "manifests": [{
            "mediaType": MEDIA_TYPE_OCI_MANIFEST,
            "artifactType": MEDIA_TYPE_PICHI_ARTIFACT,
            "digest": manifest_digest,
            "size": manifest_bytes.len(),
            "annotations": { ANN_REF_NAME: reference },
        }],
    });
    let index_bytes = to_canonical_json(&index)?;
    fs::write(dir.join("index.json"), &index_bytes)
        .with_context(|| format!("writing {}/index.json", dir.display()))?;

    Ok(manifest_digest)
}

/// Import a raw block image as a single-scute base carapace into the OCI
/// layout at `dir`, tagged `reference`. The scute uses the 32-byte zero salt
/// (the base sentinel; deterministic identity). Returns the manifest digest.
///
/// MVP: reads the whole image into RAM (fine for a build-time tool on bounded
/// distro images); streaming is a future refinement.
pub fn import_raw(
    raw_path: &Path,
    dir: &Path,
    reference: &str,
    created: Option<&str>,
) -> Result<String> {
    let raw = fs::read(raw_path).with_context(|| format!("reading {}", raw_path.display()))?;
    let cow = crate::cow::write(&raw, crate::SCUTE_CHUNK_SIZE_SECTORS)
        .context("emitting dm-snapshot COW")?;
    let scutes = vec![ScuteLayer {
        cow,
        salt: vec![0u8; 32],
    }];
    write_layout(dir, reference, &scutes, created)
}

/// Hash `bytes`, write them to `blobs/<hex>` (content-addressed; skipped if
/// present), and return the `sha256:<hex>` digest string.
fn put_blob(blobs: &Path, bytes: &[u8]) -> Result<String> {
    let hex = hex::encode(Sha256::digest(bytes));
    let path = blobs.join(&hex);
    if !path.exists() {
        // Atomic-ish: write to a temp sibling then rename.
        let tmp = blobs.join(format!(".{hex}.tmp"));
        let mut f =
            fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all().ok();
        fs::rename(&tmp, &path).with_context(|| format!("renaming into {}", path.display()))?;
    }
    Ok(format!("sha256:{hex}"))
}

/// Serialize a JSON value to compact bytes (serde_json sorts object keys when
/// the value is built from a `Map`, giving stable output for digesting).
fn to_canonical_json(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("serializing OCI json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_valid_oci_layout() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let scutes = vec![ScuteLayer {
            cow: b"fake-cow-bytes".to_vec(),
            salt: vec![0u8; 32],
        }];
        let digest = write_layout(dir, "43", &scutes, Some("2026-06-22T00:00:00Z")).unwrap();

        // Marker + index + the manifest blob all present.
        assert_eq!(
            fs::read_to_string(dir.join("oci-layout")).unwrap(),
            r#"{"imageLayoutVersion":"1.0.0"}"#
        );
        let mhex = digest.strip_prefix("sha256:").unwrap();
        let manifest_bytes = fs::read(dir.join("blobs/sha256").join(mhex)).unwrap();
        // Manifest digest matches its bytes.
        assert_eq!(
            format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes))),
            digest
        );

        // Index references the manifest with a NON-zero size + the image
        // manifest media type (the skopeo-push fix).
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("index.json")).unwrap()).unwrap();
        let desc = &index["manifests"][0];
        assert_eq!(desc["mediaType"], MEDIA_TYPE_OCI_MANIFEST);
        assert_eq!(desc["size"].as_u64().unwrap(), manifest_bytes.len() as u64);
        assert_eq!(desc["digest"], digest);
        assert_eq!(desc["annotations"][ANN_REF_NAME], "43");

        // Manifest shape: artifactType + one scute layer with its salt.
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest["artifactType"], MEDIA_TYPE_PICHI_ARTIFACT);
        assert_eq!(manifest["layers"][0]["mediaType"], MEDIA_TYPE_PICHI_SCUTE);
        assert_eq!(
            manifest["layers"][0]["annotations"][ANN_SCUTE_SALT],
            "00".repeat(32)
        );
    }
}
