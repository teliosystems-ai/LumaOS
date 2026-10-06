//! Bounded GGUF-v3 metadata inventory for the pinned CPU/F16 runtime.
//! Tensor storage is authenticated by the preceding whole-file digest. This
//! parser does not allocate tensors, infer free RAM, or lower a worker lease.
use super::Profile;
use crate::{resources::decimal, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

const MAX_METADATA: u64 = 64 * 1024 * 1024;
const MAX_KEYS: u64 = 4096;
const MAX_ARRAY: u64 = 1_048_576;
const MAX_STRING: u64 = 65_536;
const CONTEXT_ALIGNMENT: u64 = 256;
const CPU_ALIGNMENT: u64 = 32;
const MAPPING_PAGE: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Shape {
    architecture: String,
    layers: u32,
    embedding: u32,
    attention_heads: u32,
    kv_heads: u32,
    key_width: u32,
    value_width: u32,
    training_context: u32,
}

impl Shape {
    pub(super) fn validate(&self) -> Result<()> {
        if self.architecture != "qwen3"
            || !matches!(self.layers, 28 | 36)
            || !matches!(self.embedding, 2048 | 2560)
            || !matches!(self.attention_heads, 16 | 32)
            || self.kv_heads != 8
            || self.key_width != 128
            || self.value_width != 128
            || self.training_context != 40960
            || !matches!(
                (self.layers, self.embedding, self.attention_heads),
                (28, 2048, 16) | (36, 2560, 32)
            )
        {
            return Err("unsupported CPU model layout".into());
        }
        Ok(())
    }
}

fn round_up(bytes: u64, alignment: u64) -> Result<u64> {
    bytes
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or_else(|| "allocation alignment overflow".into())
}

fn product(values: &[u64]) -> Result<u64> {
    values.iter().try_fold(1u64, |total, value| {
        total
            .checked_mul(*value)
            .ok_or_else(|| "model layout product overflow".into())
    })
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    // The whole file's mmap/page-cache charge is counted once, not once per
    // request or once as weights and again as a shared file cache.
    #[serde(with = "decimal")]
    weights_and_file_cache_bytes: u64,
    #[serde(with = "decimal")]
    kv_tensor_bytes: u64,
    // Combined enforced ceiling, not a measurement of graph scratch or RSS.
    #[serde(with = "decimal")]
    runtime_and_scratch_ceiling_bytes: u64,
    #[serde(with = "decimal")]
    physical_peak_bytes: u64,
    #[serde(with = "decimal")]
    context_cells: u64,
    #[serde(with = "decimal")]
    concurrency: u64,
    #[serde(with = "decimal")]
    device_bytes: u64,
    #[serde(with = "decimal")]
    pinned_bytes: u64,
    #[serde(with = "decimal")]
    extra_prompt_and_idle_cache_bytes: u64,
}

impl Inventory {
    pub(super) fn for_profile(p: &Profile) -> Result<Self> {
        p.layout.validate()?;
        if p.context_tokens != 2048 || p.bytes == 0 {
            return Err("unsupported CPU context or empty mapped weights".into());
        }
        let shape = &p.layout;
        let cells = round_up(u64::from(p.context_tokens), CONTEXT_ALIGNMENT)?;
        let key = round_up(
            product(&[
                u64::from(shape.kv_heads),
                u64::from(shape.key_width),
                cells,
                2,
            ])?,
            CPU_ALIGNMENT,
        )?;
        let value = round_up(
            product(&[
                u64::from(shape.kv_heads),
                u64::from(shape.value_width),
                cells,
                2,
            ])?,
            CPU_ALIGNMENT,
        )?;
        let kv = product(&[
            key.checked_add(value).ok_or("KV tensor sum overflow")?,
            u64::from(shape.layers),
        ])?;
        let weights = round_up(p.bytes, MAPPING_PAGE)?;
        let other = p
            .memory_max_bytes
            .checked_sub(
                weights
                    .checked_add(kv)
                    .ok_or("physical inventory overflow")?,
            )
            .ok_or("verified weights and KV exceed worker peak")?;
        // A positive budget is mandatory; runtime overhead, graph scratch,
        // tokenizer, ingress and staging must all fit this remaining ceiling.
        if other == 0 {
            return Err("worker peak leaves no runtime and scratch capacity".into());
        }
        Ok(Self {
            weights_and_file_cache_bytes: weights,
            kv_tensor_bytes: kv,
            runtime_and_scratch_ceiling_bytes: other,
            physical_peak_bytes: p.memory_max_bytes,
            context_cells: cells,
            concurrency: 1,
            device_bytes: 0,
            pinned_bytes: 0,
            extra_prompt_and_idle_cache_bytes: 0,
        })
    }
}

struct Metadata<'a, R, F> {
    file: &'a mut R,
    check: &'a mut F,
    position: u64,
    bound: u64,
}

impl<R: Read, F: FnMut() -> Result<()>> Metadata<'_, R, F> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<()> {
        (self.check)()?;
        let end = self
            .position
            .checked_add(bytes.len().try_into()?)
            .ok_or("GGUF metadata offset overflow")?;
        if end > self.bound {
            return Err("GGUF metadata exceeds bounded file prefix".into());
        }
        self.file.read_exact(bytes)?;
        self.position = end;
        (self.check)()
    }
    fn u32(&mut self) -> Result<u32> {
        let mut bytes = [0; 4];
        self.read(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn u64(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        self.read(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn string(&mut self, limit: u64) -> Result<String> {
        let count = self.u64()?;
        if count > limit || count > self.bound.saturating_sub(self.position) {
            return Err("oversized GGUF metadata string".into());
        }
        let mut bytes = vec![0; count.try_into()?];
        self.read(&mut bytes)?;
        Ok(String::from_utf8(bytes)?)
    }
    fn skip(&mut self, count: u64) -> Result<()> {
        if count > self.bound.saturating_sub(self.position) {
            return Err("GGUF metadata value exceeds bounded prefix".into());
        }
        // Reading, rather than seeking past unobserved EOF, proves every value
        // exists. Chunking keeps cancellation checks and memory use bounded.
        let mut buffer = [0; 4096];
        let mut remaining = count;
        while remaining > 0 {
            let size: usize = remaining.min(buffer.len() as u64).try_into()?;
            self.read(&mut buffer[..size])?;
            remaining -= size as u64;
        }
        Ok(())
    }
    fn boolean(&mut self) -> Result<()> {
        let mut byte = [0];
        self.read(&mut byte)?;
        if byte[0] > 1 {
            return Err("invalid GGUF boolean".into());
        }
        Ok(())
    }
    fn value(&mut self, kind: u32) -> Result<Value> {
        match kind {
            4 => Ok(Value::U32(self.u32()?)),
            8 => Ok(Value::Text(self.string(MAX_STRING)?)),
            7 => {
                self.boolean()?;
                Ok(Value::Other)
            }
            9 => {
                let element = self.u32()?;
                let count = self.u64()?;
                if count > MAX_ARRAY {
                    return Err("oversized GGUF metadata array".into());
                }
                match element {
                    8 => {
                        for _ in 0..count {
                            self.string(MAX_STRING)?;
                        }
                    }
                    7 => {
                        for _ in 0..count {
                            self.boolean()?;
                        }
                    }
                    _ => self.skip(product(&[count, scalar_size(element)?])?)?,
                }
                Ok(Value::Other)
            }
            _ => {
                self.skip(scalar_size(kind)?)?;
                Ok(Value::Other)
            }
        }
    }
}

fn scalar_size(kind: u32) -> Result<u64> {
    match kind {
        0 | 1 => Ok(1),
        2 | 3 => Ok(2),
        4..=6 => Ok(4),
        10..=12 => Ok(8),
        // Strings and booleans have dedicated validation above. Arrays may
        // not contain arrays; future unknown scalar types fail closed.
        _ => Err("unsupported or nested GGUF metadata type".into()),
    }
}

enum Value {
    U32(u32),
    Text(String),
    Other,
}

pub(super) fn verify(
    file: &mut (impl Read + Seek),
    p: &Profile,
    mut check: impl FnMut() -> Result<()>,
) -> Result<Inventory> {
    let inventory = Inventory::for_profile(p)?;
    check()?;
    file.seek(SeekFrom::Start(0))?;
    let mut metadata = Metadata {
        file,
        check: &mut check,
        position: 0,
        bound: p.bytes.min(MAX_METADATA),
    };
    let mut magic = [0; 4];
    metadata.read(&mut magic)?;
    if magic != *b"GGUF" || metadata.u32()? != 3 {
        return Err("CPU model requires little-endian GGUF version 3".into());
    }
    let tensors = metadata.u64()?;
    let count = metadata.u64()?;
    if tensors == 0 || tensors > 8192 || count == 0 || count > MAX_KEYS {
        return Err("GGUF header counts exceed supported bounds".into());
    }
    let mut keys = BTreeSet::new();
    let mut values = BTreeMap::new();
    for _ in 0..count {
        let key = metadata.string(512)?;
        if key.is_empty() || key.bytes().any(|byte| byte == 0) || !keys.insert(key.clone()) {
            return Err("empty, unsafe or duplicate GGUF metadata key".into());
        }
        let kind = metadata.u32()?;
        let value = metadata.value(kind)?;
        if key == "general.architecture" || key.starts_with("qwen3.") || key.starts_with("split.") {
            values.insert(key, value);
        }
    }
    match values.get("general.architecture") {
        Some(Value::Text(architecture)) if architecture == &p.layout.architecture => (),
        _ => return Err("verified GGUF architecture differs from catalog".into()),
    }
    let integer = |key: &str| -> Result<u32> {
        match values.get(key) {
            Some(Value::U32(value)) => Ok(*value),
            _ => Err(format!("missing or non-uint32 GGUF layout field: {key}").into()),
        }
    };
    for (key, expected) in [
        ("qwen3.block_count", p.layout.layers),
        ("qwen3.embedding_length", p.layout.embedding),
        ("qwen3.attention.head_count", p.layout.attention_heads),
        ("qwen3.attention.head_count_kv", p.layout.kv_heads),
        ("qwen3.context_length", p.layout.training_context),
    ] {
        if integer(key)? != expected {
            return Err(format!("verified GGUF layout differs from catalog: {key}").into());
        }
    }
    // The runtime defaults absent K/V widths to embedding / attention heads.
    // That is 80 for Qwen3-4B, not its actual 128. Never guess from d_model.
    for (key, expected) in [
        ("qwen3.attention.key_length", p.layout.key_width),
        ("qwen3.attention.value_length", p.layout.value_width),
    ] {
        let actual = if values.contains_key(key) {
            integer(key)?
        } else {
            p.layout.embedding / p.layout.attention_heads
        };
        if actual != expected {
            return Err(format!("verified GGUF cache width differs from catalog: {key}").into());
        }
    }
    for key in values.keys() {
        if key.starts_with("split.")
            || key.contains("sliding_window")
            || key.ends_with("_swa")
            || key.contains("recurrent")
            || key.contains("expert")
        {
            return Err(
                "sharded, sliding-window, recurrent or expert layout is unsupported".into(),
            );
        }
    }
    check()?;
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bundle, model};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;

    fn text(value: &str) -> Vec<u8> {
        let mut bytes = (value.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }
    fn entries(p: &Profile) -> Vec<(String, u32, Vec<u8>)> {
        let mut entries = vec![("general.architecture".into(), 8, text("qwen3"))];
        for (key, value) in [
            ("block_count", p.layout.layers),
            ("embedding_length", p.layout.embedding),
            ("attention.head_count", p.layout.attention_heads),
            ("attention.head_count_kv", p.layout.kv_heads),
            ("attention.key_length", p.layout.key_width),
            ("attention.value_length", p.layout.value_width),
            ("context_length", p.layout.training_context),
        ] {
            entries.push((format!("qwen3.{key}"), 4, value.to_le_bytes().to_vec()));
        }
        entries
    }
    fn encoded(entries: &[(String, u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = b"GGUF".to_vec();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (key, kind, value) in entries {
            bytes.extend_from_slice(&text(key));
            bytes.extend_from_slice(&kind.to_le_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }
    fn parse(p: &Profile, entries: &[(String, u32, Vec<u8>)]) -> Result<Inventory> {
        verify(&mut Cursor::new(encoded(entries)), p, || Ok(()))
    }

    #[test]
    fn exact_f16_cache_bytes_and_physical_sum_for_both_pinned_profiles() {
        for (id, kv) in [
            ("qwen3-4b-q4-k-m", 301_989_888),
            ("qwen3-1-7b-q4-k-m", 234_881_024),
        ] {
            let p = super::super::profile(id).unwrap();
            let inventory = parse(&p, &entries(&p)).unwrap();
            assert_eq!(inventory.kv_tensor_bytes, kv);
            assert_eq!(inventory.context_cells, 2048);
            assert_eq!(inventory.concurrency, 1);
            assert_eq!(inventory.weights_and_file_cache_bytes % 4096, 0);
            assert_eq!(
                inventory.weights_and_file_cache_bytes
                    + kv
                    + inventory.runtime_and_scratch_ceiling_bytes,
                p.memory_max_bytes
            );
            let serialized = serde_json::to_value(&inventory).unwrap();
            assert!(serialized
                .as_object()
                .unwrap()
                .values()
                .all(|value| value.is_string()));
        }
    }
    #[test]
    fn head_width_defaults_match_runtime_and_do_not_guess_from_embedding() {
        for (id, admitted) in [("qwen3-4b-q4-k-m", false), ("qwen3-1-7b-q4-k-m", true)] {
            let p = super::super::profile(id).unwrap();
            let mut fields = entries(&p);
            fields.retain(|(key, _, _)| {
                !key.ends_with("key_length") && !key.ends_with("value_length")
            });
            assert_eq!(parse(&p, &fields).is_ok(), admitted);
        }
    }
    #[test]
    fn every_shape_mismatch_and_wrong_type_refuses() {
        let p = super::super::profile("qwen3-4b-q4-k-m").unwrap();
        for index in 1..entries(&p).len() {
            let mut fields = entries(&p);
            fields[index].2 = 1u32.to_le_bytes().to_vec();
            assert!(parse(&p, &fields).is_err());
            fields[index].1 = 6;
            assert!(parse(&p, &fields).is_err());
        }
        let mut fields = entries(&p);
        fields[0].2 = text("llama");
        assert!(parse(&p, &fields).is_err());
    }
    #[test]
    fn duplicate_missing_and_unsupported_layouts_refuse() {
        let p = super::super::profile("qwen3-4b-q4-k-m").unwrap();
        let mut fields = entries(&p);
        fields.push(fields[1].clone());
        assert!(parse(&p, &fields).is_err());
        fields = entries(&p);
        fields.remove(1);
        assert!(parse(&p, &fields).is_err());
        for key in [
            "split.count",
            "qwen3.attention.sliding_window",
            "qwen3.attention.key_length_swa",
            "qwen3.expert_count",
            "qwen3.recurrent_count",
        ] {
            let mut fields = entries(&p);
            fields.push((key.into(), 4, 1u32.to_le_bytes().to_vec()));
            assert!(parse(&p, &fields).is_err());
        }
    }
    #[test]
    fn all_truncated_prefixes_and_bad_header_counts_refuse() {
        let p = super::super::profile("qwen3-4b-q4-k-m").unwrap();
        let bytes = encoded(&entries(&p));
        for length in 0..bytes.len() {
            assert!(verify(&mut Cursor::new(&bytes[..length]), &p, || Ok(())).is_err());
        }
        for (offset, value) in [
            (8, 0),
            (8, 8193),
            (16, 0),
            (16, MAX_KEYS + 1),
            (16, u64::MAX),
        ] {
            let mut wrong = bytes.clone();
            wrong[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(verify(&mut Cursor::new(wrong), &p, || Ok(())).is_err());
        }
        let mut wrong = bytes;
        wrong[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(verify(&mut Cursor::new(wrong), &p, || Ok(())).is_err());
    }
    #[test]
    fn metadata_array_limits_types_and_boolean_encoding_refuse() {
        let p = super::super::profile("qwen3-4b-q4-k-m").unwrap();
        for (element, count) in [(4u32, MAX_ARRAY + 1), (9, 1), (99, 0), (4, u64::MAX)] {
            let mut value = element.to_le_bytes().to_vec();
            value.extend_from_slice(&count.to_le_bytes());
            let mut fields = entries(&p);
            fields.push(("unknown.array".into(), 9, value));
            assert!(parse(&p, &fields).is_err());
        }
        let mut fields = entries(&p);
        fields.push(("unknown.bool".into(), 7, vec![2]));
        assert!(parse(&p, &fields).is_err());
        fields = entries(&p);
        fields.push((
            "unknown.string".into(),
            8,
            (MAX_STRING + 1).to_le_bytes().to_vec(),
        ));
        assert!(parse(&p, &fields).is_err());
    }
    #[test]
    fn bounded_unrelated_tokenizer_arrays_are_scanned_without_retaining_tokens() {
        let p = super::super::profile("qwen3-4b-q4-k-m").unwrap();
        let mut fields = entries(&p);
        let mut value = 8u32.to_le_bytes().to_vec();
        value.extend_from_slice(&2u64.to_le_bytes());
        value.extend_from_slice(&text("hello"));
        value.extend_from_slice(&text("world"));
        fields.push(("tokenizer.ggml.tokens".into(), 9, value));
        assert!(parse(&p, &fields).is_ok());
    }
    #[test]
    fn file_bound_and_cancellation_apply_to_every_metadata_read() {
        let mut p = super::super::profile("qwen3-4b-q4-k-m").unwrap();
        let bytes = encoded(&entries(&p));
        p.bytes = bytes.len() as u64 - 1;
        assert!(verify(&mut Cursor::new(&bytes), &p, || Ok(())).is_err());
        p.bytes += 1;
        let mut calls = 0;
        let error = verify(&mut Cursor::new(&bytes), &p, || {
            calls += 1;
            if calls == 40 {
                Err("lease fenced".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(calls, 40);
        assert_eq!(error.to_string(), "lease fenced");
    }
    #[test]
    fn checked_products_alignment_and_peak_exhaustion_refuse() {
        assert!(product(&[u64::MAX, 2]).is_err());
        assert!(round_up(u64::MAX, 32).is_err());
        let mut p = super::super::profile("qwen3-4b-q4-k-m").unwrap();
        p.memory_max_bytes = p.bytes;
        assert!(Inventory::for_profile(&p).is_err());
        p.bytes = u64::MAX;
        assert!(Inventory::for_profile(&p).is_err());
    }

    #[test]
    fn digest_layout_and_inherited_descriptor_verify_one_actual_inode() {
        let directory =
            std::env::temp_dir().join(format!("luma-layout-descriptor-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("model.gguf");
        let mut p = model::profile("qwen3-4b-q4-k-m").unwrap();
        let bytes = encoded(&entries(&p));
        p.bytes = bytes.len() as u64;
        p.sha256 = bundle::hex(&Sha256::digest(&bytes));
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let mut verified = model::verified_runtime_file(&path, &p, || Ok(())).unwrap();
        assert_eq!(verified.stream_position().unwrap(), 0);
        let displaced = directory.join("verified-original.gguf");
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"substituted pathname").unwrap();
        let mut actual = Vec::new();
        verified.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        assert!(model::verified_runtime_file(&path, &p, || Ok(())).is_err());
        drop(verified);
        fs::remove_file(path).unwrap();
        fs::remove_file(displaced).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn authenticated_checksum_does_not_admit_an_incompatible_layout() {
        let directory =
            std::env::temp_dir().join(format!("luma-layout-incompatible-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("model.gguf");
        let mut p = model::profile("qwen3-4b-q4-k-m").unwrap();
        let mut fields = entries(&p);
        fields[1].2 = 28u32.to_le_bytes().to_vec();
        let bytes = encoded(&fields);
        p.bytes = bytes.len() as u64;
        p.sha256 = bundle::hex(&Sha256::digest(&bytes));
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let error = model::verified_runtime_file(&path, &p, || Ok(())).unwrap_err();
        assert!(error.to_string().contains("layout differs from catalog"));
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn scalar_and_array_types_are_bounded_and_fully_read() {
        let p = model::profile("qwen3-4b-q4-k-m").unwrap();
        for kind in [0, 1, 2, 3, 4, 5, 6, 10, 11, 12] {
            let mut fields = entries(&p);
            fields.push((
                "unknown.scalar".into(),
                kind,
                vec![0; scalar_size(kind).unwrap() as usize],
            ));
            let mut array = kind.to_le_bytes().to_vec();
            array.extend_from_slice(&2u64.to_le_bytes());
            array.extend_from_slice(&vec![0; scalar_size(kind).unwrap() as usize * 2]);
            fields.push(("unknown.array".into(), 9, array));
            assert!(parse(&p, &fields).is_ok());
        }
        let mut fields = entries(&p);
        fields.push(("unknown.boolean".into(), 7, vec![1]));
        let mut array = 7u32.to_le_bytes().to_vec();
        array.extend_from_slice(&2u64.to_le_bytes());
        array.extend_from_slice(&[0, 1]);
        fields.push(("unknown.array".into(), 9, array));
        assert!(parse(&p, &fields).is_ok());
        fields.last_mut().unwrap().2.pop();
        assert!(parse(&p, &fields).is_err());
        let mut malformed = entries(&p);
        malformed.push((
            "unknown.string".into(),
            8,
            vec![1, 0, 0, 0, 0, 0, 0, 0, 255],
        ));
        assert!(parse(&p, &malformed).is_err());
    }
}
