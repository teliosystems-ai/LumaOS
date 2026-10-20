//! Closed initial source/build/test profile. Receipts carry observations, never
//! executable authority; the parent controller owns PAM, grants and drainage.
use super::*;
use std::collections::BTreeMap;

pub(super) const MAX_REQUEST: usize = 65_536;
pub(super) const LANGUAGE: &str = "c99-freestanding-tcc-v1";
const VERSION: &str = "0.9.27+git20200814.62c30a4a-1";
const DEPENDENCIES: [&str; 2] = [
    "luma-syscall-v1",
    "tinycc-libtcc1-0.9.27+git20200814.62c30a4a-1",
];
const FILES: [&str; 23] = [
    "compiler-init",
    "compiler-init.c",
    "compiler-base.cpio",
    "test-init",
    "test-base.cpio",
    "luma.h",
    "freestanding_runtime.c",
    "libtcc1.a",
    "relink/compiler-init.o",
    "relink/libtcc.a",
    "relink/libtcc.h",
    "relink/copyright",
    "relink/guest_init.c",
    "relink/relink.sh",
    "build-runner.py",
    "prepare-build.py",
    "relink/source/tcc_0.9.27+git20200814.62c30a4a-1.dsc",
    "relink/source/tcc_0.9.27+git20200814.62c30a4a.orig.tar.bz2",
    "relink/source/tcc_0.9.27+git20200814.62c30a4a-1.debian.tar.xz",
    "relink/source-provenance.json",
    "relink/LGPL-2",
    "relink/LGPL-2.1",
    "relink/GPL-2",
];

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Test {
    stdin_hex: String,
    expected_exit: u8,
    expected_stdout_hex: String,
    expected_stderr_hex: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    schema_version: u32,
    language: String,
    declared_dependencies: Vec<String>,
    source_hex: String,
    tests: Vec<Test>,
}

fn source_profile(source: &[u8]) -> Result<()> {
    if source.is_empty()
        || source.len() > 16384
        || source.iter().any(|b| !matches!(*b, 9 | 10 | 13 | 32..=126))
    {
        return Err("generated source requires bounded ASCII C99-subset text".into());
    }
    let text = std::str::from_utf8(source)?;
    if ["\\\n", "\\\r\n", "%:", "??"]
        .iter()
        .any(|v| text.contains(v))
        || text
            .lines()
            .any(|line| line.contains('#') && line.trim() != "#include \"luma.h\"")
    {
        return Err("only the declared luma.h include is supported".into());
    }
    // Lex identifiers outside C comments and literals. Raw byte searching would
    // incorrectly reject harmless documentation/output text as compiler syntax.
    let mut at = 0;
    while at < source.len() {
        if source[at..].starts_with(b"//") {
            while at < source.len() && source[at] != b'\n' {
                at += 1;
            }
        } else if source[at..].starts_with(b"/*") {
            at += 2;
            while at + 1 < source.len() && !source[at..].starts_with(b"*/") {
                at += 1;
            }
            at = (at + 2).min(source.len());
        } else if matches!(source[at], b'\'' | b'"') {
            let delimiter = source[at];
            at += 1;
            while at < source.len() {
                if source[at] == b'\\' {
                    at = (at + 2).min(source.len());
                } else if source[at] == delimiter {
                    at += 1;
                    break;
                } else {
                    at += 1;
                }
            }
        } else if source[at].is_ascii_alphabetic() || source[at] == b'_' {
            let start = at;
            at += 1;
            while at < source.len() && (source[at].is_ascii_alphanumeric() || source[at] == b'_') {
                at += 1;
            }
            let token = &text[start..at];
            if matches!(token, "asm" | "__asm" | "__asm__" | "__attribute__")
                || token.starts_with("__builtin")
            {
                return Err("assembler/compiler extensions are outside this C99 subset".into());
            }
        } else {
            at += 1;
        }
    }
    Ok(())
}

pub(super) fn parse(bytes: &[u8]) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("generated build request exceeds fixed bound".into());
    }
    let request: Request = serde_json::from_slice(bytes)?;
    if request.schema_version != 2
        || request.language != LANGUAGE
        || request.declared_dependencies != DEPENDENCIES
        || !(1..=2).contains(&request.tests.len())
        || serde_json::to_vec(&request)? != bytes
    {
        return Err("unsupported or noncanonical generated build profile".into());
    }
    source_profile(&unhex(&request.source_hex, 16384)?)?;
    for test in &request.tests {
        unhex(&test.stdin_hex, 2048)?;
        unhex(&test.expected_stdout_hex, 2048)?;
        unhex(&test.expected_stderr_hex, 2048)?;
    }
    Ok(request)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    language: String,
    compiler_version: String,
    source_max_bytes: usize,
    compiler_executable_max_bytes: usize,
    executable_max_bytes: usize,
    elf_hardening: String,
    test_max_count: usize,
    stream_max_bytes: usize,
    compile_timeout_ms: u32,
    test_timeout_ms: u32,
    total_timeout_ms: u32,
    memory_mib: u32,
    compiler_package_sha256: String,
    compiler_library_package_sha256: String,
    runtime_manifest_sha256: String,
    files: BTreeMap<String, String>,
}

fn manifest() -> Result<(Vec<u8>, Manifest)> {
    let path = Path::new("/usr/share/luma-os/generated/build-manifest.json");
    for item in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(item)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("generated compiler manifest requires immutable image ancestors".into());
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > 16384
    {
        return Err("invalid generated compiler manifest file".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(16385).read_to_end(&mut bytes)?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&std::fs::symlink_metadata(path)?)
    {
        return Err("generated compiler manifest changed".into());
    }
    let value: Manifest = serde_json::from_slice(&bytes)?;
    if value.schema_version != 1
        || value.language != LANGUAGE
        || value.compiler_version != VERSION
        || value.source_max_bytes != 16384
        || value.compiler_executable_max_bytes != 32768
        || value.executable_max_bytes != 36864
        || value.elf_hardening != "static-elf-stack-v1"
        || value.test_max_count != 2
        || value.stream_max_bytes != 2048
        || value.compile_timeout_ms != 5000
        || value.test_timeout_ms != 1000
        || value.total_timeout_ms != 15000
        || value.memory_mib != 128
        || value.compiler_package_sha256
            != "8c8617f69cdbd8a9efb6ff20a1930d577a4348f41c53bbaa02932c2101c8c1f1"
        || value.compiler_library_package_sha256
            != "92b0128468d4fb0749efc317da319cddd89ab1507dad55a9daaecbf62614f36c"
        || value.runtime_manifest_sha256 != super::runtime_digest()?
        || value.files.len() != FILES.len()
        || FILES.iter().any(|name| !value.files.contains_key(*name))
        || value.files.values().any(|digest| !io::hash(digest))
        || value.files.get("relink/libtcc.a").map(String::as_str)
            != Some("99487d6c78619ec6a9003641d938e5c59f2342b006d31619f8a056084f51dd11")
        || value.files.get("libtcc1.a").map(String::as_str)
            != Some("66cffad205235f5c0ca72e028b574476a031b43dad7b13656461093f38bcff93")
        || value.files.get("relink/libtcc.h").map(String::as_str)
            != Some("de4930a8f312241f269ad26f07f8fd1aa6d119fe89212d9e89c516c12cc0885c")
        || value.files.get("relink/copyright").map(String::as_str)
            != Some("cbc67ed9530ac30b60e382b02968efc5a7de2895f50cd7c51e6c70811a8df115")
    {
        return Err("unsupported generated compiler manifest contract".into());
    }
    Ok((bytes, value))
}

pub(super) fn runtime_digest() -> Result<String> {
    Ok(io::digest(&manifest()?.0))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Compiler {
    status: String,
    value: u32,
    stdout_hex: String,
    stderr_hex: String,
    executable_hex: String,
    executable_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    index: usize,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_value: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr_hex: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    schema_version: u32,
    runtime_sha256: String,
    request_sha256: String,
    source_hex: String,
    language: String,
    declared_dependencies: Vec<String>,
    toolchain_files: BTreeMap<String, String>,
    compiler: Compiler,
    executable_hex: String,
    executable_sha256: String,
    elf_hardening: String,
    artifact_status: String,
    test_oracles: Vec<Test>,
    tests: Vec<Observation>,
    all_tests_passed: bool,
}

fn elf16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("validated ELF field"))
}
fn elf32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("validated ELF field"))
}
fn elf64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("validated ELF field"))
}

/// Same strict static-ELF load policy as the v1 trusted Python runner, also
/// checked here so a forged worker cannot substitute a different build result.
fn static_elf(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 64
        || bytes.len() > 36864
        || bytes[..7] != *b"\x7fELF\x02\x01\x01"
        || !matches!(bytes[7], 0 | 3)
        || bytes[8..16].iter().any(|b| *b != 0)
        || elf16(bytes, 16) != 2
        || elf16(bytes, 18) != 62
        || elf32(bytes, 20) != 1
        || elf32(bytes, 48) != 0
        || elf16(bytes, 52) != 64
        || elf16(bytes, 54) != 56
    {
        return Err("invalid generated static ELF header".into());
    }
    let offset = elf64(bytes, 32);
    let count = elf16(bytes, 56) as u64;
    if !(1..=64).contains(&count)
        || offset < 64
        || offset
            .checked_add(count * 56)
            .map_or(true, |end| end > bytes.len() as u64)
    {
        return Err("invalid generated static program table".into());
    }
    let sections = elf16(bytes, 60) as u64;
    let section_offset = elf64(bytes, 40);
    if if sections > 0 {
        elf16(bytes, 58) != 64
            || sections > 4096
            || section_offset < 64
            || section_offset
                .checked_add(sections * 64)
                .map_or(true, |end| end > bytes.len() as u64)
            || elf16(bytes, 62) as u64 >= sections
    } else {
        section_offset != 0 || elf16(bytes, 62) != 0
    } {
        return Err("invalid generated static section table".into());
    }
    let mut loads: Vec<(u64, u64)> = Vec::new();
    let (mut total, mut stack, mut tls, mut entry_valid) = (0u64, 0u32, 0u32, false);
    let entry = elf64(bytes, 24);
    for index in 0..count {
        let at = (offset + index * 56) as usize;
        let kind = elf32(bytes, at);
        let access = elf32(bytes, at + 4);
        let file = elf64(bytes, at + 8);
        let address = elf64(bytes, at + 16);
        let size = elf64(bytes, at + 32);
        let memory = elf64(bytes, at + 40);
        let alignment = elf64(bytes, at + 48);
        if !matches!(
            kind,
            0 | 1 | 4 | 6 | 7 | 0x6474e551 | 0x6474e552 | 0x6474e553
        ) || access & !7 != 0
            || size > memory
            || file
                .checked_add(size)
                .map_or(true, |end| end > bytes.len() as u64)
        {
            return Err("invalid generated static segment".into());
        }
        if kind == 0x6474e551 {
            stack += 1;
            if access & 1 != 0 || stack > 1 {
                return Err("invalid generated stack".into());
            }
        }
        if kind == 7 {
            tls += 1;
            if tls > 1 || memory > 1048576 {
                return Err("invalid generated TLS".into());
            }
        }
        if kind != 1 {
            continue;
        }
        let end = address
            .checked_add(memory)
            .ok_or("generated ELF address overflow")?;
        if access & 3 == 3
            || memory == 0
            || address < 0x10000
            || end >= 0x0000800000000000
            || !matches!(alignment, 0 | 1)
                && (!alignment.is_power_of_two()
                    || alignment > 2097152
                    || address % alignment != file % alignment)
        {
            return Err("invalid generated load geometry".into());
        }
        let rounded = (address & !4095, (end + 4095) & !4095);
        if loads
            .iter()
            .any(|prior| rounded.0 < prior.1 && prior.0 < rounded.1)
        {
            return Err("overlapping generated load pages".into());
        }
        loads.push(rounded);
        total = total
            .checked_add(memory)
            .ok_or("generated load sum overflow")?;
        if access & 1 != 0 && address <= entry && entry < address + size {
            entry_valid = true;
        }
    }
    if !entry_valid || loads.is_empty() || total > 33554432 || stack != 1 {
        return Err("generated entry/stack/memory policy failed".into());
    }
    Ok(())
}

fn harden_elf(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 64
        || raw.len() > 32768
        || raw[..7] != *b"\x7fELF\x02\x01\x01"
        || elf16(raw, 16) != 2
        || elf16(raw, 18) != 62
        || elf32(raw, 20) != 1
        || elf16(raw, 52) != 64
        || elf16(raw, 54) != 56
    {
        return Err("unsupported compiler ELF header".into());
    }
    let offset = elf64(raw, 32);
    let count = elf16(raw, 56) as u64;
    if !(1..=63).contains(&count)
        || offset < 64
        || offset
            .checked_add(count * 56)
            .map_or(true, |end| end > raw.len() as u64)
    {
        return Err("invalid compiler program table".into());
    }
    let mut records = Vec::new();
    for index in 0..count {
        let at = (offset + index * 56) as usize;
        let kind = elf32(raw, at);
        let flags = elf32(raw, at + 4);
        let file = elf64(raw, at + 8);
        let size = elf64(raw, at + 32);
        let memory = elf64(raw, at + 40);
        if !matches!(kind, 0 | 1 | 4 | 7 | 0x6474e552 | 0x6474e553)
            || flags & !7 != 0
            || flags & 3 == 3
            || size > memory
            || file
                .checked_add(size)
                .map_or(true, |end| end > raw.len() as u64)
        {
            return Err("unsupported/dynamic/PHDR/WX compiler segment".into());
        }
        if kind != 1 || size != 0 || memory != 0 {
            records.extend_from_slice(&raw[at..at + 56]);
        }
    }
    let mut stack = [0u8; 56];
    stack[..4].copy_from_slice(&0x6474e551u32.to_le_bytes());
    stack[4..8].copy_from_slice(&6u32.to_le_bytes());
    stack[48..56].copy_from_slice(&16u64.to_le_bytes());
    records.extend_from_slice(&stack);
    let new_offset = (raw.len() + 7) & !7;
    let mut result = raw.to_vec();
    result.resize(new_offset, 0);
    result.extend_from_slice(&records);
    if result.len() > 36864 {
        return Err("hardened compiler artifact exceeds finite bound".into());
    }
    result[32..40].copy_from_slice(&(new_offset as u64).to_le_bytes());
    result[56..58].copy_from_slice(&((records.len() / 56) as u16).to_le_bytes());
    static_elf(&result)?;
    Ok(result)
}

fn validate(
    value: &Receipt,
    request: &Request,
    request_digest: &str,
    runtime: &str,
    files: &BTreeMap<String, String>,
) -> Result<()> {
    let original = unhex(&value.compiler.executable_hex, 32768)?;
    let executable = unhex(&value.executable_hex, 36864)?;
    let compiled = value.compiler.status == "exit" && value.compiler.value == 0;
    let hardened = if compiled {
        harden_elf(&original).ok()
    } else {
        None
    };
    if value.schema_version != 2
        || value.runtime_sha256 != runtime
        || value.request_sha256 != request_digest
        || value.source_hex != request.source_hex
        || value.language != LANGUAGE
        || value.declared_dependencies != request.declared_dependencies
        || &value.toolchain_files != files
        || value.compiler.executable_sha256 != io::digest(&original)
        || value.executable_sha256 != io::digest(&executable)
        || compiled == original.is_empty()
        || !match value.compiler.status.as_str() {
            "exit" => value.compiler.value <= 255,
            "signal" => (1..=64).contains(&value.compiler.value),
            "timeout" | "output_limit" => value.compiler.value <= 255,
            _ => false,
        }
        || !match value.artifact_status.as_str() {
            "not_produced" => {
                !compiled && executable.is_empty() && value.elf_hardening == "not_attempted"
            }
            "rejected_static_elf" => {
                compiled
                    && hardened.is_none()
                    && executable.is_empty()
                    && value.elf_hardening == "rejected"
            }
            "validated_static_amd64" => {
                hardened.as_deref() == Some(executable.as_slice())
                    && value.elf_hardening == "static-elf-stack-v1"
            }
            _ => false,
        }
        || value.tests.len() != request.tests.len()
        || value.test_oracles != request.tests
    {
        return Err("generated build receipt differs from admitted request/toolchain".into());
    }
    unhex(&value.compiler.stdout_hex, 2048)?;
    unhex(&value.compiler.stderr_hex, 2048)?;
    let runnable = value.artifact_status == "validated_static_amd64";
    let mut all_passed = runnable;
    for (index, (observation, test)) in value.tests.iter().zip(&request.tests).enumerate() {
        if observation.index != index {
            return Err("generated build test index differs".into());
        }
        if !runnable {
            if observation.status != "not_run"
                || observation.reason.as_deref() != Some("compile_or_static_validation_failed")
                || observation.execution_status.is_some()
                || observation.execution_value.is_some()
                || observation.stdout_hex.is_some()
                || observation.stderr_hex.is_some()
            {
                return Err("unbuilt generated program cannot claim a test observation".into());
            }
            all_passed = false;
            continue;
        }
        let (status, code, stdout, stderr) = match (
            &observation.execution_status,
            observation.execution_value,
            &observation.stdout_hex,
            &observation.stderr_hex,
        ) {
            (Some(status), Some(code), Some(stdout), Some(stderr))
                if observation.reason.is_none() =>
            {
                (status.as_str(), code, stdout, stderr)
            }
            _ => return Err("generated build test lacks actual bounded observation".into()),
        };
        if !match status {
            "exit" | "timeout" | "output_limit" => code <= 255,
            "signal" => (1..=64).contains(&code),
            _ => false,
        } {
            return Err("invalid generated build test completion".into());
        }
        unhex(stdout, 2048)?;
        unhex(stderr, 2048)?;
        let passed = status == "exit"
            && code == test.expected_exit as u32
            && *stdout == test.expected_stdout_hex
            && *stderr == test.expected_stderr_hex;
        if observation.status != if passed { "passed" } else { "failed" } {
            return Err("generated build test result fabricates an oracle match".into());
        }
        all_passed &= passed;
    }
    if value.all_tests_passed != all_passed {
        return Err("generated aggregate fabricates validation".into());
    }
    Ok(())
}

pub(super) fn receipt(bytes: &[u8], request_bytes: &[u8], runtime: &str) -> Result<Receipt> {
    if bytes.is_empty() || bytes.len() as u64 >= super::MAX_OUTPUT {
        return Err("generated build receipt exceeds bound".into());
    }
    let value: Receipt = serde_json::from_slice(bytes)?;
    validate(
        &value,
        &parse(request_bytes)?,
        &io::digest(request_bytes),
        runtime,
        &manifest()?.1.files,
    )?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema_version: 2,
            language: LANGUAGE.into(),
            declared_dependencies: DEPENDENCIES.iter().map(|value| value.to_string()).collect(),
            source_hex: crate::bundle::hex(b"#include \"luma.h\"\nint main(void){return 0;}\n"),
            tests: vec![Test {
                stdin_hex: String::new(),
                expected_exit: 0,
                expected_stdout_hex: String::new(),
                expected_stderr_hex: String::new(),
            }],
        }
    }
    #[test]
    fn generated_build_closed_request_rejects_dependencies_flags_unknowns_and_noncanonical_bytes() {
        let request = request();
        let bytes = serde_json::to_vec(&request).unwrap();
        assert!(parse(&bytes).is_ok());
        let mut changed = bytes.clone();
        changed.push(b'\n');
        assert!(parse(&changed).is_err());
        for (key, value) in [
            ("language", serde_json::json!("python")),
            ("declared_dependencies", serde_json::json!(["libc"])),
            ("flags", serde_json::json!(["-run"])),
            ("tests", serde_json::json!([])),
        ] {
            let mut value_map: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value_map[key] = value;
            assert!(parse(&serde_json::to_vec(&value_map).unwrap()).is_err());
        }
    }
    #[test]
    fn generated_source_subset_refuses_hidden_preprocessing_and_assembler_dependencies() {
        for text in [
            "#include </etc/shadow>",
            "#define X 1",
            "%:include \"x\"",
            "??=include \"x\"",
            "#include \\\n\"luma.h\"",
            "__asm__(\".incbin /source.c\");",
            "__builtin_alloca(4)",
            "asm(\"hlt\");",
        ] {
            assert!(source_profile(text.as_bytes()).is_err(), "{text}");
        }
        assert!(source_profile(
            b"/* asm is documentation */ int main(void){const char *a=\"__asm__\";return a[0];}"
        )
        .is_ok());
    }
    fn compiler_elf() -> Vec<u8> {
        let mut raw = vec![0u8; 512];
        raw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        raw[16..18].copy_from_slice(&2u16.to_le_bytes());
        raw[18..20].copy_from_slice(&62u16.to_le_bytes());
        raw[20..24].copy_from_slice(&1u32.to_le_bytes());
        raw[24..32].copy_from_slice(&0x4000b0u64.to_le_bytes());
        raw[32..40].copy_from_slice(&64u64.to_le_bytes());
        raw[52..54].copy_from_slice(&64u16.to_le_bytes());
        raw[54..56].copy_from_slice(&56u16.to_le_bytes());
        raw[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (at, flags, file, address, size) in [
            (64usize, 5u32, 0u64, 0x400000u64, 512u64),
            (120, 6, 512, 0x600200, 0),
        ] {
            raw[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            raw[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            raw[at + 8..at + 16].copy_from_slice(&file.to_le_bytes());
            raw[at + 16..at + 24].copy_from_slice(&address.to_le_bytes());
            raw[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
            raw[at + 40..at + 48].copy_from_slice(&size.to_le_bytes());
            raw[at + 48..at + 56].copy_from_slice(&4096u64.to_le_bytes());
        }
        raw
    }
    fn successful() -> (Request, Receipt, BTreeMap<String, String>) {
        let request = request();
        let raw = compiler_elf();
        let runnable = harden_elf(&raw).unwrap();
        let files: BTreeMap<_, _> = FILES
            .iter()
            .map(|name| (name.to_string(), "a".repeat(64)))
            .collect();
        let value = Receipt {
            schema_version: 2,
            runtime_sha256: "b".repeat(64),
            request_sha256: io::digest(&serde_json::to_vec(&request).unwrap()),
            source_hex: request.source_hex.clone(),
            language: LANGUAGE.into(),
            declared_dependencies: request.declared_dependencies.clone(),
            toolchain_files: files.clone(),
            compiler: Compiler {
                status: "exit".into(),
                value: 0,
                stdout_hex: String::new(),
                stderr_hex: String::new(),
                executable_hex: crate::bundle::hex(&raw),
                executable_sha256: io::digest(&raw),
            },
            executable_hex: crate::bundle::hex(&runnable),
            executable_sha256: io::digest(&runnable),
            elf_hardening: "static-elf-stack-v1".into(),
            artifact_status: "validated_static_amd64".into(),
            test_oracles: request.tests.clone(),
            tests: vec![Observation {
                index: 0,
                status: "passed".into(),
                reason: None,
                execution_status: Some("exit".into()),
                execution_value: Some(0),
                stdout_hex: Some(String::new()),
                stderr_hex: Some(String::new()),
            }],
            all_tests_passed: true,
        };
        (request, value, files)
    }
    #[test]
    fn explicit_hardening_preserves_all_original_bytes_except_two_header_fields() {
        let raw = compiler_elf();
        let hardened = harden_elf(&raw).unwrap();
        assert!(static_elf(&raw).is_err());
        assert!(static_elf(&hardened).is_ok());
        for at in 0..raw.len() {
            if !(32..40).contains(&at) && !(56..58).contains(&at) {
                assert_eq!(raw[at], hardened[at]);
            }
        }
        assert_eq!(elf64(&hardened, 32), raw.len() as u64);
        assert_eq!(elf16(&hardened, 56), 2);
        // A BSS-only LOAD is not empty and must be preserved, never discarded.
        let mut bss = raw.clone();
        bss[160..168].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(elf16(&harden_elf(&bss).unwrap(), 56), 3);
        for (offset, bytes) in [
            (64, 6u32.to_le_bytes()),
            (64, 2u32.to_le_bytes()),
            (68, 7u32.to_le_bytes()),
        ] {
            let mut changed = raw.clone();
            changed[offset..offset + 4].copy_from_slice(&bytes);
            assert!(harden_elf(&changed).is_err());
        }
        let mut alias = raw;
        alias[136..144].copy_from_slice(&0x400200u64.to_le_bytes());
        alias[160..168].copy_from_slice(&4096u64.to_le_bytes());
        assert!(harden_elf(&alias).is_err());
    }
    #[test]
    fn source_build_receipt_refuses_fabricated_tests_and_original_or_runnable_tampering() {
        let (request, receipt, files) = successful();
        let digest = receipt.request_sha256.clone();
        assert!(validate(&receipt, &request, &digest, &"b".repeat(64), &files).is_ok());
        for (pointer, change) in [
            ("/all_tests_passed", serde_json::json!(false)),
            ("/tests/0/execution_value", serde_json::json!(1)),
            ("/tests/0/status", serde_json::json!("not_run")),
            (
                "/compiler/executable_sha256",
                serde_json::json!("c".repeat(64)),
            ),
            ("/executable_sha256", serde_json::json!("c".repeat(64))),
            ("/elf_hardening", serde_json::json!("none")),
            ("/test_oracles/0/expected_exit", serde_json::json!(1)),
            (
                "/compiler/executable_hex",
                serde_json::json!(format!("00{}", &receipt.compiler.executable_hex[2..])),
            ),
            (
                "/executable_hex",
                serde_json::json!(format!("00{}", &receipt.executable_hex[2..])),
            ),
        ] {
            let mut changed = serde_json::to_value(&receipt).unwrap();
            *changed.pointer_mut(pointer).unwrap() = change;
            let changed: Receipt = serde_json::from_value(changed).unwrap();
            assert!(
                validate(&changed, &request, &digest, &"b".repeat(64), &files).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn simultaneous_maximum_source_artifacts_tests_and_closure_fit_whole_admitted_response() {
        let (_, mut value, _) = successful();
        value.source_hex = "61".repeat(16384);
        value.compiler.executable_hex = "aa".repeat(32768);
        value.executable_hex = "bb".repeat(36864);
        value.compiler.stdout_hex = "cc".repeat(2048);
        value.compiler.stderr_hex = "dd".repeat(2048);
        value.test_oracles = vec![
            Test {
                stdin_hex: "aa".repeat(2048),
                expected_exit: 255,
                expected_stdout_hex: "bb".repeat(2048),
                expected_stderr_hex: "cc".repeat(2048)
            };
            2
        ];
        value.tests = (0..2)
            .map(|index| Observation {
                index,
                status: "failed".into(),
                reason: None,
                execution_status: Some("output_limit".into()),
                execution_value: Some(255),
                stdout_hex: Some("dd".repeat(2048)),
                stderr_hex: Some("ee".repeat(2048)),
            })
            .collect();
        let whole = super::super::Output {
            schema_version: 1,
            request_sha256: "a".repeat(64),
            binding: "b".repeat(64),
            lease: crate::resources::Token {
                lease_id: "c".repeat(128),
                generation: u64::MAX,
                manager_epoch: "d".repeat(64),
            },
            guest: super::super::Guest::Build(value),
        };
        let encoded = serde_json::to_vec(&whole).unwrap();
        assert!(
            encoded.len() + 4096 < super::super::MAX_OUTPUT as usize,
            "{}",
            encoded.len()
        );
    }
}
