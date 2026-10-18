//! Fixed image-pinned inert document HTML -> PDF converter. No arbitrary Office
//! import, script, URL, filter, environment, executable or host directory input.
//! Called only by the separately leased original Read/Export worker. Conversion
//! bytes are not a grant, content checkpoint, sender signature or native test.
use crate::{artifacts as io, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const MAX_PDF: usize = 16 * 1024 * 1024;
pub(crate) const UID: u32 = 986;
const PROFILE: &str = "libreoffice-document-html-pdf-v1";
const MANIFEST: &str = "/usr/share/luma-os/adapters/office-pdf-v1.json";
const RUNTIME: &str = "/run/luma-office-export";
const FILES: [&str; 3] = [
    "/usr/bin/bwrap",
    "/usr/lib/libreoffice/program/soffice.bin",
    "/usr/lib/libreoffice/program/libmergedlo.so",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Package {
    name: String,
    version: String,
    architecture: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    profile: String,
    packages: Vec<Package>,
    files: Vec<Pin>,
    input_profile: String,
    output_media_type: String,
    max_input_bytes: u64,
    max_output_bytes: u64,
    timeout_seconds: u64,
    memory_bytes: u64,
    tasks: u64,
    native_qualified: bool,
}

fn private_root(path: &Path, mode: u32) -> Result<()> {
    if fs::canonicalize(path)? != path {
        return Err("Office runtime/source alias refused".into());
    }
    for ancestor in path.ancestors() {
        let value = fs::symlink_metadata(ancestor)?;
        if !value.is_dir() || value.uid() != 0 || value.mode() & 0o022 != 0 {
            return Err("Office runtime/source ancestor not root protected".into());
        }
    }
    if fs::metadata(path)?.mode() & 0o7777 != mode {
        return Err("Office directory mode differs".into());
    }
    Ok(())
}
fn identity(value: &fs::Metadata) -> (u64, u64, u64, u64, u32, u32, u32, i64, i64, i64, i64) {
    (
        value.dev(),
        value.ino(),
        value.len(),
        value.nlink(),
        value.uid(),
        value.gid(),
        value.mode(),
        value.mtime(),
        value.mtime_nsec(),
        value.ctime(),
        value.ctime_nsec(),
    )
}
fn read_pin(
    path: &Path,
    maximum: u64,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<(Pin, Vec<u8>)> {
    check()?;
    if fs::canonicalize(path)? != path {
        return Err("Office pinned file alias refused".into());
    }
    private_root(
        path.parent().ok_or("Office file parent absent")?,
        fs::metadata(path.parent().unwrap())?.mode() & 0o7777,
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7022 != 0
        || before.len() == 0
        || before.len() > maximum
    {
        return Err("Office image file metadata/bounds refused".into());
    }
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut retained = Vec::new();
    let mut block = [0u8; 32768];
    // These are bounded PUBLIC immutable image bytes, never source content or
    // an effect. Bracket the whole hash with current authorization instead of
    // replaying the TPM-backed C history for every library block. No pin or
    // private result is returned until the final current check succeeds.
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or("Office image read overflow")?;
        if size > maximum {
            return Err("Office image file grew past bound".into());
        }
        digest.update(&block[..count]);
        if maximum <= 65536 {
            retained.extend_from_slice(&block[..count]);
        }
    }
    if size != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&fs::symlink_metadata(path)?)
    {
        return Err("Office image file changed during pin check".into());
    }
    check()?;
    Ok((
        Pin {
            path: path.to_str().ok_or("Office path encoding")?.into(),
            bytes: size,
            sha256: crate::bundle::hex(&digest.finalize()),
        },
        retained,
    ))
}
fn manifest(bytes: &[u8]) -> Result<Manifest> {
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err("Office manifest size refused".into());
    }
    let value: Manifest = serde_json::from_slice(bytes)?;
    let names = ["bubblewrap", "libreoffice-core", "libreoffice-writer"];
    if serde_json::to_vec(&value)? != bytes
        || value.schema_version != 1
        || value.profile != PROFILE
        || value.packages.len() != 3
        || value.files.len() != 3
        || value.input_profile != "native-generated-inert-document-html-v1"
        || value.output_media_type != "application/pdf"
        || value.max_input_bytes != 1024 * 1024
        || value.max_output_bytes != MAX_PDF as u64
        || value.timeout_seconds != 30
        || value.memory_bytes != 1024 * 1024 * 1024
        || value.tasks != 32
        || value.native_qualified
    {
        return Err("Office manifest closed profile/bounds differ".into());
    }
    for (package, name) in value.packages.iter().zip(names) {
        if package.name != name
            || package.architecture != "amd64"
            || package.version.is_empty()
            || package.version.len() > 128
            || !package.version.as_bytes()[0].is_ascii_digit()
            || !package
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+:~_-".contains(&b))
        {
            return Err("Office actual installed package tuple refused".into());
        }
    }
    for (pin, path) in value.files.iter().zip(FILES) {
        if pin.path != path
            || pin.bytes == 0
            || pin.bytes > 256 * 1024 * 1024
            || !io::hash(&pin.sha256)
        {
            return Err("Office exact file pin refused".into());
        }
    }
    Ok(value)
}
pub(crate) fn installed(check: &mut dyn FnMut() -> Result<()>) -> Result<String> {
    let (_, bytes) = read_pin(Path::new(MANIFEST), 65536, check)?;
    let value = manifest(&bytes)?;
    for expected in value.files {
        let (actual, _) = read_pin(Path::new(&expected.path), 256 * 1024 * 1024, check)?;
        if actual.bytes != expected.bytes || actual.sha256 != expected.sha256 {
            return Err("Office installed image file no longer matches its fixed tuple".into());
        }
    }
    Ok(io::digest(&bytes))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversionReceipt {
    pub schema_version: u32,
    pub profile: String,
    pub adapter_sha256: String,
    pub document_source_sha256: String,
    pub html_sha256: String,
    pub pdf_sha256: String,
    pub pdf_bytes: u64,
    pub converter_exit_code: u32,
}
pub(crate) struct Converted {
    pub bytes: Vec<u8>,
    pub receipt: ConversionReceipt,
}

pub(crate) fn arguments(work: &Path) -> Result<Vec<String>> {
    let name = work
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("Office private workspace name absent")?;
    if work.parent() != Some(Path::new(RUNTIME))
        || name.len() != 32
        || crate::tpm::decode::<16>(name).is_err()
    {
        return Err("Office converter requires exact private runtime workspace".into());
    }
    let text = work.to_str().ok_or("Office workspace path encoding")?;
    Ok(vec![
        "--unshare-all".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--clearenv".into(),
        "--setenv".into(),
        "PATH".into(),
        "/usr/bin".into(),
        "--setenv".into(),
        "HOME".into(),
        "/home/office".into(),
        "--setenv".into(),
        "LANG".into(),
        "C.UTF-8".into(),
        "--setenv".into(),
        "LC_ALL".into(),
        "C.UTF-8".into(),
        "--setenv".into(),
        "SAL_USE_VCLPLUGIN".into(),
        "svp".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        "--symlink".into(),
        "usr/lib".into(),
        "/lib".into(),
        "--symlink".into(),
        "usr/lib64".into(),
        "/lib64".into(),
        "--symlink".into(),
        "usr/bin".into(),
        "/bin".into(),
        "--dir".into(),
        "/etc".into(),
        "--ro-bind".into(),
        "/etc/fonts".into(),
        "/etc/fonts".into(),
        "--ro-bind".into(),
        "/etc/libreoffice".into(),
        "/etc/libreoffice".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--dir".into(),
        "/home".into(),
        "--dir".into(),
        "/home/office".into(),
        "--dir".into(),
        "/input".into(),
        "--ro-bind".into(),
        format!("{text}/document.html"),
        "/input/document.html".into(),
        "--bind".into(),
        format!("{text}/output"),
        "/output".into(),
        "--chdir".into(),
        "/tmp".into(),
        "--".into(),
        FILES[1].into(),
        "-env:UserInstallation=file:///home/office/profile".into(),
        "--headless".into(),
        "--nologo".into(),
        "--nodefault".into(),
        "--norestore".into(),
        "--infilter=HTML (StarWriter)".into(),
        "--convert-to".into(),
        "pdf:writer_pdf_Export".into(),
        "--outdir".into(),
        "/output".into(),
        "/input/document.html".into(),
    ])
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Workspace(PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn chown(path: &Path) -> Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(path.as_ptr(), UID, UID) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
pub(crate) fn convert(
    source: &[u8],
    expected_adapter: &str,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<Converted> {
    check()?;
    if unsafe { libc::geteuid() } != 0 || installed(check)? != expected_adapter {
        return Err(
            "Office requires exact installed adapter and bounded privileged supervisor".into(),
        );
    }
    let rendered = luma_content::document::render(source)?;
    check()?;
    private_root(Path::new(RUNTIME), 0o711)?;
    let work = Workspace(Path::new(RUNTIME).join(crate::resources::random_id()?));
    fs::DirBuilder::new().mode(0o700).create(&work.0)?;
    let output = work.0.join("output");
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let input = work.0.join("document.html");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&input)?;
    file.write_all(rendered.canonical_html.as_bytes())?;
    file.sync_all()?;
    drop(file);
    chown(&input)?;
    chown(&output)?;
    chown(&work.0)?;
    let mut command = Command::new(FILES[0]);
    command
        .args(arguments(&work.0)?)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(UID, UID, UID) != 0
                || libc::setresuid(UID, UID, UID) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    check()?;
    let mut running = Running(command.spawn()?);
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        check()?;
        if Instant::now() >= deadline {
            return Err("Office converter deadline expired; original worker remains subject to cgroup drainage".into());
        }
        for entry in fs::read_dir(&output)? {
            let entry = entry?;
            let value = entry.metadata()?;
            if entry.file_name() != "document.pdf"
                || !value.is_file()
                || value.len() > MAX_PDF as u64
            {
                return Err("Office converter output inventory/bound refused".into());
            }
        }
        if let Some(status) = running.0.try_wait()? {
            if !status.success() {
                return Err("actual pinned Office converter failed".into());
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    check()?;
    let path = output.join("document.pdf");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != UID
        || before.nlink() != 1
        || before.len() < 16
        || before.len() > MAX_PDF as u64
    {
        return Err("Office final PDF inode/byte bound refused".into());
    }
    let mut bytes = Vec::new();
    Read::take(&mut file, MAX_PDF as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&fs::symlink_metadata(path)?)
        || !bytes.starts_with(b"%PDF-")
        || !bytes
            .windows(5)
            .rev()
            .take(1024)
            .any(|window| window == b"%%EOF")
    {
        return Err("Office actual PDF integrity/framing changed".into());
    }
    if installed(check)? != expected_adapter {
        return Err("Office image tuple changed during conversion".into());
    }
    check()?;
    Ok(Converted {
        receipt: ConversionReceipt {
            schema_version: 1,
            profile: PROFILE.into(),
            adapter_sha256: expected_adapter.into(),
            document_source_sha256: io::digest(source),
            html_sha256: rendered.html_sha256,
            pdf_sha256: io::digest(&bytes),
            pdf_bytes: bytes.len() as u64,
            converter_exit_code: 0,
        },
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn converter_plan_has_no_host_identity_network_or_arbitrary_arguments() {
        let work = Path::new(RUNTIME).join("ab".repeat(16));
        let args = arguments(&work).unwrap();
        for fixed in [
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--headless",
            "--norestore",
            "pdf:writer_pdf_Export",
        ] {
            assert!(args.iter().any(|value| value == fixed));
        }
        assert!(!args.iter().any(|value| value.contains("/var/lib/luma-os")
            || value.contains("/dev/tpm")
            || value.contains("DBUS")
            || value == "--share-net"));
        assert!(arguments(Path::new("/tmp/caller-selected")).is_err());
        assert!(arguments(&Path::new(RUNTIME).join("../escape")).is_err());
        assert!(arguments(&Path::new(RUNTIME).join("AB".repeat(16))).is_err());
    }
    #[test]
    fn real_system_file_pin_is_bounded_and_invokes_current_boundary() {
        let path = Path::new("/usr/bin/true");
        let mut calls = 0;
        let (pin, _) = read_pin(path, 256 * 1024 * 1024, &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert!(calls >= 2);
        assert_eq!(pin.bytes, fs::metadata(path).unwrap().len());
        assert_eq!(pin.sha256, io::digest(&fs::read(path).unwrap()));
        assert!(read_pin(path, 1, &mut || Ok(())).is_err());
        assert!(read_pin(path, 256 * 1024 * 1024, &mut || Err("revoked".into())).is_err());
        let mut checks = 0;
        assert!(read_pin(path, 256 * 1024 * 1024, &mut || {
            checks += 1;
            if checks == 1 {
                Ok(())
            } else {
                Err("revoked after public hash".into())
            }
        })
        .is_err());
        assert_eq!(checks, 2);
    }
}
