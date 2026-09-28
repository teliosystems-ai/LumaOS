//! Local TPM2 transport and exact NV-extend checkpoint boundary.
//! No owner/platform authorization, provisioning, clearing, hierarchy changes,
//! network transport selection, external fallback, or production custody claim.
use crate::{bundle, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{c_char, c_void, CString};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const PROFILE: &str = "local-tpm2";
const DEVICE: &str = "/dev/tpmrm0";
const INDEX: u32 = 0x01804c41;
// AUTHWRITE | TPM_NT_EXTEND | AUTHREAD | NO_DA | WRITTEN. In particular no
// OWNERWRITE, ordinary NV_Write, POLICYWRITE, WRITE_STCLEAR or ORDERLY.
const ATTRIBUTES: u32 = 0x22040044;

extern "C" {
    fn luma_tpm_open(transport: *const c_char, context: *mut *mut c_void) -> u32;
    fn luma_tpm_close(context: *mut c_void);
    fn luma_tpm_clock(
        context: *mut c_void,
        clock: *mut u64,
        reset: *mut u32,
        restart: *mut u32,
        safe: *mut u8,
    ) -> u32;
    fn luma_tpm_pcrs(context: *mut c_void, output: *mut u8) -> u32;
    fn luma_tpm_index_exists(context: *mut c_void, index: u32, exists: *mut u8) -> u32;
    fn luma_tpm_index(
        context: *mut c_void,
        index: u32,
        auth: *const u8,
        name: *mut u8,
        attributes: *mut u32,
        size: *mut u16,
        algorithm: *mut u16,
        policy_size: *mut u16,
    ) -> u32;
    fn luma_tpm_read(context: *mut c_void, value: *mut u8) -> u32;
    fn luma_tpm_extend(context: *mut c_void, digest: *const u8) -> u32;
}

fn check(code: u32) -> Result<()> {
    if code != 0 {
        return Err(
            format!("TPM2 operation refused/unavailable ({code:#010x}); no fallback").into(),
        );
    }
    Ok(())
}

struct Context(*mut c_void);
impl Drop for Context {
    fn drop(&mut self) {
        unsafe { luma_tpm_close(self.0) };
    }
}
impl Context {
    fn open(transport: &str) -> Result<Self> {
        let transport = CString::new(transport)?;
        let mut raw = std::ptr::null_mut();
        check(unsafe { luma_tpm_open(transport.as_ptr(), &mut raw) })?;
        if raw.is_null() {
            return Err("TPM library returned no context".into());
        }
        Ok(Self(raw))
    }

    fn local() -> Result<Self> {
        let metadata = fs::symlink_metadata(DEVICE)
            .map_err(|error| format!("local TPM2 required at {DEVICE}: {error}; no fallback"))?;
        if !metadata.file_type().is_char_device() || metadata.uid() != 0 {
            return Err("local TPM2 resource-manager character device required".into());
        }
        // Never use environment-selected/default TCTIs in the product path.
        Self::open("device:/dev/tpmrm0")
    }

    fn clock(&mut self) -> Result<Clock> {
        let mut result = Clock {
            milliseconds: 0,
            reset_count: 0,
            restart_count: 0,
        };
        let mut safe = 0;
        check(unsafe {
            luma_tpm_clock(
                self.0,
                &mut result.milliseconds,
                &mut result.reset_count,
                &mut result.restart_count,
                &mut safe,
            )
        })?;
        if safe != 1 {
            return Err("TPM clock is unsafe; privileged authorization denied".into());
        }
        Ok(result)
    }

    fn admission(&mut self) -> Result<Admission> {
        let mut occupied = 1;
        check(unsafe { luma_tpm_index_exists(self.0, INDEX, &mut occupied) })?;
        if occupied != 0 {
            return Err("local TPM2 Admin index is occupied; preserve existing state; no automatic overwrite or recovery".into());
        }
        let mut pcrs = [0u8; 64];
        check(unsafe { luma_tpm_pcrs(self.0, pcrs.as_mut_ptr()) })?;
        Ok(Admission {
            clock: self.clock()?,
            pcr7_sha256: bundle::hex(&pcrs[..32]),
            pcr11_sha256: bundle::hex(&pcrs[32..]),
        })
    }
}

/// Read-only admission observation, NOT enrollment, attestation or NV reservation.
#[derive(Clone, Debug, Serialize)]
pub struct Admission {
    clock: Clock,
    pcr7_sha256: String,
    pcr11_sha256: String,
}
impl Admission {
    fn compare(&self, current: &Self) -> Result<()> {
        current.clock.elapsed_since(self.clock)?;
        if self.pcr7_sha256 != current.pcr7_sha256 || self.pcr11_sha256 != current.pcr11_sha256 {
            return Err("TPM boot measurements changed during installation admission".into());
        }
        Ok(())
    }

    pub fn recheck(&self) -> Result<()> {
        self.compare(&installation_admission()?)
    }

    pub fn intent(&self, admin_login: &str) -> serde_json::Value {
        // Informational installation intent only. No consumer may use this
        // record to bootstrap authority: it has no authenticated enrollment.
        serde_json::json!({"schema_version":1,"profile":PROFILE,
            "candidate_admin_login":admin_login,"candidate_admin_uid":1001,
            "checkpoint_index":INDEX,"enrollment_status":"required",
            "product_admin_active":false,"admission_observation":self,
            "observation_is_attestation":false,"gate_closing":false})
    }
}

pub fn installation_admission() -> Result<Admission> {
    crate::require_root()?;
    Context::local()?.admission()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Clock {
    pub milliseconds: u64,
    pub reset_count: u32,
    pub restart_count: u32,
}
impl Clock {
    /// Future callers must keep grants boot-bound. TPM powered-time is not
    /// UTC and cannot certify catalog wall-clock expiry.
    pub fn elapsed_since(self, issued: Self) -> Result<u64> {
        if self.reset_count != issued.reset_count || self.restart_count != issued.restart_count {
            return Err("TPM boot epoch changed; renew authorization".into());
        }
        self.milliseconds
            .checked_sub(issued.milliseconds)
            .ok_or_else(|| "TPM clock regressed".into())
    }
}

pub fn probe() -> Result<serde_json::Value> {
    crate::require_root()?;
    let mut context = Context::local()?;
    let clock = context.clock()?;
    let mut pcrs = [0u8; 64];
    check(unsafe { luma_tpm_pcrs(context.0, pcrs.as_mut_ptr()) })?;
    Ok(
        serde_json::json!({"schema_version":1,"admin_profile":PROFILE,
        "transport":"device:/dev/tpmrm0","clock":clock,
        "pcr7_sha256":bundle::hex(&pcrs[..32]),"pcr11_sha256":bundle::hex(&pcrs[32..]),
        "clock_is_utc":false,"enrolled":false,"gate_closing":false}),
    )
}

pub fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid canonical TPM digest".into());
    }
    let mut output = [0u8; N];
    for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(output)
}

pub fn extend_value(previous: [u8; 32], event: [u8; 32]) -> [u8; 32] {
    Sha256::digest([previous.as_slice(), event.as_slice()].concat()).into()
}

pub trait Checkpoint {
    fn read(&mut self) -> Result<[u8; 32]>;
    fn clock(&mut self) -> Result<Clock>;
    /// Caller must durably fence a prepared event before entering this method.
    /// Any error may be an applied write with a lost reply: never auto-retry.
    fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]>;
}

pub struct LocalAnchor {
    context: Context,
    _lock: File,
}

impl LocalAnchor {
    fn connect(
        mut context: Context,
        index: u32,
        name: [u8; 34],
        auth: &[u8; 32],
        lock: File,
    ) -> Result<Self> {
        if index != INDEX || name[..2] != [0, 0x0b] {
            return Err("unsupported TPM index/name".into());
        }
        let mut actual = [0u8; 34];
        let (mut attributes, mut size, mut algorithm, mut policy_size) = (0, 0, 0, 0);
        check(unsafe {
            luma_tpm_index(
                context.0,
                index,
                auth.as_ptr(),
                actual.as_mut_ptr(),
                &mut attributes,
                &mut size,
                &mut algorithm,
                &mut policy_size,
            )
        })?;
        if actual != name
            || attributes != ATTRIBUTES
            || size != 32
            || algorithm != 0xb
            || policy_size != 0
        {
            return Err("TPM index identity, algorithm or attributes changed".into());
        }
        context.clock()?;
        let mut anchor = Self {
            context,
            _lock: lock,
        };
        anchor.read()?; // Authenticated read: metadata alone proves no authority.
        Ok(anchor)
    }

    pub fn installed() -> Result<Self> {
        crate::require_root()?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            schema_version: u32,
            profile: String,
            index: u32,
            nv_name: String,
        }
        let config: Config = serde_json::from_slice(&private_read(
            Path::new("/var/lib/luma-os/admin/anchor.json"),
            4096,
        )?)?;
        if config.schema_version != 1 || config.profile != PROFILE {
            return Err("unsupported Admin checkpoint profile".into());
        }
        let mut secret =
            private_read(Path::new("/run/credentials/luma-admin.service/nv-auth"), 32)?;
        let secret_array: std::result::Result<&[u8; 32], _> = secret.as_slice().try_into();
        let result = (|| match secret_array {
            Ok(auth) => Self::connect(
                Context::local()?,
                config.index,
                decode(&config.nv_name)?,
                auth,
                exclusive_lock(Path::new("/run/luma-admin/anchor.lock"))?,
            ),
            Err(_) => Err("TPM credential must be exactly 32 bytes".into()),
        })();
        // Never log or serialize authorization material, including error paths.
        for byte in &mut secret {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        result
    }
}

impl Checkpoint for LocalAnchor {
    fn read(&mut self) -> Result<[u8; 32]> {
        let mut value = [0u8; 32];
        check(unsafe { luma_tpm_read(self.context.0, value.as_mut_ptr()) })?;
        Ok(value)
    }
    fn clock(&mut self) -> Result<Clock> {
        self.context.clock()
    }
    fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
        if self.read()? != expected {
            return Err("TPM checkpoint conflict; reconciliation required".into());
        }
        // This is a sole-writer CAS under the retained service lock, not a TPM
        // hardware CAS primitive or a multi-host replication protocol.
        check(unsafe { luma_tpm_extend(self.context.0, event.as_ptr()) })?;
        let wanted = extend_value(expected, event);
        if self.read()? != wanted {
            return Err("TPM checkpoint outcome ambiguous; reconciliation required".into());
        }
        Ok(wanted)
    }
}

pub(crate) fn private_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    private_directory(path.parent().ok_or("missing private state parent")?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > limit
    {
        return Err("unsafe/oversized private Admin state".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("Admin state grew beyond bound".into());
    }
    Ok(bytes)
}

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    let parent = fs::symlink_metadata(path)?;
    if !parent.is_dir() || parent.uid() != unsafe { libc::geteuid() } || parent.mode() & 0o077 != 0
    {
        return Err("unsafe Admin state directory".into());
    }
    Ok(())
}

pub(crate) fn exclusive_lock(path: &Path) -> Result<File> {
    private_directory(path.parent().ok_or("missing lock parent")?)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err("unsafe Admin lock".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another Admin checkpoint writer is active".into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_journal::{Entry, Store};

    fn emulator() -> (String, std::path::PathBuf, [u8; 32], [u8; 34]) {
        let directory = std::path::PathBuf::from(
            std::env::var("LUMA_TPM_TEST_DIRECTORY").expect("isolated emulator fixture required"),
        );
        assert!(
            directory.starts_with("/tmp")
                && directory
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("luma-tpm-")
        );
        let transport = format!("swtpm:path={}/tpm.sock", directory.display());
        let auth: [u8; 32] = private_read(&directory.join("auth"), 32)
            .unwrap()
            .try_into()
            .unwrap();
        let mut public = Vec::new();
        public.extend(INDEX.to_be_bytes());
        public.extend(0x000bu16.to_be_bytes());
        public.extend(ATTRIBUTES.to_be_bytes());
        public.extend(0u16.to_be_bytes());
        public.extend(32u16.to_be_bytes());
        let mut name = [0u8; 34];
        name[1] = 0xb;
        name[2..].copy_from_slice(&Sha256::digest(public));
        (transport, directory, auth, name)
    }

    fn connect_fixture() -> LocalAnchor {
        let (transport, dir, auth, name) = emulator();
        LocalAnchor::connect(
            Context::open(&transport).unwrap(),
            INDEX,
            name,
            &auth,
            exclusive_lock(&dir.join("anchor.lock")).unwrap(),
        )
        .unwrap()
    }

    #[test]
    #[ignore = "requires isolated emulator admission fixture"]
    fn emulator_install_admission() {
        let (transport, _, _, _) = emulator();
        let mut context = Context::open(&transport).unwrap();
        match std::env::var("LUMA_TPM_TEST_ADMISSION").unwrap().as_str() {
            "free" => {
                let first = context.admission().unwrap();
                first.compare(&context.admission().unwrap()).unwrap();
                let intent = first.intent("lumaadmin");
                assert_eq!(intent["profile"], "local-tpm2");
                assert_eq!(intent["enrollment_status"], "required");
                assert_eq!(intent["product_admin_active"], false);
            }
            "occupied" => assert!(context.admission().is_err()),
            _ => panic!("invalid test fixture mode"),
        }
    }

    #[test]
    fn install_recheck_rejects_epoch_pcr_and_time_changes() {
        let original = Admission {
            clock: Clock {
                milliseconds: 100,
                reset_count: 1,
                restart_count: 1,
            },
            pcr7_sha256: "11".repeat(32),
            pcr11_sha256: "22".repeat(32),
        };
        original.compare(&original).unwrap();
        for field in 0..5 {
            let mut changed = original.clone();
            match field {
                0 => changed.clock.milliseconds -= 1,
                1 => changed.clock.reset_count += 1,
                2 => changed.clock.restart_count += 1,
                3 => changed.pcr7_sha256 = "33".repeat(32),
                _ => changed.pcr11_sha256 = "44".repeat(32),
            }
            assert!(original.compare(&changed).is_err());
        }
    }

    #[test]
    #[ignore = "requires an isolated swtpm fixture; native/tests/tpm_integration.py"]
    fn emulator_nv_journal_and_rollback() {
        let (transport, dir, auth, name) = emulator();
        let mut wrong_name = name;
        wrong_name[33] ^= 1;
        assert!(LocalAnchor::connect(
            Context::open(&transport).unwrap(),
            INDEX,
            wrong_name,
            &auth,
            exclusive_lock(&dir.join("anchor.lock")).unwrap()
        )
        .is_err());
        let mut wrong_auth = auth;
        wrong_auth[0] ^= 1;
        assert!(LocalAnchor::connect(
            Context::open(&transport).unwrap(),
            INDEX,
            name,
            &wrong_auth,
            exclusive_lock(&dir.join("anchor.lock")).unwrap()
        )
        .is_err());
        let mut anchor = connect_fixture();
        assert!(exclusive_lock(&dir.join("anchor.lock")).is_err());
        let original = anchor.read().unwrap();
        assert!(anchor.advance([0; 32], [1; 32]).is_err());
        assert_eq!(anchor.read().unwrap(), original);
        let clock = anchor.clock().unwrap();
        let path = dir.join("journal.json");
        let old = fs::read(&path).unwrap();
        let mut store = Store::open(anchor, &path).unwrap();
        for i in 0..16 {
            let at: Clock =
                serde_json::from_value(store.status().unwrap()["clock"].clone()).unwrap();
            store
                .append(Entry {
                    request_id: format!("emulator-{i}"),
                    authenticated_uid: 1001,
                    clock: at,
                    activity: "checkpoint.test".into(),
                    payload_sha256: format!("{i:064x}"),
                })
                .unwrap();
        }
        assert_eq!(store.status().unwrap()["events"], 16);
        drop(store);
        let current = fs::read(&path).unwrap();
        crate::platform::write_atomic(&path, &old, 0o600).unwrap();
        assert!(Store::open(connect_fixture(), &path).is_err());
        let mut tampered: serde_json::Value = serde_json::from_slice(&current).unwrap();
        tampered["entries"][0]["payload_sha256"] = serde_json::json!("ff".repeat(32));
        crate::platform::write_atomic(&path, &serde_json::to_vec(&tampered).unwrap(), 0o600)
            .unwrap();
        assert!(Store::open(connect_fixture(), &path).is_err());
        fs::remove_file(&path).unwrap();
        assert!(Store::open(connect_fixture(), &path).is_err());
        crate::platform::write_atomic(&path, &current, 0o600).unwrap();
        let pending = path.with_extension("pending.json");
        crate::platform::write_atomic(&pending, &current, 0o600).unwrap();
        assert!(Store::open(connect_fixture(), &path).is_err());
        fs::remove_file(pending).unwrap();
        Store::open(connect_fixture(), &path)
            .unwrap()
            .status()
            .unwrap();
        crate::platform::write_atomic(
            &dir.join("previous-clock.json"),
            &serde_json::to_vec(&clock).unwrap(),
            0o600,
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires restarted swtpm retaining the same NV state"]
    fn emulator_restart_and_external_change() {
        let (_, dir, _, _) = emulator();
        let old: Clock =
            serde_json::from_slice(&fs::read(dir.join("previous-clock.json")).unwrap()).unwrap();
        let path = dir.join("journal.json");
        let mut anchor = connect_fixture();
        let now = anchor.clock().unwrap();
        assert!(now.elapsed_since(old).is_err());
        let original = anchor.read().unwrap();
        drop(anchor);
        let mut store = Store::open(connect_fixture(), &path).unwrap();
        assert_eq!(store.status().unwrap()["events"], 16);
        drop(store);
        let mut anchor = connect_fixture();
        anchor.advance(original, [0x55; 32]).unwrap();
        drop(anchor);
        assert!(Store::open(connect_fixture(), &path).is_err());
    }

    #[test]
    #[ignore = "requires isolated emulator fixture with absent/replaced NV index"]
    fn emulator_rejects_missing_or_redefined_index() {
        let (transport, dir, auth, name) = emulator();
        assert!(LocalAnchor::connect(
            Context::open(&transport).unwrap(),
            INDEX,
            name,
            &auth,
            exclusive_lock(&dir.join("anchor.lock")).unwrap()
        )
        .is_err());
    }
    #[test]
    fn tpm_time_is_boot_bound_and_never_wall_clock() {
        let issued = Clock {
            milliseconds: 10,
            reset_count: 1,
            restart_count: 2,
        };
        assert_eq!(issued.elapsed_since(issued).unwrap(), 0);
        assert!(Clock {
            milliseconds: 9,
            ..issued
        }
        .elapsed_since(issued)
        .is_err());
        assert!(Clock {
            reset_count: 2,
            ..issued
        }
        .elapsed_since(issued)
        .is_err());
        assert!(Clock {
            restart_count: 3,
            ..issued
        }
        .elapsed_since(issued)
        .is_err());
    }
    #[test]
    fn canonical_names_are_exact() {
        assert!(decode::<32>(&"A".repeat(64)).is_err());
        assert!(decode::<34>(&"a".repeat(64)).is_err());
        assert_eq!(decode::<32>(&"00".repeat(32)).unwrap(), [0u8; 32]);
        assert_ne!(
            extend_value([0; 32], [1; 32]),
            extend_value([1; 32], [0; 32])
        );
    }
}
