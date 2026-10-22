//! Operation-scoped immutable observations, not authority. Complete bytes are
//! read through one retained FD before use; every later boundary checks that
//! the same held and named inode, mount, permissions and change time remain.
//! The original operation and actual C checkpoint are checked by the caller.
use super::super::*;
use crate::content_checkpoint::PersistentDirectory;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

pub(super) struct Pinned {
    path: PathBuf,
    parent: MemberParent,
    file: File,
    metadata: fs::Metadata,
    mount: u64,
    bytes: Vec<u8>,
    mode: u32,
}
impl Pinned {
    pub fn capture(
        path: PathBuf,
        expected: &[u8],
        mode: u32,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        if expected.is_empty() || expected.len() > MAX_FILE || !matches!(mode, 0o400 | 0o600) {
            return Err("invalid bounded pinned C DATA observation".into());
        }
        check()?;
        let parent = MemberParent::capture(&path)?;
        let file = parent.open(&path, libc::O_RDONLY, 0)?;
        let metadata = file.metadata()?;
        let mount = PersistentDirectory::mount(&file)?;
        let value = Self {
            path,
            parent,
            file,
            metadata,
            mount,
            bytes: expected.to_vec(),
            mode,
        };
        value.verify(check)?;
        Ok(value)
    }
    pub fn check(&self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        self.parent.check()?;
        let named = self.parent.open(&self.path, libc::O_RDONLY, 0)?;
        for file in [&self.file, &named] {
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != self.mode
                || metadata.len() as usize != self.bytes.len()
                || file_identity(&metadata) != file_identity(&self.metadata)
                || metadata.blocks() != self.metadata.blocks()
                || PersistentDirectory::mount(file)? != self.mount
                || metadata.dev() != self.parent.identity.0
                || self.mount != self.parent.mount
            {
                return Err(
                    "held immutable C DATA changed its exact named physical observation".into(),
                );
            }
        }
        self.parent.check()?;
        check()
    }
    pub fn verify(&self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        self.check(check)?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut buffer = [0_u8; 32768];
        for expected in self.bytes.chunks(buffer.len()) {
            self.check(check)?;
            file.read_exact(&mut buffer[..expected.len()])?;
            self.check(check)?;
            if &buffer[..expected.len()] != expected {
                return Err("complete retained C DATA bytes changed".into());
            }
        }
        let mut tail = [0_u8; 1];
        self.check(check)?;
        if file.read(&mut tail)? != 0 {
            return Err("retained C DATA acquired a trailing byte".into());
        }
        self.check(check)
    }
}
