use super::*;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;

pub(super) const MAX_FRAME: usize = 65536;
pub(super) struct Bounded<T> {
    inner: T,
    used: usize,
    limit: usize,
}
impl<T> Bounded<T> {
    pub fn new(inner: T, limit: usize) -> Self {
        Self {
            inner,
            used: 0,
            limit,
        }
    }
}
impl<T: AsRawFd> AsRawFd for Bounded<T> {
    fn as_raw_fd(&self) -> i32 {
        self.inner.as_raw_fd()
    }
}
impl<T: Read> Read for Bounded<T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.used);
        if remaining == 0 {
            return Err(std::io::Error::other(
                "editor aggregate input budget exhausted",
            ));
        }
        let size = bytes.len().min(remaining);
        let n = self.inner.read(&mut bytes[..size])?;
        self.used += n;
        Ok(n)
    }
}
impl<T: Write> Write for Bounded<T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.used);
        if remaining == 0 {
            return Err(std::io::Error::other(
                "editor aggregate output budget exhausted",
            ));
        }
        let n = self.inner.write(&bytes[..bytes.len().min(remaining)])?;
        self.used += n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Edit {
    Title {
        text: String,
    },
    Insert {
        index: usize,
        block: document::Block,
    },
    Replace {
        index: usize,
        block: document::Block,
    },
    Remove {
        index: usize,
    },
    Preview {},
    Freeze {},
    Cancel {},
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Command {
    pub sequence: u32,
    pub expected_source_sha256: String,
    pub operation: Edit,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct View {
    pub schema_version: u32,
    pub sequence: u32,
    pub source_sha256: String,
    pub document: document::Source,
    pub frozen: bool,
    pub saved: bool,
}
pub(super) struct Editor {
    request: StartRequest,
    document: document::Source,
    sequence: u32,
    terminal: bool,
}
impl Editor {
    pub fn new(request: StartRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            document: request.document.clone(),
            request,
            sequence: 0,
            terminal: false,
        })
    }
    pub fn view(&self) -> Result<View> {
        Ok(View {
            schema_version: 1,
            sequence: self.sequence,
            source_sha256: io::digest(&source(&self.document)?),
            document: self.document.clone(),
            frozen: self.terminal,
            saved: false,
        })
    }
    pub fn apply(&mut self, command: Command) -> Result<Option<Checkpoint>> {
        if self.terminal
            || self.sequence >= MAX_COMMANDS
            || command.sequence != self.sequence + 1
            || command.expected_source_sha256 != self.view()?.source_sha256
        {
            return Err("editor sequence/base is stale or session exhausted".into());
        }
        let mut next = self.document.clone();
        let frozen = match command.operation {
            Edit::Title { text } => {
                next.title = text;
                false
            }
            Edit::Insert { index, block } => {
                if index > next.blocks.len() {
                    return Err("editor insert index invalid".into());
                }
                next.blocks.insert(index, block);
                false
            }
            Edit::Replace { index, block } => {
                *next
                    .blocks
                    .get_mut(index)
                    .ok_or("editor replace index invalid")? = block;
                false
            }
            Edit::Remove { index } => {
                if index >= next.blocks.len() {
                    return Err("editor remove index invalid".into());
                }
                next.blocks.remove(index);
                false
            }
            Edit::Preview {} => false,
            Edit::Freeze {} => true,
            Edit::Cancel {} => {
                self.terminal = true;
                return Err("editor explicitly cancelled; draft is not saved".into());
            }
        };
        source(&next)?;
        self.document = next;
        self.sequence = command.sequence;
        self.terminal = frozen;
        if frozen {
            Ok(Some(Checkpoint::new(&self.request, self.document.clone())?))
        } else {
            Ok(None)
        }
    }
}
pub(super) fn parse_command(bytes: &[u8]) -> Result<Command> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("editor command bound exceeded".into());
    }
    let command: Command = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&command)? != bytes {
        return Err("editor command must be canonical closed typed data".into());
    }
    Ok(command)
}
pub(super) fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn ready(fd: i32, events: i16, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
    loop {
        check()?;
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut p, 1, 100) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if n > 0 {
            if p.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err("editor transport failed".into());
            }
            return Ok(());
        }
    }
}
fn exact_read(
    file: &mut (impl Read + AsRawFd),
    mut bytes: &mut [u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    while !bytes.is_empty() {
        ready(file.as_raw_fd(), libc::POLLIN, check)?;
        let n = match file.read(bytes) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Err("editor transport ended before complete frame".into());
        }
        bytes = &mut bytes[n..];
    }
    check()
}
pub(super) fn receive(
    file: &mut (impl Read + AsRawFd),
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    exact_read(file, &mut header, check)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err("editor wire frame length refused".into());
    }
    let mut bytes = vec![0; len];
    exact_read(file, &mut bytes, check)?;
    Ok(bytes)
}
pub(super) fn require_eof(
    file: &mut (impl Read + AsRawFd),
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    loop {
        ready(file.as_raw_fd(), libc::POLLIN, check)?;
        let mut byte = [0u8; 1];
        match file.read(&mut byte) {
            Ok(0) => return check(),
            Ok(_) => return Err("editor terminal frame has trailing bytes or another frame".into()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                ()
            }
            Err(e) => return Err(e.into()),
        }
    }
}
pub(super) fn send(
    file: &mut (impl Write + AsRawFd),
    bytes: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("editor wire output length refused".into());
    }
    let packet = [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat();
    let mut remaining = packet.as_slice();
    while !remaining.is_empty() {
        ready(file.as_raw_fd(), libc::POLLOUT, check)?;
        let n = match file.write(remaining) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Err("editor transport closed during output".into());
        }
        remaining = &remaining[n..];
    }
    check()
}
