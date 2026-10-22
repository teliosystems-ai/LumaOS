use crate::Result;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub(super) trait FramedOutput {
    fn exact(&mut self, bytes: &[u8], check: &mut dyn FnMut() -> Result<()>) -> Result<()>;
    fn bytes(&self) -> u64;
    fn digest(&self) -> [u8; 32];
    fn flush(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()>;
}

pub(super) struct Input<R> {
    pub(super) stream: R,
    pub(super) bytes: u64,
    pub(super) maximum: u64,
    hash: Sha256,
}
impl<R: Read> Input<R> {
    pub(super) fn new(stream: R, maximum: u64) -> Self {
        Self {
            stream,
            bytes: 0,
            maximum,
            hash: Sha256::new(),
        }
    }
    pub(super) fn exact(
        &mut self,
        length: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        let next = self
            .bytes
            .checked_add(length as u64)
            .ok_or("package input overflow")?;
        if next > self.maximum {
            return Err("package exceeds original finite input".into());
        }
        check()?;
        let mut result = vec![0; length];
        let mut at = 0;
        while at < length {
            check()?;
            let end = (at + 4096).min(length);
            let count = match self.stream.read(&mut result[at..end]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                value => value?,
            };
            check()?;
            if count == 0 {
                return Err("truncated whole snapshot package".into());
            }
            self.hash.update(&result[at..at + count]);
            self.bytes += count as u64;
            at += count;
        }
        check()?;
        Ok(result)
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }
    pub(super) fn eof(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        loop {
            check()?;
            let mut byte = [0];
            let result = self.stream.read(&mut byte);
            check()?;
            match result {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) => return Ok(()),
                Ok(_) => return Err("trailing data after whole snapshot trailer".into()),
                Err(e) => return Err(e.into()),
            }
        }
    }
}
pub(super) struct Output<W> {
    stream: W,
    pub(super) bytes: u64,
    maximum: u64,
    hash: Sha256,
}
impl<W: Write> Output<W> {
    pub(super) fn new(stream: W, maximum: u64) -> Self {
        Self {
            stream,
            bytes: 0,
            maximum,
            hash: Sha256::new(),
        }
    }
    pub(super) fn exact(
        &mut self,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if self
            .bytes
            .checked_add(bytes.len() as u64)
            .map_or(true, |n| n > self.maximum)
        {
            return Err("package output exceeds original finite reservation".into());
        }
        for chunk in bytes.chunks(4096) {
            let mut at = 0;
            while at < chunk.len() {
                check()?;
                let count = match self.stream.write(&chunk[at..]) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    value => value?,
                };
                check()?;
                if count == 0 {
                    return Err("whole snapshot package output made no progress".into());
                }
                self.hash.update(&chunk[at..at + count]);
                self.bytes += count as u64;
                at += count;
            }
        }
        check()
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }
    pub(super) fn flush(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        check()?;
        self.stream.flush()?;
        check()
    }
}
impl<W: Write> FramedOutput for Output<W> {
    fn exact(&mut self, bytes: &[u8], check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        Output::exact(self, bytes, check)
    }
    fn bytes(&self) -> u64 {
        self.bytes
    }
    fn digest(&self) -> [u8; 32] {
        Output::digest(self)
    }
    fn flush(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        Output::flush(self, check)
    }
}
