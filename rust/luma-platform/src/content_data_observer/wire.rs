//! No generic descriptor endpoint: only bounded canonical byte frames travel.
use super::*;
use std::os::fd::AsRawFd;
fn wait(
    socket: &UnixStream,
    events: i16,
    deadline: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    if Instant::now() >= deadline {
        return Err("observer transport deadline expired".into());
    }
    let mut p = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };
    let count = unsafe { libc::poll(&mut p, 1, 100) };
    let error = if count < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    check()?;
    if let Some(error) = error {
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    if p.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err("observer socket failed".into());
    }
    Ok(())
}
fn transfer(
    socket: &UnixStream,
    bytes: &mut [u8],
    write: bool,
    deadline: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        check()?;
        if Instant::now() >= deadline {
            return Err("observer bounded transport deadline expired".into());
        }
        let length = (bytes.len() - at).min(4096);
        let count = unsafe {
            if write {
                libc::send(
                    socket.as_raw_fd(),
                    bytes[at..].as_ptr().cast(),
                    length,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            } else {
                libc::recv(
                    socket.as_raw_fd(),
                    bytes[at..].as_mut_ptr().cast(),
                    length,
                    libc::MSG_DONTWAIT,
                )
            }
        };
        let error = if count < 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        check()?;
        if count > 0 {
            at += count as usize;
        } else if count == 0 {
            return Err("observer peer closed before complete frame".into());
        } else {
            let error = error.ok_or("observer OS error missing")?;
            match error.kind() {
                std::io::ErrorKind::Interrupted => (),
                std::io::ErrorKind::WouldBlock => wait(
                    socket,
                    if write { libc::POLLOUT } else { libc::POLLIN },
                    deadline,
                    check,
                )?,
                _ => return Err(error.into()),
            }
        }
    }
    check()
}
pub(super) fn send(
    socket: &UnixStream,
    bytes: &[u8],
    deadline: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > FRAME {
        return Err("observer output frame outside bound".into());
    }
    let mut size = (bytes.len() as u32).to_be_bytes();
    transfer(socket, &mut size, true, deadline, check)?;
    for chunk in bytes.chunks(4096) {
        let mut owned = chunk.to_vec();
        transfer(socket, &mut owned, true, deadline, check)?;
    }
    check()
}
pub(super) fn receive(
    socket: &UnixStream,
    deadline: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let mut word = [0; 4];
    transfer(socket, &mut word, false, deadline, check)?;
    let size = u32::from_be_bytes(word) as usize;
    if size == 0 || size > FRAME {
        return Err("observer input frame outside bound".into());
    }
    check()?;
    let mut bytes = vec![0; size];
    transfer(socket, &mut bytes, false, deadline, check)?;
    Ok(bytes)
}
