//! Bounded concurrent transport only. Reader threads have no resource store,
//! controller access or effect authority. The broker coordinator owns dispatch.
use super::*;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;

const MAX_READERS: usize = 16;
const REPLY_WAIT: Duration = Duration::from_secs(12);

pub(super) struct Incoming {
    pub stream: UnixStream,
    pub bytes: Vec<u8>,
    reply: SyncSender<serde_json::Value>,
}
impl Incoming {
    pub fn respond(self, result: Result<serde_json::Value>) {
        let value =
            result.unwrap_or_else(|_| serde_json::json!({"schema_version":1,"result":"denied"}));
        // At most one response, never wait for a non-reading client here.
        // A disconnected/expired reader does not roll back any durable effect.
        let _ = self.reply.try_send(value);
    }
}

pub(super) struct Ingress {
    completed: Receiver<Incoming>,
    sender: SyncSender<Incoming>,
    readers: Vec<(u32, JoinHandle<()>)>,
}
impl Ingress {
    pub fn new() -> Self {
        let (sender, completed) = mpsc::sync_channel(MAX_READERS);
        Self {
            completed,
            sender,
            readers: vec![],
        }
    }
    fn limit(uid: u32) -> Result<usize> {
        match uid {
            0 => Ok(8),
            989 | 990 => Ok(4),
            _ => Err("broker peer identity denied before frame input".into()),
        }
    }
    fn reap(&mut self) {
        let mut index = 0;
        while index < self.readers.len() {
            if self.readers[index].1.is_finished() {
                let (_, thread) = self.readers.swap_remove(index);
                let _ = thread.join();
            } else {
                index += 1;
            }
        }
    }
    pub fn accept(&mut self, mut stream: UnixStream) -> Result<()> {
        // Authenticate before allocating a frame, thread or queue entry.
        let uid = credentials(&stream)?.uid;
        let limit = Self::limit(uid)?;
        self.reap();
        if self.readers.len() >= MAX_READERS
            || self
                .readers
                .iter()
                .filter(|(owner, _)| *owner == uid)
                .count()
                >= limit
        {
            return Err("broker peer transport quota exhausted".into());
        }
        let sender = self.sender.clone();
        let thread = std::thread::Builder::new()
            .name("broker-frame".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let result = (|| -> Result<()> {
                    let bytes = read_frame(&mut stream)?;
                    let (reply, response) = mpsc::sync_channel(1);
                    sender
                        .try_send(Incoming {
                            stream: stream.try_clone()?,
                            bytes,
                            reply,
                        })
                        .map_err(|_| "broker frame queue unavailable")?;
                    let value = response
                        .recv_timeout(REPLY_WAIT)
                        .map_err(|_| "broker operation outcome unavailable")?;
                    write_frame(&mut stream, &serde_json::to_vec(&value)?)
                })();
                if result.is_err() {
                    // Close the bounded connection; never echo untrusted input
                    // or manufacture a success after framing/dispatch failure.
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            })?;
        self.readers.push((uid, thread));
        Ok(())
    }
    pub fn receive(&mut self) -> Option<Incoming> {
        self.reap();
        self.completed.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wait(ingress: &mut Ingress) -> Incoming {
        let until = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(frame) = ingress.receive() {
                return frame;
            }
            assert!(Instant::now() < until, "completed frame did not arrive");
            std::thread::yield_now();
        }
    }
    #[test]
    fn slow_headers_and_waiting_operations_do_not_block_a_ready_resource_frame() {
        let mut ingress = Ingress::new();
        let (mut partial, reader) = UnixStream::pair().unwrap();
        ingress.accept(reader).unwrap();
        partial.write_all(&[0]).unwrap();
        let (mut waiting, reader) = UnixStream::pair().unwrap();
        ingress.accept(reader).unwrap();
        write_frame(&mut waiting, b"slow-operation").unwrap();
        let slow = wait(&mut ingress);
        assert_eq!(slow.bytes, b"slow-operation");
        let (mut client, reader) = UnixStream::pair().unwrap();
        ingress.accept(reader).unwrap();
        write_frame(&mut client, b"resource-renew").unwrap();
        let ready = wait(&mut ingress);
        assert_eq!(ready.bytes, b"resource-renew");
        assert_eq!(
            credentials(&ready.stream).unwrap().pid,
            std::process::id() as i32
        );
        ready.respond(Ok(serde_json::json!({"result":"ok"})));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&read_frame(&mut client).unwrap()).unwrap()
                ["result"],
            "ok"
        );
        slow.respond(Err("effect outcome uncertain".into()));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&read_frame(&mut waiting).unwrap())
                .unwrap()["result"],
            "denied"
        );
        partial.shutdown(std::net::Shutdown::Both).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while !ingress.readers.is_empty() {
            ingress.reap();
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
    }
    #[test]
    fn each_peer_has_a_finite_distinct_transport_quota_and_unknown_peers_refuse() {
        assert_eq!(Ingress::limit(0).unwrap(), 8);
        assert_eq!(Ingress::limit(989).unwrap(), 4);
        assert_eq!(Ingress::limit(990).unwrap(), 4);
        for uid in [988, 1000, u32::MAX] {
            assert!(Ingress::limit(uid).is_err());
        }
        let mut ingress = Ingress::new();
        let mut clients = vec![];
        for _ in 0..8 {
            let (client, reader) = UnixStream::pair().unwrap();
            ingress.accept(reader).unwrap();
            clients.push(client);
        }
        let (client, reader) = UnixStream::pair().unwrap();
        assert!(ingress.accept(reader).is_err());
        assert_eq!(ingress.readers.len(), 8);
        drop(client);
        drop(clients);
        let until = Instant::now() + Duration::from_secs(1);
        while !ingress.readers.is_empty() {
            ingress.reap();
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
    }
    #[test]
    fn malformed_truncated_and_oversized_frames_never_enter_the_authority_queue() {
        let mut ingress = Ingress::new();
        for size in [0u32, MAX_FRAME as u32 + 1, 5] {
            let (mut client, reader) = UnixStream::pair().unwrap();
            ingress.accept(reader).unwrap();
            client.write_all(&size.to_be_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Both).unwrap();
        }
        let until = Instant::now() + Duration::from_secs(1);
        while !ingress.readers.is_empty() {
            assert!(ingress.receive().is_none());
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        assert!(ingress.receive().is_none());
    }
}
