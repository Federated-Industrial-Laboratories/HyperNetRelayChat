// SPDX-License-Identifier: Apache-2.0
//! Bounded local JSON lines use private sockets or an explicitly entrusted stdio child.
use super::{Credential, Error, REQUEST_BYTES, RESPONSE_BYTES, Result, broker::Broker};
use crate::service::files;
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

fn line<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > limit || bytes.last() != Some(&b'\n') {
        return Err(io::Error::other("invalid frame"));
    }
    bytes.pop();
    Ok(Some(bytes))
}
fn write_line(writer: &mut impl Write, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::State)?;
    if bytes.len() > RESPONSE_BYTES {
        return Err(Error::Capacity);
    }
    writer
        .write_all(&bytes)
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|_| Error::Transport)
}
pub(super) fn write_fd(fd: std::os::fd::RawFd, value: &Value, stop: &AtomicBool) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| Error::State)?;
    if bytes.len() > RESPONSE_BYTES {
        return Err(Error::Capacity);
    }
    bytes.push(b'\n');
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::Transport);
    }
    struct Restore(std::os::fd::RawFd, libc::c_int);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::fcntl(self.0, libc::F_SETFL, self.1);
            }
        }
    }
    let _restore = Restore(fd, flags);
    let end = Instant::now() + Duration::from_secs(5);
    let mut written = 0;
    while written < bytes.len() {
        if stop.load(Ordering::Acquire) || Instant::now() >= end {
            return Err(Error::Transport);
        }
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut ready, 1, 100) };
        if polled < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Transport);
        }
        if polled == 0 {
            continue;
        }
        let count =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if count < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(Error::Transport);
        }
        if count == 0 {
            return Err(Error::Transport);
        }
        written += count as usize;
    }
    Ok(())
}
pub(super) fn input_line(input: std::os::fd::RawFd, stop: &AtomicBool) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let mut started = None;
    while !stop.load(Ordering::Acquire) {
        if started.is_some_and(|at: Instant| at.elapsed() > Duration::from_secs(10)) {
            return Err(Error::Invalid);
        }
        let mut fd = libc::pollfd {
            fd: input,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut fd, 1, 100) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Transport);
        }
        if rc == 0 {
            continue;
        }
        let mut byte = [0];
        let count = unsafe { libc::read(input, byte.as_mut_ptr().cast(), byte.len()) };
        let read = if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        };
        match read {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err(Error::Invalid),
            Ok(_) if byte[0] == b'\n' => return Ok(Some(bytes)),
            Ok(_) => {
                started.get_or_insert_with(Instant::now);
                bytes.push(byte[0]);
                if bytes.len() > REQUEST_BYTES {
                    return Err(Error::Invalid);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(_) => return Err(Error::Transport),
        }
    }
    Ok(None)
}
fn peer(stream: &UnixStream) -> Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    if rc != 0
        || size as usize != std::mem::size_of::<libc::ucred>()
        || credentials.uid != unsafe { libc::geteuid() }
    {
        return Err(Error::Denied);
    }
    Ok(())
}
struct Job {
    bytes: Vec<u8>,
    reply: mpsc::SyncSender<Value>,
    end: Instant,
}
fn connection(
    mut stream: UnixStream,
    sender: mpsc::SyncSender<Job>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| Error::Transport)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::Transport)?;
    for _ in 0..256 {
        let end = Instant::now() + Duration::from_secs(10);
        let mut bytes = Vec::new();
        loop {
            if stop.load(Ordering::Acquire) || Instant::now() >= end {
                return Ok(());
            }
            // A bounded single-byte delimiter read avoids consuming a second request.
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    bytes.push(byte[0]);
                    if bytes.len() > REQUEST_BYTES {
                        return Err(Error::Invalid);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return Err(Error::Transport),
            }
        }
        let (reply, receive) = mpsc::sync_channel(1);
        sender
            .try_send(Job {
                bytes,
                reply,
                end: Instant::now() + Duration::from_secs(30),
            })
            .map_err(|_| Error::Capacity)?;
        let response = receive
            .recv_timeout(Duration::from_secs(45))
            .map_err(|_| Error::Transport)?;
        write_line(&mut stream, &response)?;
    }
    Ok(())
}
pub fn serve(config: &Path, stdio: bool, stop: Arc<AtomicBool>) -> Result<()> {
    let mut broker = Broker::open(config)?;
    if stdio {
        let input = io::stdin().lock();
        let output = io::stdout().lock();
        while !stop.load(Ordering::Acquire) {
            let Some(bytes) = input_line(input.as_raw_fd(), &stop)? else {
                break;
            };
            if let Err(error) = write_fd(output.as_raw_fd(), &broker.handle(&bytes), &stop) {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                return Err(error);
            }
        }
        return Ok(());
    }
    let path = super::socket_path(config)?;
    let directory = path.parent().ok_or(Error::Invalid)?;
    if !directory.try_exists().map_err(|_| Error::State)? {
        files::directory(directory, true).map_err(|_| Error::State)?;
    }
    files::directory(directory, false).map_err(|_| Error::State)?;
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Denied);
        }
        fs::remove_file(&path).map_err(|_| Error::Transport)?;
    }
    let listener = UnixListener::bind(&path).map_err(|_| Error::Transport)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|_| Error::Transport)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| Error::Transport)?;
    let (sender, receive) = mpsc::sync_channel::<Job>(16);
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    let result = (|| {
        while !stop.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let _ = workers.swap_remove(i).join();
                } else {
                    i += 1;
                }
            }
            match listener.accept() {
                Ok((stream, _)) if workers.len() < 4 => {
                    let sender = sender.clone();
                    let stop = Arc::clone(&stop);
                    workers.push(thread::spawn(move || {
                        let _ = connection(stream, sender, stop);
                    }));
                }
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(_) => return Err(Error::Transport),
            }
            match receive.recv_timeout(Duration::from_millis(50)) {
                Ok(job) => {
                    let response = if Instant::now() < job.end {
                        broker.handle(&job.bytes)
                    } else {
                        Error::Capacity.response(Value::Null)
                    };
                    let _ = job.reply.try_send(response);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => broker.tick(),
                Err(_) => return Err(Error::Transport),
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    drop(receive);
    for worker in workers {
        let _ = worker.join();
    }
    let _ = fs::remove_file(&path);
    if config.parent() != Some(directory) {
        let _ = fs::remove_dir(directory);
    }
    result
}
pub fn request(socket: &Path, credential: &Path, method: &str, params: Value) -> Result<Value> {
    files::directory(socket.parent().ok_or(Error::Invalid)?, false).map_err(|_| Error::Denied)?;
    let credential = Credential::load(credential)?;
    let mut stream = UnixStream::connect(socket).map_err(|_| Error::Transport)?;
    peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(45)))
        .map_err(|_| Error::Transport)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::Transport)?;
    let value = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params,"auth":credential});
    let bytes = serde_json::to_vec(&value).map_err(|_| Error::Invalid)?;
    if bytes.len() > REQUEST_BYTES {
        return Err(Error::Invalid);
    }
    stream
        .write_all(&bytes)
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|_| Error::Transport)?;
    let bytes = line(&mut io::BufReader::new(stream), RESPONSE_BYTES)
        .map_err(|_| Error::Transport)?
        .ok_or(Error::Transport)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Transport)
}
