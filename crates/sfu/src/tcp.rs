//! ICE-TCP framing: RFC 4571, as RFC 6544 uses it. Each packet is a 2-byte big-endian length,
//! then that many bytes. Both the SFU and the headless client use it.

use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;

use mio::net::TcpStream;

/// The largest frame either side sends or takes. Larger than any packet str0m makes, and
/// the same as one UDP read.
pub(crate) const FRAME_MAX: usize = 2000;
/// Bytes waiting to go out on one stream. A packet that would pass it is dropped, as UDP
/// would lose it.
const BACKLOG: usize = 256 * 1024;
/// One read from a stream.
const CHUNK: usize = 4096;

/// A frame length of zero or over the cap. The stream is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadFrame;

/// Splits a byte stream into frames.
#[derive(Debug, Default)]
pub struct Framer {
    buf: Vec<u8>,
    max: usize,
}

impl Framer {
    /// Frames of up to `max` bytes.
    pub fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
        }
    }

    /// Adds bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole frame, if one is buffered.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, BadFrame> {
        let Some(&[high, low]) = self.buf.get(..2) else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes([high, low]));
        if len == 0 || len > self.max {
            return Err(BadFrame);
        }
        let Some(frame) = self.buf.get(2..2 + len) else {
            return Ok(None);
        };
        let frame = frame.to_vec();
        self.buf.drain(..2 + len);
        Ok(Some(frame))
    }
}

/// Appends `packet` to `out` as one frame. False if it is empty, too big, or `out` is full.
pub fn encode(packet: &[u8], out: &mut Vec<u8>) -> bool {
    let Ok(len) = u16::try_from(packet.len()) else {
        return false;
    };
    if len == 0 || packet.len() > FRAME_MAX || out.len() + 2 + packet.len() > BACKLOG {
        return false;
    }
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(packet);
    true
}

/// How a read ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readout {
    /// Nothing more to read for now.
    Drained,
    /// The read budget ran out with bytes still waiting. Read again soon.
    More,
    /// The peer closed, the stream failed, or it sent a bad frame.
    Closed,
}

/// One TCP stream: framed reads and a bounded write backlog.
pub(crate) struct Conn {
    pub socket: TcpStream,
    pub peer: SocketAddr,
    framer: Framer,
    out: Vec<u8>,
}

impl Conn {
    pub fn new(socket: TcpStream, peer: SocketAddr) -> Self {
        Self {
            socket,
            peer,
            framer: Framer::new(FRAME_MAX),
            out: Vec::new(),
        }
    }

    /// Reads up to `budget` bytes and hands each whole frame to `frame`, which returns false
    /// to close the stream.
    pub fn read(&mut self, budget: usize, mut frame: impl FnMut(&[u8]) -> bool) -> Readout {
        let mut buf = [0; CHUNK];
        let mut taken = 0;
        loop {
            if taken >= budget {
                return Readout::More;
            }
            let n = match self.socket.read(&mut buf) {
                Ok(0) => return Readout::Closed,
                Ok(n) => n,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Readout::Drained,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Readout::Closed,
            };
            taken += n;
            let Some(bytes) = buf.get(..n) else {
                return Readout::Closed;
            };
            self.framer.push(bytes);
            loop {
                match self.framer.next_frame() {
                    Ok(Some(packet)) => {
                        if !frame(&packet) {
                            return Readout::Closed;
                        }
                    }
                    Ok(None) => break,
                    Err(BadFrame) => return Readout::Closed,
                }
            }
        }
    }

    /// Queues one packet. False if it was dropped.
    pub fn queue(&mut self, packet: &[u8]) -> bool {
        encode(packet, &mut self.out)
    }

    /// Writes what it can. `Ok(true)` once nothing is waiting.
    pub fn flush(&mut self) -> io::Result<bool> {
        while !self.out.is_empty() {
            match self.socket.write(&self.out) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.out.drain(..n);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                // Not connected yet: a client's connect is still in flight.
                Err(error) if error.kind() == ErrorKind::NotConnected => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::{encode, BadFrame, Framer, FRAME_MAX};

    #[test]
    fn frames_split_across_reads_come_out_whole() {
        let mut out = Vec::new();
        assert!(encode(b"hello", &mut out));
        assert!(encode(b"there", &mut out));
        let mut framer = Framer::new(FRAME_MAX);
        let (first, rest) = out.split_at(4);
        framer.push(first);
        assert_eq!(framer.next_frame(), Ok(None));
        framer.push(rest);
        assert_eq!(framer.next_frame(), Ok(Some(b"hello".to_vec())));
        assert_eq!(framer.next_frame(), Ok(Some(b"there".to_vec())));
        assert_eq!(framer.next_frame(), Ok(None));
    }

    #[test]
    fn an_empty_or_oversized_frame_is_refused() {
        let mut framer = Framer::new(10);
        framer.push(&[0, 0]);
        assert_eq!(framer.next_frame(), Err(BadFrame));
        let mut framer = Framer::new(10);
        framer.push(&[0, 11]);
        assert_eq!(framer.next_frame(), Err(BadFrame));
        assert!(!encode(&[], &mut Vec::new()));
        assert!(!encode(&[0; FRAME_MAX + 1], &mut Vec::new()));
    }
}
