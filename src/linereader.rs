//! Reading one line at a time without trusting the peer to end it.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// What a read produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A complete line, in the buffer, with its terminator removed.
    Read,
    /// A line longer than the limit. Its bytes were dropped as they arrived, so
    /// the buffer is empty and the connection is still usable — the caller
    /// decides whether to say so or to close.
    TooLong,
    /// The peer has nothing more to send.
    Eof,
}

/// One line at a time, holding at most `limit` bytes of any of them.
///
/// `read_until` grows its buffer until it finds a newline, so a peer that sends
/// megabytes and never sends one can make this server hold every byte. That
/// costs the peer a socket and some bandwidth and costs the server memory,
/// which is the wrong way round — and on the link port it can be done before
/// the peer has proved it is allowed to talk at all.
///
/// Past the limit the bytes are dropped as they arrive. The line is over the
/// limit either way; what is at stake is only whether this server pays to find
/// out.
pub struct BoundedLines {
    buf: Vec<u8>,
    limit: usize,
    /// Set once the line went past the limit, so the rest of it is dropped
    /// rather than measured again.
    over: bool,
    /// Set when a line was handed over, so the next read starts a new one. It
    /// is what makes [`BoundedLines::next`] safe to cancel: a read that was
    /// dropped part-way never set it, and picks up where it left off.
    finished: bool,
}

impl BoundedLines {
    pub fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
            over: false,
            finished: false,
        }
    }

    /// The line the last read produced, without its terminator.
    pub fn line(&self) -> &[u8] {
        &self.buf
    }

    /// Read up to the next newline.
    ///
    /// Safe to cancel: everything taken from the reader is kept here, so a read
    /// dropped by a `select!` that chose another branch loses nothing. This is
    /// the property `read_until` has and the reason it is worth keeping —
    /// without it a keepalive firing mid-line would silently eat a command.
    pub async fn next<R>(&mut self, reader: &mut R) -> std::io::Result<Line>
    where
        R: AsyncBufRead + Unpin,
    {
        if self.finished {
            self.buf.clear();
            self.over = false;
            self.finished = false;
        }
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                self.finished = true;
                // A last line with no terminator is still a line; the read
                // after this one reports the end.
                return Ok(if self.over {
                    Line::TooLong
                } else if self.buf.is_empty() {
                    Line::Eof
                } else {
                    Line::Read
                });
            }
            let (chunk, end) = match available.iter().position(|b| *b == b'\n') {
                Some(i) => (&available[..i], Some(i + 1)),
                None => (available, None),
            };
            // One byte of slack, because the carriage return before the newline
            // is the terminator rather than part of the line, and it is not
            // known to be there until the newline arrives.
            if !self.over {
                if self.buf.len() + chunk.len() > self.limit + 1 {
                    self.over = true;
                    self.buf.clear();
                } else {
                    self.buf.extend_from_slice(chunk);
                }
            }
            let consumed = end.unwrap_or(available.len());
            reader.consume(consumed);
            if end.is_some() {
                self.finished = true;
                while self.buf.ends_with(b"\r") {
                    self.buf.pop();
                }
                if self.over || self.buf.len() > self.limit {
                    self.buf.clear();
                    return Ok(Line::TooLong);
                }
                return Ok(Line::Read);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_all(input: &[u8], limit: usize) -> Vec<(Line, String)> {
        let mut reader = tokio::io::BufReader::new(input);
        let mut lines = BoundedLines::new(limit);
        let mut out = Vec::new();
        loop {
            let outcome = lines.next(&mut reader).await.unwrap();
            let text = String::from_utf8_lossy(lines.line()).into_owned();
            let done = outcome == Line::Eof;
            out.push((outcome, text));
            if done {
                return out;
            }
        }
    }

    #[tokio::test]
    async fn lines_come_back_one_at_a_time_without_their_terminator() {
        let got = read_all(b"one\r\ntwo\nthree\r\n", 64).await;
        assert_eq!(
            got,
            vec![
                (Line::Read, "one".to_string()),
                (Line::Read, "two".to_string()),
                (Line::Read, "three".to_string()),
                (Line::Eof, String::new()),
            ]
        );
    }

    /// The point of the whole thing: a peer that never sends a newline must not
    /// be able to make this server hold what it wrote.
    #[tokio::test]
    async fn a_line_past_the_limit_is_not_kept() {
        let mut input = vec![b'x'; 10_000];
        input.extend_from_slice(b"\r\nafter\r\n");
        let got = read_all(&input, 64).await;
        assert_eq!(
            got,
            vec![
                (Line::TooLong, String::new()),
                (Line::Read, "after".to_string()),
                (Line::Eof, String::new()),
            ],
            "the oversized line should be dropped and the next one still arrive"
        );
    }

    /// A peer that sends nothing but bytes, for ever, and never a newline.
    #[tokio::test]
    async fn a_peer_that_never_ends_its_line_is_not_buffered() {
        let input = vec![b'x'; 1_000_000];
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut lines = BoundedLines::new(512);
        assert_eq!(lines.next(&mut reader).await.unwrap(), Line::TooLong);
        assert!(
            lines.line().is_empty(),
            "held {} bytes for a 512-byte limit",
            lines.line().len()
        );
    }

    /// A line exactly at the limit is a line, not an overflow.
    #[tokio::test]
    async fn the_limit_itself_is_allowed() {
        let mut input = vec![b'y'; 64];
        input.extend_from_slice(b"\r\n");
        let got = read_all(&input, 64).await;
        assert_eq!(got[0].0, Line::Read);
        assert_eq!(got[0].1.len(), 64);
    }

    /// The reason this is a struct and not a function.
    ///
    /// The read sits in a `select!` next to a keepalive timer. If the timer
    /// fires while half a line has arrived, this future is dropped — and what
    /// it had already taken off the socket must survive, or a command a client
    /// sent would silently never happen. `read_until` promises this, and
    /// anything replacing it has to promise the same.
    #[tokio::test]
    async fn a_read_that_is_cancelled_loses_nothing() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = tokio::io::BufReader::new(reader);
        let mut lines = BoundedLines::new(512);

        writer.write_all(b"PRIVMSG #chan :half").await.unwrap();
        // No newline yet, so this read cannot finish. Something else wins.
        tokio::select! {
            _ = lines.next(&mut reader) => panic!("a line with no end should not have finished"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }

        writer.write_all(b" of it\r\n").await.unwrap();
        assert_eq!(lines.next(&mut reader).await.unwrap(), Line::Read);
        assert_eq!(
            String::from_utf8_lossy(lines.line()),
            "PRIVMSG #chan :half of it",
            "the half that arrived before the cancellation was lost"
        );
    }
}
