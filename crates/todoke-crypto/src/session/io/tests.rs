//! The incremental record reader and the write loop over scripted pipes:
//! prefixes are validated before buffering (§4.1, §5, §13), progress
//! survives `Pending` and short reads, and pipe failures surface as
//! errors, never as partial records.

use std::collections::VecDeque;
use std::task::Waker;

use proptest::prelude::*;
use todoke_proto::session::ErrorCode;

use super::*;

/// One scripted `poll_read`/`poll_write` result.
#[derive(Clone, Debug)]
enum Step {
    /// Up to this many bytes (reads: from the stream; writes: accepted).
    Bytes(usize),
    Pending,
    Fail(io::ErrorKind),
}

/// A pipe that replays `steps`, then reports end of stream (reads) or
/// accepts everything (writes).
struct Scripted {
    stream: VecDeque<u8>,
    steps: VecDeque<Step>,
    written: Vec<u8>,
}

impl Scripted {
    fn new(stream: &[u8], steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            stream: stream.iter().copied().collect(),
            steps: steps.into_iter().collect(),
            written: Vec::new(),
        }
    }
}

impl AsyncRead for Scripted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let limit = match self.steps.pop_front() {
            Some(Step::Pending) => return Poll::Pending,
            Some(Step::Fail(kind)) => return Poll::Ready(Err(kind.into())),
            Some(Step::Bytes(limit)) => limit,
            None => usize::MAX,
        };
        let count = buf.len().min(limit).min(self.stream.len());
        for (slot, byte) in buf.iter_mut().zip(self.stream.drain(..count)) {
            *slot = byte;
        }
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = match self.steps.pop_front() {
            Some(Step::Pending) => return Poll::Pending,
            Some(Step::Fail(kind)) => return Poll::Ready(Err(kind.into())),
            Some(Step::Bytes(limit)) => buf.len().min(limit),
            None => buf.len(),
        };
        self.written.extend_from_slice(&buf[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Polls the reader until it stops, as a caller re-polling after every
/// `Pending` would; returns the records and the error that ended it.
fn read_all(pipe: &mut Scripted, framing: Framing) -> (Vec<Vec<u8>>, SessionError) {
    let mut reader = RecordReader::new();
    let mut cx = Context::from_waker(Waker::noop());
    let mut records = Vec::new();
    loop {
        match reader.poll_record(pipe, framing, &mut cx) {
            Poll::Ready(Ok(record)) => records.push(record),
            Poll::Ready(Err(error)) => return (records, error),
            Poll::Pending => {}
        }
    }
}

/// Independent reference: the bodies of the valid records at the start of
/// `stream`, and why reading stops after them.
fn reference(stream: &[u8], framing: Framing) -> (Vec<Vec<u8>>, SessionError) {
    let mut records = Vec::new();
    let mut rest = stream;
    loop {
        let Some((prefix, after)) = rest.split_first_chunk::<2>() else {
            return (records, SessionError::Closed);
        };
        let length = usize::from(u16::from_be_bytes(*prefix));
        let valid = match framing {
            Framing::Prelude => (1..=8192).contains(&length),
            Framing::Transport => length >= 20,
        };
        if !valid {
            return (records, SessionError::Protocol(ErrorCode::MALFORMED));
        }
        let Some(body) = after.get(..length) else {
            return (records, SessionError::Closed);
        };
        records.push(body.to_vec());
        rest = &after[length..];
    }
}

fn framed(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = Vec::new();
    for body in bodies {
        let length = u16::try_from(body.len()).unwrap_or(u16::MAX);
        stream.extend_from_slice(&length.to_be_bytes());
        stream.extend_from_slice(body);
    }
    stream
}

const MALFORMED: SessionError = SessionError::Protocol(ErrorCode::MALFORMED);

#[test]
fn prefixes_outside_the_bounds_are_rejected_before_buffering() {
    for (framing, length, valid) in [
        (Framing::Prelude, 0_u16, false),
        (Framing::Prelude, 1, true),
        (Framing::Prelude, 8192, true),
        (Framing::Prelude, 8193, false),
        (Framing::Prelude, u16::MAX, false),
        (Framing::Transport, 0, false),
        (Framing::Transport, 19, false),
        (Framing::Transport, 20, true),
        (Framing::Transport, u16::MAX, true),
    ] {
        let body = vec![0xab; usize::from(length)];
        let mut stream = length.to_be_bytes().to_vec();
        stream.extend_from_slice(&body);
        let mut pipe = Scripted::new(&stream, []);
        let (records, error) = read_all(&mut pipe, framing);
        if valid {
            assert_eq!((records, error), (vec![body], SessionError::Closed));
        } else {
            assert_eq!(
                (records.len(), error),
                (0, MALFORMED),
                "{framing:?} {length}"
            );
            // Nothing after the prefix was read.
            assert_eq!(pipe.stream.len(), body.len(), "{framing:?} {length}");
        }
    }
}

#[test]
fn end_of_stream_inside_a_record_is_a_close_not_a_record() {
    let stream = framed(&[vec![1; 30], vec![2; 25]]);
    for cut in 0..=stream.len() {
        let mut pipe = Scripted::new(&stream[..cut], []);
        let (records, error) = read_all(&mut pipe, Framing::Transport);
        assert_eq!(error, SessionError::Closed, "cut {cut}");
        let complete = if cut >= 59 { 2 } else { usize::from(cut >= 32) };
        assert_eq!(records.len(), complete, "cut {cut}");
    }
}

#[test]
fn pipe_errors_surface_with_their_kind() {
    let stream = framed(&[vec![7; 40]]);
    for (steps, kind) in [
        (vec![], io::ErrorKind::ConnectionReset),
        (vec![Step::Bytes(1), Step::Pending], io::ErrorKind::TimedOut),
        (
            vec![Step::Bytes(2), Step::Bytes(10)],
            io::ErrorKind::BrokenPipe,
        ),
    ] {
        let mut steps = steps;
        steps.push(Step::Fail(kind));
        let mut pipe = Scripted::new(&stream, steps);
        let (records, error) = read_all(&mut pipe, Framing::Transport);
        assert_eq!((records.len(), error), (0, SessionError::Io(kind)));
    }
}

/// A write that makes no progress or fails is an error; short writes and
/// `Pending` resume where they stopped.
#[test]
fn write_loop_resumes_short_writes_and_reports_failures() {
    let record: Vec<u8> = (0..=99).collect();
    let mut cx = Context::from_waker(Waker::noop());
    let mut pipe = Scripted::new(
        &[],
        [
            Step::Bytes(3),
            Step::Pending,
            Step::Bytes(50),
            Step::Pending,
        ],
    );
    let mut written = 0;
    let mut polls = 0;
    let result = loop {
        polls += 1;
        if let Poll::Ready(result) = poll_write_all(&mut pipe, &record, &mut written, &mut cx) {
            break result;
        }
    };
    assert_eq!(result, Ok(()));
    assert_eq!((polls, written), (3, record.len()));
    assert_eq!(pipe.written, record);
    for (step, expected) in [
        (Step::Bytes(0), io::ErrorKind::WriteZero),
        (
            Step::Fail(io::ErrorKind::BrokenPipe),
            io::ErrorKind::BrokenPipe,
        ),
    ] {
        let mut pipe = Scripted::new(&[], [Step::Bytes(10), step]);
        let mut written = 0;
        assert_eq!(
            poll_write_all(&mut pipe, &record, &mut written, &mut cx),
            Poll::Ready(Err(SessionError::Io(expected)))
        );
        assert_eq!(written, 10);
    }
}

fn arb_step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (1..80usize).prop_map(Step::Bytes),
        1 => Just(Step::Pending),
    ]
}

proptest! {
    /// Any stream, delivered in any pattern of short reads and `Pending`,
    /// yields exactly the reference records and stop reason.
    #[test]
    fn reader_matches_the_reference_under_any_chunking(
        bodies in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..120), 0..6),
        tail in proptest::collection::vec(any::<u8>(), 0..6),
        steps in proptest::collection::vec(arb_step(), 0..64),
        transport in any::<bool>(),
    ) {
        let framing = if transport { Framing::Transport } else { Framing::Prelude };
        let mut stream = framed(&bodies);
        stream.extend_from_slice(&tail);
        let mut pipe = Scripted::new(&stream, steps);
        prop_assert_eq!(read_all(&mut pipe, framing), reference(&stream, framing));
    }
}
