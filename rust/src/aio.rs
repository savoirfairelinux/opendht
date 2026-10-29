//! Runtime-independent futures and bounded streams, enabled by the `async` feature.
//!
//! Runners and listeners stay on their creating thread. Use a local executor or
//! Tokio `LocalSet`; received values own their native storage and can be
//! transferred between threads without another payload copy.

use crate::{DhtRunner, InfoHash, OpToken, PkId, QueryResult, Value};
use futures_channel::{mpsc, oneshot};
use futures_core::Stream;
use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// A listener update; expiration events retain the expired value's metadata.
pub struct ValueEvent {
    pub value: Box<Value>,
    pub expired: bool,
}

/// A native completion mapped to an I/O result.
///
/// Operations start immediately, before this future is polled. Dropping it
/// abandons the result but does not undo a put, ping, bootstrap, or shutdown.
#[must_use = "operations run immediately; await their result or explicitly drop it"]
pub struct Operation {
    receiver: oneshot::Receiver<io::Result<()>>,
}

impl Future for Operation {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.receiver).poll(context).map(|outcome| {
            outcome.unwrap_or_else(|_| Err(stopped("DHT operation ended without completion")))
        })
    }
}

fn operation() -> (oneshot::Sender<io::Result<()>>, Operation) {
    let (sender, receiver) = oneshot::channel();
    (sender, Operation { receiver })
}

fn outcome(success: bool) -> io::Result<()> {
    if success {
        Ok(())
    } else {
        Err(io::Error::other(
            "DHT operation failed or the runner stopped",
        ))
    }
}

fn stopped(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, message)
}

#[derive(Clone)]
struct StreamCompletion(Arc<Mutex<Option<oneshot::Sender<io::Result<()>>>>>);

impl StreamCompletion {
    fn finish(&self, result: io::Result<()>) {
        let sender = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(sender) = sender {
            let _ = sender.send(result);
        }
    }
}

struct StreamSender<T> {
    values: mpsc::Sender<T>,
    completion: StreamCompletion,
}

impl<T> StreamSender<T> {
    fn send(&mut self, value: io::Result<T>) -> bool {
        let value = match value {
            Ok(value) => value,
            Err(error) => {
                self.completion.finish(Err(error));
                return false;
            }
        };
        match self.values.try_send(value) {
            Ok(()) => true,
            Err(error) => {
                if error.is_full() {
                    self.completion.finish(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "DHT stream capacity exceeded; restart the operation to resynchronize",
                    )));
                }
                false
            }
        }
    }
}

/// A bounded get or query stream.
///
/// Buffered items precede a terminal error. Native failure, runner shutdown,
/// and buffer overflow are never reported as successful EOF.
/// Dropping the stream stops delivery; native work stops at its next callback
/// or when the runner is joined.
#[must_use = "streams must be polled to receive values and completion errors"]
pub struct OperationStream<T> {
    values: mpsc::Receiver<T>,
    completion: oneshot::Receiver<io::Result<()>>,
    completed: bool,
    outcome: Option<io::Result<()>>,
}

impl<T: Unpin> Stream for OperationStream<T> {
    type Item = io::Result<T>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        if !stream.completed
            && let Poll::Ready(result) = Pin::new(&mut stream.completion).poll(context)
        {
            stream.completed = true;
            stream.outcome = Some(
                result.unwrap_or_else(|_| Err(stopped("DHT stream ended without completion"))),
            );
            stream.values.close();
        }
        match Pin::new(&mut stream.values).poll_next(context) {
            Poll::Ready(Some(value)) => Poll::Ready(Some(Ok(value))),
            Poll::Ready(None) if stream.completed => {
                Poll::Ready(stream.outcome.take().and_then(Result::err).map(Err))
            }
            _ => Poll::Pending,
        }
    }
}

fn stream_channel<T>(capacity: usize) -> (StreamSender<T>, OperationStream<T>) {
    let (values, receiver) = mpsc::channel(capacity - 1);
    let (completed, completion) = oneshot::channel();
    (
        StreamSender {
            values,
            completion: StreamCompletion(Arc::new(Mutex::new(Some(completed)))),
        },
        OperationStream {
            values: receiver,
            completion,
            completed: false,
            outcome: None,
        },
    )
}

struct RunnerState {
    runner: RefCell<Box<DhtRunner>>,
    stopping: Arc<AtomicBool>,
}

impl Drop for RunnerState {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}

/// A listener registration that cancels itself when dropped or terminated.
///
/// The runner is retained until this registration is dropped. Calling `join()`
/// stops all registrations and makes pending listeners report an error.
#[must_use = "dropping a listener cancels its native registration"]
pub struct Listener {
    state: Rc<RunnerState>,
    hash: InfoHash,
    token: Option<Box<OpToken>>,
    stream: OperationStream<ValueEvent>,
}

impl Listener {
    fn cancel(&mut self) {
        if let Some(token) = self.token.take() {
            self.state
                .runner
                .borrow_mut()
                .cancel_listen(&self.hash, token);
        }
    }
}

impl Stream for Listener {
    type Item = io::Result<ValueEvent>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = Pin::new(&mut self.stream).poll_next(context);
        if matches!(result, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.cancel();
        }
        result
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// A shared, thread-bound async adapter for an already configured runner.
///
/// Clones share a runner without making native handles `Send` or `Sync`.
/// Native calls are short; futures and streams never hold a mutable runner
/// borrow while waiting. The default stream capacity is 64 items.
///
/// ```compile_fail
/// use opendht::{aio::AsyncDhtRunner, DhtRunner};
/// let runner = AsyncDhtRunner::new(DhtRunner::new());
/// std::thread::spawn(move || runner.join().unwrap());
/// ```
#[derive(Clone)]
pub struct AsyncDhtRunner {
    state: Rc<RunnerState>,
    capacity: usize,
}

impl AsyncDhtRunner {
    pub fn new(runner: Box<DhtRunner>) -> Self {
        Self::with_capacity(runner, 64).expect("default stream capacity is valid")
    }

    /// Set the maximum number of queued values per get, query, or listener.
    /// A slow consumer receives `WouldBlock` and the stream terminates.
    pub fn with_capacity(runner: Box<DhtRunner>, capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream capacity must be positive",
            ));
        }
        Ok(Self {
            state: Rc::new(RunnerState {
                runner: RefCell::new(runner),
                stopping: Arc::new(AtomicBool::new(false)),
            }),
            capacity,
        })
    }

    pub fn put(&self, hash: &InfoHash, value: Box<Value>, permanent: bool) -> Operation {
        let (sender, pending) = operation();
        self.state.runner.borrow_mut().put(
            hash,
            value,
            move |success| {
                let _ = sender.send(outcome(success));
            },
            permanent,
        );
        pending
    }

    pub fn put_signed(&self, hash: &InfoHash, value: Box<Value>, permanent: bool) -> Operation {
        let (sender, pending) = operation();
        self.state.runner.borrow_mut().put_signed(
            hash,
            value,
            move |success| {
                let _ = sender.send(outcome(success));
            },
            permanent,
        );
        pending
    }

    pub fn put_encrypted(
        &self,
        hash: &InfoHash,
        recipient: &PkId,
        value: Box<Value>,
        permanent: bool,
    ) -> Operation {
        let (sender, pending) = operation();
        self.state.runner.borrow_mut().put_encrypted(
            hash,
            recipient,
            value,
            move |success| {
                let _ = sender.send(outcome(success));
            },
            permanent,
        );
        pending
    }

    pub fn ping(&self, address: SocketAddr) -> Operation {
        let (sender, pending) = operation();
        self.state
            .runner
            .borrow_mut()
            .ping(address, move |success| {
                let _ = sender.send(outcome(success));
            });
        pending
    }

    /// Bootstrap pre-resolved addresses concurrently; one successful peer suffices.
    /// DNS resolution is left to the application's executor.
    pub fn bootstrap(&self, addresses: &[SocketAddr]) -> Operation {
        let (sender, pending) = operation();
        if addresses.is_empty() {
            let _ = sender.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one bootstrap address is required",
            )));
            return pending;
        }
        let completion = StreamCompletion(Arc::new(Mutex::new(Some(sender))));
        let remaining = Arc::new(std::sync::atomic::AtomicUsize::new(addresses.len()));
        for &address in addresses {
            let completion = completion.clone();
            let remaining = remaining.clone();
            self.state
                .runner
                .borrow_mut()
                .ping(address, move |success| {
                    if success {
                        completion.finish(Ok(()));
                    }
                    if remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
                        completion.finish(outcome(false));
                    }
                });
        }
        pending
    }

    pub fn get(&self, hash: &InfoHash) -> OperationStream<Box<Value>> {
        let (mut sender, stream) = stream_channel(self.capacity);
        let completion = sender.completion.clone();
        self.state.runner.borrow_mut().get(
            hash,
            move |value| sender.send(Ok(value)),
            move |success| completion.finish(outcome(success)),
        );
        stream
    }

    pub fn get_filtered(
        &self,
        hash: &InfoHash,
        filter: &str,
    ) -> io::Result<OperationStream<Box<Value>>> {
        let (mut sender, stream) = stream_channel(self.capacity);
        let completion = sender.completion.clone();
        self.state.runner.borrow_mut().get_filtered(
            hash,
            filter,
            move |value| sender.send(Ok(value)),
            move |success| completion.finish(outcome(success)),
        )?;
        Ok(stream)
    }

    pub fn query(&self, hash: &InfoHash, query: &str) -> io::Result<OperationStream<QueryResult>> {
        let (mut sender, stream) = stream_channel(self.capacity);
        let completion = sender.completion.clone();
        self.state.runner.borrow_mut().query(
            hash,
            query,
            move |row| sender.send(Ok(row)),
            move |success| completion.finish(outcome(success)),
        )?;
        Ok(stream)
    }

    pub fn listen(&self, hash: &InfoHash) -> io::Result<Listener> {
        self.listen_filtered(hash, "")
    }

    pub fn listen_filtered(&self, hash: &InfoHash, filter: &str) -> io::Result<Listener> {
        let (mut sender, stream) = stream_channel(self.capacity);
        let token = self.state.runner.borrow_mut().listen_filtered(
            hash,
            filter,
            move |value, expired| sender.send(Ok(ValueEvent { value, expired })),
        )?;
        Ok(Listener {
            state: self.state.clone(),
            hash: InfoHash { d: hash.d },
            token: Some(token),
            stream,
        })
    }

    /// Request graceful shutdown. Call `join()` after this future succeeds when
    /// persistence is required. Joining first reports an interrupted shutdown.
    pub fn shutdown(&self) -> Operation {
        let (sender, pending) = operation();
        let stopping = self.state.stopping.clone();
        self.state.runner.borrow_mut().shutdown(move || {
            let result = if stopping.load(Ordering::SeqCst) {
                Err(stopped("runner joined before graceful shutdown completed"))
            } else {
                Ok(())
            };
            let _ = sender.send(result);
        });
        pending
    }

    /// Drive a non-threaded runner without waiting for any async operation.
    pub fn loop_once(&self) -> io::Result<()> {
        self.state.runner.borrow_mut().loop_once()
    }

    /// Stop the runner and wait for native callbacks. This is a blocking call,
    /// not an async wait, and must not be invoked from a native DHT callback.
    pub fn join(&self) -> io::Result<()> {
        self.state.stopping.store(true, Ordering::SeqCst);
        self.state.runner.borrow_mut().join()
    }
}
