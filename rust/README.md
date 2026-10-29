# Rust Bindings for OpenDHT

## Build and Test

Install Rust and the native OpenDHT C library. From this directory:

```sh
cargo build --all-targets
cargo test --all-targets
cargo test --doc
cargo run --example dhtnode
```

To use an uninstalled native build, set its library search paths. For example,
from the repository root on macOS:

```sh
cmake -S . -B build-bindings -DOPENDHT_C=ON -DBUILD_TESTING=ON
cmake --build build-bindings
ctest --test-dir build-bindings -R test_c --output-on-failure
LIBRARY_PATH="$PWD/build-bindings" \
DYLD_LIBRARY_PATH="$PWD/build-bindings" \
RUSTFLAGS="-L native=$PWD/build-bindings" \
cargo test --manifest-path rust/Cargo.toml --all-targets
```

On Linux use `LD_LIBRARY_PATH` instead of `DYLD_LIBRARY_PATH`; on Windows add
the native DLL directory to `PATH`. When linking an AddressSanitizer native
build, use the same compiler runtime, for example
`RUSTFLAGS="-L native=$PWD/build-bindings -C linker=clang -C link-arg=-fsanitize=address"`.

## Ownership and Errors

Startup, crypto import/generation, serialization, and fallible settings return
`std::io::Result`. Public-key `pack()` exports bytes; `unpack(bytes)` replaces a
key only after successful import. Crypto methods accept binary buffers, including
embedded NULs. Passwords and other C strings reject embedded NULs.

Callbacks are owned `Send + 'static` closures, not borrowed `&mut` closures.
Use `move` captures and channels or `Arc` for shared application state. Native
runner and crypto handles remain thread-bound. `Value` is `Send`, not `Sync`:
it can move between threads, and mutation requires exclusive `&mut` access.
Get/listen callbacks receive ordinary owned `Box<Value>` objects and can move
them directly through channels. Callback panics are contained at the FFI
boundary; a panicking value callback stops its operation.

The same `Value` type is used for construction, callback delivery, async streams,
and publication. `as_slice()` borrows the payload; `user_type()` and `push_type()`
borrow strings. `owner()` returns a retained public-key handle without exporting
it. `as_bytes()` explicitly copies the payload into a Rust `Vec<u8>`.
Received values can be edited directly and passed to `put` without converting
or cloning them. `boxed()` explicitly creates an additional independent copy.

```rust
use opendht::{DhtRunner, InfoHash, Value};
use std::sync::mpsc;

let mut runner = DhtRunner::new();
runner.run(0)?;
let hash = InfoHash::get("example");
let (sent, received) = mpsc::channel();
let token = runner.listen(&hash, move |value, expired| {
		if !expired { let _ = sent.send(value); }
		true
})?;
runner.put(&hash, Value::new("hello"), |_| {}, false);
let value = received.recv_timeout(std::time::Duration::from_secs(5))?;
assert_eq!(value.as_slice(), b"hello");
runner.cancel_listen(&hash, token);
runner.join()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`join()` waits for native callbacks, releases registrations, and permits restart.
Do not invoke it from a DHT callback. `shutdown(callback)` requests graceful
shutdown; wait for its callback before `join()` when persistence is required.
Dropping a listener token frees only the token; explicitly call `cancel_listen`
to remove the registration, or call `join()` to stop all operations. Pending
get/put/query completions are reported as failure when the runner stops.

For non-threaded operation set `config.threaded = false` and repeatedly call
`loop_once()`. Priority operations can take an iteration before normal work.
`run_bind` selects IPv4/IPv6 bind addresses; `bound_port` reports OS-assigned ports.

## Async API

The optional `async` feature adds `opendht::aio::AsyncDhtRunner`. It uses futures
channels without depending on Tokio or any other executor. The callback API and
default dependency set are unchanged.

```toml
[dependencies]
opendht = { version = "0.6", features = ["async"] }
futures = "0.3"
```

Configure and start a normal `DhtRunner`, then transfer it into
`AsyncDhtRunner::new(runner)`. Clones share the same runner. Run the complete
two-node loopback example with:

```sh
cargo run --features async --example dhtnode_async
cargo test --all-features --all-targets
cargo test --all-features --doc
```

With an already running async adapter:

```rust,ignore
use futures::{StreamExt, TryStreamExt};
use opendht::{InfoHash, Value};

let hash = InfoHash::get("example");
let mut updates = runner.listen(&hash)?;
runner.put(&hash, Value::new("hello"), false).await?;
let update = updates.next().await.transpose()?;
drop(updates);
let values: Vec<_> = runner.get(&hash).try_collect().await?;
runner.shutdown().await?;
runner.join()?;
```

- `put`, `put_signed`, `put_encrypted`, and `ping` return futures resolving to
	`io::Result<()>`. `bootstrap(&[SocketAddr])` contacts pre-resolved peers
	concurrently and succeeds when any peer responds. Resolve hostnames through
	the application's runtime before calling it.
- `get`, `get_filtered`, and `query` return fallible streams. Get/listen values
	are the same owned `Box<Value>` objects delivered by the callback API,
	with borrowed access to payload and metadata. Listener `ValueEvent`s also
	preserve the expiration flag.
- Streams buffer at most 64 items by default; `with_capacity` changes this
	limit. A full buffer stops delivery and yields `WouldBlock` after buffered
	items, then ends. Restart the operation to obtain a fresh snapshot. Native
	failures and runner termination also yield errors rather
	than successful EOF. Duplicate native deliveries are not suppressed.
- Dropping a listener immediately queues native cancellation and releases its
	token. Listeners retain the runner until dropped. Dropping get/query streams
	stops delivery at the next native callback, or when the runner is joined.
	Dropping a completion future abandons its result but does not cancel the
	native operation or undo a permanent put.
- Runner adapters and listeners remain thread-bound. Use `block_on`, a local
	executor, or Tokio `LocalSet`, not `tokio::spawn`. Received values and query rows can
	be sent to other threads. Non-threaded runners still require independent
	`loop_once()` calls while waiting. `join()` remains blocking; await graceful
	`shutdown()` first when persistence is required.

Received values are copied once by the native callback bridge to isolate them
from mutable DHT storage. Async streams move those exact boxes through their
channels without copying payloads or rebuilding metadata. Borrowed data remains
valid for the value's lifetime, even after the callback returns or the runner
stops. Put operations consume their box, so Rust cannot continue mutating a value
after native code retains it. Malformed UTF-8 metadata is reported when its
string accessor is called, rather than eagerly failing the entire stream.

`value.owner()` returns the existing `PublicKey` type, not a second key class or
DER bytes. Call `pack()` only when exported bytes are actually needed. Shared
const owner-key fingerprint caches are initialized on the callback thread before
transfer. Replacing a returned key through `unpack()` changes that handle, not
the value's owner key.

## Typed Records

Enable `serde` for typed MessagePack operations on `AsyncDhtRunner`. This feature
also enables `async`; neither Serde nor MessagePack is required by default.

```toml
[dependencies]
opendht = { version = "0.6", features = ["serde"] }
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
futures = "0.3"
```

With an already running async adapter:

```rust,ignore
use futures::TryStreamExt;
use opendht::InfoHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Service {
	version: u32,
	name: String,
	port: u16,
	#[serde(with = "serde_bytes")]
	payload: Vec<u8>,
}

let hash = InfoHash::get("services/chat");
let mut updates = runner.listen_typed::<Service>(&hash)?;
let record = Service {
	version: 1, name: "chat".into(), port: 4222, payload: vec![0, 0x80, 0xff],
};
runner.put_typed(&hash, &record, false).await?;
if let Some(event) = updates.try_next().await? {
	println!("{}: {:?}", event.value.raw.id(), event.value.data);
}
drop(updates);
let records: Vec<_> = runner.get_typed::<Service>(&hash).try_collect().await?;
```

Typed puts accept `Serialize`, including unsized values. Typed reads require
`DeserializeOwned`, without imposing `Clone`, `Send`, or `Unpin` on the record.
Decoding happens when the consumer polls, not in native callbacks. Each
`TypedValue<T>` exposes decoded `data` and the original owned `raw: Box<Value>`, retaining
payload bytes and all metadata. Decoding borrows the raw payload directly, with
no intermediate byte-buffer copy; allocations required by the decoded record
still apply. `TypedEvent<T>` preserves the expiration flag.

`TypedError` distinguishes `Serialize`, `Deserialize { id, source }`, and native
`Operation` errors, preserving the underlying error through `Error::source()`.
An invalid MessagePack payload or incompatible schema yields a per-value error; keep
polling to read subsequent records. `try_collect()` short-circuits on any error.
Buffer limits, terminal native failures, and listener cancellation on drop are
unchanged from the async API.

`put_typed` is an ordinary lazy async method: it serializes and starts publication
only when polled. Serialization failure does not start a native put. Dropping
the future after publication starts does not undo the put. Typed puts use the
default native metadata; for custom IDs/types or signed/encrypted publication,
serialize into a `Value` and use the existing untyped methods. Raw get/listen
values can also be decoded with `TypedValue::<T>::try_from(value)` or
`TypedEvent::<T>::try_from(event)`.

The wire payload is compact MessagePack, following OpenDHT's serialization
convention. Structs are encoded as arrays in field order; field order is part
of the wire schema. No schema version or envelope is inserted; applications
control their record format and versioning. Use `#[serde(with = "serde_bytes")]`
on byte buffers (or `serde_bytes::ByteBuf`) for native MessagePack `bin` values;
plain `Vec<u8>` otherwise serializes as an integer array. Run the complete typed
loopback example with:

```sh
cargo run --features serde --example dhtnode_async
```

## Extended APIs

- Values expose explicit IDs, user types, value types, sequence numbers,
	push priorities, and push types.
- Keys and certificates support persistence; identities support RSA and EC
	generation. Private keys support binary signing and RSA decryption.
- `get_filtered`, `listen_filtered`, and `query` accept native SQL-like filters,
	such as `WHERE value_type=17`, `WHERE seq=7`, and
	`SELECT id,user_type WHERE value_type=17`.
	Projected fields are optional owned values in `QueryResult`.
- `register_type` installs native type policy and expiration settings.
- Configuration accepts owned status and certificate-store callbacks.
	Certificate lookup/registration and connectivity changes are exposed.
- Push token/topic/platform setters forward native settings.
	`push_notification_received` returns a `PushNotification`; call `poll()` for
	the native result. In non-threaded mode continue driving `loop_once()`.
	Disabled builds return `IgnoredDisabled`; stopped runners return the native
	ignored outcome. Push tokens remain valid after the runner stops.