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
handles are thread-bound; send copied data through channels rather than moving
a runner or value handle between threads. Handles own stable native pointers
and can be moved out of or back into their Rust boxes on the same thread.
Callback panics are contained at the
FFI boundary; a panicking value callback stops its operation.

`Value::boxed()` creates an independent copy, including payload and metadata,
so a retained value does not alias mutable native storage or in-flight puts.

```rust
use opendht::{DhtRunner, InfoHash, Value};
use std::sync::mpsc;

let mut runner = DhtRunner::new();
runner.run(0)?;
let hash = InfoHash::get("example");
let (sent, received) = mpsc::channel();
let token = runner.listen(&hash, move |value, expired| {
		if !expired { let _ = sent.send(value.as_bytes()); }
		true
})?;
runner.put(&hash, Value::new("hello"), |_| {}, false);
let bytes = received.recv_timeout(std::time::Duration::from_secs(5))?;
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
	are independent `ValueSnapshot`s containing payload, ID, type, sequence,
	priority, user/push types, signer public-key bytes, and recipient. Listener
	`ValueEvent`s also preserve the expiration flag.
- Streams buffer at most 64 items by default; `with_capacity` changes this
	limit. A full buffer stops delivery and yields `WouldBlock` after buffered
	items, then ends. Restart the operation to obtain a fresh snapshot. Native
	failures, invalid metadata, and runner termination also yield errors rather
	than successful EOF. Duplicate native deliveries are not suppressed.
- Dropping a listener immediately queues native cancellation and releases its
	token. Listeners retain the runner until dropped. Dropping get/query streams
	stops delivery at the next native callback, or when the runner is joined.
	Dropping a completion future abandons its result but does not cancel the
	native operation or undo a permanent put.
- Runner adapters and listeners remain thread-bound. Use `block_on`, a local
	executor, or Tokio `LocalSet`, not `tokio::spawn`. Snapshots and query rows can
	be sent to other threads. Non-threaded runners still require independent
	`loop_once()` calls while waiting. `join()` remains blocking; await graceful
	`shutdown()` first when persistence is required.

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