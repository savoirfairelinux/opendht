# OpenDHT: a Distributed Hash Table

OpenDHT is a Kademlia-based distributed hash table for storing and retrieving
small values over a peer-to-peer network without a central server. Common uses
include peer discovery, service announcements, and decentralized applications.

The `opendht` crate provides Rust bindings to [OpenDHT](https://opendht.net), with
callback-based and runtime-independent async APIs. Capabilities include signed
and encrypted values, filtered reads, metadata queries, and typed MessagePack
records through Serde.

## Get Started

Add the crate to your dependencies:

```toml
[dependencies]
opendht = "0.6"
```

The native OpenDHT library with C bindings must be installed separately; it is
not bundled with the crate. See the
[build guide](https://github.com/savoirfairelinux/opendht/blob/master/rust/BUILD.md)
for native installation, library paths, and source builds.

`DhtRunner` manages a node, `InfoHash` identifies a DHT key, and `Value` contains
the payload and metadata stored under that key. `put` publishes values, `get`
retrieves them, and `listen` subscribes to value updates and expiration events.

This example starts a node on an OS-assigned port, bootstraps into the public
network, and listens for a value it publishes.

```rust
use opendht::{DhtRunner, InfoHash, Value};
use std::{sync::mpsc, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut runner = DhtRunner::new();
    runner.run(0)?;
    runner.bootstrap("bootstrap.jami.net", 4222)?;

    let key = InfoHash::get("my-app/hello");
    let (sender, receiver) = mpsc::channel();
    let listener = runner.listen(&key, move |value, expired| {
        if !expired {
            let _ = sender.send(value);
        }
        true
    })?;

    runner.put(&key, Value::new("Hello from Rust!"), |_| {}, false);
    let value = receiver.recv_timeout(Duration::from_secs(5))?;
    println!("{}", String::from_utf8_lossy(value.as_slice()));

    runner.cancel_listen(&key, listener);
    runner.join()?;
    Ok(())
}
```

A bootstrap server supplies initial peers. Applications can use public
bootstrap servers or known peers on a private network. Values expire, and their
availability depends on participating nodes; the DHT does not provide durable
storage guarantees.

## Optional Features

| Feature | Capabilities |
|---------|--------------|
| Default | Callback-based `DhtRunner`, binary values, keys, certificates, and signed/encrypted operations. |
| `async` | `aio::AsyncDhtRunner` with publication futures, bounded read/update streams, and automatic listener cancellation on drop. |
| `serde` | Serde-backed MessagePack records with `put_typed`, `get_typed`, and `listen_typed`. Enables `async`. |

Enable `async` in the dependency configuration:

```toml
[dependencies]
opendht = { version = "0.6", features = ["async"] }
futures = "0.3"
```

Create the adapter with `AsyncDhtRunner::new(runner)` after starting a
`DhtRunner`. The adapter is runtime-independent and thread-bound; use a local
executor or Tokio's `LocalSet`. Dropping a listener stream cancels its
subscription. Streams use bounded buffers and report `WouldBlock` on overflow.

This example waits for a bootstrap peer, publishes a value with `.await`, and
reads matching values as a stream:

```rust,no_run
use futures::{executor::block_on, TryStreamExt};
use opendht::{aio::AsyncDhtRunner, DhtRunner, InfoHash, Value};
use std::{io, net::ToSocketAddrs};

fn main() -> io::Result<()> {
    let mut runner = DhtRunner::new();
    runner.run(0)?;
    let runner = AsyncDhtRunner::new(runner);
    let peers: Vec<_> = ("bootstrap.jami.net", 4222).to_socket_addrs()?.collect();

    block_on(async {
        runner.bootstrap(&peers).await?;
        let key = InfoHash::get("my-app/hello-async");
        runner.put(&key, Value::new("Hello from async Rust!"), false).await?;

        let mut values = runner.get(&key);
        while let Some(value) = values.try_next().await? {
            println!("{}", String::from_utf8_lossy(value.as_slice()));
        }

        runner.shutdown().await?;
        runner.join()
    })
}
```

### Typed Records

The `serde` feature adds typed async operations and also enables `async`.
`put_typed` serializes records implementing `Serialize`; `get_typed` and
`listen_typed` decode records implementing `DeserializeOwned`. Typed reads retain
the decoded record alongside its original payload and native metadata.

Structs are serialized as compact MessagePack arrays. Field order is part of
the wire format and must remain compatible across schema changes. `serde_bytes`
encodes binary fields using MessagePack's binary representation.

## Working With Values

GET and LISTEN callbacks and async streams deliver owned `Box<Value>` instances.
Received values implement `Send` but not `Sync`; they can be retained after the
runner stops, moved to another thread, modified, and republished. `as_slice()`
borrows the payload without copying; `as_bytes()` allocates a separate `Vec<u8>`.

Values expose metadata including IDs, types, sequence numbers, and owner keys.
Filters select values by metadata, and queries return selected metadata fields.

`DhtRunner::listen` returns a token that must be passed to `cancel_listen` to
unsubscribe. Dropping the token does not cancel the registration; dropping an
async listener stream does.

`join()` stops the runner and waits for its threads to exit. It must not be
called from a callback. For graceful shutdown and configured state persistence,
wait for `shutdown` to complete before calling `join()`.

## Learn More

- [API reference](https://docs.rs/opendht)
- [Callback example](https://github.com/savoirfairelinux/opendht/blob/master/rust/examples/dhtnode.rs)
- [Async and typed two-node example](https://github.com/savoirfairelinux/opendht/blob/master/rust/examples/dhtnode_async.rs)
- [Build and test guide](https://github.com/savoirfairelinux/opendht/blob/master/rust/BUILD.md)
- [OpenDHT project and issue tracker](https://github.com/savoirfairelinux/opendht)