# OpenDHT: a kademlia Distributed Hash Table

Store, discover, and share small pieces of data across a peer-to-peer network,
without a central server. OpenDHT is useful for peer discovery, service
announcements, and decentralized applications.

The `opendht` crate brings [OpenDHT](https://opendht.net) to Rust, with callbacks,
optional async streams, and typed records through Serde. It also supports signed
and encrypted values for applications that need authentication or privacy.

## Get Started

Add the crate to your dependencies:

```toml
[dependencies]
opendht = "0.6"
```

You also need the native OpenDHT library with C bindings installed on your system;
the crate does not bundle it. See the
[build guide](https://github.com/savoirfairelinux/opendht/blob/master/rust/BUILD.md)
for native installation, library paths, and source builds.

Three types get you started: `DhtRunner` runs a node, `InfoHash` identifies a key,
and `Value` holds the data stored under that key. You can publish with `put`,
retrieve with `get`, or watch for changes with `listen`.

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

The bootstrap server introduces your node to other peers. You can replace it
with a known peer on your own network.
A DHT is not a durable database: values expire, and availability depends on the
participating peers.

## Optional Features

| Feature | What you get |
|---------|--------------|
| Default | Callback-based `DhtRunner`, binary values, keys, certificates, and signed/encrypted operations. |
| `async` | `aio::AsyncDhtRunner` with futures for publication and streams for reads and updates. |
| `serde` | Typed MessagePack records with `put_typed`, `get_typed`, and `listen_typed`. Includes `async`. |

For async applications, enable the feature in your dependency:

```toml
[dependencies]
opendht = { version = "0.6", features = ["async"] }
futures = "0.3"
```

Start a `DhtRunner`, then wrap it with `AsyncDhtRunner::new(runner)`. The adapter
does not require a particular runtime. Runners stay on the thread that owns them,
so use a local executor or Tokio's `LocalSet`, rather than `tokio::spawn`.
Dropping an async listener cancels its subscription. Streams use bounded buffers
and report an error if the consumer cannot keep up.

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

Prefer working with Rust structs? Enable `serde` instead of `async`, and derive
`Serialize` and `Deserialize` on your records. Typed reads provide both the
decoded record and its original value metadata. Records use compact MessagePack:
struct field order is part of the wire format, so plan for schema changes.
Use `serde_bytes` for fields that should be encoded as binary buffers.

## Working With Values

Received values are yours to keep, send to another thread, edit, or publish
again. Use `as_slice()` to borrow the payload or `as_bytes()` when you need a
separate byte vector. Values also carry metadata such as IDs, types, sequence
numbers, and owner keys. Filtered reads and queries help select the values your
application needs.

Callbacks use owned `move` closures; channels are a convenient way to deliver
results to the rest of your application. With the callback API, explicitly call
`cancel_listen` when finished: dropping its token alone does not unsubscribe.
Call `join()` outside callbacks to stop the runner and wait for pending work.
For graceful shutdown and persistence, wait for `shutdown` to complete before
calling `join()`.

## Learn More

- [API reference](https://docs.rs/opendht)
- [Callback example](https://github.com/savoirfairelinux/opendht/blob/master/rust/examples/dhtnode.rs)
- [Async and typed two-node example](https://github.com/savoirfairelinux/opendht/blob/master/rust/examples/dhtnode_async.rs)
- [Build and test guide](https://github.com/savoirfairelinux/opendht/blob/master/rust/BUILD.md)
- [OpenDHT project and issue tracker](https://github.com/savoirfairelinux/opendht)