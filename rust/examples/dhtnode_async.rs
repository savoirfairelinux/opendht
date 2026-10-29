use futures::{executor::block_on, StreamExt, TryStreamExt};
use opendht::{aio::AsyncDhtRunner, DhtRunner, DhtRunnerConfig, InfoHash, Value};
use std::io;
use std::net::SocketAddr;

fn main() -> io::Result<()> {
    let mut source = DhtRunner::new();
    let mut destination = DhtRunner::new();
    source.run_bind("127.0.0.1", "::1", 0, DhtRunnerConfig::new())?;
    destination.run_bind("127.0.0.1", "::1", 0, DhtRunnerConfig::new())?;
    let address = SocketAddr::from(([127, 0, 0, 1], destination.bound_port(libc::AF_INET as _)));
    let source = AsyncDhtRunner::new(source);
    let destination = AsyncDhtRunner::new(destination);

    block_on(async {
        source.bootstrap(&[address]).await?;
        let hash = InfoHash::get("async example");
        let mut updates = destination.listen(&hash)?;
        source
            .put(&hash, Value::with_id(b"hello from Rust async", 42), false)
            .await?;
        let event = updates
            .next()
            .await
            .ok_or_else(|| io::Error::other("listener ended before receiving a value"))??;
        println!(
            "LISTEN {}: {} (expired: {})",
            event.value.id,
            String::from_utf8_lossy(&event.value.data),
            event.expired,
        );
        drop(updates);

        let values: Vec<_> = destination.get(&hash).try_collect().await?;
        println!("GET: {} values", values.len());
        source.shutdown().await?;
        destination.shutdown().await?;
        source.join()?;
        destination.join()
    })
}
