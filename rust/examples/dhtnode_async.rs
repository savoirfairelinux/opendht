use futures::{executor::block_on, StreamExt, TryStreamExt};
use opendht::{aio::AsyncDhtRunner, DhtRunner, DhtRunnerConfig, InfoHash, Value};
use std::error::Error;
use std::io;
use std::net::SocketAddr;

fn main() -> Result<(), Box<dyn Error>> {
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
            event.value.id(),
            String::from_utf8_lossy(event.value.as_slice()),
            event.expired,
        );
        drop(updates);

        let values: Vec<_> = destination.get(&hash).try_collect().await?;
        println!("GET: {} values", values.len());

        #[cfg(feature = "serde")]
        {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct Service {
                version: u32,
                name: String,
                port: u16,
                #[serde(with = "serde_bytes")]
                payload: Vec<u8>,
            }

            let hash = InfoHash::get("typed async example");
            let mut updates = destination.listen_typed::<Service>(&hash)?;
            let record = Service {
                version: 1,
                name: "chat".into(),
                port: 4222,
                payload: vec![0, 0x80, 0xff],
            };
            source.put_typed(&hash, &record, false).await?;
            let event = updates.next().await.ok_or_else(|| {
                io::Error::other("typed listener ended before receiving a value")
            })??;
            println!(
                "TYPED LISTEN {}: {:?}",
                event.value.raw.id(),
                event.value.data
            );
            drop(updates);
            let values: Vec<_> = destination
                .get_typed::<Service>(&hash)
                .try_collect()
                .await?;
            println!("TYPED GET: {} records", values.len());
        }

        source.shutdown().await?;
        destination.shutdown().await?;
        source.join()?;
        destination.join()?;
        Ok(())
    })
}
