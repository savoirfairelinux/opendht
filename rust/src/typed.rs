//! MessagePack-encoded typed operations, enabled by the `serde` feature.
//!
//! This feature enables `async` and adds methods to [`AsyncDhtRunner`]. Values
//! use compact MessagePack payloads, with no binding-specific envelope or
//! implicit schema version. Structs are encoded as arrays in field order.
//! Applications can include a version field in their records and use
//! `serde_bytes` for binary fields rather than arrays of integers.
//!
//! ```no_run
//! use futures::TryStreamExt;
//! use opendht::{aio::AsyncDhtRunner, InfoHash};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct Service {
//!     version: u32,
//!     name: String,
//!     port: u16,
//!     #[serde(with = "serde_bytes")]
//!     payload: Vec<u8>,
//! }
//!
//! async fn exchange(
//!     runner: &AsyncDhtRunner,
//!     key: &InfoHash,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let mut updates = runner.listen_typed::<Service>(key)?;
//!     let record = Service {
//!         version: 1, name: "chat".into(), port: 4222, payload: vec![0, 0x80, 0xff],
//!     };
//!     runner.put_typed(key, &record, false).await?;
//!     if let Some(event) = updates.try_next().await? {
//!         println!("{}: {:?}", event.value.raw.id(), event.value.data);
//!     }
//!     drop(updates);
//!     let records: Vec<_> = runner.get_typed::<Service>(key).try_collect().await?;
//!     Ok(())
//! }
//! ```

use crate::aio::{AsyncDhtRunner, ValueEvent};
use crate::{InfoHash, Value};
use futures_core::Stream;
use serde::{de::DeserializeOwned, Serialize};
use std::error::Error;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A decoded record together with its original payload and native metadata.
pub struct TypedValue<T> {
    pub data: T,
    pub raw: Box<Value>,
}

impl<T: fmt::Debug> fmt::Debug for TypedValue<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedValue")
            .field("data", &self.data)
            .field("id", &self.raw.id())
            .field("seq", &self.raw.seq())
            .finish_non_exhaustive()
    }
}

/// A decoded listener update, including whether the record expired.
#[derive(Debug)]
pub struct TypedEvent<T> {
    pub value: TypedValue<T>,
    pub expired: bool,
}

/// Typed operations distinguish native failures from payload format errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum TypedError {
    Operation(io::Error),
    Serialize(rmp_serde::encode::Error),
    Deserialize {
        id: u64,
        source: rmp_serde::decode::Error,
    },
}

impl fmt::Display for TypedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(error) => write!(formatter, "DHT operation failed: {error}"),
            Self::Serialize(error) => write!(formatter, "could not serialize typed value: {error}"),
            Self::Deserialize { id, source } => {
                write!(formatter, "could not deserialize DHT value {id}: {source}")
            }
        }
    }
}

impl Error for TypedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Operation(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::Deserialize { source, .. } => Some(source),
        }
    }
}

impl<T: DeserializeOwned> TryFrom<Box<Value>> for TypedValue<T> {
    type Error = TypedError;

    fn try_from(raw: Box<Value>) -> Result<Self, Self::Error> {
        let data =
            rmp_serde::from_slice(raw.as_slice()).map_err(|source| TypedError::Deserialize {
                id: raw.id(),
                source,
            })?;
        Ok(Self { data, raw })
    }
}

impl<T: DeserializeOwned> TryFrom<ValueEvent> for TypedEvent<T> {
    type Error = TypedError;

    fn try_from(event: ValueEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            value: event.value.try_into()?,
            expired: event.expired,
        })
    }
}

struct DecodeStream<Source: Stream, Output> {
    source: Source,
    decode: fn(Source::Item) -> Result<Output, TypedError>,
}

impl<Source: Stream + Unpin, Output> Stream for DecodeStream<Source, Output> {
    type Item = Result<Output, TypedError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        Pin::new(&mut stream.source)
            .poll_next(context)
            .map(|item| item.map(stream.decode))
    }
}

fn decode<Input, Output: TryFrom<Input, Error = TypedError>>(
    input: io::Result<Input>,
) -> Result<Output, TypedError> {
    input.map_err(TypedError::Operation)?.try_into()
}

impl AsyncDhtRunner {
    /// Serialize a record as MessagePack and publish it when this future is polled.
    ///
    /// Unlike untyped `put`, this operation is lazy. Serialization failure does
    /// not start a native put. Dropping it after publication starts does not
    /// undo the put. Use the untyped API to customize value IDs and metadata.
    pub async fn put_typed<T: Serialize + ?Sized>(
        &self,
        hash: &InfoHash,
        value: &T,
        permanent: bool,
    ) -> Result<(), TypedError> {
        let bytes = rmp_serde::to_vec(value).map_err(TypedError::Serialize)?;
        self.put(hash, Value::from_bytes(&bytes), permanent)
            .await
            .map_err(TypedError::Operation)
    }

    /// Start a get and decode each MessagePack payload on the consumer's thread.
    ///
    /// A malformed or incompatible record yields a per-value error; polling can
    /// continue to subsequent records. Native errors remain terminal. The stream
    /// does not borrow the runner or hash, and records need not be `Unpin`.
    pub fn get_typed<T: DeserializeOwned>(
        &self,
        hash: &InfoHash,
    ) -> impl Stream<Item = Result<TypedValue<T>, TypedError>> + Unpin + use<T> {
        DecodeStream {
            source: self.get(hash),
            decode: decode::<_, TypedValue<T>>,
        }
    }

    /// Listen for MessagePack records, preserving metadata and expiration events.
    ///
    /// Decode errors do not cancel the registration. Dropping this stream does
    /// cancel it, including when a short-circuiting consumer stops on an error.
    pub fn listen_typed<T: DeserializeOwned>(
        &self,
        hash: &InfoHash,
    ) -> io::Result<impl Stream<Item = Result<TypedEvent<T>, TypedError>> + Unpin + use<T>> {
        Ok(DecodeStream {
            source: self.listen(hash)?,
            decode: decode::<_, TypedEvent<T>>,
        })
    }
}
