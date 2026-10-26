// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

extern crate libc;
extern crate os_socketaddr;

mod blob;
pub mod crypto;
mod dhtrunner;
mod ffi;
mod infohash;
mod pkid;
mod value;

pub use blob::Blob;
pub use dhtrunner::{
    DhtNodeConfig, DhtRunner, DhtRunnerConfig, DhtSecureConfig, NodeStatus, OpToken,
    PushNotification, PushNotificationResult, QueryResult,
};
pub use infohash::InfoHash;
pub use pkid::PkId;
pub use value::{DataView, Value};

pub(crate) unsafe fn checked_box<T>(raw: *mut T) -> std::io::Result<Box<T>> {
    if raw.is_null() {
        Err(std::io::Error::other("native operation failed"))
    } else {
        Ok(Box::from_raw(raw))
    }
}
