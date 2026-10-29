// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

extern crate libc;
extern crate os_socketaddr;

macro_rules! native_handle {
    ($name:ident, $delete:ident) => {
        pub struct $name {
            raw: std::ptr::NonNull<crate::ffi::$name>,
        }

        impl $name {
            pub(crate) unsafe fn from_raw(
                raw: *mut crate::ffi::$name,
            ) -> std::io::Result<Box<Self>> {
                let raw = std::ptr::NonNull::new(raw)
                    .ok_or_else(|| std::io::Error::other("native operation failed"))?;
                Ok(Box::new(Self { raw }))
            }

            pub(crate) fn as_ptr(&self) -> *mut crate::ffi::$name {
                self.raw.as_ptr()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { crate::ffi::$delete(self.as_ptr()) }
            }
        }
    };
}

mod blob;
pub mod crypto;
mod dhtrunner;
mod ffi;
mod infohash;
mod pkid;
mod value;

#[cfg(feature = "async")]
pub mod aio;

#[cfg(feature = "serde")]
pub mod typed;

pub use blob::Blob;
pub use dhtrunner::{
    DhtNodeConfig, DhtRunner, DhtRunnerConfig, DhtSecureConfig, NodeStatus, OpToken,
    PushNotification, PushNotificationResult, QueryResult,
};
pub use infohash::InfoHash;
pub use pkid::PkId;
pub use value::{DataView, Value};
