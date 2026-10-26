// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

use crate::ffi::*;

pub use crate::ffi::Blob;

impl Blob {
    pub fn data(&self) -> DataView {
        unsafe { dht_blob_get_data(self) }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let data = self.data();
        if data.size == 0 {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(data.data, data.size).to_vec() }
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        unsafe { dht_blob_delete(&mut *self) }
    }
}
