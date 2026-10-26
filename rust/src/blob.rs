// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

use crate::ffi::{self, DataView};

native_handle!(Blob, dht_blob_delete);

impl Blob {
    pub fn data(&self) -> DataView {
        unsafe { ffi::dht_blob_get_data(self.as_ptr()) }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let data = self.data();
        if data.size == 0 {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(data.data, data.size).to_vec() }
    }
}
