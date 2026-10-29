// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#![allow(dead_code)]

use crate::crypto::PublicKey;
use crate::{ffi, InfoHash};
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::slice;
use std::str;

pub use crate::ffi::DataView;

native_handle!(Value, dht_value_unref);

impl Value {
    pub fn with_id(data: &[u8], id: u64) -> Box<Value> {
        unsafe {
            Self::from_raw(ffi::dht_value_with_id_new(data.as_ptr(), data.len(), id))
                .expect("value allocation failed")
        }
    }

    pub fn new(data: &str) -> Box<Value> {
        Self::from_bytes(data.as_bytes())
    }
    pub fn from_bytes(data: &[u8]) -> Box<Value> {
        unsafe {
            Self::from_raw(ffi::dht_value_new(data.as_ptr(), data.len()))
                .expect("value allocation failed")
        }
    }

    pub fn id(&self) -> u64 {
        unsafe { ffi::dht_value_get_id(self.as_ptr()) }
    }

    fn dataview(&self) -> DataView {
        unsafe { ffi::dht_value_get_data(self.as_ptr()) }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        unsafe {
            let dv = ffi::dht_value_get_data(self.as_ptr());
            if dv.size == 0 {
                return Vec::new();
            }
            let slice = slice::from_raw_parts(dv.data, dv.size);
            slice.to_vec()
        }
    }

    pub fn boxed(&self) -> Box<Value> {
        unsafe { Self::from_raw(ffi::dht_value_copy(self.as_ptr())).expect("value copy failed") }
    }

    pub fn recipient(&self) -> InfoHash {
        unsafe { ffi::dht_value_get_recipient(self.as_ptr()) }
    }

    pub fn owner(&self) -> Option<Box<PublicKey>> {
        unsafe { PublicKey::from_raw(ffi::dht_value_get_owner(self.as_ptr())).ok() }
    }

    pub fn user_type(&self) -> Result<String, str::Utf8Error> {
        unsafe {
            Ok(CStr::from_ptr(ffi::dht_value_get_user_type(self.as_ptr()))
                .to_str()?
                .to_owned())
        }
    }

    pub fn set_user_type(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value)?;
        unsafe {
            ffi::dht_value_set_user_type(self.as_ptr(), value.as_ptr());
        }
        Ok(())
    }

    pub fn value_type(&self) -> u16 {
        unsafe { ffi::dht_value_get_type(self.as_ptr()) }
    }
    pub fn set_value_type(&mut self, value: u16) {
        unsafe {
            ffi::dht_value_set_type(self.as_ptr(), value);
        }
    }
    pub fn seq(&self) -> u16 {
        unsafe { ffi::dht_value_get_seq(self.as_ptr()) }
    }
    pub fn set_seq(&mut self, value: u16) {
        unsafe {
            ffi::dht_value_set_seq(self.as_ptr(), value);
        }
    }
    pub fn priority(&self) -> u32 {
        unsafe { ffi::dht_value_get_priority(self.as_ptr()) }
    }
    pub fn set_priority(&mut self, value: u32) {
        unsafe {
            ffi::dht_value_set_priority(self.as_ptr(), value);
        }
    }
    pub fn push_type(&self) -> Result<String, str::Utf8Error> {
        unsafe {
            Ok(CStr::from_ptr(ffi::dht_value_get_push_type(self.as_ptr()))
                .to_str()?
                .to_owned())
        }
    }
    pub fn set_push_type(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value)?;
        unsafe {
            ffi::dht_value_set_push_type(self.as_ptr(), value.as_ptr());
        }
        Ok(())
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let dataview = self.dataview();
            if dataview.size == 0 {
                return Ok(());
            }
            let slice = slice::from_raw_parts(dataview.data, dataview.size);
            write!(f, "{}", str::from_utf8(slice).unwrap_or(""))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_moves_between_threads_without_copying_payload() {
        let mut value = Value::from_bytes(b"native\0payload\xff");
        value.set_user_type("borrowed metadata").unwrap();
        let view = unsafe { ffi::dht_value_get_data(value.as_ptr()) };
        let value = std::thread::spawn(move || {
            value.set_seq(7);
            value
        })
        .join()
        .unwrap();
        assert_eq!(value.as_slice().as_ptr(), view.data);
        assert_eq!(value.as_slice(), b"native\0payload\xff");
        assert_eq!(value.seq(), 7);
        let user_type: &str = value.user_type().unwrap();
        assert_eq!(user_type, "borrowed metadata");
    }

    #[test]
    fn empty_value_payload_is_borrowed_safely() {
        let value = Value::from_bytes(&[]);
        assert!(value.as_slice().is_empty());
        assert_eq!(value.as_slice(), &[]);
    }
}
