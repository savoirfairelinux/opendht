// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#![allow(dead_code)]

use crate::ffi::*;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::slice;
use std::str;

pub use crate::ffi::{DataView, Value};

impl Value {
    pub fn with_id(data: &[u8], id: u64) -> Box<Value> {
        unsafe {
            crate::checked_box(dht_value_with_id_new(data.as_ptr(), data.len(), id))
                .expect("value allocation failed")
        }
    }

    pub fn new(data: &str) -> Box<Value> {
        unsafe { Box::from_raw(dht_value_new(data.as_bytes().as_ptr(), data.len())) }
    }
    pub fn from_bytes(data: &[u8]) -> Box<Value> {
        unsafe { Box::from_raw(dht_value_new(data.as_ptr(), data.len())) }
    }

    pub fn id(&self) -> u64 {
        unsafe { dht_value_get_id(self) }
    }

    fn dataview(&self) -> DataView {
        unsafe { dht_value_get_data(self) }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        unsafe {
            let dv = dht_value_get_data(self);
            if dv.size == 0 {
                return Vec::new();
            }
            let slice = slice::from_raw_parts(dv.data, dv.size);
            slice.to_vec()
        }
    }

    pub fn boxed(&self) -> Box<Value> {
        unsafe { crate::checked_box(dht_value_copy(self)).expect("value copy failed") }
    }

    pub fn recipient(&self) -> InfoHash {
        unsafe { dht_value_get_recipient(self) }
    }

    pub fn owner(&self) -> Option<Box<PublicKey>> {
        unsafe {
            let ptr = dht_value_get_owner(self);
            if ptr.is_null() {
                return None;
            }
            Some(Box::from_raw(ptr))
        }
    }

    pub fn user_type(&self) -> Result<String, str::Utf8Error> {
        unsafe {
            Ok(CStr::from_ptr(dht_value_get_user_type(self))
                .to_str()?
                .to_owned())
        }
    }

    pub fn set_user_type(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value)?;
        unsafe {
            dht_value_set_user_type(self, value.as_ptr());
        }
        Ok(())
    }

    pub fn value_type(&self) -> u16 {
        unsafe { dht_value_get_type(self) }
    }
    pub fn set_value_type(&mut self, value: u16) {
        unsafe {
            dht_value_set_type(self, value);
        }
    }
    pub fn seq(&self) -> u16 {
        unsafe { dht_value_get_seq(self) }
    }
    pub fn set_seq(&mut self, value: u16) {
        unsafe {
            dht_value_set_seq(self, value);
        }
    }
    pub fn priority(&self) -> u32 {
        unsafe { dht_value_get_priority(self) }
    }
    pub fn set_priority(&mut self, value: u32) {
        unsafe {
            dht_value_set_priority(self, value);
        }
    }
    pub fn push_type(&self) -> Result<String, str::Utf8Error> {
        unsafe {
            Ok(CStr::from_ptr(dht_value_get_push_type(self))
                .to_str()?
                .to_owned())
        }
    }
    pub fn set_push_type(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value)?;
        unsafe {
            dht_value_set_push_type(self, value.as_ptr());
        }
        Ok(())
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        unsafe { dht_value_unref(&mut *self) }
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
