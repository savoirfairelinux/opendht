extern crate libc;

mod ffi;
use ffi::*;
pub use ffi::{ DhtRunner, InfoHash, Value };

use std::fmt;
use std::ffi::CStr;
use std::ffi::CString;
use std::str;
use std::slice;
use libc::c_void;

// TODO separate into files

impl InfoHash {
    pub fn new() -> InfoHash {
        InfoHash {
            d: [0; 20]
        }
    }

    pub fn random() -> InfoHash {
        let mut h = InfoHash::new();
        unsafe {
            dht_infohash_random(&mut h);
        }
        h
    }

    pub fn get(data: &str) -> InfoHash {
        let mut h = InfoHash::new();
        unsafe {
            let c_str = CString::new(data).unwrap();
            dht_infohash_get(&mut h, c_str.as_ptr() as *mut u8, data.len());
        }
        h
    }

    pub fn is_zero(&self) -> bool {
        unsafe {
            dht_infohash_is_zero(self)
        }
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let self_str = CStr::from_ptr(
                    dht_infohash_print(self)
                ).to_str().unwrap_or("");
            write!(f, "{}", self_str)
        }
    }
}

impl Blob {
    pub fn data(&self) -> DataView {
        unsafe {
            dht_blob_get_data(self)
        }
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        unsafe {
            dht_blob_delete(&mut *self)
        }
    }
}

impl fmt::Display for PkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let self_str = CStr::from_ptr(
                    dht_pkid_print(self)
                ).to_str().unwrap_or("");
            write!(f, "{}", self_str)
        }
    }
}


impl DhtRunner {
    pub fn new() -> Box<DhtRunner> {
        unsafe {
            Box::from_raw(dht_runner_new())
        }
    }

    pub fn run(&mut self, port: u16) {
        unsafe {
            dht_runner_run(&mut *self, port)
        }
    }

    pub fn bootstrap(&mut self, host: &str, service: u16) {
        unsafe {
            dht_runner_bootstrap(&mut *self,
                CString::new(host).unwrap().as_ptr(),
                CString::new(service.to_string()).unwrap().as_ptr())
        }
    }

    pub fn get(&mut self, h: &InfoHash,
               get_cb: extern fn(*mut Value, *mut c_void),
               done_cb: extern fn(bool, *mut c_void),
               cb_user_data: *mut c_void) {

        unsafe {
            dht_runner_get(&mut *self, h, get_cb, done_cb, cb_user_data)
        }
    }

    pub fn put(&mut self, h: &InfoHash, v: Box<Value>,
               done_cb: extern fn(bool, *mut c_void),
               cb_user_data: *mut c_void) {

        unsafe {
            dht_runner_put(&mut *self, h, &*v, done_cb, cb_user_data)
        }
    }

    pub fn listen(&mut self, h: &InfoHash,
                  cb: extern fn(*mut Value, bool, *mut c_void),
                  cb_user_data: *mut c_void) -> Box<OpToken> {
        unsafe {
            Box::from_raw(dht_runner_listen(&mut *self, h, cb, cb_user_data))
        }
    }

    pub fn cancel_listen(&mut self, h: &InfoHash, token: Box<OpToken>) {

        unsafe {
            dht_runner_cancel_listen(&mut *self, h, &*token)
        }
    }

    pub fn shutdown(&mut self,
                    done_cb: extern fn(bool, *mut c_void),
                    cb_user_data: *mut c_void)
    {
        unsafe {
            dht_runner_shutdown(&mut *self, done_cb, cb_user_data)
        }
    }
}

impl Drop for DhtRunner {
    fn drop(&mut self) {
        unsafe {
            dht_runner_delete(&mut *self)
        }
    }
}

impl Value {
    pub fn new(data: &str) -> Box<Value> {
        unsafe {
            Box::from_raw(dht_value_new(data.as_bytes().as_ptr(),
                data.as_bytes().len()))
        }
    }

    fn dataview(&self) -> DataView {
        unsafe {
            dht_value_get_data(self)
        }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        unsafe {
            dht_value_unref(&mut *self)
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let dataview = self.dataview();
            let slice = slice::from_raw_parts(dataview.data, dataview.size);
            write!(f, "{}", str::from_utf8(slice).unwrap_or(""))
        }
    }
}

impl Drop for OpToken {
    fn drop(&mut self) {
        unsafe {
            dht_op_token_delete(&mut *self)
        }
    }
}

impl PublicKey {
    pub fn new() -> Box<PublicKey> {
        unsafe {
            Box::from_raw(dht_publickey_new())
        }
    }

    pub fn unpack(&mut self, data: Vec<u8>) -> i32 {
        unsafe {
            dht_publickey_unpack(&mut *self, data.as_ptr(), data.len())
        }
    }

    // TODO slice instead of CString
    pub fn pack(&mut self, data: &CString) -> i32 {
        unsafe {
            dht_publickey_pack(&mut *self,
                data.as_ptr(),
                data.as_bytes().len())
        }
    }

    pub fn id(&self) -> InfoHash {
        unsafe {
            dht_publickey_get_id(self)
        }
    }

    pub fn long_id(&self) -> PkId {
        unsafe {
            dht_publickey_get_long_id(self)
        }
    }

    pub fn check_signature(&self, data: &CString, signature: &CString) -> bool {
        unsafe {
            dht_publickey_check_signature(self,
                data.as_ptr(), data.as_bytes().len(),
                signature.as_ptr(), signature.as_bytes().len())
        }
    }

    pub fn encrypt(&self, data: &CString) -> Box<Blob> {
        unsafe {
            Box::from_raw(dht_publickey_encrypt(self,
                data.as_ptr(), data.as_bytes().len()))
        }
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            dht_publickey_delete(&mut *self)
        }
    }
}

impl PrivateKey {
    pub fn new(key_length_bits: u32) -> Box<PrivateKey> {
        unsafe {
            Box::from_raw(dht_privatekey_generate(key_length_bits))
        }
    }

    pub fn import(data: &str, password: &CString) -> Box<PrivateKey> {
        unsafe {
            Box::from_raw(dht_privatekey_import(data.as_ptr(),
                data.as_bytes().len(), password.as_ptr()))
        }
    }

    pub fn public_key(&self) -> Box<PublicKey> {
        unsafe {
            Box::from_raw(dht_privatekey_get_publickey(self))
        }
    }

}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            dht_privatekey_delete(&mut *self)
        }
    }
}