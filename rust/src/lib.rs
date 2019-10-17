extern crate libc;

mod ffi;
use ffi::*;
pub use ffi::{ DhtRunner, InfoHash, Value};

use std::fmt;
use std::ffi::CStr;
use std::ffi::CString;
use std::str;
use std::slice;
use libc::c_void;

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

    pub fn bootstrap(&mut self, host: &CString, service: &CString) {
        unsafe {
            dht_runner_bootstrap(&mut *self, host.as_ptr(), service.as_ptr())
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

    pub fn put(&mut self, h: &InfoHash, v: *const Value,
                done_cb: extern fn(bool, *mut c_void),
                cb_user_data: *mut c_void) {

        unsafe {
            dht_runner_put(&mut *self, h, v, done_cb, cb_user_data)
        }
    }

    pub fn listen(&mut self, h: &InfoHash,
                cb: extern fn(*mut Value, bool, *mut c_void),
                cb_user_data: *mut c_void) -> *const OpToken {
        unsafe {
            dht_runner_listen(&mut *self, h, cb, cb_user_data)
        }
    }

    pub fn cancel_listen(&mut self, h: &InfoHash, token: *const OpToken) {

        unsafe {
            dht_runner_cancel_listen(&mut *self, h, token)
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


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn print_random_infohash() {
        unsafe {
            let h = InfoHash {};
            println!("{:?}", dht_infohash_print(&h));
        }
        //println!("{:?}", InfoHash::print(&*InfoHash::new()));
    }
}
