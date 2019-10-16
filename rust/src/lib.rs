extern crate libc;
use std::fmt;
use std::ffi::CStr;
use std::ffi::CString;
use std::ptr;
use std::str;
use std::slice;
use libc::{c_char, c_void, in_port_t, size_t, uint8_t};

const HASH_LEN: usize = 20;

#[repr(C)]
pub struct InfoHash
{
    d: [u8; HASH_LEN],
}

#[repr(C)]
pub struct DhtRunner
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct Value
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct DataView
{
    data: *const uint8_t,
    size: size_t
}


#[link(name = "opendht-c")]
extern {    
    fn dht_infohash_print(h: *const InfoHash) -> *mut c_char;
    fn dht_infohash_random(h: *mut InfoHash);
    fn dht_infohash_get(h: *mut InfoHash, dat: *mut uint8_t, dat_size: size_t);

    fn dht_value_get_data(data: *const Value) -> DataView;

    fn dht_runner_new() -> *mut DhtRunner;
    fn dht_runner_delete(dht: *mut DhtRunner);
    fn dht_runner_run(dht: *mut DhtRunner, port: in_port_t);
    fn dht_runner_bootstrap(dht: *mut DhtRunner, host: *const c_char, service: *const c_char);
    fn dht_runner_get(dht: *mut DhtRunner, h: *const InfoHash,
                      get_cb: extern fn(*mut Value, *mut c_void),
                      done_cb: extern fn(bool, *mut c_void),
                      cb_user_data: *mut c_void);
}

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
}

impl Drop for DhtRunner {
    fn drop(&mut self) {
        unsafe {
            dht_runner_delete(&mut *self)
        }
    }
}

impl Value {
    fn dataview(&self) -> DataView {
        unsafe {
            dht_value_get_data(self)
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
