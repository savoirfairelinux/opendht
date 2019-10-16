extern crate libc;
use std::fmt;
use std::ffi::CStr;
use std::ffi::CString;
use libc::{c_char, c_void, in_port_t, sockaddr, socklen_t};

const HASH_LEN: usize = 20;

#[repr(C)]
pub struct InfoHash
{
    d: [u8; HASH_LEN],
}

#[repr(C)]
pub struct DhtRunner;

#[repr(C)]
pub struct Value;


// TODO remove Box?
// TODO callbacks
// TODO dhtnode-rust

#[link(name = "opendht-c")]
extern {
    fn dht_infohash_print(h: *const InfoHash) -> *mut c_char;
    fn dht_infohash_random(h: *mut InfoHash);



    fn dht_runner_new() -> *mut DhtRunner;
    fn dht_runner_delete(dht: *mut DhtRunner);
    fn dht_runner_run(dht: *mut DhtRunner, port: in_port_t);
    fn dht_runner_ping(dht: *mut DhtRunner, addr: *mut sockaddr, addr_len: socklen_t);
    fn dht_runner_get(dht: *mut DhtRunner, h: *const InfoHash,
                      get_cb: extern fn(*mut Value, i32, *mut c_void),
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

    pub fn ping(&mut self, addr: &CString, addr_len: u32) {
        unsafe {
            let mut s = sockaddr {
                sa_family: 0 /* TODO AF_UNSPEC */,
                sa_data: [0; 14] /* TODO */,
            };
            dht_runner_ping(&mut *self, &mut s, addr_len)
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
