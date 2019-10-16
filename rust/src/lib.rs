extern crate libc;
use std::ffi::CString;
use libc::c_char;

#[repr(C)]
struct InfoHash {}

#[link(name = "opendht-c")]
extern {
    fn dht_infohash_print(h: *const InfoHash) -> *mut c_char;
    fn dht_infohash_random(h: *mut InfoHash) -> ();
}

impl InfoHash {
    pub fn new() -> Box<InfoHash> {
        let mut h = Box::new(InfoHash {});
        unsafe {
            dht_infohash_random(&mut *h);
        }
        h
    }
    pub fn print(&self) -> CString{
        unsafe {
            CString::from_raw(dht_infohash_print(&*self))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn print_random_infohash() {
        println!("{:?}", InfoHash::print(&*InfoHash::new()));
    }
}
