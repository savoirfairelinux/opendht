extern crate opendht;
use std::ffi::CString;
use std::{thread, time};
use libc::c_void;

use opendht::*;

extern fn get_cb(v: *mut Value, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _handler: &mut Handler = unsafe { &mut *(ptr as *mut Handler) };
    unsafe {
        println!("Got data: {}", *v);
    }
}

extern fn done_cb(ok: bool, ptr: *mut c_void) {
    let _handler: &mut Handler = unsafe { &mut *(ptr as *mut Handler) };
    println!("In done - {}", ok);
}

struct Handler {
    _data: u8,
}


fn main() {
    println!("{}", InfoHash::random());
    println!("{}", InfoHash::new());
    println!("{}", InfoHash::get("alice"));

    let mut dht = DhtRunner::new();
    dht.run(1412);
    // TODO take slice in boostrap
    dht.bootstrap(
        &CString::new("bootstrap.jami.net").unwrap(),
        &CString::new("4222").unwrap()
    );
    let ten_secs = time::Duration::from_secs(10);
    let mut handler = Handler {
        _data: 8,
    };
    loop {
        println!("Get /alice");
        let ptr = &mut handler as *mut _ as *mut c_void;
        dht.get(&InfoHash::get("alice"), get_cb, done_cb, ptr);
        let v = Value::new("hi!");
        dht.put(&InfoHash::get("bob"), Box::into_raw(v), done_cb, ptr);
        thread::sleep(ten_secs);
    }
}