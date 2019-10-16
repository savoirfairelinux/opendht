extern crate opendht;

use opendht::*;

fn main() {
    println!("{}", InfoHash::random());
    println!("{}", InfoHash::new());
//
    //let mut dht = DhtRunner::new();
    //dht.run(1412);
    //let bootstrap_address = CString::new("bootstrap.jami.net").unwrap();
    //dht.ping(&bootstrap_address, bootstrap_address.len());
}