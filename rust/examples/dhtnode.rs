/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

extern crate opendht;
use std::{ thread, time };

use opendht::{ InfoHash, DhtRunner, DhtRunnerConfig, Value };
// use opendht::crypto::*;

fn main() {
    println!("{}", InfoHash::random());
    println!("{}", InfoHash::new());
    println!("{}", InfoHash::new().is_zero());
    println!("{}", InfoHash::get("alice"));
    println!("{}", InfoHash::get("alice").is_zero());


    let mut dht = DhtRunner::new();
    let /*mut*/ config = DhtRunnerConfig::new();
    //// If you want to inject a certificate, uncomment the following lines and previous mut.
    //// Note: you can generate a certificate with
    //// openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout example.key -out example.crt -subj /CN=example.com
    //let cert = DhtCertificate::import("example.crt").ok().expect("Invalid cert file");
    //let pk = PrivateKey::import("example.key", "");
    //config.set_identity(cert, pk);
    dht.run_config(1412, config);
    dht.bootstrap("bootstrap.jami.net", 4222);
    println!("Current node id: {}", dht.node_id());

    let /* mut */ data = 42;
    let mut get_cb = |v: Box<Value>| {
        //data += 1;
        println!("GET: VALUE CB - data: {} - v: {}", data, v);
        true
    };
    let mut done_cb = |ok: bool| {
        println!("GET: DONE CB - data: {} - ok: {}", data, ok);
    };

    dht.get(&InfoHash::get("alice"), &mut get_cb, &mut done_cb);

    let mut put_done_cb = |ok: bool| {
        println!("PUT: DONE CB - data: {} - ok: {}", data, ok);
    };
    dht.put(&InfoHash::get("bob"), Value::new("hi!"), &mut put_done_cb, false);


    println!("Start listening /foo");
    let mut value_cb = |v, expired| {
        println!("LISTEN: DONE CB - data: {} - v: {} - expired: {}", data, v, expired);
        true
    };
    let token = dht.listen(&InfoHash::get("foo"), &mut value_cb);
    let one_min = time::Duration::from_secs(10);
    thread::sleep(one_min);
    dht.cancel_listen(&InfoHash::get("foo"), token);
    println!("Public ips: {:#?}", dht.public_addresses());
}