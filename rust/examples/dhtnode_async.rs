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
use std::{thread, time};

use opendht::{ InfoHash, DhtRunner, DhtRunnerConfig, Value };
// use opendht::crypto::*;
use futures::prelude::*;

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
    use std::net::ToSocketAddrs;
    let addrs = "bootstrap.jami.net:4222".to_socket_addrs().unwrap();

    futures::executor::block_on(async {
        let r = dht.bootstrap_async(addrs).await;

        println!("Current node id: {}", dht.node_id());

        let mut stream = dht.get_async(&InfoHash::get("bob"));

        while let Ok(Some(value)) = stream.try_next().await {
            println!("GOT: VALUE - value: {}", value);
        }

        dht.put_async(&InfoHash::get("bob"), Value::new("hi!"), false).await;

        println!("Start listening /foo (sleep 10s)");
        let mut stream = dht.listen_async(&InfoHash::get("foo"));
        let one_min = time::Duration::from_secs(10);
        thread::sleep(one_min);
        while let Some((v, expired)) = stream.next().await {
            println!("LISTEN: DONE CB - v: {} - expired: {}", v, expired);
        }
    });

    println!("Public ips: {:#?}", dht.public_addresses());
}