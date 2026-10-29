use opendht::crypto::{DhtCertificate, DhtIdentity, PrivateKey, PublicKey};
use opendht::{DhtRunner, DhtRunnerConfig, InfoHash, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

#[test]
fn hex_hash_parsing_checks_string_lengths() {
    for length in 0..40 {
        assert!(InfoHash::from_hex(&"a".repeat(length)).is_zero());
    }
    let hash = InfoHash::get("hex parsing regression");
    let encoded = hash.to_string();
    assert!(hash == InfoHash::from_hex(&encoded));
    assert!(hash == InfoHash::from_hex(&encoded.to_uppercase()));
    assert!(InfoHash::from_hex(&"z".repeat(40)).is_zero());
}

#[test]
fn values_can_move_out_of_their_box() {
    let mut value = *Value::with_id(b"moved value", 42);
    value.set_seq(7);
    assert_eq!(value.id(), 42);
    assert_eq!(value.seq(), 7);
    assert_eq!(value.as_bytes(), b"moved value");
    let value = Box::new(value);
    assert_eq!(value.as_bytes(), b"moved value");
}

#[test]
fn native_handles_can_move_out_of_their_boxes() {
    let private = *PrivateKey::new(2048).unwrap();
    let public = *private.public_key();
    let signature = private.sign(b"moved handles").unwrap();
    assert!(public.check_signature(b"moved handles", &signature));
    let encrypted = *public.encrypt(b"moved blob").unwrap();
    assert_eq!(
        private.decrypt(&encrypted.as_bytes()).unwrap().as_bytes(),
        b"moved blob"
    );
    let certificate = *DhtIdentity::new_ec("moved certificate")
        .unwrap()
        .certificate;
    let restored = DhtCertificate::from_bytes(&certificate.serialize().unwrap()).unwrap();
    assert!(certificate.id() == restored.id());

    let mut runner = *DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.threaded = false;
    runner.run_config(0, config).unwrap();
    let hash = InfoHash::get("moved listener token");
    let (sent, received) = mpsc::channel();
    let token = *runner
        .listen(&hash, move |value, expired| {
            if !expired {
                sent.send(value.as_bytes()).unwrap();
            }
            true
        })
        .unwrap();
    runner.put(&hash, Value::new("moved callback value"), |_| {}, false);
    runner.loop_once().unwrap();
    assert_eq!(
        received.recv_timeout(Duration::from_secs(5)).unwrap(),
        b"moved callback value"
    );
    runner.cancel_listen(&hash, Box::new(token));
    let push = runner.push_notification_received(&[]).unwrap();
    runner.loop_once().unwrap();
    let mut push = Box::new(push);
    assert!(push.poll().unwrap().is_some());
    runner.join().unwrap();
    let mut runner = Box::new(runner);
    runner.run(0).unwrap();
    runner.join().unwrap();
}

#[test]
fn value_metadata_and_borrowed_strings() {
    let mut value = Value::with_id(b"binary\0value", 42);
    value.set_user_type("application/octet-stream").unwrap();
    value.set_value_type(17);
    value.set_seq(23);
    value.set_priority(1);
    value.set_push_type("audioCall").unwrap();
    assert_eq!(value.id(), 42);
    assert_eq!(value.as_bytes(), b"binary\0value");
    assert_eq!(value.user_type().unwrap(), "application/octet-stream");
    assert_eq!(value.user_type().unwrap(), "application/octet-stream");
    assert_eq!(value.value_type(), 17);
    assert_eq!(value.seq(), 23);
    assert_eq!(value.priority(), 1);
    assert_eq!(value.push_type().unwrap(), "audioCall");
    let mut copy = value.boxed();
    copy.set_priority(2);
    assert_eq!(value.priority(), 1);
    assert_eq!(copy.priority(), 2);
    assert!(value.owner().is_none());
    assert!(value.recipient().is_zero());
    assert!(Value::new("").as_bytes().is_empty());
}

#[test]
fn crypto_errors_are_results() {
    assert!(PrivateKey::new(1).is_err());
    assert!(PrivateKey::from_bytes(&[1, 2, 3], "").is_err());
    assert!(PublicKey::new("not a key").is_err());
    assert!(DhtCertificate::from_bytes(&[1, 2, 3]).is_err());
}

#[test]
fn binary_crypto_and_password_slices() {
    let private = PrivateKey::new(2048).unwrap();
    let backing = String::from("password-extra");
    let password = &backing[..8];
    let packed = private.serialize(password).unwrap();
    let restored = PrivateKey::from_bytes(&packed, password).unwrap();
    assert!(PrivateKey::from_bytes(&packed, "wrong").is_err());
    assert!(PrivateKey::from_bytes(&packed, "bad\0password").is_err());
    let mut public = PublicKey::new(restored.public_key().pack().unwrap()).unwrap();
    public.unpack(private.public_key().pack().unwrap()).unwrap();
    let data = b"binary\0message\xff";
    let signature = restored.sign(data).unwrap();
    assert!(public.check_signature(data, &signature));
    assert!(!public.check_signature(b"changed", &signature));
    let encrypted = public.encrypt(data).unwrap();
    assert_eq!(
        restored.decrypt(&encrypted.as_bytes()).unwrap().as_bytes(),
        data
    );
    assert!(restored.decrypt(b"invalid").is_err());
    let plain = private.serialize("").unwrap();
    assert!(PrivateKey::from_bytes(&plain, "").is_ok());
    let ec = PrivateKey::new_ec().unwrap();
    assert!(ec
        .public_key()
        .check_signature(data, ec.sign(data).unwrap()));
    assert!(ec.public_key().encrypt(data).is_err());
}

#[test]
fn identity_persistence() {
    let identity = DhtIdentity::new("binding regression").unwrap();
    let certificate = identity.certificate.serialize().unwrap();
    let restored = DhtCertificate::from_bytes(&certificate).unwrap();
    assert!(identity.certificate.id() == restored.id());
    assert!(DhtRunner::new().register_certificate(&restored).is_err());
    assert!(DhtIdentity::generate("child", &identity).is_ok());
    assert!(DhtIdentity::new_ec("elliptic curve").is_ok());
}

struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn join_releases_pending_callbacks_and_allows_restart() {
    let mut runner = DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.threaded = false;
    let status_released = Arc::new(AtomicUsize::new(0));
    let status_counter = DropCounter(status_released.clone());
    config.set_status_callback(move |_, _| {
        let _ = &status_counter;
    });
    config.set_proxy_user_agent("regression").unwrap();
    config.set_proxy_user_agent("replacement").unwrap();
    runner.run_config(0, config).unwrap();
    assert!(runner.is_running());
    assert_ne!(runner.bound_port(libc::AF_INET as _), 0);
    let hash = InfoHash::get("callback ownership");
    let released = Arc::new(AtomicUsize::new(0));
    let counter = DropCounter(released.clone());
    let token = runner
        .listen(&hash, move |_, _| {
            let _ = &counter;
            true
        })
        .unwrap();
    let (sent, received) = mpsc::channel();
    runner.get(
        &hash,
        |_| true,
        move |ok| {
            sent.send(ok).unwrap();
        },
    );
    runner.join().unwrap();
    assert_eq!(status_released.load(Ordering::SeqCst), 1);
    assert_eq!(released.load(Ordering::SeqCst), 1);
    assert!(!received.recv_timeout(Duration::from_secs(5)).unwrap());
    drop(token);
    assert!(!runner.is_running());
    runner.run(0).unwrap();
    runner.join().unwrap();
}

#[test]
fn nonthreaded_loop_executes_owned_callbacks() {
    let mut runner = DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.threaded = false;
    runner.run_config(0, config).unwrap();
    let hash = InfoHash::get("loop progress");
    let seen = Arc::new(AtomicUsize::new(0));
    let callback_seen = seen.clone();
    let token = runner
        .listen(&hash, move |value, expired| {
            if !expired {
                assert_eq!(value.as_bytes(), b"test");
                callback_seen.fetch_add(1, Ordering::SeqCst);
            }
            true
        })
        .unwrap();
    runner.put(&hash, Value::new("test"), |_| {}, false);
    runner.loop_once().unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    runner.cancel_listen(&hash, token);
    runner.join().unwrap();
}

#[test]
fn shutdown_owns_its_callback_and_contains_panics() {
    let mut runner = DhtRunner::new();
    let (sent, received) = mpsc::channel();
    runner.shutdown(move || {
        sent.send(42).unwrap();
    });
    assert_eq!(received.recv_timeout(Duration::from_secs(5)).unwrap(), 42);
    runner.get(
        &InfoHash::new(),
        |_| true,
        |_| panic!("callback panic must not unwind into C"),
    );
}

#[test]
fn startup_errors_reach_rust() {
    let socket4 = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket4.local_addr().unwrap().port();
    let _socket6 = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port)).unwrap();
    assert!(DhtRunner::new().run(port).is_err());
}

#[test]
fn bound_filtered_queries_and_extension_hooks() {
    let mut runner = DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.threaded = false;
    config.set_status_callback(|_, _| {});
    config.set_certificate_store(|_| Vec::new());
    runner.run_bind("127.0.0.1", "::1", 0, config).unwrap();
    runner.register_type(17, "regression", 60, false).unwrap();
    runner.connectivity_changed().unwrap();
    runner.set_push_notification_token("token").unwrap();
    runner.set_push_notification_topic("topic").unwrap();
    runner.set_push_notification_platform("android").unwrap();
    runner.loop_once().unwrap();
    let hash = InfoHash::get("filtered query");
    let seen = Arc::new(AtomicUsize::new(0));
    let callback_seen = seen.clone();
    let token = runner
        .listen_filtered(&hash, "WHERE value_type=17", move |value, expired| {
            if !expired {
                assert_eq!(value.id(), 42);
                callback_seen.fetch_add(1, Ordering::SeqCst);
            }
            true
        })
        .unwrap();
    let mut value = Value::with_id(b"query result", 42);
    value.set_value_type(17);
    value.set_user_type("regression").unwrap();
    runner.put(&hash, value, |_| {}, false);
    runner.loop_once().unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    let (sent, received) = mpsc::channel();
    runner
        .query(
            &hash,
            "SELECT id,user_type WHERE value_type=17",
            move |fields| {
                sent.send((fields.id, fields.user_type)).unwrap();
                true
            },
            |_| {},
        )
        .unwrap();
    runner.loop_once().unwrap();
    let (id, user_type) = received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(id, Some(42));
    assert_eq!(user_type, Some(b"regression".to_vec()));
    let mut push = runner
        .push_notification_received(&[("session", "regression")])
        .unwrap();
    runner.loop_once().unwrap();
    assert!(push.poll().unwrap().is_some());
    runner.cancel_listen(&hash, token);
    runner.join().unwrap();
}

#[test]
fn threaded_sequence_filters_roundtrip() {
    let mut source = DhtRunner::new();
    let mut destination = DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.dht_config.id = Some(DhtIdentity::new_ec("sequence publisher").unwrap());
    source.run_bind("127.0.0.1", "::1", 0, config).unwrap();
    destination
        .run_bind("127.0.0.1", "::1", 0, DhtRunnerConfig::new())
        .unwrap();
    let (sent, received) = mpsc::channel();
    destination.ping(
        ([127, 0, 0, 1], source.bound_port(libc::AF_INET as _)).into(),
        move |ok| {
            sent.send(ok).unwrap();
        },
    );
    assert!(received.recv_timeout(Duration::from_secs(10)).unwrap());

    let hash = InfoHash::get("network sequence filter");
    let (sent, received) = mpsc::channel();
    let token = destination
        .listen_filtered(&hash, "WHERE seq=7", move |value, expired| {
            if !expired {
                let _ = sent.send((value.id(), value.seq(), value.as_bytes()));
            }
            true
        })
        .unwrap();
    let mut value = Value::with_id(b"sequence seven", 42);
    value.set_seq(7);
    let (sent, done) = mpsc::channel();
    source.put_signed(
        &hash,
        value,
        move |ok| {
            let _ = sent.send(ok);
        },
        false,
    );
    assert!(done.recv_timeout(Duration::from_secs(10)).unwrap());
    assert_eq!(
        received.recv_timeout(Duration::from_secs(10)).unwrap(),
        (42, 7, b"sequence seven".to_vec())
    );

    let (sent, received) = mpsc::channel();
    let (completed, done) = mpsc::channel();
    destination
        .get_filtered(
            &hash,
            "WHERE seq=7",
            move |value| {
                let _ = sent.send((value.id(), value.seq()));
                true
            },
            move |ok| {
                let _ = completed.send(ok);
            },
        )
        .unwrap();
    assert_eq!(
        received.recv_timeout(Duration::from_secs(10)).unwrap(),
        (42, 7)
    );
    assert!(done.recv_timeout(Duration::from_secs(10)).unwrap());

    let (sent, received) = mpsc::channel();
    let (completed, done) = mpsc::channel();
    destination
        .query(
            &hash,
            "SELECT id,seq WHERE seq=7",
            move |row| {
                let _ = sent.send((row.id, row.seq));
                true
            },
            move |ok| {
                let _ = completed.send(ok);
            },
        )
        .unwrap();
    assert_eq!(
        received.recv_timeout(Duration::from_secs(10)).unwrap(),
        (Some(42), Some(7))
    );
    assert!(done.recv_timeout(Duration::from_secs(10)).unwrap());

    let (sent, received) = mpsc::channel();
    let (completed, done) = mpsc::channel();
    destination
        .get_filtered(
            &hash,
            "WHERE seq=8",
            move |_| {
                let _ = sent.send(());
                true
            },
            move |ok| {
                let _ = completed.send(ok);
            },
        )
        .unwrap();
    assert!(done.recv_timeout(Duration::from_secs(10)).unwrap());
    assert!(received.try_recv().is_err());
    destination.cancel_listen(&hash, token);
    destination.join().unwrap();
    source.join().unwrap();
}

#[test]
fn threaded_signed_and_encrypted_roundtrips() {
    let mut source = DhtRunner::new();
    let mut destination = DhtRunner::new();
    for (runner, name) in [(&mut source, "source"), (&mut destination, "destination")] {
        let mut config = DhtRunnerConfig::new();
        config.dht_config.id = Some(DhtIdentity::new(name).unwrap());
        runner.run_bind("127.0.0.1", "::1", 0, config).unwrap();
    }
    let recipient = destination.public_key().unwrap().long_id();
    let (sent, received) = mpsc::channel();
    source.ping(
        ([127, 0, 0, 1], destination.bound_port(libc::AF_INET as _)).into(),
        move |ok| {
            sent.send(ok).unwrap();
        },
    );
    assert!(received.recv_timeout(Duration::from_secs(10)).unwrap());
    for encrypted in [false, true] {
        let hash = InfoHash::get(if encrypted {
            "threaded encrypted"
        } else {
            "threaded signed"
        });
        let (sent, received) = mpsc::channel();
        let token = destination
            .listen(&hash, move |value, expired| {
                if !expired {
                    let _ = sent.send(value.as_bytes());
                }
                true
            })
            .unwrap();
        let (sent, done) = mpsc::channel();
        let callback = move |ok| {
            let _ = sent.send(ok);
        };
        if encrypted {
            source.put_encrypted(
                &hash,
                &recipient,
                Value::new("network value"),
                callback,
                false,
            );
        } else {
            source.put_signed(&hash, Value::new("network value"), callback, false);
        }
        assert!(done.recv_timeout(Duration::from_secs(15)).unwrap());
        assert_eq!(
            received.recv_timeout(Duration::from_secs(15)).unwrap(),
            b"network value"
        );
        destination.cancel_listen(&hash, token);
    }
    for runner in [&mut source, &mut destination] {
        let (sent, received) = mpsc::channel();
        runner.shutdown(move || {
            sent.send(()).unwrap();
        });
        received.recv_timeout(Duration::from_secs(15)).unwrap();
        runner.join().unwrap();
    }
}

#[test]
fn callbacks_move_mutable_values_without_copying() {
    let mut runner = DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.threaded = false;
    runner.run_config(0, config).unwrap();
    let hash = InfoHash::get("single Value callback ownership");
    let (listen_sent, listen_received) = mpsc::channel();
    let _token = runner
        .listen(&hash, move |mut value: Box<Value>, expired| {
            if !expired {
                value.set_seq(8);
                let pointer = value.as_slice().as_ptr() as usize;
                let _ = listen_sent.send((pointer, value));
            }
            true
        })
        .unwrap();
    let mut value = Value::with_id(b"immutable\0payload\xff", 42);
    value.set_seq(7);
    value.set_user_type("application/immutable").unwrap();
    value.set_push_type("call").unwrap();
    runner.put(&hash, value, |_| {}, false);
    runner.loop_once().unwrap();

    let (get_sent, get_received) = mpsc::channel();
    runner.get(
        &hash,
        move |value: Box<Value>| {
            let pointer = value.as_slice().as_ptr() as usize;
            let _ = get_sent.send((pointer, value));
            true
        },
        |_| {},
    );
    runner.loop_once().unwrap();
    runner.join().unwrap();

    for (received, expected_seq) in [(listen_received, 8), (get_received, 7)] {
        let (pointer, value) = received.recv_timeout(Duration::from_secs(5)).unwrap();
        let value = std::thread::spawn(move || {
            let mut value = value;
            assert_eq!(value.as_slice().as_ptr() as usize, pointer);
            assert_eq!(value.as_slice(), b"immutable\0payload\xff");
            assert_eq!(value.id(), 42);
            assert_eq!(value.seq(), expected_seq);
            let user_type: &str = value.user_type().unwrap();
            assert_eq!(user_type, "application/immutable");
            let push_type: &str = value.push_type().unwrap();
            assert_eq!(push_type, "call");
            value.set_seq(9);
            assert_eq!(value.as_slice().as_ptr() as usize, pointer);
            value
        })
        .join()
        .unwrap();
        let mut editable = value.boxed();
        editable.set_seq(10);
        assert_eq!(value.seq(), 9);
        assert_eq!(editable.seq(), 10);
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use futures::{executor::block_on, future, Future, StreamExt, TryStreamExt};
    use opendht::aio::AsyncDhtRunner;
    use std::pin::pin;
    use std::time::Instant;

    fn nonthreaded(capacity: usize) -> AsyncDhtRunner {
        let mut runner = DhtRunner::new();
        let mut config = DhtRunnerConfig::new();
        config.threaded = false;
        runner.run_bind("127.0.0.1", "::1", 0, config).unwrap();
        runner.register_type(17, "async test", 1, false).unwrap();
        AsyncDhtRunner::with_capacity(runner, capacity).unwrap()
    }

    fn drive<Output>(runner: &AsyncDhtRunner, operation: impl Future<Output = Output>) -> Output {
        let mut operation = pin!(operation);
        let deadline = Instant::now() + Duration::from_secs(15);
        block_on(future::poll_fn(|context| {
            assert!(Instant::now() < deadline, "async operation timed out");
            runner.loop_once().unwrap();
            context.waker().wake_by_ref();
            operation.as_mut().poll(context)
        }))
    }

    fn wait<Output>(operation: impl Future<Output = Output>) -> Output {
        let (finished, stopped) = mpsc::channel();
        let (expired, deadline) = futures::channel::oneshot::channel();
        let watchdog = std::thread::spawn(move || {
            if stopped.recv_timeout(Duration::from_secs(20)).is_err() {
                let _ = expired.send(());
            }
        });
        let outcome = block_on(future::select(Box::pin(operation), deadline));
        let _ = finished.send(());
        watchdog.join().unwrap();
        match outcome {
            future::Either::Left((output, _)) => output,
            future::Either::Right(_) => panic!("async operation timed out"),
        }
    }

    #[test]
    fn async_listener_preserves_owned_metadata() {
        let runner = nonthreaded(8);
        let hash = InfoHash::get("async metadata");
        let mut listener = runner.listen_filtered(&hash, "WHERE seq=7").unwrap();
        let mut value = Value::with_id(b"async\0binary\xff", 42);
        value.set_value_type(17);
        value.set_seq(7);
        value.set_priority(2);
        value.set_user_type("application/async").unwrap();
        value.set_push_type("call").unwrap();
        let _pending = runner.put(&hash, value, false);
        let event = drive(&runner, listener.next()).unwrap().unwrap();
        assert!(!event.expired);
        assert_eq!(event.value.as_slice(), b"async\0binary\xff");
        assert_eq!(event.value.id(), 42);
        assert_eq!(event.value.value_type(), 17);
        assert_eq!(event.value.seq(), 7);
        assert_eq!(event.value.priority(), 2);
        assert_eq!(event.value.user_type().unwrap(), "application/async");
        assert_eq!(event.value.push_type().unwrap(), "call");
        assert!(event.value.owner().is_none());
        assert!(event.value.recipient().is_zero());
        let event = std::thread::spawn(move || event).join().unwrap();
        assert_eq!(event.value.as_slice(), b"async\0binary\xff");
        drop(listener);
        runner.loop_once().unwrap();
        runner.join().unwrap();
    }

    #[test]
    fn async_listener_delivers_expiration_events() {
        let runner = nonthreaded(8);
        let hash = InfoHash::get("async expiration");
        let mut listener = runner.listen(&hash).unwrap();
        let mut value = Value::with_id(b"expires", 42);
        value.set_value_type(17);
        let _pending = runner.put(&hash, value, false);
        assert!(!drive(&runner, listener.next()).unwrap().unwrap().expired);
        let event = drive(&runner, listener.next()).unwrap().unwrap();
        assert!(event.expired);
        assert_eq!(event.value.id(), 42);
        assert_eq!(event.value.as_slice(), b"expires");
        drop(listener);
        runner.join().unwrap();
    }

    #[test]
    fn async_overflow_is_reported_after_buffered_values() {
        let runner = nonthreaded(1);
        let hash = InfoHash::get("async overflow");
        let mut listener = runner.listen(&hash).unwrap();
        for id in 1..=3 {
            let _pending = runner.put(&hash, Value::with_id(b"queued", id), false);
            runner.loop_once().unwrap();
        }
        assert_eq!(
            drive(&runner, listener.next()).unwrap().unwrap().value.id(),
            1
        );
        let error = drive(&runner, listener.next()).unwrap().err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(drive(&runner, listener.next()).is_none());
        drop(listener);
        runner.join().unwrap();
    }

    #[test]
    fn async_listener_retains_runner_until_drop() {
        let released = Arc::new(AtomicUsize::new(0));
        let counter = DropCounter(released.clone());
        let mut native = DhtRunner::new();
        let mut config = DhtRunnerConfig::new();
        config.threaded = false;
        config.set_status_callback(move |_, _| {
            let _ = &counter;
        });
        native.run_config(0, config).unwrap();
        let runner = AsyncDhtRunner::new(native);
        let listener = runner.listen(&InfoHash::get("retained runner")).unwrap();
        drop(runner);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        drop(listener);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn async_join_completes_pending_operations_and_streams() {
        let runner = nonthreaded(8);
        let hash = InfoHash::get("async shutdown failures");
        let put = runner.put(&hash, Value::new("pending"), false);
        let mut values = runner.get(&hash);
        let mut query = runner.query(&hash, "SELECT id").unwrap();
        let mut listener = runner.listen(&hash).unwrap();
        let ping = runner.ping("127.0.0.1:9".parse().unwrap());
        let bootstrap = runner.bootstrap(&["127.0.0.1:9".parse().unwrap()]);
        let shutdown = runner.shutdown();
        runner.join().unwrap();
        assert!(wait(put).is_err());
        assert!(wait(ping).is_err());
        assert!(wait(bootstrap).is_err());
        assert!(wait(shutdown).is_err());
        assert!(wait(values.next()).unwrap().is_err());
        assert!(wait(values.next()).is_none());
        assert!(wait(query.next()).unwrap().is_err());
        assert!(wait(query.next()).is_none());
        assert!(wait(listener.next()).unwrap().is_err());
        assert!(wait(listener.next()).is_none());
        drop(listener);
    }

    #[test]
    fn async_stream_reports_runner_destruction() {
        let runner = nonthreaded(8);
        let mut values = runner.get(&InfoHash::get("dropped async runner"));
        drop(runner);
        assert!(wait(values.next()).unwrap().is_err());
        assert!(wait(values.next()).is_none());
    }

    #[test]
    fn async_invalid_inputs_and_dropped_operations() {
        assert!(AsyncDhtRunner::with_capacity(DhtRunner::new(), 0).is_err());
        let runner = nonthreaded(8);
        let hash = InfoHash::get("async cancellation");
        let error = wait(runner.bootstrap(&[])).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(runner.get_filtered(&hash, "WHERE user_type=\0").is_err());
        assert!(runner.listen_filtered(&hash, "WHERE user_type=\0").is_err());
        assert!(runner.query(&hash, "SELECT\0 id").is_err());
        let mut invalid = runner.get_filtered(&hash, "WHERE invalid=1").unwrap();
        assert!(wait(invalid.next()).unwrap().is_err());
        assert!(wait(invalid.next()).is_none());
        drop(runner.get(&hash));
        drop(runner.query(&hash, "SELECT id").unwrap());
        drop(runner.put(&hash, Value::new("abandoned"), false));
        drop(runner.ping("127.0.0.1:9".parse().unwrap()));
        let listener = runner.listen(&hash).unwrap();
        drop(listener);
        runner.loop_once().unwrap();
        runner.join().unwrap();
    }

    #[test]
    fn async_threaded_network_roundtrips() {
        let mut nodes = Vec::new();
        for name in ["async source", "async destination"] {
            let mut runner = DhtRunner::new();
            let mut config = DhtRunnerConfig::new();
            config.dht_config.id = Some(DhtIdentity::new(name).unwrap());
            runner.run_bind("127.0.0.1", "::1", 0, config).unwrap();
            nodes.push(runner);
        }
        let destination_native = nodes.pop().unwrap();
        let address = (
            [127, 0, 0, 1],
            destination_native.bound_port(libc::AF_INET as _),
        )
            .into();
        let recipient = destination_native.public_key().unwrap().long_id();
        let signer = nodes.last().unwrap().public_key().unwrap().id();
        let source = AsyncDhtRunner::new(nodes.pop().unwrap());
        let destination = AsyncDhtRunner::new(destination_native);
        wait(source.bootstrap(&["127.0.0.1:9".parse().unwrap(), address])).unwrap();

        for mode in ["plain", "signed", "encrypted"] {
            let hash = InfoHash::get(mode);
            let mut listener = destination.listen(&hash).unwrap();
            let mut value = Value::with_id(b"async network\0value", 42);
            value.set_seq(7);
            let put = match mode {
                "signed" => source.put_signed(&hash, value, false),
                "encrypted" => source.put_encrypted(&hash, &recipient, value, false),
                _ => source.put(&hash, value, false),
            };
            wait(put).unwrap();
            let event = wait(listener.next()).unwrap().unwrap();
            assert!(!event.expired);
            assert_eq!(event.value.as_slice(), b"async network\0value");
            if mode != "plain" {
                assert!(event.value.owner().is_some());
                assert!(event.value.owner().unwrap().id() == signer);
                let event = std::thread::spawn(move || event).join().unwrap();
                assert!(event.value.owner().unwrap().id() == signer);
            }
            drop(listener);
            if mode == "signed" {
                let values: Vec<_> = wait(
                    destination
                        .get_filtered(&hash, "WHERE seq=7")
                        .unwrap()
                        .try_collect(),
                )
                .unwrap();
                assert!(values
                    .iter()
                    .any(|value| value.id() == 42 && value.seq() == 7));
            }
            let values: Vec<_> = wait(destination.get(&hash).try_collect()).unwrap();
            assert!(values
                .iter()
                .any(|value| value.as_slice() == b"async network\0value"));
            let rows: Vec<_> =
                wait(destination.query(&hash, "SELECT id").unwrap().try_collect()).unwrap();
            assert!(rows.iter().any(|row| row.id == Some(42)));
        }

        wait(source.shutdown()).unwrap();
        wait(destination.shutdown()).unwrap();
        source.join().unwrap();
        destination.join().unwrap();
    }

    #[cfg(feature = "serde")]
    mod typed {
        use super::*;
        use opendht::typed::TypedError;
        use serde::{Deserialize, Serialize};
        use std::error::Error;
        use std::marker::PhantomPinned;

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Record {
            version: u32,
            name: String,
            ports: Vec<u16>,
            #[serde(with = "serde_bytes")]
            payload: Vec<u8>,
        }

        fn record() -> Record {
            Record {
                version: 1,
                name: "node-\u{03bb}\0".into(),
                ports: vec![4222, 8443],
                payload: vec![0, 0x80, 0xff, 1],
            }
        }

        #[test]
        fn typed_listener_decodes_compact_msgpack_binary() {
            #[derive(Debug, PartialEq, Deserialize)]
            struct Packet {
                #[serde(with = "serde_bytes")]
                payload: Vec<u8>,
            }

            let runner = nonthreaded(8);
            let hash = InfoHash::get("typed MessagePack binary fixture");
            let mut listener = runner.listen_typed::<Packet>(&hash).unwrap();
            let fixture = [0x91, 0xc4, 0x04, 0x00, 0x80, 0xff, 0x01];
            let _pending = runner.put(&hash, Value::with_id(&fixture, 42), false);
            let event = drive(&runner, listener.next()).unwrap().unwrap();
            assert_eq!(event.value.raw.as_slice(), fixture);
            assert_eq!(event.value.data.payload, [0, 0x80, 0xff, 1]);
            drop(listener);
            runner.join().unwrap();
        }

        #[test]
        fn typed_listener_preserves_metadata_and_expiration() {
            let runner = nonthreaded(8);
            let hash = InfoHash::get("typed metadata");
            let mut listener = runner.listen_typed::<Record>(&hash).unwrap();
            let mut value = Value::with_id(&rmp_serde::to_vec(&record()).unwrap(), 42);
            value.set_value_type(17);
            value.set_seq(7);
            value.set_user_type("application/typed-test").unwrap();
            let _pending = runner.put(&hash, value, false);
            let event = drive(&runner, listener.next()).unwrap().unwrap();
            assert!(!event.expired);
            assert_eq!(event.value.data, record());
            assert_eq!(event.value.raw.id(), 42);
            assert_eq!(event.value.raw.value_type(), 17);
            assert_eq!(event.value.raw.seq(), 7);
            assert_eq!(
                event.value.raw.user_type().unwrap(),
                "application/typed-test"
            );
            assert_eq!(
                rmp_serde::from_slice::<Record>(event.value.raw.as_slice()).unwrap(),
                record()
            );
            let event = drive(&runner, listener.next()).unwrap().unwrap();
            assert!(event.expired);
            assert_eq!(event.value.data, record());
            assert_eq!(event.value.raw.id(), 42);
            drop(listener);
            runner.join().unwrap();
        }

        #[test]
        fn typed_decode_errors_do_not_end_listener() {
            let runner = nonthreaded(8);
            let hash = InfoHash::get("typed mixed payloads");
            let mut listener = runner.listen_typed::<Record>(&hash).unwrap();
            for (id, payload) in [(1, [0xc1].as_slice()), (2, [0x11].as_slice())] {
                let _pending = runner.put(&hash, Value::with_id(payload, id), false);
                let error = drive(&runner, listener.next()).unwrap().err().unwrap();
                assert!(error.source().is_some());
                assert!(
                    matches!(error, TypedError::Deserialize { id: value_id, .. } if value_id == id)
                );
            }
            let _pending = runner.put(
                &hash,
                Value::with_id(&rmp_serde::to_vec(&record()).unwrap(), 3),
                false,
            );
            let event = drive(&runner, listener.next()).unwrap().unwrap();
            assert_eq!(event.value.raw.id(), 3);
            assert_eq!(event.value.data, record());
            runner.join().unwrap();
            let error = wait(listener.next()).unwrap().err().unwrap();
            assert!(matches!(error, TypedError::Operation(_)));
            assert!(wait(listener.next()).is_none());
        }

        #[test]
        fn typed_put_distinguishes_serialization_and_native_errors() {
            struct Unserializable;

            impl Serialize for Unserializable {
                fn serialize<Serializer>(
                    &self,
                    _: Serializer,
                ) -> Result<Serializer::Ok, Serializer::Error>
                where
                    Serializer: serde::Serializer,
                {
                    Err(serde::ser::Error::custom(
                        "intentional serialization failure",
                    ))
                }
            }

            let runner = AsyncDhtRunner::new(DhtRunner::new());
            let hash = InfoHash::get("typed put errors");
            let error = wait(runner.put_typed(&hash, &Unserializable, false)).unwrap_err();
            assert!(error.source().is_some());
            assert!(matches!(error, TypedError::Serialize(_)));
            let error = wait(runner.put_typed(&hash, &record(), false)).unwrap_err();
            assert!(error.source().is_some());
            assert!(matches!(error, TypedError::Operation(_)));
            runner.join().unwrap();
        }

        #[test]
        fn typed_streams_support_non_unpin_records_and_detached_lifetimes() {
            #[derive(Serialize, Deserialize)]
            struct PinnedRecord {
                message: String,
                #[serde(skip)]
                _pin: PhantomPinned,
            }

            let runner = nonthreaded(8);
            let hash = InfoHash::get("typed pinned records");
            let mut listener = runner.listen_typed::<PinnedRecord>(&hash).unwrap();
            let value = PinnedRecord {
                message: "owned".into(),
                _pin: PhantomPinned,
            };
            let _pending = runner.put(
                &hash,
                Value::from_bytes(&rmp_serde::to_vec(&value).unwrap()),
                false,
            );
            let event = drive(&runner, listener.next()).unwrap().unwrap();
            assert_eq!(event.value.data.message, "owned");
            drop(listener);
            let mut values = runner.get_typed::<PinnedRecord>(&InfoHash::get("temporary hash"));
            drop(runner);
            assert!(matches!(
                wait(values.next()).unwrap(),
                Err(TypedError::Operation(_))
            ));
            assert!(wait(values.next()).is_none());
        }

        #[test]
        fn typed_listener_inherits_bounded_stream_errors() {
            let runner = nonthreaded(1);
            let hash = InfoHash::get("typed overflow");
            let mut listener = runner.listen_typed::<Record>(&hash).unwrap();
            for id in 1..=3 {
                let _pending = runner.put(
                    &hash,
                    Value::with_id(&rmp_serde::to_vec(&record()).unwrap(), id),
                    false,
                );
                runner.loop_once().unwrap();
            }
            assert_eq!(
                drive(&runner, listener.next())
                    .unwrap()
                    .unwrap()
                    .value
                    .raw
                    .id(),
                1
            );
            let error = drive(&runner, listener.next()).unwrap().err().unwrap();
            assert!(
                matches!(error, TypedError::Operation(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
            assert!(drive(&runner, listener.next()).is_none());
            drop(listener);
            runner.join().unwrap();
        }

        #[test]
        fn typed_threaded_put_get_listen_roundtrip() {
            let mut source = DhtRunner::new();
            let mut destination = DhtRunner::new();
            source
                .run_bind("127.0.0.1", "::1", 0, DhtRunnerConfig::new())
                .unwrap();
            destination
                .run_bind("127.0.0.1", "::1", 0, DhtRunnerConfig::new())
                .unwrap();
            let address = ([127, 0, 0, 1], destination.bound_port(libc::AF_INET as _)).into();
            let source = AsyncDhtRunner::new(source);
            let destination = AsyncDhtRunner::new(destination);
            wait(source.bootstrap(&[address])).unwrap();
            let hash = InfoHash::get("typed network record");
            let mut listener = destination.listen_typed::<Record>(&hash).unwrap();
            wait(source.put_typed(&hash, &record(), false)).unwrap();
            let event = wait(listener.next()).unwrap().unwrap();
            assert_eq!(event.value.data, record());
            assert_eq!(event.value.raw.as_slice().first(), Some(&0x94));
            assert!(event
                .value
                .raw
                .as_slice()
                .ends_with(&[0xc4, 0x04, 0x00, 0x80, 0xff, 0x01]));
            let id = event.value.raw.id();
            drop(listener);
            let values: Vec<_> =
                wait(destination.get_typed::<Record>(&hash).try_collect()).unwrap();
            assert!(values
                .iter()
                .any(|value| value.data == record() && value.raw.id() == id));
            let values: Vec<_> = wait(destination.get(&hash).try_collect()).unwrap();
            assert!(values.iter().any(|value| {
                rmp_serde::from_slice::<Record>(value.as_slice()).unwrap() == record()
            }));
            wait(source.shutdown()).unwrap();
            wait(destination.shutdown()).unwrap();
            source.join().unwrap();
            destination.join().unwrap();
        }
    }
}
