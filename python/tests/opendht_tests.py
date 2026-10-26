import asyncio
import gc
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import textwrap
import threading
import unittest
from unittest.mock import Mock
import weakref
import opendht as dht
import opendht.aio as aio

class _ListenerCallback:
    def __call__(self, value, expired):
        return True

class OpenDhtTester(unittest.TestCase):

    def test_value_security_state(self):
        key = dht.PrivateKey.generateEC()
        identity = dht.Identity(key, dht.Certificate.generate(key, "sender"))
        recipient = dht.Identity.generate("recipient", bits=2048)
        node = self._run_node(id=identity, ipv4="127.0.0.1", ipv6="::1")
        peer = self._run_node(id=recipient, ipv4="127.0.0.1", ipv6="::1")
        self.assertTrue(node.ping(peer.getBound(socket.AF_INET)))
        for method in ("put", "putSigned", "putEncrypted"):
            with self.subTest(method=method):
                value = dht.Value(method.encode())
                self.assertIs(value.isSigned(), False)
                self.assertIs(value.isEncrypted(), False)
                value.recipient = recipient.publickey.getId()
                self.assertIs(value.isEncrypted(), False)
                location = dht.InfoHash.getRandom()
                if method == "putEncrypted":
                    self.assertTrue(node.putEncrypted(location, value, recipient.publickey))
                else:
                    self.assertTrue(getattr(node, method)(location, value))
                received = peer.get(location)
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0].data, value.data)
                self.assertIs(received[0].isSigned(), method != "put")
                self.assertIs(received[0].isEncrypted(), False)

    def test_connectivity_changed(self):
        node = dht.DhtRunner()
        self.addCleanup(node.join)
        self.assertIsNone(node.connectivityChanged())
        node.run(ipv4="127.0.0.1", ipv6="::1")
        peer = self._run_node(ipv4="127.0.0.1", ipv6="::1")
        self.assertTrue(node.ping(peer.getBound(socket.AF_INET)))
        node_id = node.getNodeId()
        self.assertIsNone(node.connectivityChanged())
        self.assertTrue(node.ping(peer.getBound(socket.AF_INET)))
        self.assertEqual(node.getNodeId(), node_id)
        node.join()
        self.assertIsNone(node.connectivityChanged())

    def test_runner_mutations_release_gil(self):
        self._run_binding_script("""
            from datetime import timedelta
            from pathlib import Path
            import socket
            from tempfile import TemporaryDirectory
            import threading
            from unittest import TestCase
            check = TestCase()
            with TemporaryDirectory() as directory:
                operations = (
                    lambda node: node.registerType(dht.ValueType(42, "custom", timedelta(seconds=1))),
                    lambda node: node.enableLogging(),
                    lambda node: node.disableLogging(),
                    lambda node: node.enableFileLogging(str(Path(directory) / "node.log")),
                    lambda node: node.run(),
                    lambda node: node.run(ipv4="127.0.0.1", ipv6="::1"),
                    lambda node: node.connectivityChanged(),
                )
                for operation in operations:
                    node, peer = dht.DhtRunner(), dht.DhtRunner()
                    entered, release = threading.Event(), threading.Event()
                    def on_status(ipv4, ipv6):
                        entered.set()
                        release.wait(5)
                    try:
                        node.setOnStatusChanged(on_status)
                        node.run(ipv4="127.0.0.1", ipv6="::1")
                        peer.run(ipv4="127.0.0.1", ipv6="::1")
                        node.ping(peer.getBound(socket.AF_INET), done_cb=lambda ok: None)
                        check.assertTrue(entered.wait(5))
                        timer = threading.Timer(0.01, release.set)
                        timer.start()
                        operation(node)
                        timer.join()
                    finally:
                        release.set()
                        node.join()
                        peer.join()
        """, timeout=15)

    def test_invalid_where_is_an_exception(self):
        self._run_binding_script("""
            from unittest import TestCase
            check = TestCase()
            for expression in ("WHERE unknown=1", "WHERE id=42,unknown=test"):
                with check.assertRaises(ValueError):
                    dht.Where(expression)
            check.assertEqual(str(dht.Where("WHERE id=42")), "WHERE id=42")
        """)

    def test_type_registration_validates_state(self):
        self._run_binding_script("""
            from datetime import timedelta
            from unittest import TestCase
            check = TestCase()
            node = dht.DhtRunner()
            value_type = dht.ValueType(42, "custom", timedelta(seconds=1))
            try:
                for attempt in range(2):
                    with check.assertRaises(RuntimeError):
                        node.registerType(value_type)
                    node.run(ipv4="127.0.0.1", ipv6="::1")
                    node.registerType(value_type)
                    node.join()
            finally:
                node.join()
        """)

    def test_type_registration_validates_arguments(self):
        self._run_binding_script("""
            from unittest import TestCase
            check = TestCase()
            node = dht.DhtRunner()
            try:
                node.run(ipv4="127.0.0.1", ipv6="::1")
                with check.assertRaises(TypeError):
                    node.registerType(None)
                with check.assertRaises(ValueError):
                    node.registerType(dht.ValueType.__new__(dht.ValueType))
            finally:
                node.join()
        """)

    def test_empty_encryption_recipient_is_an_exception(self):
        self._run_binding_script("""
            import gc
            from unittest import TestCase
            from unittest.mock import Mock
            import weakref
            check = TestCase()
            key = dht.PrivateKey.generateEC()
            identity = dht.Identity(key, dht.Certificate.generate(key, "sender"))
            node = dht.DhtRunner()
            try:
                node.run(id=identity, ipv4="127.0.0.1", ipv6="::1")
                location, value = dht.InfoHash.getRandom(), dht.Value(b"encrypted")
                for recipient in (None, dht.PublicKey(), dht.InfoHash.getRandom()):
                    exception = TypeError if isinstance(recipient, dht.InfoHash) else ValueError
                    with check.assertRaises(exception):
                        node.putEncrypted(location, value, recipient)
                    callback = Mock()
                    reference = weakref.ref(callback)
                    with check.assertRaises(exception):
                        node.putEncrypted(location, value, recipient, callback)
                    callback.assert_not_called()
                    del callback
                    gc.collect()
                    check.assertIsNone(reference())
            finally:
                node.join()
        """)

    def test_observability_snapshots(self):
        node = dht.DhtRunner()
        self.addCleanup(node.join)
        self.assertFalse(node.getNodeInfo().node_id)
        self.assertEqual(node.getPublicAddress(), [])
        node.run(ipv4="127.0.0.1", ipv6="::1")
        info = node.getNodeInfo()
        bound4 = info.bound4
        self.assertIsInstance(info, dht.NodeInfo)
        self.assertEqual(info.node_id, node.getNodeId())
        self.assertEqual(info.bound4, node.getBound(socket.AF_INET).getPort())
        self.assertEqual(info.bound6, node.getBound(socket.AF_INET6).getPort())
        for stats in (info.ipv4, info.ipv6, node.getNodesStats(socket.AF_INET)):
            self.assertIsInstance(stats, dht.NodeStats)
            self.assertEqual(stats.getKnownNodes(), stats.good_nodes + stats.dubious_nodes)
            self.assertGreaterEqual(stats.getNetworkSizeEstimation(), 0)
        for field in ("ongoing_ops", "storage_values", "storage_size",
                      "local_storage_values", "local_storage_size"):
            self.assertGreaterEqual(getattr(info, field), 0)
        with self.assertRaises(AttributeError):
            info.bound4 = 1
        with self.assertRaises(ValueError):
            node.getNodesStats(socket.AF_UNSPEC)
        self.assertTrue(all(isinstance(address, dht.SockAddr)
                            for address in node.getPublicAddress(socket.AF_INET)))
        node.join()
        self.assertFalse(node.getNodeInfo().node_id)
        self.assertEqual(info.bound4, bound4)

    def test_status_callback_lifetime(self):
        node = dht.DhtRunner()
        self.addCleanup(node.join)
        changed = threading.Event()
        statuses = []
        class Callback:
            def __call__(self, ipv4, ipv6):
                statuses.append((ipv4, ipv6))
                changed.set()
        callback = Callback()
        callback_ref = weakref.ref(callback)
        node.setOnStatusChanged(callback)
        del callback
        gc.collect()
        self.assertIsNotNone(callback_ref())
        node.run(ipv4="127.0.0.1", ipv6="::1")
        peer = self._run_node(ipv4="127.0.0.1", ipv6="::1")
        self.assertTrue(node.ping(peer.getBound(socket.AF_INET)))
        self.assertTrue(changed.wait(5))
        self.assertTrue(all(isinstance(status, dht.NodeStatus)
                            for pair in statuses for status in pair))
        node.setOnStatusChanged(None)
        gc.collect()
        self.assertIsNone(callback_ref())
        with self.assertRaises(TypeError):
            node.setOnStatusChanged(42)

    def test_status_callback_cycles_are_collectible(self):
        class Observer:
            def __init__(self):
                self.node = dht.DhtRunner()
                self.node.setOnStatusChanged(self.changed)
                self.node.run()
            def changed(self, ipv4, ipv6):
                pass
        observer = Observer()
        reference = weakref.ref(observer)
        del observer
        gc.collect()
        self.assertIsNone(reference())

    def test_observability_getters_release_gil(self):
        self._run_binding_script("""
            import socket
            import threading
            from unittest import TestCase
            check = TestCase()
            for name in ("getBound", "getNodeId", "getId", "getPublicKey",
                         "getNodeInfo", "getNodesStats", "getPublicAddress",
                         "getNodeMessageStats", "getStorageLog",
                         "getRoutingTablesLog", "getSearchesLog"):
                node, peer = dht.DhtRunner(), dht.DhtRunner()
                entered, release = threading.Event(), threading.Event()
                def on_status(ipv4, ipv6):
                    entered.set()
                    release.wait(5)
                try:
                    node.setOnStatusChanged(on_status)
                    node.run(ipv4="127.0.0.1", ipv6="::1")
                    peer.run(ipv4="127.0.0.1", ipv6="::1")
                    node.ping(peer.getBound(socket.AF_INET), done_cb=lambda ok: None)
                    check.assertTrue(entered.wait(5))
                    timer = threading.Timer(0.01, release.set)
                    timer.start()
                    arguments = (socket.AF_INET,) if name in (
                        "getRoutingTablesLog", "getSearchesLog") else ()
                    getattr(node, name)(*arguments)
                    timer.join()
                finally:
                    release.set()
                    node.join()
                    peer.join()
        """, timeout=15)

    def test_query_projection(self):
        node = self._run_node(ipv4="127.0.0.1", ipv6="::1")
        peer = self._run_node(ipv4="127.0.0.1", ipv6="::1")
        self.assertTrue(node.ping(peer.getBound(socket.AF_INET)))
        key = dht.InfoHash.getRandom()
        for number, user_type in ((101, "skip"), (202, "keep")):
            value = dht.Value(b"query")
            value.id, value.user_type = number, user_type
            self.assertTrue(node.put(key, value))
        selection = (dht.Select().field(dht.ValueField.Id)
                     .field(dht.ValueField.ValueType).field(dht.ValueField.UserType))
        query = dht.Query()
        query.buildFrom(selection, dht.Where().userType("keep"))
        rows = peer.query(key, query=query)
        self.assertEqual(rows, [{dht.ValueField.Id: 202,
                                 dht.ValueField.ValueType: 0,
                                 dht.ValueField.UserType: "keep"}])
        completed = threading.Event()
        received, results = [], []
        def on_done(ok, nodes):
            results.append(ok)
            completed.set()
        peer.query(key, lambda row: received.append(row) or True, on_done, query)
        self.assertTrue(completed.wait(5))
        self.assertEqual(results, [True])
        self.assertEqual(received, rows)
        all_rows = peer.query(key)
        self.assertEqual({row[dht.ValueField.Id] for row in all_rows}, {101, 202})
        self.assertTrue(all(isinstance(row[dht.ValueField.OwnerPk], dht.InfoHash)
                    for row in all_rows))
        self.assertEqual(dht.DhtRunner().query(key), [])
        with self.assertRaises(ValueError):
            dht.Select().field(999)

    def test_listener_filters(self):
        node = self._run_node(ipv4="127.0.0.1", ipv6="::1")
        peer = self._run_node(ipv4="127.0.0.1", ipv6="::1")
        self.assertTrue(node.ping(peer.getBound(socket.AF_INET)))
        key = dht.InfoHash.getRandom()
        for number, data, user_type in ((101, b"rejected", "keep"),
                                        (202, b"accepted", "skip"),
                                        (303, b"accepted", "keep")):
            value = dht.Value(data)
            value.id, value.user_type = number, user_type
            self.assertTrue(peer.put(key, value))
        received, finished = [], threading.Event()
        def on_value(value, expired):
            received.append((value.id, expired))
            finished.set()
            return True
        token = node.listen(key, on_value, filter=lambda value: value.data == b"accepted",
                            where=dht.Where().userType("keep"))
        self.addCleanup(node.cancelListen, token)
        self.assertTrue(finished.wait(5))
        self.assertEqual(received, [(303, False)])

    def test_persistence_configuration(self):
        with TemporaryDirectory() as directory:
            state_path = Path(directory) / "state-\u00e9"
            config = dht.DhtConfig()
            config.setPersistPath(str(state_path))
            first = self._run_node(config=config)
            node_id = first.getNodeId()
            port = first.getBound(socket.AF_INET).getPort()
            self.assertNotEqual(port, 0)
            self._shutdown_node(first)
            self.assertTrue(state_path.is_file())
            self.assertTrue(Path(str(state_path) + "_port.txt").is_file())

            restored_config = dht.DhtConfig()
            restored_config.setPersistPath(str(state_path))
            second = self._run_node(config=restored_config)
            self.assertEqual(second.getNodeId(), node_id)
            self.assertEqual(second.getBound(socket.AF_INET).getPort(), port)
            self._shutdown_node(second)

    def test_disable_persistence(self):
        with TemporaryDirectory() as directory:
            config = dht.DhtConfig()
            config.setPersistPath(str(Path(directory) / "state"))
            config.setPersistPath("")
            node = self._run_node(config=config)
            self._shutdown_node(node)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_persistence_path_validation(self):
        config = dht.DhtConfig()
        for path in (None, 123):
            with self.subTest(path=path):
                with self.assertRaises(TypeError):
                    config.setPersistPath(path)
        with self.assertRaises(ValueError):
            config.setPersistPath("state\0suffix")

    def test_key_serialization(self):
        message = b"persisted identity"
        for generate in (dht.PrivateKey.generate, dht.PrivateKey.generateEC):
            key = generate()
            public_key = key.getPublicKey()
            restored_public = dht.PublicKey(public_key.serialize())
            self.assertEqual(restored_public.getLongId(), public_key.getLongId())
            self.assertEqual(bytes(restored_public), public_key.serialize())
            ca_cert = dht.Certificate.generate(key, "root", is_ca=True)
            trust = dht.TrustList()
            trust.add(ca_cert)
            for password in ("", "test-password"):
                with self.subTest(algorithm=generate.__name__, encrypted=bool(password)):
                    encoded = key.serialize(password)
                    self.assertIsInstance(encoded, bytes)
                    restored_key = dht.PrivateKey(encoded, password)
                    self.assertEqual(restored_key.getLongId(), key.getLongId())
                    certificate = dht.Certificate.generate(
                        dht.PrivateKey.generateEC(), "restored", dht.Identity(restored_key, ca_cert)
                    )
                    self.assertTrue(trust.verify(certificate))
                    if generate.__name__ == "generate":
                        self.assertTrue(restored_public.checkSignature(message, restored_key.sign(message)))
            self.assertEqual(dht.PrivateKey(bytes(key)).getLongId(), key.getLongId())

    def test_key_import_errors(self):
        for key_type in (dht.PrivateKey, dht.PublicKey):
            for encoded in (b"", b"invalid key"):
                with self.subTest(key_type=key_type.__name__, encoded=encoded):
                    with self.assertRaises((ValueError, RuntimeError)):
                        key_type(encoded)
            with self.assertRaises(ValueError):
                key_type().serialize()
            with self.assertRaises(ValueError):
                bytes(key_type())
        key = dht.PrivateKey.generateEC()
        encoded = key.serialize("test-password")
        for password in ("", "wrong-password"):
            with self.assertRaises(RuntimeError):
                dht.PrivateKey(encoded, password)
        with self.assertRaises(ValueError):
            key.serialize("test\0password")
        with self.assertRaises(ValueError):
            dht.PrivateKey(encoded, "test\0password")

    def test_identity_persistence(self):
        ca_key = dht.PrivateKey.generateEC()
        ca_cert = dht.Certificate.generate(ca_key, "root", is_ca=True)
        ca = dht.Identity(ca_key, ca_cert)
        key = dht.PrivateKey.generateEC()
        cert = dht.Certificate.generate(key, "persisted", ca)
        identity = dht.Identity(
            dht.PrivateKey(key.serialize("test-password"), "test-password"),
            dht.Certificate(bytes(cert)),
        )
        self.assertEqual(identity.publickey.getLongId(), key.getLongId())
        self.assertEqual(identity.certificate.getLongId(), cert.getLongId())
        self.assertEqual(identity.certificate.issuer.getLongId(), ca_cert.getLongId())
        trust = dht.TrustList()
        trust.add(ca_cert)
        self.assertTrue(trust.verify(identity.certificate))
        node = self._run_node(id=identity)
        self.assertEqual(node.getPublicKey().getLongId(), key.getLongId())

    def test_value_metadata(self):
        value = dht.Value(b"metadata", 42)
        self.assertEqual(value.type, 42)
        self.assertEqual(value.seq, 0)
        self.assertEqual(value.priority, 0)
        self.assertEqual(value.pushType, "")
        value.type = 7
        value.seq = 3
        value.priority = 1
        value.pushType = "audioCall-\u00e9"
        self.assertEqual((value.type, value.seq, value.priority, value.pushType), (7, 3, 1, "audioCall-\u00e9"))
        self.assertEqual(value.data, b"metadata")
        value.pushType = ""
        self.assertEqual(value.pushType, "")

    def test_value_metadata_bounds(self):
        value = dht.Value()
        for field, maximum in (("type", 65535), ("seq", 65535), ("priority", 2**32 - 1)):
            with self.subTest(field=field):
                setattr(value, field, maximum)
                self.assertEqual(getattr(value, field), maximum)
                for invalid in (-1, maximum + 1):
                    with self.assertRaises(OverflowError):
                        setattr(value, field, invalid)
                self.assertEqual(getattr(value, field), maximum)

    def _run_binding_script(self, script, timeout=10):
        core = sys.modules[dht.DhtRunner.__module__]
        bootstrap = (
            "import importlib.util, sys\n"
            f"sys.path.insert(0, {str(Path(dht.__file__).resolve().parent.parent)!r})\n"
            f"spec = importlib.util.spec_from_file_location({core.__name__!r}, {core.__file__!r})\n"
            "core = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = core\n"
            "spec.loader.exec_module(core)\n"
            "import opendht as dht\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", bootstrap + textwrap.dedent(script)],
            capture_output=True, text=True, timeout=timeout,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_pht_releases_runner(self):
        self._run_binding_script("""
            import gc
            import threading
            import weakref
            from unittest import TestCase
            check = TestCase()
            class Callback:
                def __call__(self, value, expired):
                    return True
            for use_index in (False, True):
                node = dht.DhtRunner()
                node.run()
                index = dht.Pht(b"cleanup-test", {"field": 1}, node)
                if use_index:
                    finished = threading.Event()
                    index.lookup({"field": b"x"}, done_cb=lambda ok: finished.set())
                    check.assertTrue(finished.wait(5))
                callback = Callback()
                released = threading.Event()
                weakref.finalize(callback, released.set)
                node.listen(dht.InfoHash.getRandom(), callback)
                del callback, node
                gc.collect()
                check.assertFalse(released.is_set())
                del index
                gc.collect()
                check.assertTrue(released.wait(2))
        """)

    def test_pht_pending_operation_outlives_wrapper(self):
        self._run_binding_script("""
            import gc
            import socket
            import threading
            from unittest import TestCase
            check = TestCase()
            node, peer = dht.DhtRunner(), dht.DhtRunner()
            entered, release, finished = (threading.Event() for _ in range(3))
            def pause(ok, nodes):
                entered.set()
                release.wait(5)
            try:
                node.run(ipv4="127.0.0.1", ipv6="::1")
                peer.run(ipv4="127.0.0.1", ipv6="::1")
                check.assertTrue(node.ping(peer.getBound(socket.AF_INET)))
                node.put(dht.InfoHash.getRandom(), dht.Value(b"pause"), done_cb=pause)
                check.assertTrue(entered.wait(5))
                index = dht.Pht(b"pending-test", {"field": 1}, node)
                index.lookup({"field": b"x"}, done_cb=lambda ok: finished.set())
                del index
                gc.collect()
                release.set()
                check.assertTrue(finished.wait(5))
            finally:
                release.set()
                node.join()
                peer.join()
        """, timeout=15)

    def test_value_type_lifetime(self):
        self._run_binding_script("""
            import gc
            from datetime import timedelta
            from unittest import TestCase
            check = TestCase()
            node = dht.DhtRunner()
            try:
                node.run()
                value_type = dht.ValueType(42, "test", timedelta(seconds=1))
                for name in ("second", "third"):
                    value_type.__init__(42, name, timedelta(seconds=2))
                    node.registerType(value_type)
                with check.assertRaises(TypeError):
                    value_type.__init__(42, "invalid", 1)
                node.registerType(value_type)
                del value_type
                gc.collect()
                node.put(dht.InfoHash.getRandom(), dht.Value(b"typed", 42))
            finally:
                node.join()
        """)

    def test_uninitialized_nodes_are_exceptions(self):
        self._run_binding_script("""
            from unittest import TestCase
            check = TestCase()
            for node in (dht.Node(), dht.NodeEntry().getNode()):
                for method in (node.getId, node.getAddr, node.isExpired,
                               lambda: str(node), lambda: repr(node)):
                    with check.assertRaises(ValueError):
                        method()
            nodes = dht.NodeSet()
            nodes.insert(dht.NodeEntry())
            with check.assertRaises(ValueError):
                str(nodes)
        """)

    def test_raising_completion_callbacks_release_references(self):
        for method in ("get", "put", "ping", "shutdown"):
            with self.subTest(method=method):
                self._run_binding_script(f"""
                    import gc
                    import sys
                    import weakref
                    from unittest import TestCase
                    check = TestCase()
                    errors = []
                    sys.unraisablehook = lambda error: errors.append(
                        (type(error.exc_value), str(error.exc_value))
                    )
                    class Callback:
                        def __call__(self, *args):
                            raise RuntimeError("callback failed")
                    node = dht.DhtRunner()
                    callback = Callback()
                    callback_ref = weakref.ref(callback)
                    if {method!r} == "get":
                        node.get(dht.InfoHash.getRandom(),
                                 get_cb=lambda value: True, done_cb=callback)
                    elif {method!r} == "put":
                        node.put(dht.InfoHash.getRandom(), dht.Value(b"test"),
                                 done_cb=callback)
                    elif {method!r} == "ping":
                        node.ping(dht.SockAddr(), done_cb=callback)
                    else:
                        node.shutdown(callback)
                    del callback
                    gc.collect()
                    check.assertEqual(errors, [(RuntimeError, "callback failed")])
                    check.assertIsNone(callback_ref())
                """)

    def test_run_bind_errors_are_exceptions(self):
        self._run_binding_script("""
            from unittest import TestCase
            check = TestCase()
            config = dht.DhtConfig()
            config.setBound(
                dht.SockAddr.resolve("192.0.2.1")[0],
                dht.SockAddr.resolve("2001:db8::1")[0],
            )
            node = dht.DhtRunner()
            for options in (
                {"config": config},
                {"ipv4": "192.0.2.1", "ipv6": "2001:db8::1"},
            ):
                with check.assertRaises(RuntimeError):
                    node.run(**options)
                check.assertFalse(node.isRunning())
                node.run(ipv4="127.0.0.1", ipv6="::1")
                check.assertTrue(node.isRunning())
                node.join()
        """)

    def test_pht_invalid_keys_are_exceptions(self):
        for method in ("lookup", "insert"):
            with self.subTest(method=method):
                self._run_binding_script(f"""
                    import gc
                    import weakref
                    from unittest import TestCase
                    check = TestCase()
                    class Callback:
                        def __call__(self, *args):
                            raise AssertionError("Invalid keys must not invoke callbacks")
                    node = dht.DhtRunner()
                    index = dht.Pht(b"invalid-key-test", {{"field": 1}}, node)
                    callback = Callback()
                    callback_ref = weakref.ref(callback)
                    with check.assertRaises(ValueError):
                        if {method!r} == "lookup":
                            index.lookup({{"other": b"x"}}, done_cb=callback)
                        else:
                            index.insert(
                                {{"other": b"x"}},
                                dht.IndexValue(dht.InfoHash.getRandom(), 1),
                                done_cb=callback,
                            )
                    del callback
                    gc.collect()
                    check.assertIsNone(callback_ref())
                """)

    def test_node_set_iterator_keeps_owner_alive(self):
        self._run_binding_script("""
            import gc
            from unittest import TestCase
            check = TestCase()
            entry = dht.NodeEntry()
            expected_id = entry.getId()
            nodes = dht.NodeSet()
            check.assertTrue(nodes.insert(entry))
            iterator = iter(nodes)
            del nodes
            gc.collect()
            check.assertEqual(next(iterator).getId(), expected_id)
            check.assertIs(iter(iterator), iterator)
            with check.assertRaises(StopIteration):
                next(iterator)
        """)

    def test_hash_bit_access(self):
        class BitIndex:
            def __index__(self):
                return 1

        for hash_type, width in ((dht.InfoHash, 160), (dht.PkId, 256)):
            with self.subTest(hash_type=hash_type.__name__):
                value = hash_type()
                for bit in (0, width - 1, BitIndex()):
                    self.assertFalse(value.getBit(bit))
                    value.setBit(bit, True)
                    self.assertTrue(value.getBit(bit))
                    value.setBit(bit, False)
                    self.assertFalse(value.getBit(bit))
                self.assertFalse(value)

    def test_hash_bit_bounds(self):
        for name, width in (("InfoHash", 160), ("PkId", 256)):
            with self.subTest(hash_type=name):
                self._run_binding_script(f"""
                    from unittest import TestCase
                    check = TestCase()
                    value = dht.{name}.getRandom()
                    original = value.toString()
                    for bit in ({width}, {width + 1}, -1, 2**32 - 1, 2**100):
                        with check.assertRaises(IndexError):
                            value.getBit(bit)
                        with check.assertRaises(IndexError):
                            value.setBit(bit, True)
                        check.assertEqual(value.toString(), original)
                    for bit in (None, "0", 0.5):
                        with check.assertRaises(TypeError):
                            value.getBit(bit)
                        with check.assertRaises(TypeError):
                            value.setBit(bit, True)
                """)

    def test_crypto_errors_are_exceptions(self):
        self._run_binding_script("""
            from unittest import TestCase
            check = TestCase()
            key = dht.PrivateKey.generateEC()
            with check.assertRaises(RuntimeError):
                key.decrypt(b"invalid ciphertext")
            with check.assertRaises(RuntimeError):
                key.getPublicKey().encrypt(b"message")
            with check.assertRaises(RuntimeError):
                dht.PrivateKey.generate().decrypt(b"invalid ciphertext")
            with check.assertRaises(RuntimeError):
                dht.Certificate(b"invalid certificate")
        """)

    def test_crypto_uninitialized_objects(self):
        self._run_binding_script("""
            from unittest import TestCase
            check = TestCase()
            key = dht.PrivateKey.generateEC()
            cert = dht.Certificate.generate(key, "test")
            trust = dht.TrustList()
            operations = (
                lambda: dht.PrivateKey().decrypt(b"ciphertext"),
                lambda: dht.Certificate().getName(),
                lambda: dht.Certificate().revoke(key, cert),
                lambda: cert.revoke(dht.PrivateKey(), cert),
                lambda: cert.revoke(None, cert),
                lambda: cert.revoke(key, dht.Certificate()),
                lambda: cert.revoke(key, None),
                lambda: dht.Certificate.generate(dht.PrivateKey(), "test"),
                lambda: dht.Certificate.generate(None, "test"),
                lambda: trust.add(dht.Certificate()),
                lambda: trust.add(None),
                lambda: trust.remove(dht.Certificate()),
                lambda: trust.remove(None),
                lambda: trust.verify(dht.Certificate()),
                lambda: trust.verify(None),
            )
            for operation in operations:
                with check.assertRaises(ValueError):
                    operation()
        """)

    def test_runner_shutdown_releases_gil(self):
        for close in ("node.join()", "del node"):
            with self.subTest(close=close):
                self._run_binding_script(textwrap.dedent("""
                    import threading
                    node = dht.DhtRunner()
                    node.run()
                    entered = threading.Event()
                    release = threading.Event()
                    finished = threading.Event()
                    def on_shutdown():
                        entered.set()
                        release.wait()
                        finished.set()
                    node.shutdown(on_shutdown)
                    assert entered.wait(5)
                    timer = threading.Timer(0.1, release.set)
                    timer.start()
                """) + f"\n{close}\nassert finished.is_set()\ntimer.join()\n", timeout=8)

    def _shutdown_node(self, node):
        stopped = threading.Event()
        node.shutdown(stopped.set)
        self.assertTrue(stopped.wait(5))
        node.join()

    def _run_node(self, **kwargs):
        node = dht.DhtRunner()
        self.addCleanup(node.join)
        node.run(**kwargs)
        return node

    def test_blocking_put_forwards_permanence(self):
        class RecordingRunner(dht.DhtRunner):
            def put(self, key, value, done_cb=None, permanent=False):
                self.permanent = permanent
                done_cb(True, [])

            putSigned = put

        node = RecordingRunner()
        key = dht.InfoHash.getRandom()
        value = dht.Value(b"permanent")
        for name in ("put", "putSigned"):
            for permanent in (False, True):
                with self.subTest(method=name, permanent=permanent):
                    self.assertTrue(getattr(dht.DhtRunner, name)(node, key, value, permanent=permanent))
                    self.assertIs(node.permanent, permanent)

    def test_run_default_config(self):
        self.assertIsNone(dht.DhtRunner.run.__defaults__[-1])

    def test_run_identity_isolation(self):
        key = dht.PrivateKey.generateEC()
        identity = dht.Identity(key, dht.Certificate.generate(key, "runner"))
        first = self._run_node(id=identity)
        self.assertEqual(first.getPublicKey().getLongId(), identity.publickey.getLongId())
        second = self._run_node()
        self.assertFalse(second.getId())

    def test_run_config_isolation(self):
        config = dht.DhtConfig()
        node_id = dht.InfoHash.getRandom()
        config.setNodeId(node_id)
        key = dht.PrivateKey.generateEC()
        identity = dht.Identity(key, dht.Certificate.generate(key, "runner"))
        first = self._run_node(id=identity, config=config)
        second = self._run_node(config=config)
        self.assertEqual(first.getNodeId(), node_id)
        self.assertEqual(second.getNodeId(), node_id)
        self.assertFalse(second.getId())

    def test_listener_callbacks_are_independent(self):
        node = self._run_node()
        key = dht.InfoHash.getRandom()
        first = _ListenerCallback()
        second = _ListenerCallback()
        first_released = threading.Event()
        second_released = threading.Event()
        weakref.finalize(first, first_released.set)
        weakref.finalize(second, second_released.set)
        first_token = node.listen(key, first)
        second_token = node.listen(key, second)
        del first, second
        gc.collect()
        self.assertFalse(first_released.is_set())
        self.assertFalse(second_released.is_set())
        node.cancelListen(first_token)
        node.cancelListen(first_token)
        self.assertTrue(first_released.wait(5))
        self.assertFalse(second_released.is_set())
        node.cancelListen(second_token)
        self.assertTrue(second_released.wait(5))

    def test_listener_callback_outlives_token(self):
        node = self._run_node()
        callback = _ListenerCallback()
        released = threading.Event()
        weakref.finalize(callback, released.set)
        token = node.listen(dht.InfoHash.getRandom(), callback)
        del callback, token
        gc.collect()
        self.assertFalse(released.is_set())
        node.join()
        self.assertTrue(released.is_set())

    def test_stopped_listener_releases_callback(self):
        node = dht.DhtRunner()
        callback = _ListenerCallback()
        released = threading.Event()
        weakref.finalize(callback, released.set)
        token = node.listen(dht.InfoHash.getRandom(), callback)
        del callback
        gc.collect()
        self.assertTrue(released.is_set())
        node.cancelListen(token)
        node.cancelListen(token)

    # test that DhtRunner can be instatiated and deleted without throwing
    def test_instance(self):
        for i in range(10):
            r = dht.DhtRunner()
            r.run()
            del r

    # test that bootstraping works (raw address)
    def test_bootstrap(self):
        bootstrap_node = self._run_node(ipv4="127.0.0.1")
        client_node = self._run_node(ipv4="127.0.0.1")
        self.assertTrue(client_node.ping(bootstrap_node.getBound(socket.AF_INET)))

    def test_crypto(self):
        i = dht.Identity.generate("id")
        message = dht.InfoHash.getRandom().toString()
        encrypted = i.publickey.encrypt(message)
        decrypted = i.key.decrypt(encrypted)
        self.assertTrue(message == decrypted)

    def test_crypto_ec(self):
        key = dht.PrivateKey.generateEC()
        cert = dht.Certificate.generate(key, "CA", is_ca=True)
        ca_id = dht.Identity(key, cert)
        self.assertTrue(cert.getId() == key.getPublicKey().getId())
        key2 = dht.PrivateKey.generateEC()
        cert2 = dht.Certificate.generate(key2, "cert", ca_id)
        trust = dht.TrustList()
        trust.add(cert)
        self.assertTrue(trust.verify(cert2))

    def test_trust(self):
        main_id = dht.Identity.generate("id_1")
        sub_id1 = dht.Identity.generate("sid_1", main_id)
        sub_id2 = dht.Identity.generate("sid_2", main_id)
        main_id.certificate.revoke(main_id.key, sub_id2.certificate)
        main_id2 = dht.Identity.generate("id_2")
        trust = dht.TrustList()
        trust.add(main_id.certificate)
        self.assertTrue(trust.verify(main_id.certificate))
        self.assertTrue(trust.verify(sub_id1.certificate))
        self.assertFalse(trust.verify(sub_id2.certificate))
        self.assertFalse(trust.verify(main_id2.certificate))


class AsyncOpenDhtTester(unittest.IsolatedAsyncioTestCase):

    async def test_async_observability_and_query_integration(self):
        node, peer = aio.DhtRunner(), aio.DhtRunner()
        changed = asyncio.Event()
        snapshots = []
        def on_status(ipv4, ipv6):
            snapshots.append(node.getNodeInfo())
            changed.set()
        node.setOnStatusChanged(on_status)
        try:
            node.run(ipv4="127.0.0.1", ipv6="::1")
            peer.run(ipv4="127.0.0.1", ipv6="::1")
            self.assertIsNone(node.connectivityChanged())
            self.assertTrue(await asyncio.wait_for(node.ping(peer.getBound(socket.AF_INET)), 5))
            await asyncio.wait_for(changed.wait(), 5)
            self.assertTrue(all(isinstance(info, dht.NodeInfo) for info in snapshots))
            key, value = dht.InfoHash.getRandom(), dht.Value(b"async query")
            value.id, value.user_type = 42, "async"
            self.assertTrue(await asyncio.wait_for(peer.put(key, value), 5))
            query = dht.Query("SELECT id WHERE user_type=async")
            rows = await asyncio.wait_for(node.queryAll(key, query=query), 5)
            self.assertEqual(rows, [{dht.ValueField.Id: 42}])
        finally:
            node.setOnStatusChanged(None)
            await asyncio.gather(node.join(), peer.join())

    async def test_async_query(self):
        core = Mock()
        node = aio.DhtRunner(core=core)
        key = dht.InfoHash.getRandom()
        query = dht.Query("SELECT id")
        task = asyncio.create_task(node.queryAll(key, query=query))
        await asyncio.sleep(0)
        arguments = core.query.call_args.args
        self.assertEqual(arguments[0], key)
        self.assertIs(arguments[3], query)
        row = {dht.ValueField.Id: 42}
        self.assertTrue(arguments[1](row))
        arguments[2](True, [])
        self.assertEqual(await asyncio.wait_for(task, 1), [row])

    async def test_async_listener_filters(self):
        core = Mock()
        node = aio.DhtRunner(core=core)
        key = dht.InfoHash.getRandom()
        where = dht.Where().userType("keep")
        predicate = lambda value: value.data == b"accepted"
        with node.listen(key, where=where, filter=predicate):
            arguments = core.listen.call_args.args
            self.assertEqual(arguments[0], key)
            self.assertIs(arguments[2], predicate)
            self.assertIs(arguments[3], where)

    async def test_async_status_callback_thread(self):
        core = Mock()
        node = aio.DhtRunner(core=core)
        delivered = asyncio.Event()
        thread_ids = []
        def callback(ipv4, ipv6):
            thread_ids.append(threading.get_ident())
            delivered.set()
        node.setOnStatusChanged(callback)
        dispatch = core.setOnStatusChanged.call_args.args[0]
        await asyncio.to_thread(dispatch, dht.NodeStatus.Connected, dht.NodeStatus.Disconnected)
        await asyncio.wait_for(delivered.wait(), 1)
        self.assertEqual(thread_ids, [threading.get_ident()])
        node.setOnStatusChanged(None)
        core.setOnStatusChanged.assert_called_with(None)

    async def test_async_query_failure_and_cancellation(self):
        core = Mock()
        node = aio.DhtRunner(core=core)
        key = dht.InfoHash.getRandom()
        stream = node.query(key)
        callback, done = core.query.call_args.args[1:3]
        done(False, [])
        with self.assertRaisesRegex(RuntimeError, "DHT query failed"):
            await asyncio.wait_for(stream.__anext__(), 1)
        stream = node.query(key)
        callback, done = core.query.call_args.args[1:3]
        stream.cancel()
        self.assertFalse(callback({dht.ValueField.Id: 42}))
        done(True, [])
        with self.assertRaises(StopAsyncIteration):
            await stream.__anext__()

    async def test_async_status_queued_before_removal(self):
        core = Mock()
        node = aio.DhtRunner(core=core)
        callback = Mock()
        node.setOnStatusChanged(callback)
        dispatch = core.setOnStatusChanged.call_args.args[0]
        dispatch(dht.NodeStatus.Connected, dht.NodeStatus.Disconnected)
        node.setOnStatusChanged(None)
        await asyncio.sleep(0)
        callback.assert_not_called()

    def _completion_cases(self):
        key = dht.InfoHash.getRandom()
        value = dht.Value(b"async")
        return (
            ("ping", (dht.SockAddr(),), 1, (True,), True),
            ("put", (key, value), 2, (True, []), True),
            ("putSigned", (key, value), 2, (True, []), True),
            ("putEncrypted", (key, dht.PkId.getRandom(), value), 3, (True, []), True),
            ("shutdown", (), 0, (), None),
        )

    async def test_cancel_listener(self):
        core = Mock()
        node = aio.DhtRunner(core=core)
        listener = node.listen(dht.InfoHash.getRandom())
        pending = asyncio.create_task(listener.__anext__())
        await asyncio.sleep(0)
        await node.cancelListen(listener)
        await node.cancelListen(listener)
        with self.assertRaises(StopAsyncIteration):
            await asyncio.wait_for(pending, 1)
        core.cancelListen.assert_called_once_with(core.listen.return_value)

    async def test_cancelled_completions_are_ignored(self):
        loop = asyncio.get_running_loop()
        errors = []
        self.addCleanup(loop.set_exception_handler, loop.get_exception_handler())
        loop.set_exception_handler(lambda active_loop, context: errors.append(context))
        for name, arguments, callback_index, results, expected in self._completion_cases():
            for queued_first in (False, True):
                with self.subTest(method=name, queued_first=queued_first):
                    core = Mock()
                    node = aio.DhtRunner(core=core)
                    task = asyncio.create_task(getattr(node, name)(*arguments))
                    await asyncio.sleep(0)
                    callback = getattr(core, name).call_args.args[callback_index]
                    if queued_first:
                        callback(*results)
                    task.cancel()
                    if not queued_first:
                        callback(*results)
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    await asyncio.sleep(0)
                    self.assertEqual(errors, [])

    async def test_completions_resolve_once(self):
        loop = asyncio.get_running_loop()
        errors = []
        self.addCleanup(loop.set_exception_handler, loop.get_exception_handler())
        loop.set_exception_handler(lambda active_loop, context: errors.append(context))
        for name, arguments, callback_index, results, expected in self._completion_cases():
            with self.subTest(method=name):
                core = Mock()
                node = aio.DhtRunner(core=core)
                task = asyncio.create_task(getattr(node, name)(*arguments))
                await asyncio.sleep(0)
                callback = getattr(core, name).call_args.args[callback_index]
                callback(*results)
                callback(*results)
                self.assertEqual(await asyncio.wait_for(task, 1), expected)
                await asyncio.sleep(0)
                self.assertEqual(errors, [])

if __name__ == '__main__':
    unittest.main()
