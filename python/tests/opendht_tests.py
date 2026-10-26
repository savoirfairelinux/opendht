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

    def test_persistence_configuration(self):
        with TemporaryDirectory() as directory:
            state_path = Path(directory) / "state-\u00e9"
            config = dht.DhtConfig()
            config.setPersistPath(str(state_path))
            first = self._run_node(config=config)
            node_id = first.getNodeId()
            port = first.getBound(socket.AF_INET).getPort()
            self.assertNotEqual(port, 0)
            first.join()
            self.assertTrue(state_path.is_file())
            self.assertTrue(Path(str(state_path) + "_port.txt").is_file())

            restored_config = dht.DhtConfig()
            restored_config.setPersistPath(str(state_path))
            second = self._run_node(config=restored_config)
            self.assertEqual(second.getNodeId(), node_id)
            self.assertEqual(second.getBound(socket.AF_INET).getPort(), port)
            second.join()

    def test_disable_persistence(self):
        with TemporaryDirectory() as directory:
            config = dht.DhtConfig()
            config.setPersistPath(str(Path(directory) / "state"))
            config.setPersistPath("")
            node = self._run_node(config=config)
            node.join()
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
        a = dht.DhtRunner()
        a.run()
        b = dht.DhtRunner()
        b.run()
        self.assertTrue(b.ping(a.getBound()))

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
