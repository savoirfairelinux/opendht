import gc
import threading
import unittest
import weakref
import opendht as dht

class _ListenerCallback:
    def __call__(self, value, expired):
        return True

class OpenDhtTester(unittest.TestCase):

    def _run_node(self, **kwargs):
        node = dht.DhtRunner()
        self.addCleanup(node.join)
        node.run(**kwargs)
        return node

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

if __name__ == '__main__':
    unittest.main()
