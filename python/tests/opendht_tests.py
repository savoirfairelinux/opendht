import unittest
import opendht as dht

class OpenDhtTester(unittest.TestCase):

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
        self.assertTrue(b.bootstrap(a.getBound()))

if __name__ == '__main__':
    unittest.main()
