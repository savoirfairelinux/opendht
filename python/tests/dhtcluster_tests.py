import runpy
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import netifaces


class NodeClusterTester(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = Path(__file__).resolve().parents[1] / 'tools' / 'dhtcluster.py'
        with patch.dict('sys.modules', {'opendht': Mock()}):
            cls.NodeCluster = runpy.run_path(str(script))['NodeCluster']

    def test_find_ip_interface(self):
        addresses = {
            netifaces.AF_INET: [{'addr': '127.0.0.1'}],
            netifaces.AF_INET6: [{'addr': '::1'}],
        }
        with patch('netifaces.ifaddresses', return_value=addresses) as ifaddresses:
            self.assertEqual(self.NodeCluster.find_ip('lo'), ('127.0.0.1', '::1'))
        self.assertTrue(ifaddresses.called)
        self.assertTrue(all(call.args == ('lo',) for call in ifaddresses.call_args_list))

    def test_find_ip_any(self):
        with patch('netifaces.ifaddresses') as ifaddresses:
            for iface in (None, '', 'any'):
                with self.subTest(iface=iface):
                    self.assertEqual(self.NodeCluster.find_ip(iface), ('0.0.0.0', '::0'))
        ifaddresses.assert_not_called()


if __name__ == '__main__':
    unittest.main()
