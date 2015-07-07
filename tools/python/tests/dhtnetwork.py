import signal, os, sys, ipaddress
from pyroute2 import IPDB

sys.path.append('..')
from opendht import *

class DhtNetwork(object):
    nodes = []

    @staticmethod
    def run_node(ip4, ip6, p, bootstrap=[]):
        #print("run_node", ip4, ip6, p, bootstrap)
        id = PyIdentity()
        id.generate("dhtbench"+str(p), PyIdentity(), 1024)
        n = PyDhtRunner()
        n.run(id, ipv4=ip4 if ip4 else "", ipv6=ip6 if ip6 else "", port=p)
        for b in bootstrap:
            n.bootstrap(b[0], b[1])
        #plt.pause(0.02)
        return ((ip4, ip6, p), n, id)

    @staticmethod
    def find_ip(iface):
        if not iface or iface == 'any':
            return ('0.0.0.0','')
        if_ip4 = None
        if_ip6 = None
        ipdb = IPDB()
        try:
            for ip in ipdb.interfaces[iface].ipaddr:
                if_ip = ipaddress.ip_address(ip[0])
                if isinstance(if_ip, ipaddress.IPv4Address):
                    if_ip4 = ip[0]
                elif isinstance(if_ip, ipaddress.IPv6Address):
                    if not if_ip.is_link_local:
                        if_ip6 = ip[0]
                if if_ip4 and if_ip6:
                    break
        except Exception as e:
            pass
        finally:
            ipdb.release()
        return (if_ip4, if_ip6)

    def __init__(self, iface=None, ip4=None, ip6=None, port=4000, bootstrap=[]):
        self.port = port
        ips = DhtNetwork.find_ip(iface)
        self.ip4 = ip4 if ip4 else ips[0]
        self.ip6 = ip6 if ip6 else ips[1]
        self.bootstrap = bootstrap
        #print(self.ip4, self.ip6, self.port)

    def front(self):
        if len(self.nodes) == 0:
            return None
        return self.nodes[0][1]

    def launch_node(self):
        n = DhtNetwork.run_node(self.ip4, self.ip6, self.port, self.bootstrap)
        self.nodes.append(n)
        self.port += 1
        return n

    def end_node(self):
        if not self.nodes:
            return
        random.shuffle(self.nodes)
        n = self.nodes.pop()
        n[1].join()

    def replace_node(self):
        self.end_node()
        self.launch_node()

    def resize(self, n):
        n = min(n, 500)
        l = len(self.nodes)
        if n == l:
            return
        if n > l:
            print("Launching", n-l, "nodes to reach", n)
            for i in range(l, n):
                self.launch_node()
        else:
            print("Ending", l-n, "nodes to reach", n)
            for i in range(n, l):
                self.end_node()

if __name__ == '__main__':
    import argparse, threading

    lock = threading.Condition()
    quit = False

    def handler(signum, frame):
        global quit
        with lock:
            quit = True
            lock.notify()

    signal.signal(signal.SIGALRM, handler)
    signal.signal(signal.SIGABRT, handler)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    try:
        parser = argparse.ArgumentParser(description='Create a dht network of -n nodes')
        parser.add_argument('-n', '--node-num', help='number of dht nodes to run', type=int, default=32)
        parser.add_argument('-I', '--iface', help='local interface to bind', default='any')
        parser.add_argument('-p', '--port', help='start of port range (port, port+node_num)', type=int, default=4000)
        parser.add_argument('-b', '--bootstrap', help='bootstrap address')
        parser.add_argument('-b6', '--bootstrap6', help='bootstrap address (IPv6)')
        args = parser.parse_args()

        bs = []
        if args.bootstrap:
            bs.append((args.bootstrap, str(4000)))
        if args.bootstrap6:
            bs.append((args.bootstrap6, str(4000)))

        net = DhtNetwork(iface=args.iface, port=args.port, bootstrap=bs if args.bootstrap else [])
        net.resize(args.node_num)

        with lock:
            while not quit:
                lock.wait()
    except Exception as e:
        pass
