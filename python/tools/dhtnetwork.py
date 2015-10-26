#!/usr/bin/env python3
# Copyright (C) 2015 Savoir-Faire Linux Inc.
# Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>

import sys
import signal
import random
import time
import threading
import queue

import ipaddress
import netifaces

import numpy as np

from opendht import *

class DhtNetwork(object):
    nodes = []

    @staticmethod
    def log(*to_print):
        BOLD   = "\033[1m"
        NORMAL = "\033[0m"
        print('%s[DhtNetwork-%s]%s' % (BOLD, DhtNetwork.iface, NORMAL), ':' , *to_print, file=sys.stderr)

    @staticmethod
    def run_node(ip4, ip6, p, bootstrap=[], is_bootstrap=False):
        DhtNetwork.log("run_node", ip4, ip6, p, bootstrap)
        id = Identity()
        #id.generate("dhtbench"+str(p), Identity(), 1024)
        n = DhtRunner()
        n.run(id, ipv4=ip4 if ip4 else "", ipv6=ip6 if ip6 else "", port=p, is_bootstrap=is_bootstrap)
        for b in bootstrap:
            n.bootstrap(b[0], b[1])
        #plt.pause(0.02)
        return ((ip4, ip6, p), n, id)

    @staticmethod
    def find_ip(iface):
        if not iface or iface == 'any':
            return ('0.0.0.0','')

        if_ip4 = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        if_ip6 = netifaces.ifaddresses(iface)[netifaces.AF_INET6][0]['addr']
        return (if_ip4, if_ip6)

    def __init__(self, iface=None, ip4=None, ip6=None, port=4000, bootstrap=[], first_bootstrap=False):
        DhtNetwork.iface = iface
        self.port = port
        ips = DhtNetwork.find_ip(iface)
        self.ip4 = ip4 if ip4 else ips[0]
        self.ip6 = ip6 if ip6 else ips[1]
        self.bootstrap = bootstrap
        if first_bootstrap:
            DhtNetwork.log("Starting bootstrap node")
            self.nodes.append(DhtNetwork.run_node(self.ip4, self.ip6, self.port, self.bootstrap, is_bootstrap=True))
            self.bootstrap = [(self.ip4, str(self.port))]
            self.port += 1
        #print(self.ip4, self.ip6, self.port)

    def front(self):
        if len(self.nodes) == 0:
            return None
        return self.nodes[0][1]

    def get(self, n):
        return self.nodes[n][1]

    def launch_node(self):
        n = DhtNetwork.run_node(self.ip4, self.ip6, self.port, self.bootstrap)
        self.nodes.append(n)
        if not self.bootstrap:
            DhtNetwork.log("Using fallback bootstrap", self.ip4, self.port)
            self.bootstrap = [(self.ip4, str(self.port))]
        self.port += 1
        return n

    def end_node(self, id=None, shutdown=False, last_msg_stats=None):
        """
        Ends a running node.
        
        @param id: The 40 hex chars id of the node.
        @type  id: bytes
        
        @return: If a node was deleted or not.
        @rtype : boolean
        """
        lock = threading.Condition()
        def shutdown_cb():
            nonlocal lock
            DhtNetwork.log('Done.')
            with lock:
                lock.notify()

        if not self.nodes:
            return
        if id is not None:
            for n in self.nodes:
                if n[1].getNodeId() == id:
                    if shutdown:
                        with lock:
                            DhtNetwork.log('Waiting for node to shutdown... ')
                            n[1].shutdown(shutdown_cb)
                            lock.wait()
                        if last_msg_stats:
                            last_msg_stats.append(self.getMessageStats())
                    n[1].join()
                    self.nodes.remove(n)
                    DhtNetwork.log(id, 'deleted !')
                    return True
            return False
        else:
            n = self.nodes.pop()
            n[1].join()
            return True

    def replace_node(self, id=None, shutdown=False, last_msg_stats=None):
        random.shuffle(self.nodes)
        deleted = self.end_node(id=id, shutdown=shutdown, last_msg_stats=last_msg_stats)
        if deleted:
            self.launch_node()

    def resize(self, n):
        n = min(n, 500)
        l = len(self.nodes)
        if n == l:
            return
        if n > l:
            DhtNetwork.log("Launching", n-l, "nodes")
            for i in range(l, n):
                self.launch_node()
        else:
            DhtNetwork.log("Ending", l-n, "nodes")
            #random.shuffle(self.nodes)
            for i in range(n, l):
                self.end_node()

    def getMessageStats(self):
        stats = np.array([0,0,0,0,0])
        for n in self.nodes:
            stats +=  np.array(n[1].getNodeMessageStats())
        stats_list = [len(self.nodes)]
        stats_list.extend(stats.tolist())
        return stats_list

if __name__ == '__main__':
    import argparse

    lock = threading.Condition()
    quit = False

    def notify_benchmark(answer=None):
        NOTIFY_TOKEN     = 'notify'
        NOTIFY_END_TOKEN = 'notifyend'

        sys.stdout.write('%s\n' % NOTIFY_TOKEN)
        for line in answer if answer else []:
            sys.stdout.write(str(line)+'\n')
        sys.stdout.write('%s\n' % NOTIFY_END_TOKEN)
        sys.stdout.flush()

    def listen_to_mother_nature(stdin, q):
        global quit

        def parse_req(req):
            split_req = req.split(' ')

            op = split_req[0]
            hashes = [this_hash.replace('\n', '').encode() for this_hash in split_req[1:]]

            return (op, hashes)

        while not quit:
            req = stdin.readline()
            parsed_req = parse_req(req)
            q.put(parsed_req)
            with lock:
                lock.notify()

    def handler(signum, frame):
        global quit
        with lock:
            quit = True
            lock.notify()

    signal.signal(signal.SIGALRM, handler)
    signal.signal(signal.SIGABRT, handler)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    net = None
    try:
        parser = argparse.ArgumentParser(description='Create a dht network of -n nodes')
        parser.add_argument('-n', '--node-num', help='number of dht nodes to run', type=int, default=32)
        parser.add_argument('-I', '--iface', help='local interface to bind', default='any')
        parser.add_argument('-p', '--port', help='start of port range (port, port+node_num)', type=int, default=4000)
        parser.add_argument('-b', '--bootstrap', help='bootstrap address')
        parser.add_argument('-b6', '--bootstrap6', help='bootstrap address (IPv6)')
        parser.add_argument('-bp', '--bootstrap-port', help='bootstrap port', default="4000")
        args = parser.parse_args()

        bs = []
        if args.bootstrap:
            bs.append((args.bootstrap, args.bootstrap_port))
        if args.bootstrap6:
            bs.append((args.bootstrap6, args.bootstrap_port))

        net = DhtNetwork(iface=args.iface, port=args.port, bootstrap=bs)
        net.resize(args.node_num)

        q = queue.Queue()
        t = threading.Thread(target=listen_to_mother_nature, args=(sys.stdin, q))
        t.daemon = True
        t.start()

        notify_benchmark()

        msg_stats = []

        with lock:
            while not quit:
                lock.wait()
                try:
                    req,req_args = q.get_nowait()
                except queue.Empty:
                    pass
                else:
                    REMOVE_NODE_REQ           = 'rn'
                    SHUTDOWN_NODE_REQ         = 'sdn'
                    SHUTDOWN_REPLACE_NODE_REQ = 'sdrn'
                    SHUTDOWN_CLUSTER_REQ      = 'sdc'
                    DUMP_STORAGE_REQ          = 'strl'
                    MESSAGE_STATS             = 'gms'

                    if req in [SHUTDOWN_NODE_REQ,
                               SHUTDOWN_REPLACE_NODE_REQ,
                               REMOVE_NODE_REQ]:
                        DhtNetwork.log('got node deletion request.')
                        for n in req_args:
                            if req == SHUTDOWN_NODE_REQ:
                                net.end_node(id=n, shutdown=True, last_msg_stats=msg_stats)
                            elif req == SHUTDOWN_REPLACE_NODE_REQ:
                                net.replace_node(id=n, shutdown=True, last_msg_stats=msg_stats)
                            elif req == REMOVE_NODE_REQ:
                                net.end_node(id=n, last_msg_stats=msg_stats)
                    elif req == SHUTDOWN_CLUSTER_REQ:
                        for n in net.nodes:
                            n.end_node(shutdown=True, last_msg_stats=msg_stats)
                        quit = True
                    elif req == DUMP_STORAGE_REQ:
                        for n in [m[1] for m in net.nodes if m[1].getNodeId() in req_args]:
                            net.log(n.getStorageLog())
                    elif MESSAGE_STATS in req:
                        stats = sum([np.array(x) for x in [net.getMessageStats()]+msg_stats])
                        notify_benchmark(answer=[stats])
                        msg_stats.clear()
                        continue
                    notify_benchmark()
    except Exception as e:
        DhtNetwork.log(e)
    finally:
        if net:
            net.resize(0)
