#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2015-2019 Savoir-faire Linux Inc.
# Author(s): Adrien Béraud <adrien.beraud@savoirfairelinux.com>
#            Simon Désaulniers <sim.desaulniers@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import signal
import random
import time
import threading
import queue
import re
import traceback

import ipaddress
import netifaces
import numpy as np
from pyroute2.netns.process.proxy import NSPopen
import msgpack

from opendht import *


# useful functions
b_space_join = lambda *l: b' '.join(map(bytes, l))

class DhtNetworkSubProcess(NSPopen):
    """
    Handles communication with DhtNetwork sub process.

    When instanciated, the object's thread is started and will read the sub
    process' stdout until it finds 'DhtNetworkSubProcess.NOTIFY_TOKEN' token,
    therefor, waits for the sub process to spawn.
    """
    # Packet types
    REQUEST = 'DhtNetworkSubProcess.request'
    ANSWER = 'DhtNetworkSubProcess.answer'
    OUT = 'DhtNetworkSubProcess.out'

    # requests
    PING_REQ                  = "p"
    NODE_PUT_REQ              = "np"   # "np <hash> <value>"
    NEW_NODE_REQ              = "nn"   # "nn"
    REMOVE_NODE_REQ           = "rn"   # "rn <id0>[ <id1>[ id2[...]]]"
    SHUTDOWN_NODE_REQ         = "sdn"  # "sdn <id0>[ <id1>[ id2[...]]]"
    SHUTDOWN_REPLACE_NODE_REQ = "sdrn" # "sdn <id0>[ <id1>[ id2[...]]]"
    SHUTDOWN_CLUSTER_REQ      = "sdc"  # "sdc"
    DUMP_STORAGE_REQ          = "strl" # "strl"
    MESSAGE_STATS             = "gms"  # "gms"

    def __init__(self, ns, cmd, quit=False, **kwargs):
        super(DhtNetworkSubProcess, self).__init__(ns, cmd, **kwargs)
        self._setStdoutFlags()
        self._virtual_ns = ns

        self._quit = quit
        self._lock = threading.Condition()
        self._in_queue = queue.Queue()
        self._callbacks = {}
        self._tid = 0

        # starting thread
        self._thread = threading.Thread(target=self._communicate)
        self._thread.start()

    def __repr__(self):
        return 'DhtNetwork on virtual namespace "%s"' % self._virtual_ns

    def _setStdoutFlags(self):
        """
        Sets non-blocking read flags for subprocess stdout file descriptor.
        """
        import fcntl
        flags = self.stdout.fcntl(fcntl.F_GETFL)
        self.stdout.fcntl(fcntl.F_SETFL, flags | os.O_NDELAY)

    def _communicate(self):
        """
        Communication thread. This reads and writes to the sub process.
        """
        sleep_time = 0.1

        while not self._quit:
            with self._lock:
                try:
                    packet = self._in_queue.get_nowait()

                    # sending data to sub process
                    self.stdin.write(packet)
                    self.stdin.flush()
                except queue.Empty:
                    pass

                # reading from sub process
                out_string = ''
                for p in msgpack.Unpacker(self.stdout):
                    if isinstance(p, dict):
                        self._process_packet(p)
                    else:
                        # Some non-msgpack data could slip into the stream. We
                        # have to treat those as characters.
                        out_string += chr(p)
                if out_string:
                    print(out_string)

                #waiting for next stdin req to send
                self._lock.wait(timeout=sleep_time)

        with self._lock:
            self._lock.notify()

    def _stop_communicating(self):
        """
        Stops the I/O thread from communicating with the subprocess.
        """
        if not self._quit:
            self._quit = True
            with self._lock:
                self._lock.notify()
                self._lock.wait()

    def quit(self):
        """
        Notifies thread and sub process to terminate. This is blocking call
        until the sub process finishes.
        """
        self._stop_communicating()
        self.send_signal(signal.SIGINT);
        self.wait()
        self.release()

    def _send(self, msg):
        """
        Send data to sub process.
        """
        with self._lock:
            self._in_queue.put(msg)
            self._lock.notify()

    def _process_packet(self, p):
        """
        Process msgpack packet received from
        """
        if not b'tid' in p:
            DhtNetwork.Log.err('Bad packet...')
        try:
            self._callbacks[p[b'tid']](p)
        except KeyError:
            DhtNetwork.Log.err('Unknown tid...')


    def _sendRequest(self, request, tid, done_cb):
        """
        Sends a request to the sub network and wait for output.

        @param request: The serialized request.
        @type  request: Msgpack object
        """
        self._callbacks[tid] = done_cb
        self._send(request)

    def sendPing(self, done_cb=None):
        """Sends a ping request to the DhtNetworkSubProcess.

        @param done_cb: The callback to be executed when we get a response. This
                        function takes a boolean "success" as parameter.
        @type  done_cb: Function
        """
        self._tid += 1
        def dcb(packet):
            try:
                done_cb(packet[b'success'])
            except KeyError:
                done_cb(False)
        self._sendRequest(msgpack.packb({
            DhtNetworkSubProcess.REQUEST : True,
            'tid' : self._tid,
            'req' : DhtNetworkSubProcess.PING_REQ
        }), self._tid, dcb)

    def sendGetMessageStats(self, done_cb=None):
        """
        Sends DhtNetwork sub process statistics request about nodes messages
        sent.

        @param done_cb: A function taking as parameter the returned list of
                        stats.
        @type  done_cb: function

        @return: A list [num_nodes, ping, find, get, put, listen].
        @rtype : list
        """
        self._tid += 1
        def dcb(packet):
            nonlocal done_cb
            if not done_cb:
                return
            try:
                stats = packet[b'stats']
                done_cb([] if not isinstance(stats, list) else done_cb(stats))
            except KeyError:
                done_cb([])
        self._sendRequest(msgpack.packb({
            DhtNetworkSubProcess.REQUEST : True,
            'tid' : self._tid,
            'req' : DhtNetworkSubProcess.MESSAGE_STATS
        }), self._tid, dcb)

    def sendClusterPutRequest(self, _hash, value, done_cb=None):
        """
        Sends a put operation request.

        @param _hash: the hash of the value.
        @type  _hash: bytes.
        @param value: the value.
        @type  value: bytes.
        @param done_cb: A function taking as parameter a boolean "success".
        @type  done_cb: function
        """
        self._tid += 1
        def dcb(packet):
            nonlocal done_cb
            if not done_cb:
                return
            try:
                done_cb(packet[b'success'])
            except KeyError:
                done_cb(False)
        self._sendRequest(msgpack.packb({
            DhtNetworkSubProcess.REQUEST : True,
            'tid' : self._tid,
            'req'   : DhtNetworkSubProcess.NODE_PUT_REQ,
            'hash'  : _hash,
            'value' : value
        }), self._tid, dcb)

    def sendClusterRequest(self, request, ids=[], done_cb=None):
        """
        Send request to a list of nodes or the whole cluster.

        @param request: The request. Possible values are:
            DhtNetworkSubProcess.REMOVE_NODE_REQ
            DhtNetworkSubProcess.SHUTDOWN_NODE_REQ
            DhtNetworkSubProcess.SHUTDOWN_REPLACE_NODE_REQ
            DhtNetworkSubProcess.SHUTDOWN_CLUSTER_REQ
            DhtNetworkSubProcess.DUMP_STORAGE_REQ
        @type request: bytes
        @param ids: The list of ids concerned by the request.
        @type  ids: list
        """
        self._tid += 1
        def dcb(packet):
            nonlocal done_cb
            if not done_cb:
                return
            try:
                done_cb(packet[b'success'])
            except KeyError:
                done_cb(False)
        self._sendRequest(msgpack.packb({
            DhtNetworkSubProcess.REQUEST : True,
            'tid' : self._tid,
            'req' : request,
            'ids' : ids
        }), self._tid, dcb)


class DhtNetwork(object):
    nodes = []

    class Log(object):
        BOLD   = "\033[1m"
        NORMAL = "\033[0m"
        WHITE  = "\033[97m"
        RED    = "\033[31m"
        YELLOW = "\033[33m"

        @staticmethod
        def _log_with_color(*to_print, color=None):
            color = color if color else DhtNetwork.Log.WHITE
            print('%s%s[DhtNetwork-%s]%s%s' %
                    (DhtNetwork.Log.BOLD, color, DhtNetwork.iface, DhtNetwork.Log.NORMAL, color),
                    *to_print, DhtNetwork.Log.NORMAL, file=sys.stderr)

        @staticmethod
        def log(*to_print):
            DhtNetwork.Log._log_with_color(*to_print, color=DhtNetwork.Log.WHITE)

        @staticmethod
        def warn(*to_print):
            DhtNetwork.Log._log_with_color(*to_print, color=DhtNetwork.Log.YELLOW)

        @staticmethod
        def err(*to_print):
            DhtNetwork.Log._log_with_color(*to_print, color=DhtNetwork.Log.RED)

    @staticmethod
    def run_node(ip4, ip6, p, bootstrap=[], is_bootstrap=False):
        DhtNetwork.Log.log("run_node", ip4, ip6, p, bootstrap)
        n = DhtRunner()
        n.run(ipv4=ip4 if ip4 else "", ipv6=ip6 if ip6 else "", port=p, is_bootstrap=is_bootstrap)
        for b in bootstrap:
            n.bootstrap(b[0], b[1])
        time.sleep(.01)
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
            DhtNetwork.Log.log("Starting bootstrap node")
            self.nodes.append(DhtNetwork.run_node(self.ip4, self.ip6, self.port, self.bootstrap, is_bootstrap=True))
            self.bootstrap = [(self.ip4, str(self.port))]
            self.port += 1
        #print(self.ip4, self.ip6, self.port)

    def front(self):
        if len(self.nodes) == 0:
            return None
        return self.nodes[0][1]

    def get(self, i=None):
        if not self.nodes:
            return None

        if i is None:
            l = list(self.nodes)
            random.shuffle(l)
            return l[0][1]
        else:
            return self.nodes[i][1]

    def getNodeInfoById(self, id=None):
        if id:
            for n in self.nodes:
                if n[1].getNodeId() == id:
                    return n
        return None

    def launch_node(self):
        n = DhtNetwork.run_node(self.ip4, self.ip6, self.port, self.bootstrap)
        self.nodes.append(n)
        if not self.bootstrap:
            DhtNetwork.Log.log("Using fallback bootstrap", self.ip4, self.port)
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
            DhtNetwork.Log.log('Done.')
            with lock:
                lock.notify()

        if not self.nodes:
            return
        elif id:
            n = self.getNodeInfoById(id)
            if n:
                if shutdown:
                    with lock:
                        DhtNetwork.Log.log('Waiting for node to shutdown... ')
                        n[1].shutdown(shutdown_cb)
                        lock.wait()
                    if last_msg_stats:
                        last_msg_stats.append(self.getMessageStats())
                n[1].join()
                self.nodes.remove(n)
                DhtNetwork.Log.log(id, 'deleted !')
                return True
            else:
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
            DhtNetwork.Log.log("Launching", n-l, "nodes", self.ip4, self.ip6)
            for i in range(l, n):
                self.launch_node()
        else:
            DhtNetwork.Log.log("Ending", l-n, "nodes", self.ip4, self.ip6)
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

    def send_msgpack_packet(packet):
        sys.stdout.buffer.write(packet)
        sys.stdout.buffer.flush()

    def notify_benchmark(packet, success):
        """Notifies the benchmark when an operation has been completed.

        @param success: If the operation has been successful
        @type  success: boolean
        @param packet: The packet we are providing an answer for.
        @type  packet: dict
        """
        send_msgpack_packet(msgpack.packb({
            DhtNetworkSubProcess.ANSWER : True,
            'tid'     : packet[b'tid'],
            'success' : success
        }))

    def send_stats(packet, stats):
        send_msgpack_packet(msgpack.packb({
            DhtNetworkSubProcess.ANSWER : True,
            'tid'   : packet[b'tid'],
            'stats' : stats
        }))

    def listen_to_mother_nature(q):
        global quit
        while not quit:
            for p in msgpack.Unpacker(sys.stdin.buffer.raw):
                if isinstance(p, dict) and DhtNetworkSubProcess.REQUEST.encode() in p:
                    with lock:
                        q.put(p)
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
        t = threading.Thread(target=listen_to_mother_nature, args=tuple([q]))
        t.daemon = True
        t.start()

        msg_stats = []

        with lock:
            while not quit:
                try:
                    packet = q.get_nowait()
                except queue.Empty:
                    lock.wait()
                else:
                    NODE_PUT_REQ              = DhtNetworkSubProcess.NODE_PUT_REQ
                    NEW_NODE_REQ              = DhtNetworkSubProcess.NEW_NODE_REQ
                    REMOVE_NODE_REQ           = DhtNetworkSubProcess.REMOVE_NODE_REQ
                    SHUTDOWN_NODE_REQ         = DhtNetworkSubProcess.SHUTDOWN_NODE_REQ
                    SHUTDOWN_REPLACE_NODE_REQ = DhtNetworkSubProcess.SHUTDOWN_REPLACE_NODE_REQ
                    SHUTDOWN_CLUSTER_REQ      = DhtNetworkSubProcess.SHUTDOWN_CLUSTER_REQ
                    DUMP_STORAGE_REQ          = DhtNetworkSubProcess.DUMP_STORAGE_REQ
                    MESSAGE_STATS             = DhtNetworkSubProcess.MESSAGE_STATS

                    req = packet[b'req'].decode()
                    success = True
                    if req in [SHUTDOWN_NODE_REQ, SHUTDOWN_REPLACE_NODE_REQ, REMOVE_NODE_REQ]:
                        def delete_request(req, nid):
                            global msg_stats
                            if not nid:
                                return
                            if req == SHUTDOWN_NODE_REQ:
                                net.end_node(id=nid, shutdown=True, last_msg_stats=msg_stats)
                            elif req == SHUTDOWN_REPLACE_NODE_REQ:
                                net.replace_node(id=nid, shutdown=True, last_msg_stats=msg_stats)
                            elif req == REMOVE_NODE_REQ:
                                net.end_node(id=nid, last_msg_stats=msg_stats)

                        nodes = packet[b'ids']
                        if nodes:
                            for nid in nodes:
                                delete_request(req, nid)
                        else:
                            n = net.get()
                            if n:
                                delete_request(req, n.getNodeId())
                            else:
                                success = False
                    elif req == SHUTDOWN_CLUSTER_REQ:
                        for n in net.nodes:
                            net.end_node(id=n[2], shutdown=True, last_msg_stats=msg_stats)
                        quit = True
                    elif req == NEW_NODE_REQ:
                        net.launch_node()
                    elif req == NODE_PUT_REQ:
                        _hash = packet[b'hash']
                        v = packet[b'value']
                        n = net.get()
                        if n:
                            n.put(InfoHash(_hash), Value(v))
                        else:
                            success = False
                    elif req == DUMP_STORAGE_REQ:
                        hashes = packet[b'ids']
                        for n in [m[1] for m in net.nodes if m[1].getNodeId() in hashes]:
                            net.log(n.getStorageLog())
                    elif req == MESSAGE_STATS:
                        stats = sum([np.array(x) for x in [net.getMessageStats()]+msg_stats])
                        send_stats(packet, [int(_) for _ in stats])
                        msg_stats.clear()
                        continue
                    notify_benchmark(packet, success)
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        print(type(e).__name__+':', e, file=sys.stderr)
    finally:
        if net:
            net.resize(0)
