#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Savoir-faire Linux Inc.
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

import ipaddress
import netifaces
import numpy as np
from pyroute2.netns.process.proxy import NSPopen

from opendht import *


# useful functions
b_space_join = lambda *l: b' '.join(map(bytes, l))

# TODO: find where token "notifyend" gets printed... Or switch to MSGPACK for
# serialisation of packets between both processes.
class DhtNetworkSubProcess(NSPopen):
    """
    Handles communication with DhtNetwork sub process.

    When instanciated, the object's thread is started and will read the sub
    process' stdout until it finds 'DhtNetworkSubProcess.NOTIFY_TOKEN' token,
    therefor, waits for the sub process to spawn.
    """
    # requests
    NODE_PUT_REQ              = b"np"
    NEW_NODE_REQ              = b"nn"
    REMOVE_NODE_REQ           = b"rn"
    SHUTDOWN_NODE_REQ         = b"sdn"
    SHUTDOWN_REPLACE_NODE_REQ = b'sdrn'
    SHUTDOWN_CLUSTER_REQ      = b"sdc"
    DUMP_STORAGE_REQ          = b"strl"
    MESSAGE_STATS             = b"gms"


    # tokens
    NOTIFY_TOKEN     = 'notify'
    NOTIFY_END_TOKEN = 'notifyend'

    def __init__(self, ns, cmd, quit=False, **kwargs):
        super(DhtNetworkSubProcess, self).__init__(ns, cmd, **kwargs)
        self._setStdoutFlags()
        self._virtual_ns = ns

        self._quit = quit
        self._lock = threading.Condition()
        self._in_queue = queue.Queue()
        self._out_queue = queue.Queue()

        # starting thread
        self._thread = threading.Thread(target=self._communicate)
        self._thread.daemon = True
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
        ENCODING = 'utf-8'
        sleep_time = 0.1
        stdin_line, stdout_line = '', ''

        # first read of process living. Expecting NOTIFY_TOKEN
        while DhtNetworkSubProcess.NOTIFY_TOKEN not in stdout_line:
            stdout_line = self.stdout.readline().decode()
            time.sleep(sleep_time)

        with self._lock:
            self._out_queue.put(stdout_line)

        while not self._quit:
            with self._lock:
                try:
                    stdin_line = self._in_queue.get_nowait()

                    # sending data to sub process
                    self.stdin.write(stdin_line if isinstance(stdin_line, bytes) else
                            bytes(str(stdin_line), encoding=ENCODING))
                    self.stdin.flush()
                except queue.Empty:
                    #waiting for next stdin req to send
                    self._lock.wait(timeout=sleep_time)

            # reading response from sub process
            for stdout_line in iter(self.stdout.readline, b''):
                stdout_line = stdout_line.decode().replace('\n', '')
                if stdout_line:
                    with self._lock:
                        self._out_queue.put(stdout_line)

        with self._lock:
            self._lock.notify()

    def stop_communicating(self):
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
        self.stop_communicating()
        self.send_signal(signal.SIGINT);
        self.wait()
        self.release()

    def send(self, msg):
        """
        Send data to sub process.
        """
        with self._lock:
            self._in_queue.put(msg)
            self._lock.notify()

    def getline(self):
        """
        Read line from sub process.

        @return:  A line on sub process' stdout.
        @rtype :  str
        """
        line = ''
        with self._lock:
            try:
                line = self._out_queue.get_nowait()
            except queue.Empty:
                pass
        return line

    def getlinesUntilNotify(self, answer_cb=None):
        """
        Reads the stdout queue until a proper notification is given by the sub
        process.

        @param answer_cb: Callback to call when an answer is given after notify.
                          The function takes a list of strings as argument.
        @type  answer_cb:  function
        """
        notified = False
        answer = []
        while True:
            out = self.getline()
            if out.split(' ')[0] == DhtNetworkSubProcess.NOTIFY_TOKEN:
                notified = True
            elif notified and out.split(' ')[0] == DhtNetworkSubProcess.NOTIFY_END_TOKEN:
                if answer_cb:
                    answer_cb(answer)
                break
            elif notified:
                answer.append(out)
            elif out:
                yield out
            else:
                time.sleep(0.1)

    def _sendRequest(self, request, answer_cb=None):
        """
        Sends a request to the sub network and wait for output.

        @param request: The serialized request.
        @type  request: bytes
        """
        self.send(request + b'\n')
        for line in self.getlinesUntilNotify(answer_cb=answer_cb):
            DhtNetwork.log(line)

    def sendGetMessageStats(self):
        """
        Sends DhtNetwork sub process statistics request about nodes messages
        sent.

        @return: A list [num_nodes, ping, find, get, put, listen].
        @rtype : list
        """
        stats = []
        def cb(answer):
            """
            Callback fed to getlinesUntilNotify made to recover answer from the
            DhtNetwork sub process.

            @param answer: the list of lines answered by the sub process.
            @type  answer: function
            """
            nonlocal stats
            if answer:
                stats = [int(v) for v in re.findall("[0-9]+", answer.pop())]

        self._sendRequest(DhtNetworkSubProcess.MESSAGE_STATS, answer_cb=cb)
        return stats

    def sendNodePutRequest(self, _hash, value):
        """
        Sends a put operation request.

        @param _hash: the hash of the value.
        @type  _hash: bytes.
        @param value: the value.
        @type  value: bytes.
        """
        self._sendRequest(b_space_join(DhtNetworkSubProcess.NODE_PUT_REQ, _hash,
            value))

    def sendNodesRequest(self, request, ids=b''):
        """
        Send request to a list of nodes or the whole cluster.

        @param request: The request. Possible values are:
            DhtNetworkSubProcess.NODE_PUT_REQ
            DhtNetworkSubProcess.REMOVE_NODE_REQ
            DhtNetworkSubProcess.SHUTDOWN_NODE_REQ
            DhtNetworkSubProcess.SHUTDOWN_REPLACE_NODE_REQ
            DhtNetworkSubProcess.SHUTDOWN_CLUSTER_REQ
            DhtNetworkSubProcess.DUMP_STORAGE_REQ
            DhtNetworkSubProcess.MESSAGE_STATS
        @type request: bytes
        @param ids: The list of ids concerned by the request.
        @type  ids: list
        """
        self._sendRequest(b_space_join(request, b_space_join(*ids)))

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
            DhtNetwork.log("Starting bootstrap node")
            self.nodes.append(DhtNetwork.run_node(self.ip4, self.ip6, self.port, self.bootstrap, is_bootstrap=True))
            self.bootstrap = [(self.ip4, str(self.port))]
            self.port += 1
        #print(self.ip4, self.ip6, self.port)

    def front(self):
        if len(self.nodes) == 0:
            return None
        return self.nodes[0][1]

    def get(self, i=None):
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
        else:
            return None

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
        elif id is not None:
            n = self.getNodeInfoById(id)
            if n:
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
            DhtNetwork.log("Launching", n-l, "nodes", self.ip4, self.ip6)
            for i in range(l, n):
                self.launch_node()
        else:
            DhtNetwork.log("Ending", l-n, "nodes", self.ip4, self.ip6)
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

    def notify_benchmark(answer=[]):
        sys.stdout.write('%s\n' % DhtNetworkSubProcess.NOTIFY_TOKEN)
        for line in answer:
            sys.stdout.write(str(line)+'\n')
        sys.stdout.write('%s\n' % DhtNetworkSubProcess.NOTIFY_END_TOKEN)
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
                    NODE_PUT_REQ              = DhtNetworkSubProcess.NODE_PUT_REQ.decode()
                    NEW_NODE_REQ              = DhtNetworkSubProcess.NEW_NODE_REQ.decode()
                    REMOVE_NODE_REQ           = DhtNetworkSubProcess.REMOVE_NODE_REQ.decode()
                    SHUTDOWN_NODE_REQ         = DhtNetworkSubProcess.SHUTDOWN_NODE_REQ.decode()
                    SHUTDOWN_REPLACE_NODE_REQ = DhtNetworkSubProcess.SHUTDOWN_REPLACE_NODE_REQ.decode()
                    SHUTDOWN_CLUSTER_REQ      = DhtNetworkSubProcess.SHUTDOWN_CLUSTER_REQ.decode()
                    DUMP_STORAGE_REQ          = DhtNetworkSubProcess.DUMP_STORAGE_REQ.decode()
                    MESSAGE_STATS             = DhtNetworkSubProcess.MESSAGE_STATS.decode()

                    if req in [SHUTDOWN_NODE_REQ,
                               SHUTDOWN_REPLACE_NODE_REQ,
                               REMOVE_NODE_REQ]:
                        def delete_request(req, n):
                            global msg_stats
                            if req == SHUTDOWN_NODE_REQ:
                                net.end_node(id=n, shutdown=True, last_msg_stats=msg_stats)
                            elif req == SHUTDOWN_REPLACE_NODE_REQ:
                                net.replace_node(id=n, shutdown=True, last_msg_stats=msg_stats)
                            elif req == REMOVE_NODE_REQ:
                                net.end_node(id=n, last_msg_stats=msg_stats)

                        if len(req) > 0:
                            for n in req_args:
                                delete_request(req, n)
                        else:
                            delete_request(req, net.get().getNodeId())
                    elif req == SHUTDOWN_CLUSTER_REQ:
                        for n in net.nodes:
                            net.end_node(id=n[2], shutdown=True, last_msg_stats=msg_stats)
                        quit = True
                    elif req == NEW_NODE_REQ:
                        net.launch_node()
                    elif req == NODE_PUT_REQ:
                        _hash, v = req_args[:2]
                        net.get().put(InfoHash(_hash), Value(v))

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
