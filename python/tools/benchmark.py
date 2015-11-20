#!/usr/bin/env python3
# Copyright (C) 2015-2016 Savoir-faire Linux Inc.
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
import subprocess
import time
import random
import string
import threading
import queue
import signal
import argparse
import re

from pyroute2.netns.process.proxy import NSPopen
import numpy as np
import matplotlib.pyplot as plt

from dhtnetwork import DhtNetwork
from opendht import *

class WorkBench():
    """
    This contains the initialisation information, such as ipv4/ipv6, number of
    nodes and cluster to create, etc. This class is also used to initialise and
    finish the network.
    """
    def __init__(self, ifname='ethdht', virtual_locs=8, node_num=32, remote_bootstrap=None, loss=0, delay=0, disable_ipv4=False,
            disable_ipv6=False):
        self.ifname       = ifname
        self.virtual_locs = virtual_locs
        self.node_num     = node_num
        self.clusters     = min(virtual_locs, node_num)
        self.node_per_loc = int(self.node_num / self.clusters)
        self.loss         = loss
        self.delay        = delay
        self.disable_ipv4 = disable_ipv4
        self.disable_ipv6 = disable_ipv6

        self.remote_bootstrap = remote_bootstrap
        self.local_bootstrap  = None
        self.bs_port          = "5000"
        self.procs            = [None for _ in range(self.clusters)]

    def get_bootstrap(self):
        if not self.local_bootstrap:
            self.local_bootstrap = DhtNetwork(iface='br'+self.ifname,
                    first_bootstrap=False if self.remote_bootstrap else True,
                    bootstrap=[(self.remote_bootstrap, self.bs_port)] if self.remote_bootstrap else [])
        return self.local_bootstrap

    def create_virtual_net(self):
        if self.virtual_locs > 1:
            cmd = ["python3", "virtual_network_builder.py", "-i", self.ifname, "-n", str(self.clusters), '-l', str(self.loss), '-d', str(self.delay)]
            if not self.disable_ipv4:
                cmd.append('-4')
            if not self.disable_ipv6:
                cmd.append('-6')
            print(cmd)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            output, err = p.communicate()
            print(output.decode())

    def destroy_virtual_net(self):
        print('Shuting down the virtual IP network.')
        subprocess.call(["python3", "virtual_network_builder.py", "-i", self.ifname, "-n", str(self.clusters), "-r"])

    def start_cluster(self, i):
        if self.local_bootstrap:
            cmd = ["python3", "dhtnetwork.py", "-n", str(self.node_per_loc), '-I', self.ifname+str(i)+'.1']
            if self.remote_bootstrap:
                cmd.extend(['-b', self.remote_bootstrap, '-bp', "5000"])
            else:
                if not self.disable_ipv4 and self.local_bootstrap.ip4:
                    cmd.extend(['-b', self.local_bootstrap.ip4])
                if not self.disable_ipv6 and self.local_bootstrap.ip6:
                    cmd.extend(['-b6', self.local_bootstrap.ip6])
            self.procs[i] = DhtNetworkSubProcess('node'+str(i), cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            while DhtNetworkSubProcess.NOTIFY_TOKEN not in self.procs[i].getline():
                # waiting for process to spawn
                time.sleep(0.5)
        else:
            raise Exception('First create bootstrap.')

    def stop_cluster(self, i):
        """
        Stops a cluster sub process. All nodes are put down without graceful
        shutdown.
        """
        if self.procs[i]:
            try:
                self.procs[i].quit()
            except Exception as e:
                print(e)
            self.procs[i] = None

    def replace_cluster(self):
        """
        Same as stop_cluster(), but creates a new cluster right after.
        """
        n = random.randrange(0, self.clusters)
        self.stop_cluster(n)
        self.start_cluster(n)

    def resize_clusters(self, n):
        """
        Resizes the list of clusters to be of length ``n``.
        """
        procs_count = len(self.procs)
        if procs_count < n:
            for i in range(n-procs_count):
                self.procs.append(None)
                self.start_cluster(procs_count+i)
        else:
            for i in range(procs_count-n):
                self.stop_cluster(procs_count-i-1)


class DhtNetworkSubProcess(NSPopen):
    """
    Handles communication with DhtNetwork sub process.

    When instanciated, the object's thread is started and will read the sub
    process' stdout until it finds 'DhtNetworkSubProcess.NOTIFY_TOKEN' token,
    therefor, waits for the sub process to spawn.
    """
    # requests
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
                          The function takes a list of lines as argument.
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

            :answer: the list of lines answered by the sub process.
            """
            nonlocal stats
            if answer:
                stats = [int(v) for v in re.findall("[0-9]+", answer.pop())]

        self.send(DhtNetworkSubProcess.MESSAGE_STATS + b'\n')
        for line in self.getlinesUntilNotify(answer_cb=cb):
            DhtNetwork.log(line)

        return stats

    def sendNodesRequest(self, request, ids):
        """
        Shutsdown nodes on the DhtNetwork sub process.

        @param request: The request
        @type  request: bytes
        @param     ids: ids of nodes concerned by the request.
        @type      ids: list
        """
        serialized_req = request + b' ' + b' '.join(map(bytes, ids))
        self.send(serialized_req + b'\n')
        for line in self.getlinesUntilNotify():
            DhtNetwork.log(line)

    def sendShutdown(self):
        """
        Shutdown the whole cluster. This does not terminate comunicating thread;
        use quit().
        """
        self.send(DhtNetworkSubProcess.SHUTDOWN_CLUSTER_REQ + b'\n')
        for line in self.getlinesUntilNotify():
            DhtNetwork.log(line)

    def sendDumpStorage(self, ids):
        """
        Dumps storage log from nodes with id in `ids`.
        """
        serialized_req = DhtNetworkSubProcess.DUMP_STORAGE_REQ + b' ' + \
                    b' '.join(map(bytes, ids))
        self.send(serialized_req + b'\n')
        for line in self.getlinesUntilNotify():
            DhtNetwork.log(line)


def random_hash():
    return InfoHash(''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(40)).encode())

class FeatureTest(object):
    """
    This is base test. A method run() implementation is required.
    """
    #static variables used by class callbacks
    successfullTransfer = lambda lv,fv: len(lv) == len(fv)
    done = 0
    lock = None
    foreign_nodes = None
    foreign_values = None

    def __init__(self, test, workbench):
        self._test = test
        self.wb = workbench
        self.bootstrap = self.wb.get_bootstrap()

    @staticmethod
    def getcb(value):
        DhtNetwork.log('[GET]: %s' % value)
        FeatureTest.foreign_values.append(value)
        return True

    @staticmethod
    def putDoneCb(ok, nodes):
        if not ok:
            DhtNetwork.log("[PUT]: failed!")
        with FeatureTest.lock:
            FeatureTest.done -= 1
            FeatureTest.lock.notify()

    @staticmethod
    def getDoneCb(ok, nodes):
        with FeatureTest.lock:
            if not ok:
                DhtNetwork.log("[GET]: failed!")
            else:
                for node in nodes:
                    if not node.getNode().isExpired():
                        FeatureTest.foreign_nodes.append(node.getId().toString())
            FeatureTest.done -= 1
            FeatureTest.lock.notify()

    def _dhtPut(self, producer, _hash, *values):
        for val in values:
            with FeatureTest.lock:
                DhtNetwork.log('[PUT]: %s' % val)
                FeatureTest.done += 1
                producer.put(_hash, val, FeatureTest.putDoneCb)
                while FeatureTest.done > 0:
                    FeatureTest.lock.wait()

    def _dhtGet(self, consumer, _hash):
        FeatureTest.foreign_values = []
        FeatureTest.foreign_nodes = []
        with FeatureTest.lock:
            FeatureTest.done += 1
            consumer.get(_hash, FeatureTest.getcb, FeatureTest.getDoneCb)
            while FeatureTest.done > 0:
                FeatureTest.lock.wait()


    def run(self):
        raise NotImplementedError('This method must be implemented.')

class PersistenceTest(FeatureTest):
    """
    This tests persistence of data on the network.
    """

    def __init__(self, test, workbench, *opts):
        """
        @param test: is one of the following:
                     - 'mult_time': test persistence of data based on internal
                       OpenDHT storage maintenance timings.
                     - 'delete': test persistence of data upon deletion of
                       nodes.
                     - 'replace': replacing cluster successively.
        @type  test: string


        OPTIONS

        - dump_str_log: enables storage log at test ending.
        """

        # opts
        super(PersistenceTest, self).__init__(test, workbench)
        self._dump_storage = True if 'dump_str_log' in opts else False
        self._plot = True if 'plot' in opts else False

    def _result(self, local_values, new_nodes):
        bootstrap = self.bootstrap
        if not FeatureTest.successfullTransfer(local_values, FeatureTest.foreign_values):
            DhtNetwork.log('[GET]: Only %s on %s values persisted.' %
                    (len(FeatureTest.foreign_values), len(local_values)))
        else:
            DhtNetwork.log('[GET]: All values successfully persisted.')
        if FeatureTest.foreign_values:
            if new_nodes:
                DhtNetwork.log('Values are newly found on:')
                for node in new_nodes:
                    DhtNetwork.log(node)
                if self._dump_storage:
                    DhtNetwork.log('Dumping all storage log from '\
                                  'hosting nodes.')

                    for proc in self.wb.procs:
                        proc.sendDumpStorage(FeatureTest.foreign_nodes)
            else:
                DhtNetwork.log("Values didn't reach new hosting nodes after shutdown.")

    def run(self):
        try:
            if self._test == 'delete':
                self._deleteTest()
            elif self._test == 'replace':
                self._resplaceClusterTest()
            elif self._test == 'mult_time':
                self._multTimeTest()
        except Exception as e:
            print(e)
        finally:
            bootstrap.resize(1)

    #-----------
    #-  Tests  -
    #-----------

    def _deleteTest(self):
        """
        It uses Dht shutdown call from the API to gracefuly finish the nodes one
        after the other.
        """
        FeatureTest.done = 0
        FeatureTest.lock = threading.Condition()
        FeatureTest.foreign_nodes = []
        FeatureTest.foreign_values = []

        bootstrap = self.bootstrap

        ops_count = []

        bootstrap.resize(3)
        consumer = bootstrap.get(1)
        producer = bootstrap.get(2)

        myhash = random_hash()
        local_values = [Value(b'foo'), Value(b'bar'), Value(b'foobar')]

        self._dhtPut(producer, myhash, *local_values)

        #checking if values were transfered
        self._dhtGet(consumer, myhash)
        if not FeatureTest.successfullTransfer(local_values, FeatureTest.foreign_values):
            if FeatureTest.foreign_values:
                DhtNetwork.log('[GET]: Only ', len(FeatureTest.foreign_values) ,' on ',
                        len(local_values), ' values successfully put.')
            else:
                DhtNetwork.log('[GET]: 0 values successfully put')


        if FeatureTest.foreign_values and FeatureTest.foreign_nodes:
            DhtNetwork.log('Values are found on :')
            for node in FeatureTest.foreign_nodes:
                DhtNetwork.log(node)

            DhtNetwork.log("Waiting a minute for the network to settle down.")
            time.sleep(60)

            for _ in range(max(1, int(self.wb.node_num/32))):
                DhtNetwork.log('Removing all nodes hosting target values...')
                cluster_ops_count = 0
                for proc in self.wb.procs:
                    DhtNetwork.log('[REMOVE]: sending shutdown request to', proc)
                    proc.sendNodesRequest(
                            DhtNetworkSubProcess.SHUTDOWN_NODE_REQ,
                            FeatureTest.foreign_nodes
                    )
                    DhtNetwork.log('sending message stats request')
                    stats = proc.sendGetMessageStats()
                    cluster_ops_count += sum(stats[1:])
                    #DhtNetwork.log("Waiting 15 seconds for packets to work their way effectively.")
                    #time.sleep(15)
                ops_count.append(cluster_ops_count/self.wb.node_num)

                # checking if values were transfered to new nodes
                foreign_nodes_before_delete = FeatureTest.foreign_nodes
                DhtNetwork.log('[GET]: trying to fetch persistent values')
                self._dhtGet(consumer, myhash)
                new_nodes = set(FeatureTest.foreign_nodes) - set(foreign_nodes_before_delete)

                self._result(local_values, new_nodes)

            if self._plot:
                plt.plot(ops_count, color='blue')
                plt.draw()
                plt.ioff()
                plt.show()
        else:
            DhtNetwork.log("[GET]: either couldn't fetch values or nodes hosting values...")

    def _resplaceClusterTest(self):
        """
        It replaces all clusters one after the other.
        """
        FeatureTest.done = 0
        FeatureTest.lock = threading.Condition()
        FeatureTest.foreign_nodes = []
        FeatureTest.foreign_values = []

        clusters = opts['clusters'] if 'clusters' in opts else 5

        bootstrap = self.bootstrap

        bootstrap.resize(3)
        consumer = bootstrap.get(1)
        producer = bootstrap.get(2)

        myhash = random_hash()
        local_values = [Value(b'foo'), Value(b'bar'), Value(b'foobar')]

        self._dhtPut(producer, myhash, *local_values)
        self._dhtGet(consumer, myhash)
        initial_nodes = FeatureTest.foreign_nodes

        DhtNetwork.log('Replacing', clusters, 'random clusters successively...')
        for n in range(clusters):
            i = random.randint(0, len(self.wb.procs)-1)
            proc = self.wb.procs[i]
            DhtNetwork.log('Replacing', proc)
            proc.sendShutdown()
            self.wb.stop_cluster(i)
            self.wb.start_cluster(i)

        DhtNetwork.log('[GET]: trying to fetch persistent values')
        self._dhtGet(consumer, myhash)
        new_nodes = set(FeatureTest.foreign_nodes) - set(initial_nodes)

        self._result(local_values, new_nodes)

    def _multTimeTest(self):
        """
        Multiple put() calls are made from multiple nodes to multiple hashes
        after what a set of 8 nodes is created around each hashes in order to
        enable storage maintenance each nodes. Therefor, this tests will wait 10
        minutes for the nodes to trigger storage maintenance.
        """
        FeatureTest.done = 0
        FeatureTest.lock = threading.Condition()
        FeatureTest.foreign_nodes = []
        FeatureTest.foreign_values = []
        bootstrap = self.bootstrap

        N_PRODUCERS = 16

        hashes = []
        values = [Value(b'foo')]
        nodes = set([])

        # prevents garbage collecting of unused flood nodes during the test.
        flood_nodes = []

        def gottaGetThemAllPokeNodes(nodes=None):
            nonlocal consumer, hashes
            for h in hashes:
                self._dhtGet(consumer, h)
                if nodes is not None:
                    for n in FeatureTest.foreign_nodes:
                        nodes.add(n)

        def createNodesAroundHash(_hash, radius=4):
            nonlocal flood_nodes

            _hash_str = _hash.toString().decode()
            _hash_int = int(_hash_str, 16)
            for i in range(-radius, radius+1):
                _hash_str = '{:40x}'.format(_hash_int + i)
                config = DhtConfig()
                config.setNodeId(InfoHash(_hash_str.encode()))
                n = DhtRunner()
                n.run(config=config)
                n.bootstrap(self.bootstrap.ip4,
                            str(self.bootstrap.port))
                flood_nodes.append(n)

        bootstrap.resize(N_PRODUCERS+2)
        consumer = bootstrap.get(1)
        producers = (bootstrap.get(n) for n in range(2,N_PRODUCERS+2))
        for p in producers:
            hashes.append(random_hash())
            self._dhtPut(p, hashes[-1], *values)

        gottaGetThemAllPokeNodes(nodes=nodes)

        DhtNetwork.log("Values are found on:")
        for n in nodes:
            DhtNetwork.log(n)

        DhtNetwork.log("Creating 8 nodes around all of these nodes...")
        for _hash in hashes:
            createNodesAroundHash(_hash)

        DhtNetwork.log('Waiting 10 minutes for normal storage maintenance.')
        time.sleep(10*60)

        DhtNetwork.log('Deleting old nodes from previous search.')
        for proc in self.wb.procs:
            DhtNetwork.log('[REMOVE]: sending shutdown request to', proc)
            proc.sendNodesRequest(
                DhtNetworkSubProcess.REMOVE_NODE_REQ,
                nodes
            )

        # new consumer (fresh cache)
        bootstrap.resize(N_PRODUCERS+3)
        consumer = bootstrap.get(N_PRODUCERS+2)

        nodes_after_time = set([])
        gottaGetThemAllPokeNodes(nodes=nodes_after_time)
        self._result(values, nodes_after_time - nodes)

class PerformanceTest(FeatureTest):
    """
    Tests for general performance of dht operations.
    """

    def __init__(self, test, workbench, *opts):
        """
        @param test: is one of the following:
                     - 'gets': multiple get operations and statistical results.
                     - 'delete': perform multiple put() operations followed
                       by targeted deletion of nodes hosting the values. Doing
                       so until half of the nodes on the network remain.
        @type  test: string
        """
        super(PerformanceTest, self).__init__(test, workbench)

    def run(self):
        try:
            if self._test == 'gets':
                self._getsTimesTest()
            elif self._test == 'delete':
                self._delete()
        except Exception as e:
            print(e)
        finally:
            self.bootstrap.resize(1)


    ###########
    #  Tests  #
    ###########

    def _getsTimesTest(self):
        """
        Tests for performance of the DHT doing multiple get() operation.
        """
        bootstrap = self.bootstrap

        plt.ion()

        fig, axes = plt.subplots(2, 1)
        fig.tight_layout()

        lax = axes[0]
        hax = axes[1]

        lines = None#ax.plot([])
        #plt.ylabel('time (s)')
        hax.set_ylim(0, 2)

        # let the network stabilise
        plt.pause(60)

        #start = time.time()
        times = []

        lock = threading.Condition()
        done = 0

        def getcb(v):
            nonlocal bootstrap
            DhtNetwork.log("found", v)
            return True

        def donecb(ok, nodes):
            nonlocal bootstrap, lock, done, times
            t = time.time()-start
            with lock:
                if not ok:
                    DhtNetwork.log("failed !")
                times.append(t)
                done -= 1
                lock.notify()

        def update_plot():
            nonlocal lines
            while lines:
                l = lines.pop()
                l.remove()
                del l
            lines = plt.plot(times, color='blue')
            plt.draw()

        def run_get():
            nonlocal done
            done += 1
            start = time.time()
            bootstrap.front().get(InfoHash.getRandom(), getcb, lambda ok, nodes: donecb(ok, nodes, start))

        plt.pause(5)

        plt.show()
        update_plot()

        times = []
        for n in range(10):
            self.wb.replace_cluster()
            plt.pause(2)
            DhtNetwork.log("Getting 50 random hashes succesively.")
            for i in range(50):
                with lock:
                    done += 1
                    start = time.time()
                    bootstrap.front().get(InfoHash.getRandom(), getcb, donecb)
                    while done > 0:
                        lock.wait()
                        update_plot()
                update_plot()
            print("Took", np.sum(times), "mean", np.mean(times), "std", np.std(times), "min", np.min(times), "max", np.max(times))

        print('GET calls timings benchmark test : DONE. '  \
                'Close Matplotlib window for terminating the program.')
        plt.ioff()
        plt.show()

    def _delete(self):
        """
        Tests for performance of get() and put() operations on the network while
        deleting around the target hash.
        """

        FeatureTest.done = 0
        FeatureTest.lock = threading.Condition()
        FeatureTest.foreign_nodes = []
        FeatureTest.foreign_values = []

        bootstrap = self.bootstrap

        bootstrap.resize(3)
        consumer = bootstrap.get(1)
        producer = bootstrap.get(2)

        myhash = random_hash()
        local_values = [Value(b'foo'), Value(b'bar'), Value(b'foobar')]

        for _ in range(max(1, int(self.wb.node_num/32))):
            self._dhtGet(consumer, myhash)
            DhtNetwork.log("Waiting 15 seconds...")
            time.sleep(15)

            self._dhtPut(producer, myhash, *local_values)

            #checking if values were transfered
            self._dhtGet(consumer, myhash)
            DhtNetwork.log('Values are found on :')
            for node in FeatureTest.foreign_nodes:
                DhtNetwork.log(node)

            if not FeatureTest.successfullTransfer(local_values, FeatureTest.foreign_values):
                if FeatureTest.foreign_values:
                    DhtNetwork.log('[GET]: Only ', len(FeatureTest.foreign_values) ,' on ',
                            len(local_values), ' values successfully put.')
                else:
                    DhtNetwork.log('[GET]: 0 values successfully put')

            DhtNetwork.log('Removing all nodes hosting target values...')
            for proc in self.wb.procs:
                DhtNetwork.log('[REMOVE]: sending shutdown request to', proc)
                proc.sendNodesRequest(
                        DhtNetworkSubProcess.SHUTDOWN_NODE_REQ,
                        FeatureTest.foreign_nodes
                )

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Run, test and benchmark a '\
            'DHT network on a local virtual network with simulated packet '\
            'loss and latency.')
    ifConfArgs = parser.add_argument_group('Virtual interface configuration')
    ifConfArgs.add_argument('-i', '--ifname', default='ethdht', help='interface name')
    ifConfArgs.add_argument('-n', '--node-num', type=int, default=32, help='number of dht nodes to run')
    ifConfArgs.add_argument('-v', '--virtual-locs', type=int, default=8,
            help='number of virtual locations (node clusters)')
    ifConfArgs.add_argument('-l', '--loss', type=int, default=0, help='simulated cluster packet loss (percent)')
    ifConfArgs.add_argument('-d', '--delay', type=int, default=0, help='simulated cluster latency (ms)')
    ifConfArgs.add_argument('-b', '--bootstrap', default=None, help='Bootstrap node to use (if any)')
    ifConfArgs.add_argument('-no4', '--disable-ipv4', action="store_true", help='Enable IPv4')
    ifConfArgs.add_argument('-no6', '--disable-ipv6', action="store_true", help='Enable IPv6')

    testArgs = parser.add_argument_group('Test arguments')
    testArgs.add_argument('-t', '--test', type=str, default=None, required=True, help='Specifies the test.')
    testArgs.add_argument('-o', '--opt', type=str, default=[], nargs='+',
            help='Options passed to tests routines.')

    featureArgs = parser.add_mutually_exclusive_group(required=True)
    featureArgs.add_argument('--performance', action='store_true', default=0,
            help='Launches performance benchmark test. Available args for "-t" are: gets.')
    featureArgs.add_argument('--data-persistence', action='store_true', default=0,
            help='Launches data persistence benchmark test. '\
                    'Available args for "-t" are: delete, replace, mult_time. '\
                    'Available args for "-o" are : dump_str_log')


    args = parser.parse_args()

    wb = WorkBench(args.ifname, args.virtual_locs, args.node_num, loss=args.loss,
            delay=args.delay, disable_ipv4=args.disable_ipv4,
            disable_ipv6=args.disable_ipv6)
    wb.create_virtual_net()

    bootstrap = wb.get_bootstrap()
    bootstrap.resize(1)
    print("Launching", wb.node_num, "nodes (", wb.clusters, "clusters of", wb.node_per_loc, "nodes)")

    try:
        for i in range(wb.clusters):
            wb.start_cluster(i)

        if args.performance:
            PerformanceTest(args.test, wb, *args.opt).run()
        elif args.data_persistence:
            PersistenceTest(args.test, wb, *args.opt).run()

    except Exception as e:
        print(e)
    finally:
        for p in wb.procs:
            if p:
                p.quit()
        bootstrap.resize(0)
        sys.stdout.write('Shutting down the virtual IP network... ')
        sys.stdout.flush()
        wb.destroy_virtual_net()
        print('Done.')
