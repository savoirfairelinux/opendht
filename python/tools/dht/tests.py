# -*- coding: utf-8 -*-
# Copyright (C) 2015 Savoir-Faire Linux Inc.
# Author(s): Adrien Béraud <adrien.beraud@savoirfairelinux.com>
#            Simon Désaulniers <sim.desaulniers@gmail.com>

import os
import threading
import random
import string
import time
import subprocess
import re

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

from opendht import *
from dht.network import DhtNetwork, DhtNetworkSubProcess

############
#  Common  #
############

# matplotlib display format for bits (b, Kb, Mb)
bit_format = None
Kbit_format = FuncFormatter(lambda x, pos: '%1.1f' % (x*1024**-1) + 'Kb')
Mbit_format = FuncFormatter(lambda x, pos: '%1.1f' % (x*1024**-2) + 'Mb')

def random_hash():
    return InfoHash(''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(40)).encode())

def reset_before_test(featureTestMethod):
    """
    This is a decorator for all test methods needing reset().

    @param featureTestMethod: The method to be decorated. All decorated methods
                              must have 'self' object as first arg.
    @type  featureTestMethod: function
    """
    def call(*args, **kwargs):
        self = args[0]
        if isinstance(self, FeatureTest):
            self._reset()
        return featureTestMethod(*args, **kwargs)
    return call

def display_plot(yvals, xvals=None, yformatter=None, display_time=3, **kwargs):
    """
    Displays a plot of data in interactive mode. This method is made to be
    called successively for plot refreshing.

    @param yvals:  Ordinate values (float).
    @type  yvals:  list
    @param xvals:  Abscissa values (float).
    @type  xvals:  list
    @param yformatter:  The matplotlib FuncFormatter to use for y values.
    @type  yformatter:  matplotlib.ticker.FuncFormatter
    @param displaytime:  The time matplotlib can take to refresht the plot.
    @type  displaytime:  int
    """
    plt.ion()
    plt.clf()
    plt.show()
    if yformatter:
        plt.axes().yaxis.set_major_formatter(Kbit_format)
    if xvals:
        plt.plot(xvals, yvals, **kwargs)
    else:
        plt.plot(yvals, **kwargs)
    plt.pause(display_time)

def iftop_traffic_data(ifname, interval=2, rate_type='send_receive'):
    """
    Generator (yields data) function collecting traffic data from iftop
    subprocess.

    @param ifname: Interface to listen to.
    @type  ifname: string
    @param interval: Interval of time between to data collections. Possible
                     values are 2, 10 or 40.
    @type  interval: int
    @param rates: (default: send_receive) Wether to pick "send", "receive"
                  or "send and receive" rates. Possible values : "send",
                  "receive" and "send_receive".
    @type  rates: string
    @param _format: Format in which to display data on the y axis.
                    Possible values: Mb, Kb or b.
    @type  _format: string
    """
    # iftop stdout string format
    SEND_RATE_STR               = "Total send rate"
    RECEIVE_RATE_STR            = "Total receive rate"
    SEND_RECEIVE_RATE_STR       = "Total send and receive rate"
    RATE_STR = {
            "send"         : SEND_RATE_STR,
            "receive"      : RECEIVE_RATE_STR,
            "send_receive" : SEND_RECEIVE_RATE_STR
    }
    TWO_SECONDS_RATE_COL    = 0
    TEN_SECONDS_RATE_COL    = 1
    FOURTY_SECONDS_RATE_COL = 2
    COLS = {
            2  : TWO_SECONDS_RATE_COL,
            10 : TEN_SECONDS_RATE_COL,
            40 : FOURTY_SECONDS_RATE_COL
    }
    FLOAT_REGEX = "[0-9]+[.]*[0-9]*"
    BIT_REGEX = "[KM]*b"

    iftop = subprocess.Popen(["iftop", "-i", ifname, "-t"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    while True:
        line = iftop.stdout.readline().decode()
        if RATE_STR[rate_type] in line:
            rate, unit = re.findall("("+FLOAT_REGEX+")("+BIT_REGEX+")", line)[COLS[interval]]
            rate = float(rate)
            if unit == "Kb":
                rate *= 1024
            elif unit == "Mb":
                rate *= 1024**2
            yield rate

###########
#  Tests  #
###########

class FeatureTest(object):
    done = 0
    lock = None

    """
    This is a base test.
    """

    def __init__(self, test, workbench):
        """
        @param test: The test string indicating the test to run. This string is
                     determined in the child classes.
        @type  test: string

        @param workbench: A WorkBench object to use inside this test.
        @type  workbench: WorkBench
        """
        self._test = test
        self._workbench = workbench

    def _reset(self):
        """
        Resets some static variables.

        This method is most likely going to be called before each tests.
        """
        FeatureTest.done = 0
        FeatureTest.lock = threading.Condition()

    def run(self):
        raise NotImplementedError('This method must be implemented.')



##################################
#               DHT              #
##################################

class DhtFeatureTest(FeatureTest):
    """
    This is base test. A method run() implementation is required.
    """
    #static variables used by class callbacks
    successfullTransfer = lambda lv,fv: len(lv) == len(fv)
    foreignNodes = None
    foreignValues = None

    def __init__(self, test, workbench):
        super(DhtFeatureTest, self).__init__(test, workbench)
        self.bootstrap = self._workbench.get_bootstrap()

    def _reset(self):
        super(DhtFeatureTest, self)._reset()
        DhtFeatureTest.foreignNodes = []
        DhtFeatureTest.foreignValues = []

    @staticmethod
    def getcb(value):
        vstr = value.__str__()[:100]
        DhtNetwork.log('[GET]: %s' % vstr + ("..." if len(vstr) > 100 else ""))
        DhtFeatureTest.foreignValues.append(value)
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
                        DhtFeatureTest.foreignNodes.append(node.getId().toString())
            FeatureTest.done -= 1
            FeatureTest.lock.notify()

    def _dhtPut(self, producer, _hash, *values):
        with FeatureTest.lock:
            for val in values:
                    vstr = val.__str__()[:100]
                    DhtNetwork.log('[PUT]:', _hash.toString(), '->', vstr + ("..." if len(vstr) > 100 else ""))
                    FeatureTest.done += 1
                    producer.put(_hash, val, DhtFeatureTest.putDoneCb)
            while FeatureTest.done > 0:
                FeatureTest.lock.wait()

    def _dhtGet(self, consumer, _hash):
        DhtFeatureTest.foreignValues = []
        DhtFeatureTest.foreignNodes = []
        with FeatureTest.lock:
            FeatureTest.done += 1
            DhtNetwork.log('[GET]:', _hash.toString())
            consumer.get(_hash, DhtFeatureTest.getcb, DhtFeatureTest.getDoneCb)
            while FeatureTest.done > 0:
                FeatureTest.lock.wait()

    def _gottaGetThemAllPokeNodes(self, consumer, hashes, nodes=None):
        for h in hashes:
            self._dhtGet(consumer, h)
            if nodes is not None:
                for n in DhtFeatureTest.foreignNodes:
                    nodes.add(n)


class PersistenceTest(DhtFeatureTest):
    """
    This tests persistence of data on the network.
    """

    def __init__(self, test, workbench, opts):
        """
        @param test: is one of the following:
                     - 'mult_time': test persistence of data based on internal
                       OpenDHT storage maintenance timings.
                     - 'delete': test persistence of data upon deletion of
                       nodes.
                     - 'replace': replacing cluster successively.
        @type  test: string


        OPTIONS

        - dump_str_log:  Enables storage log at test ending.
        - keep_alive:    Keeps the test running indefinately. This may be useful
                         to manually analyse the network traffic during a longer
                         period.
        - num_producers: Number of producers of data during a DHT test.
        - num_values:    Number of values to initialize the DHT with.
        """

        # opts
        super(PersistenceTest, self).__init__(test, workbench)
        self._traffic_plot  = True if 'traffic_plot' in opts else False
        self._dump_storage  = True if 'dump_str_log' in opts else False
        self._op_plot       = True if 'op_plot' in opts else False
        self._keep_alive    = True if 'keep_alive' in opts else False
        self._num_producers = opts['num_producers'] if 'num_producers' in opts else None
        self._num_values    = opts['num_values'] if 'num_values' in opts else None

    def _trigger_dp(self, trigger_nodes, _hash, count=1):
        """
        Triggers the data persistence over time. In order to this, `count` nodes
        are created with an id around the hash of a value.

        @param trigger_nodes: List of created nodes. The nodes created in this
                              function are append to this list.
        @type  trigger_nodes: list
        @param _hash: Is the id of the value around which creating nodes.
        @type  _hash: InfoHash
        @param count: The number of nodes to create with id around the id of
                      value.
        @type  count: int
        """
        _hash_str = _hash.toString().decode()
        _hash_int = int(_hash_str, 16)
        for i in range(int(-count/2), int(count/2)+1):
            _hash_str = '{:40x}'.format(_hash_int + i)
            config = DhtConfig()
            config.setNodeId(InfoHash(_hash_str.encode()))
            n = DhtRunner()
            n.run(config=config)
            n.bootstrap(self.bootstrap.ip4,
                        str(self.bootstrap.port))
            DhtNetwork.log('Node','['+_hash_str+']',
                           'started around', _hash.toString().decode()
                           if n.isRunning() else
                           'failed to start...'
            )
            trigger_nodes.append(n)

    def _result(self, local_values, new_nodes):
        bootstrap = self.bootstrap
        if not DhtFeatureTest.successfullTransfer(local_values, DhtFeatureTest.foreignValues):
            DhtNetwork.log('[GET]: Only %s on %s values persisted.' %
                    (len(DhtFeatureTest.foreignValues), len(local_values)))
        else:
            DhtNetwork.log('[GET]: All values successfully persisted.')
        if DhtFeatureTest.foreignValues:
            if new_nodes:
                DhtNetwork.log('Values are newly found on:')
                for node in new_nodes:
                    DhtNetwork.log(node)
                if self._dump_storage:
                    DhtNetwork.log('Dumping all storage log from '\
                                  'hosting nodes.')
                    for proc in self._workbench.procs:
                        proc.sendNodesRequest(DhtNetworkSubProcess.DUMP_STORAGE_REQ, DhtFeatureTest.foreignNodes)
            else:
                DhtNetwork.log("Values didn't reach new hosting nodes after shutdown.")

    def run(self):
        try:
            if self._test == 'normal':
                self._totallyNormalTest()
            elif self._test == 'delete':
                self._deleteTest()
            elif self._test == 'replace':
                self._replaceClusterTest()
            elif self._test == 'mult_time':
                self._multTimeTest()
            else:
                raise NameError("This test is not defined '" + self._test + "'")
        except Exception as e:
            print(e)
        finally:
            if self._traffic_plot or self._op_plot:
                plot_fname = "traffic-plot"
                print('plot saved to', plot_fname)
                plt.savefig(plot_fname)
            self.bootstrap.resize(1)

    ###########
    #  Tests  #
    ###########

    @reset_before_test
    def _totallyNormalTest(self):
        """
        Reproduces a network in a realistic state.
        """
        trigger_nodes = []
        wb = self._workbench
        bootstrap = self.bootstrap
        # Value representing an ICE packet. Each ICE packet is around 1KB.
        VALUE_SIZE = 1024
        NUM_VALUES = self._num_values/wb.node_num if self._num_values else 5
        nr_values = NUM_VALUES * wb.node_num
        nr_nodes = wb.node_num
        nr_nodes_cv = threading.Condition()

        values = [b''.join(random.choice(string.hexdigits).encode() for _ in range(VALUE_SIZE)) for __ in range(NUM_VALUES)]
        hashes = [random_hash() for _ in range(wb.node_num)]

        # initial set of values
        i = 0
        for h in hashes:
           self._dhtPut(bootstrap.front(), h, *[Value(v) for v in values])
           print("at: ", i)
           i += 1

        def normalBehavior(do, t, log=None):
            nonlocal nr_values
            while True:
                do()
                time.sleep(random.choice(range(t)))

        def putRequest():
            nonlocal hashes, values, nr_values
            nr_values += 1
            DhtNetwork.log("Random value put on the DHT.", "(now "+ str(nr_values)+" values on the dht)")
            random.choice(wb.procs).sendNodePutRequest(random.choice(hashes).toString(), random.choice(values))
        puts = threading.Thread(target=normalBehavior, args=(putRequest, 30))
        puts.daemon = True
        puts.start()
        def newNodeRequest():
            nonlocal nr_nodes
            with nr_nodes_cv:
                nr_nodes += 1
                DhtNetwork.log("Node joining the DHT.", "(now "+str(nr_nodes)+" nodes on the dht)")
                nr_nodes_cv.notify()
            random.choice(wb.procs).sendNodesRequest(DhtNetworkSubProcess.NEW_NODE_REQ)
        connections = threading.Thread(target=normalBehavior, args=(newNodeRequest, 1*60))
        connections.daemon = True
        connections.start()
        def shutdownNodeRequest():
            nonlocal nr_nodes
            with nr_nodes_cv:
                nr_nodes -= 1
                DhtNetwork.log("Node quitting the DHT.", "(now "+str(nr_nodes)+" nodes on the dht)")
                nr_nodes_cv.notify()
            random.choice(wb.procs).sendNodesRequest(DhtNetworkSubProcess.SHUTDOWN_NODE_REQ)
        shutdowns = threading.Thread(target=normalBehavior, args=(shutdownNodeRequest, 1*60))
        shutdowns.daemon = True
        shutdowns.start()

        for h in hashes:
           self._trigger_dp(trigger_nodes, h)

        if self._traffic_plot:
            ydata = []
            xdata = []
            # warning: infinite loop
            interval = 2
            for rate in iftop_traffic_data("br"+wb.ifname, interval=interval):
                ydata.append(rate)
                xdata.append((xdata[-1] if len(xdata) > 0 else 0) + interval)
                display_plot(ydata, xvals=xdata, yformatter=Kbit_format, color='blue')
        else:
            # blocks in matplotlib thread
            while True:
                plt.pause(3600)


    @reset_before_test
    def _deleteTest(self):
        """
        It uses Dht shutdown call from the API to gracefuly finish the nodes one
        after the other.
        """
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
        if not DhtFeatureTest.successfullTransfer(local_values, DhtFeatureTest.foreignValues):
            if DhtFeatureTest.foreignValues:
                DhtNetwork.log('[GET]: Only ', len(DhtFeatureTest.foreignValues) ,' on ',
                        len(local_values), ' values successfully put.')
            else:
                DhtNetwork.log('[GET]: 0 values successfully put')


        if DhtFeatureTest.foreignValues and DhtFeatureTest.foreignNodes:
            DhtNetwork.log('Values are found on :')
            for node in DhtFeatureTest.foreignNodes:
                DhtNetwork.log(node)

            for _ in range(max(1, int(self._workbench.node_num/32))):
                DhtNetwork.log('Removing all nodes hosting target values...')
                cluster_ops_count = 0
                for proc in self._workbench.procs:
                    DhtNetwork.log('[REMOVE]: sending shutdown request to', proc)
                    proc.sendNodesRequest(
                            DhtNetworkSubProcess.SHUTDOWN_NODE_REQ,
                            DhtFeatureTest.foreignNodes
                    )
                    DhtNetwork.log('sending message stats request')
                    stats = proc.sendGetMessageStats()
                    cluster_ops_count += sum(stats[1:])
                    DhtNetwork.log("5 seconds wait...")
                    time.sleep(5)
                ops_count.append(cluster_ops_count/self._workbench.node_num)

                # checking if values were transfered to new nodes
                foreignNodes_before_delete = DhtFeatureTest.foreignNodes
                DhtNetwork.log('[GET]: trying to fetch persistent values')
                self._dhtGet(consumer, myhash)
                new_nodes = set(DhtFeatureTest.foreignNodes) - set(foreignNodes_before_delete)

                self._result(local_values, new_nodes)

            if self._op_plot:
                display_plot(ops_count, color='blue')
        else:
            DhtNetwork.log("[GET]: either couldn't fetch values or nodes hosting values...")

    @reset_before_test
    def _replaceClusterTest(self):
        """
        It replaces all clusters one after the other.
        """
        clusters = 8

        bootstrap = self.bootstrap

        bootstrap.resize(3)
        consumer = bootstrap.get(1)
        producer = bootstrap.get(2)

        myhash = random_hash()
        local_values = [Value(b'foo'), Value(b'bar'), Value(b'foobar')]

        self._dhtPut(producer, myhash, *local_values)
        self._dhtGet(consumer, myhash)
        initial_nodes = DhtFeatureTest.foreignNodes

        DhtNetwork.log('Replacing', clusters, 'random clusters successively...')
        for n in range(clusters):
            i = random.randint(0, len(self._workbench.procs)-1)
            proc = self._workbench.procs[i]
            DhtNetwork.log('Replacing', proc)
            proc.sendNodesRequest(DhtNetworkSubProcess.SHUTDOWN_CLUSTER_REQ)
            self._workbench.stop_cluster(i)
            self._workbench.start_cluster(i)

        DhtNetwork.log('[GET]: trying to fetch persistent values')
        self._dhtGet(consumer, myhash)
        new_nodes = set(DhtFeatureTest.foreignNodes) - set(initial_nodes)

        self._result(local_values, new_nodes)

    @reset_before_test
    def _multTimeTest(self):
        """
        Multiple put() calls are made from multiple nodes to multiple hashes
        after what a set of 8 nodes is created around each hashes in order to
        enable storage maintenance each nodes. Therefor, this tests will wait 10
        minutes for the nodes to trigger storage maintenance.
        """
        trigger_nodes = []
        bootstrap = self.bootstrap

        N_PRODUCERS = self._num_producers if self._num_values else 16
        DP_TIMEOUT = 1

        hashes = []

        # Generating considerable amount of values of size 1KB.
        VALUE_SIZE = 1024
        NUM_VALUES = self._num_values if self._num_values else 50
        values = [Value(''.join(random.choice(string.hexdigits) for _ in range(VALUE_SIZE)).encode()) for _ in range(NUM_VALUES)]

        bootstrap.resize(N_PRODUCERS+2)
        consumer = bootstrap.get(N_PRODUCERS+1)
        producers = (bootstrap.get(n) for n in range(1,N_PRODUCERS+1))
        for p in producers:
            hashes.append(random_hash())
            self._dhtPut(p, hashes[-1], *values)

        once = True
        while self._keep_alive or once:
            nodes = set([])
            self._gottaGetThemAllPokeNodes(consumer, hashes, nodes=nodes)

            DhtNetwork.log("Values are found on:")
            for n in nodes:
                DhtNetwork.log(n)

            DhtNetwork.log("Creating 8 nodes around all of these hashes...")
            for _hash in hashes:
                self._trigger_dp(trigger_nodes, _hash, count=8)

            DhtNetwork.log('Waiting', DP_TIMEOUT+1, 'minutes for normal storage maintenance.')
            time.sleep((DP_TIMEOUT+1)*60)

            DhtNetwork.log('Deleting old nodes from previous search.')
            for proc in self._workbench.procs:
                DhtNetwork.log('[REMOVE]: sending delete request to', proc)
                proc.sendNodesRequest(
                    DhtNetworkSubProcess.REMOVE_NODE_REQ,
                    nodes)

            # new consumer (fresh cache)
            bootstrap.resize(N_PRODUCERS+1)
            bootstrap.resize(N_PRODUCERS+2)
            consumer = bootstrap.get(N_PRODUCERS+1)

            nodes_after_time = set([])
            self._gottaGetThemAllPokeNodes(consumer, hashes, nodes=nodes_after_time)
            self._result(values, nodes_after_time - nodes)

            once = False


class PerformanceTest(DhtFeatureTest):
    """
    Tests for general performance of dht operations.
    """

    def __init__(self, test, workbench, opts):
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
            else:
                raise NameError("This test is not defined '" + self._test + "'")
        except Exception as e:
            print(e)
        finally:
            self.bootstrap.resize(1)


    ###########
    #  Tests  #
    ###########

    @reset_before_test
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
        plt.pause(20)

        #start = time.time()
        times = []

        lock = threading.Condition()
        done = 0

        def getcb(v):
            nonlocal bootstrap
            DhtNetwork.log("found", v)
            return True

        def donecb(ok, nodes, start):
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
            if len(times) > 1:
                n, bins, lines = hax.hist(times, 100, normed=1, histtype='stepfilled', color='g')
                hax.set_ylim(min(n), max(n))
                lines.extend(lax.plot(times, color='blue'))
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
            self._workbench.replace_cluster()
            plt.pause(2)
            DhtNetwork.log("Getting 50 random hashes succesively.")
            for i in range(50):
                with lock:
                    for _ in range(1):
                        run_get()
                    while done > 0:
                        lock.wait()
                        update_plot()
                        plt.pause(.1)
                update_plot()
            print("Took", np.sum(times), "mean", np.mean(times), "std", np.std(times), "min", np.min(times), "max", np.max(times))

        print('GET calls timings benchmark test : DONE. '  \
                'Close Matplotlib window for terminating the program.')
        plt.ioff()
        plt.show()

    @reset_before_test
    def _delete(self):
        """
        Tests for performance of get() and put() operations on the network while
        deleting around the target hash.
        """


        bootstrap = self.bootstrap

        bootstrap.resize(3)
        consumer = bootstrap.get(1)
        producer = bootstrap.get(2)

        myhash = random_hash()
        local_values = [Value(b'foo'), Value(b'bar'), Value(b'foobar')]

        for _ in range(max(1, int(self._workbench.node_num/32))):
            self._dhtGet(consumer, myhash)
            DhtNetwork.log("Waiting 15 seconds...")
            time.sleep(15)

            self._dhtPut(producer, myhash, *local_values)

            #checking if values were transfered
            self._dhtGet(consumer, myhash)
            DhtNetwork.log('Values are found on :')
            for node in DhtFeatureTest.foreignNodes:
                DhtNetwork.log(node)

            if not DhtFeatureTest.successfullTransfer(local_values, DhtFeatureTest.foreignValues):
                if DhtFeatureTest.foreignValues:
                    DhtNetwork.log('[GET]: Only ', len(DhtFeatureTest.foreignValues) ,' on ',
                            len(local_values), ' values successfully put.')
                else:
                    DhtNetwork.log('[GET]: 0 values successfully put')

            DhtNetwork.log('Removing all nodes hosting target values...')
            for proc in self._workbench.procs:
                DhtNetwork.log('[REMOVE]: sending shutdown request to', proc)
                proc.sendNodesRequest(
                        DhtNetworkSubProcess.SHUTDOWN_NODE_REQ,
                        DhtFeatureTest.foreignNodes
                )
