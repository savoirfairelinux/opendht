# -*- coding: utf-8 -*-
# Copyright (C) 2015-2019 Savoir-Faire Linux Inc.
# Author(s): Adrien Béraud <adrien.beraud@savoirfairelinux.com>
#            Simon Désaulniers <sim.desaulniers@gmail.com>

import sys
import os
import threading
import random
import string
import time
import subprocess
import re
import traceback
import collections

from matplotlib.ticker import FuncFormatter
import math

import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout


from opendht import *
from dht.network import DhtNetwork, DhtNetworkSubProcess

############
#  Common  #
############

# matplotlib display format for bits (b, Kb, Mb)
bit_format = None
Kbit_format = FuncFormatter(lambda x, pos: '%1.1f' % (x*1024**-1) + 'Kb')
Mbit_format = FuncFormatter(lambda x, pos: '%1.1f' % (x*1024**-2) + 'Mb')

def random_str_val(size=1024):
    """Creates a random string value of specified size.

    @param size:  Size, in bytes, of the value.
    @type  size:  int

    @return:  Random string value
    @rtype :  str
    """
    return ''.join(random.choice(string.hexdigits) for _ in range(size))


def random_hash():
    """Creates random InfoHash.
    """
    return InfoHash(random_str_val(size=40).encode())

def timer(f, *args):
    """
    Start a timer which count time taken for execute function f

    @param f : Function to time
    @type  f : function

    @param args : Arguments of the function f
    @type  args : list

    @rtype : timer
    @return : Time taken by the function f
    """
    start = time.time()
    f(*args)

    return time.time() - start

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

def display_traffic_plot(ifname):
    """Displays the traffic plot for a given interface name.

    @param ifname:  Interface name.
    @type  ifname:  string
    """
    ydata = []
    xdata = []
    # warning: infinite loop
    interval = 2
    for rate in iftop_traffic_data(ifname, interval=interval):
        ydata.append(rate)
        xdata.append((xdata[-1] if len(xdata) > 0 else 0) + interval)
        display_plot(ydata, xvals=xdata, yformatter=Kbit_format, color='blue')

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
    """
    This is a base test.
    """

    done = 0
    lock = None

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
        self._bootstrap = self._workbench.get_bootstrap()

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
#               PHT              #
##################################

class PhtTest(FeatureTest):
    """TODO
    """

    indexEntries = None
    prefix       = None
    key          = None

    def __init__(self, test, workbench, opts):
        """
        @param test: is one of the following:
                     - 'insert': indexes a considerable amount of data in
                       the PHT structure.
                       TODO
        @type  test: string

        @param opts: Dictionnary containing options for the test. Allowed
                     options are:
                     - 'num_keys': this specifies the number of keys to insert
                                   in the PHT during the test.
        @type  opts: dict
        """
        super(PhtTest, self).__init__(test, workbench)
        self._num_keys = opts['num_keys'] if 'num_keys' in opts else 32
        self._timer = True if 'timer' in opts else False

    def _reset(self):
        super(PhtTest, self)._reset()
        PhtTest.indexEntries = []

    @staticmethod
    def lookupCb(vals, prefix):
        PhtTest.indexEntries = list(vals)
        PhtTest.prefix = prefix.decode()
        DhtNetwork.log('Index name: <todo>')
        DhtNetwork.log('Leaf prefix:', prefix)
        for v in vals:
            DhtNetwork.log('[ENTRY]:', v)

    @staticmethod
    def lookupDoneCb(ok):
        DhtNetwork.log('[LOOKUP]:', PhtTest.key, "--", "success!" if ok else "Fail...")
        with FeatureTest.lock:
            FeatureTest.lock.notify()

    @staticmethod
    def insertDoneCb(ok):
        DhtNetwork.log('[INSERT]:', PhtTest.key, "--", "success!" if ok else "Fail...")
        with FeatureTest.lock:
            FeatureTest.lock.notify()

    @staticmethod
    def drawTrie(trie_dict):
        """
        Draws the trie structure of the PHT from dictionnary.

        @param trie_dict: Dictionnary of index entries (prefix -> entry).
        @type  trie_dict: dict
        """
        prefixes = list(trie_dict.keys())
        if len(prefixes) == 0:
            return

        edges = list([])
        for prefix in prefixes:
            for i in range(-1, len(prefix)-1):
                u = prefix[:i+1]
                x = ("." if i == -1 else u, u+"0")
                y = ("." if i == -1 else u, u+"1")
                if x not in edges:
                    edges.append(x)
                if y not in edges:
                    edges.append(y)

        # TODO: use a binary tree position layout...
        #   UPDATE : In a better way [change lib]
        G = nx.Graph(sorted(edges, key=lambda x: len(x[0])))
        plt.title("PHT: Tree")
        pos=graphviz_layout(G,prog='dot')
        nx.draw(G, pos, with_labels=True, node_color='white')
        plt.show()

    def run(self):
        try:
            if self._test == 'insert':
                self._insertTest()
        except Exception as e:
            print(e)
        finally:
            self._bootstrap.resize(1)

    ###########
    #  Tests  #
    ###########

    @reset_before_test
    def _insertTest(self):
        """TODO: Docstring for _massIndexTest.
        """
        bootstrap = self._bootstrap
        bootstrap.resize(2)
        dht = bootstrap.get(1)

        NUM_DIG  = max(math.log(self._num_keys, 2)/4, 5) # at least 5 digit keys.
        keyspec = collections.OrderedDict([('foo', NUM_DIG)])
        pht = Pht(b'foo_index', keyspec, dht)

        DhtNetwork.log('PHT has',
                       pht.MAX_NODE_ENTRY_COUNT,
                       'node'+ ('s' if pht.MAX_NODE_ENTRY_COUNT > 1 else ''),
                       'per leaf bucket.')
        keys = [{
            [_ for _ in keyspec.keys()][0] :
            ''.join(random.SystemRandom().choice(string.hexdigits)
                for _ in range(NUM_DIG)).encode()
            } for n in range(self._num_keys)]
        all_entries = {}

        # Index all entries.
        for key in keys:
            PhtTest.key = key
            with FeatureTest.lock:
                time_taken = timer(pht.insert, key, IndexValue(random_hash()), PhtTest.insertDoneCb)
                if self._timer:
                    DhtNetwork.log('This insert step took : ', time_taken, 'second')
                FeatureTest.lock.wait()

        time.sleep(1)

        # Recover entries now that the trie is complete.
        for key in keys:
            PhtTest.key = key
            with FeatureTest.lock:
                time_taken = timer(pht.lookup, key, PhtTest.lookupCb, PhtTest.lookupDoneCb)
                if self._timer:
                    DhtNetwork.log('This lookup step took : ', time_taken, 'second')
                FeatureTest.lock.wait()

            all_entries[PhtTest.prefix] = [e.__str__()
                                           for e in PhtTest.indexEntries]

        for p in all_entries.keys():
            DhtNetwork.log('All entries under prefix', p, ':')
            DhtNetwork.log(all_entries[p])
        PhtTest.drawTrie(all_entries)

##################################
#               DHT              #
##################################

class DhtFeatureTest(FeatureTest):
    """
    This is a base dht test.
    """
    #static variables used by class callbacks
    successfullTransfer = lambda lv,fv: len(lv) == len(fv)
    foreignNodes = None
    foreignValues = None

    def __init__(self, test, workbench):
        super(DhtFeatureTest, self).__init__(test, workbench)

    def _reset(self):
        super(DhtFeatureTest, self)._reset()
        DhtFeatureTest.foreignNodes = []
        DhtFeatureTest.foreignValues = []

    @staticmethod
    def getcb(value):
        vstr = value.__str__()[:100]
        DhtNetwork.Log.log('[GET]: %s' % vstr + ("..." if len(vstr) > 100 else ""))
        DhtFeatureTest.foreignValues.append(value)
        return True

    @staticmethod
    def putDoneCb(ok, nodes):
        with FeatureTest.lock:
            if not ok:
                DhtNetwork.Log.log("[PUT]: failed!")
            FeatureTest.done -= 1
            FeatureTest.lock.notify()

    @staticmethod
    def getDoneCb(ok, nodes):
        with FeatureTest.lock:
            if not ok:
                DhtNetwork.Log.log("[GET]: failed!")
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
                DhtNetwork.Log.log('[PUT]:', _hash.toString(), '->', vstr + ("..." if len(vstr) > 100 else ""))
                FeatureTest.done += 1
                producer.put(_hash, val, DhtFeatureTest.putDoneCb)
            while FeatureTest.done > 0:
                FeatureTest.lock.wait()

    def _dhtGet(self, consumer, _hash):
        DhtFeatureTest.foreignValues = []
        DhtFeatureTest.foreignNodes = []
        with FeatureTest.lock:
            FeatureTest.done += 1
            DhtNetwork.Log.log('[GET]:', _hash.toString())
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
            n.bootstrap(self._bootstrap.ip4,
                        str(self._bootstrap.port))
            DhtNetwork.log('Node','['+_hash_str+']',
                           'started around', _hash.toString().decode()
                           if n.isRunning() else
                           'failed to start...'
            )
            trigger_nodes.append(n)

    def _result(self, local_values, new_nodes):
        bootstrap = self._bootstrap
        if not DhtFeatureTest.successfullTransfer(local_values, DhtFeatureTest.foreignValues):
            DhtNetwork.Log.log('[GET]: Only %s on %s values persisted.' %
                    (len(DhtFeatureTest.foreignValues), len(local_values)))
        else:
            DhtNetwork.Log.log('[GET]: All values successfully persisted.')
        if DhtFeatureTest.foreignValues:
            if new_nodes:
                DhtNetwork.Log.log('Values are newly found on:')
                for node in new_nodes:
                    DhtNetwork.Log.log(node)
                if self._dump_storage:
                    DhtNetwork.Log.log('Dumping all storage log from '\
                                  'hosting nodes.')
                    for proc in self._workbench.procs:
                        proc.sendClusterRequest(DhtNetworkSubProcess.DUMP_STORAGE_REQ, DhtFeatureTest.foreignNodes)
            else:
                DhtNetwork.Log.log("Values didn't reach new hosting nodes after shutdown.")

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
            traceback.print_tb(e.__traceback__)
            print(type(e).__name__+':', e, file=sys.stderr)
        finally:
            if self._traffic_plot or self._op_plot:
                plot_fname = "traffic-plot"
                print('plot saved to', plot_fname)
                plt.savefig(plot_fname)
            self._bootstrap.resize(1)

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
        bootstrap = self._bootstrap
        # Value representing an ICE packet. Each ICE packet is around 1KB.
        VALUE_SIZE = 1024
        num_values_per_hash = self._num_values/wb.node_num if self._num_values else 5

        # nodes and values counters
        total_nr_values = 0
        nr_nodes = wb.node_num
        op_cv = threading.Condition()

        # values string in string format. Used for sending cluster request.
        hashes = [random_hash() for _ in range(wb.node_num)]

        def normalBehavior(do, t):
            nonlocal total_nr_values, op_cv
            while True:
                with op_cv:
                    do()
                time.sleep(random.uniform(0.0, float(t)))

        def putRequest():
            nonlocal hashes, VALUE_SIZE, total_nr_values
            lock = threading.Condition()
            def dcb(success):
                nonlocal total_nr_values, lock
                if success:
                    total_nr_values += 1
                    DhtNetwork.Log.log("INFO: "+ str(total_nr_values)+" values put on the dht since begining")
                with lock:
                    lock.notify()
            with lock:
                DhtNetwork.Log.warn("Random value put on the DHT...")
                random.choice(wb.procs).sendClusterPutRequest(random.choice(hashes).toString(),
                                                              random_str_val(size=VALUE_SIZE).encode(),
                                                              done_cb=dcb)
                lock.wait()

        puts = threading.Thread(target=normalBehavior, args=(putRequest, 30.0/wb.node_num))
        puts.daemon = True
        puts.start()

        def newNodeRequest():
            nonlocal nr_nodes
            lock = threading.Condition()
            def dcb(success):
                nonlocal nr_nodes, lock
                nr_nodes += 1
                DhtNetwork.Log.log("INFO: now "+str(nr_nodes)+" nodes on the dht")
                with lock:
                    lock.notify()
            with lock:
                DhtNetwork.Log.warn("Node joining...")
                random.choice(wb.procs).sendClusterRequest(DhtNetworkSubProcess.NEW_NODE_REQ, done_cb=dcb)
                lock.wait()

        connections = threading.Thread(target=normalBehavior, args=(newNodeRequest, 1*50.0/wb.node_num))
        connections.daemon = True
        connections.start()

        def shutdownNodeRequest():
            nonlocal nr_nodes
            lock = threading.Condition()
            def dcb(success):
                nonlocal nr_nodes, lock
                if success:
                    nr_nodes -= 1
                    DhtNetwork.Log.log("INFO: now "+str(nr_nodes)+" nodes on the dht")
                else:
                    DhtNetwork.Log.err("Oops.. No node to shutodwn.")

                with lock:
                    lock.notify()
            with lock:
                DhtNetwork.Log.warn("Node shutting down...")
                random.choice(wb.procs).sendClusterRequest(DhtNetworkSubProcess.SHUTDOWN_NODE_REQ, done_cb=dcb)
                lock.wait()

        shutdowns = threading.Thread(target=normalBehavior, args=(shutdownNodeRequest, 1*60.0/wb.node_num))
        shutdowns.daemon = True
        shutdowns.start()

        if self._traffic_plot:
            display_traffic_plot('br'+wb.ifname)
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
        bootstrap = self._bootstrap

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
                DhtNetwork.Log.log('[GET]: Only ', len(DhtFeatureTest.foreignValues) ,' on ',
                        len(local_values), ' values successfully put.')
            else:
                DhtNetwork.Log.log('[GET]: 0 values successfully put')


        if DhtFeatureTest.foreignValues and DhtFeatureTest.foreignNodes:
            DhtNetwork.Log.log('Values are found on :')
            for node in DhtFeatureTest.foreignNodes:
                DhtNetwork.Log.log(node)

            for _ in range(max(1, int(self._workbench.node_num/32))):
                DhtNetwork.Log.log('Removing all nodes hosting target values...')
                cluster_ops_count = 0
                for proc in self._workbench.procs:
                    DhtNetwork.Log.log('[REMOVE]: sending shutdown request to', proc)
                    lock = threading.Condition()
                    def dcb(success):
                        nonlocal lock
                        if not success:
                            DhtNetwork.Log.err("Failed to shutdown.")
                        with lock:
                            lock.notify()

                    with lock:
                        proc.sendClusterRequest(
                            DhtNetworkSubProcess.SHUTDOWN_NODE_REQ,
                            DhtFeatureTest.foreignNodes,
                            done_cb=dcb
                        )
                        lock.wait()
                    DhtNetwork.Log.log('sending message stats request')
                    def msg_dcb(stats):
                        nonlocal cluster_ops_count, lock
                        if stats:
                            cluster_ops_count += sum(stats[1:])
                        with lock:
                            lock.notify()
                    with lock:
                        proc.sendGetMessageStats(done_cb=msg_dcb)
                        lock.wait()
                    DhtNetwork.Log.log("5 seconds wait...")
                    time.sleep(5)
                ops_count.append(cluster_ops_count/self._workbench.node_num)

                # checking if values were transfered to new nodes
                foreignNodes_before_delete = DhtFeatureTest.foreignNodes
                DhtNetwork.Log.log('[GET]: trying to fetch persistent values')
                self._dhtGet(consumer, myhash)
                new_nodes = set(DhtFeatureTest.foreignNodes) - set(foreignNodes_before_delete)

                self._result(local_values, new_nodes)

            if self._op_plot:
                display_plot(ops_count, color='blue')
        else:
            DhtNetwork.Log.log("[GET]: either couldn't fetch values or nodes hosting values...")

        if traffic_plot_thread:
            print("Traffic plot running for ever. Ctrl-c for stopping it.")
            traffic_plot_thread.join()

    @reset_before_test
    def _replaceClusterTest(self):
        """
        It replaces all clusters one after the other.
        """
        clusters = 8

        bootstrap = self._bootstrap

        bootstrap.resize(3)
        consumer = bootstrap.get(1)
        producer = bootstrap.get(2)

        myhash = random_hash()
        local_values = [Value(b'foo'), Value(b'bar'), Value(b'foobar')]

        self._dhtPut(producer, myhash, *local_values)
        self._dhtGet(consumer, myhash)
        initial_nodes = DhtFeatureTest.foreignNodes

        DhtNetwork.Log.log('Replacing', clusters, 'random clusters successively...')
        for n in range(clusters):
            i = random.randint(0, len(self._workbench.procs)-1)
            proc = self._workbench.procs[i]
            DhtNetwork.Log.log('Replacing', proc)
            proc.sendClusterRequest(DhtNetworkSubProcess.SHUTDOWN_CLUSTER_REQ)
            self._workbench.stop_cluster(i)
            self._workbench.start_cluster(i)

        DhtNetwork.Log.log('[GET]: trying to fetch persistent values')
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
        bootstrap = self._bootstrap

        N_PRODUCERS = self._num_producers if self._num_values else 16
        DP_TIMEOUT = 1

        hashes = []

    # Generating considerable amount of values of size 1KB.
        VALUE_SIZE = 1024
        NUM_VALUES = self._num_values if self._num_values else 50
        values = [Value(random_str_val(size=VALUE_SIZE).encode()) for _ in range(NUM_VALUES)]

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

            DhtNetwork.Log.log("Values are found on:")
            for n in nodes:
                DhtNetwork.Log.log(n)

            DhtNetwork.Log.log("Creating 8 nodes around all of these hashes...")
            for _hash in hashes:
                self._trigger_dp(trigger_nodes, _hash, count=8)

            DhtNetwork.Log.log('Waiting', DP_TIMEOUT+1, 'minutes for normal storage maintenance.')
            time.sleep((DP_TIMEOUT+1)*60)

            DhtNetwork.Log.log('Deleting old nodes from previous search.')
            for proc in self._workbench.procs:
                DhtNetwork.Log.log('[REMOVE]: sending delete request to', proc)
                proc.sendClusterRequest(
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
            traceback.print_tb(e.__traceback__)
            print(type(e).__name__+':', e, file=sys.stderr)
        finally:
            self._bootstrap.resize(1)


    ###########
    #  Tests  #
    ###########

    @reset_before_test
    def _getsTimesTest(self):
        """
        Tests for performance of the DHT doing multiple get() operation.
        """
        bootstrap = self._bootstrap

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
            DhtNetwork.Log.log("found", v)
            return True

        def donecb(ok, nodes, start):
            nonlocal bootstrap, lock, done, times
            t = time.time()-start
            with lock:
                if not ok:
                    DhtNetwork.Log.log("failed !")
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
            DhtNetwork.Log.log("Getting 50 random hashes succesively.")
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

        bootstrap = self._bootstrap

        bootstrap.resize(3)
        consumer = bootstrap.get(1)
        producer = bootstrap.get(2)

        myhash = random_hash()
        local_values = [Value(b'foo'), Value(b'bar'), Value(b'foobar')]

        for _ in range(max(1, int(self._workbench.node_num/32))):
            self._dhtGet(consumer, myhash)
            DhtNetwork.Log.log("Waiting 15 seconds...")
            time.sleep(15)

            self._dhtPut(producer, myhash, *local_values)

            #checking if values were transfered
            self._dhtGet(consumer, myhash)
            DhtNetwork.Log.log('Values are found on :')
            for node in DhtFeatureTest.foreignNodes:
                DhtNetwork.Log.log(node)

            if not DhtFeatureTest.successfullTransfer(local_values, DhtFeatureTest.foreignValues):
                if DhtFeatureTest.foreignValues:
                    DhtNetwork.Log.log('[GET]: Only ', len(DhtFeatureTest.foreignValues) ,' on ',
                            len(local_values), ' values successfully put.')
                else:
                    DhtNetwork.Log.log('[GET]: 0 values successfully put')

            DhtNetwork.Log.log('Removing all nodes hosting target values...')
            for proc in self._workbench.procs:
                DhtNetwork.Log.log('[REMOVE]: sending shutdown request to', proc)
                proc.sendClusterRequest(
                        DhtNetworkSubProcess.SHUTDOWN_NODE_REQ,
                        DhtFeatureTest.foreignNodes
                )
