# Copyright (C) 2015 Savoir-Faire Linux Inc.
# Author(s): Adrien Béraud <adrien.beraud@savoirfairelinux.com>
#            Simon Désaulniers <sim.desaulniers@gmail.com>

import threading
import random
import string
import time
import math

import numpy as np
import matplotlib.pyplot as plt
import networkx as nx

from opendht import *
from dht.network import DhtNetwork, DhtNetworkSubProcess

######################
#  Common functions  #
######################

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

        edges = set([])
        for prefix in prefixes:
            for i in range(-1, len(prefix)-1):
                u = prefix[:i+1]
                edges.add( ("" if i == -1 else u, u+"0") )
                edges.add( ("" if i == -1 else u, u+"1") )

        # TODO: use a binary tree position layout...
        G = nx.Graph(list(edges))
        nx.draw(G, with_labels=True, node_color='white')
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
        pht = Pht(b'foo_index', dht)

        DhtNetwork.log('PHT has',
                       pht.MAX_NODE_ENTRY_COUNT,
                       'node'+ ('s' if pht.MAX_NODE_ENTRY_COUNT > 1 else ''),
                       'per leaf bucket.')
        NUM_DIG  = max(math.log(self._num_keys, 2)/4, 5) # at least 5 digit keys.
        keys = [{
            'foo' :
            ''.join(random.SystemRandom().choice(string.hexdigits)
                for _ in range(NUM_DIG)).encode()
            } for n in range(self._num_keys)]
        all_entries = {}

        # Index all entries.
        for key in keys:
            PhtTest.key = key
            pht.insert(key, IndexValue(random_hash()), PhtTest.insertDoneCb)
            with FeatureTest.lock:
                FeatureTest.lock.wait()

        # Recover entries now that the trie is complete.
        for key in keys:
            PhtTest.key = key
            pht.lookup(key, PhtTest.lookupCb, PhtTest.lookupDoneCb)
            with FeatureTest.lock:
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
        DhtNetwork.log('[GET]: %s' % value)
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
        for val in values:
            with FeatureTest.lock:
                DhtNetwork.log('[PUT]: %s' % val)
                FeatureTest.done += 1
                producer.put(_hash, val, DhtFeatureTest.putDoneCb)
                while FeatureTest.done > 0:
                    FeatureTest.lock.wait()

    def _dhtGet(self, consumer, _hash):
        DhtFeatureTest.foreignValues = []
        DhtFeatureTest.foreignNodes = []
        with FeatureTest.lock:
            FeatureTest.done += 1
            consumer.get(_hash, DhtFeatureTest.getcb, DhtFeatureTest.getDoneCb)
            while FeatureTest.done > 0:
                FeatureTest.lock.wait()


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

        - dump_str_log: enables storage log at test ending.
        """

        # opts
        super(PersistenceTest, self).__init__(test, workbench)
        self._dump_storage = True if 'dump_str_log' in opts else False
        self._plot = True if 'plot' in opts else False

    def _result(self, local_values, new_nodes):
        bootstrap = self._bootstrap
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
                        proc.sendDumpStorage(DhtFeatureTest.foreignNodes)
            else:
                DhtNetwork.log("Values didn't reach new hosting nodes after shutdown.")

    def run(self):
        try:
            if self._test == 'delete':
                self._deleteTest()
            elif self._test == 'replace':
                self._replaceClusterTest()
            elif self._test == 'mult_time':
                self._multTimeTest()
        except Exception as e:
            print(e)
        finally:
            self._bootstrap.resize(1)

    ###########
    #  Tests  #
    ###########

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
                DhtNetwork.log('[GET]: Only ', len(DhtFeatureTest.foreignValues) ,' on ',
                        len(local_values), ' values successfully put.')
            else:
                DhtNetwork.log('[GET]: 0 values successfully put')


        if DhtFeatureTest.foreignValues and DhtFeatureTest.foreignNodes:
            DhtNetwork.log('Values are found on :')
            for node in DhtFeatureTest.foreignNodes:
                DhtNetwork.log(node)

            #DhtNetwork.log("Waiting a minute for the network to settle down.")
            #time.sleep(60)

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
                    DhtNetwork.log("3 seconds wait...")
                    time.sleep(3)
                ops_count.append(cluster_ops_count/self._workbench.node_num)

                # checking if values were transfered to new nodes
                foreignNodes_before_delete = DhtFeatureTest.foreignNodes
                DhtNetwork.log('[GET]: trying to fetch persistent values')
                self._dhtGet(consumer, myhash)
                new_nodes = set(DhtFeatureTest.foreignNodes) - set(foreignNodes_before_delete)

                self._result(local_values, new_nodes)

            if self._plot:
                plt.plot(ops_count, color='blue')
                plt.draw()
                plt.ioff()
                plt.show()
        else:
            DhtNetwork.log("[GET]: either couldn't fetch values or nodes hosting values...")

    #TODO: complete this test.
    @reset_before_test
    def _replaceClusterTest(self):
        """
        It replaces all clusters one after the other.
        """

        #clusters = opts['clusters'] if 'clusters' in opts else 5
        clusters = 5

        bootstrap = self._bootstrap

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
            proc.sendShutdown()
            self._workbench.stop_cluster(i)
            self._workbench.start_cluster(i)

        DhtNetwork.log('[GET]: trying to fetch persistent values')
        self._dhtGet(consumer, myhash)
        new_nodes = set(DhtFeatureTest.foreignNodes) - set(initial_nodes)

        self._result(local_values, new_nodes)

    #TODO: complete this test.
    @reset_before_test
    def _multTimeTest(self):
        """
        Multiple put() calls are made from multiple nodes to multiple hashes
        after what a set of 8 nodes is created around each hashes in order to
        enable storage maintenance each nodes. Therefor, this tests will wait 10
        minutes for the nodes to trigger storage maintenance.
        """
        bootstrap = self._bootstrap

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
                    for n in DhtFeatureTest.foreignNodes:
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
                n.bootstrap(self._bootstrap.ip4,
                            str(self._bootstrap.port))
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
        for proc in self._workbench.procs:
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
        except Exception as e:
            print(e)
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
            self._workbench.replace_cluster()
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
