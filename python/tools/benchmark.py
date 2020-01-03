#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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
import signal
import argparse
import time
import random

from dht.network import DhtNetwork
from dht.network import DhtNetworkSubProcess
from dht.tests import PerformanceTest, PersistenceTest, PhtTest
from dht import virtual_network_builder
from dht import network as dhtnetwork

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
            cmd = ["python3", os.path.abspath(virtual_network_builder.__file__),
                    "-i", self.ifname,
                    "-n", str(self.clusters),
                    '-l', str(self.loss),
                    '-d', str(self.delay)]
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
        subprocess.call(["python3", os.path.abspath(virtual_network_builder.__file__), "-i", self.ifname, "-n", str(self.clusters), "-r"])

    def start_cluster(self, i):
        if self.local_bootstrap:
            cmd = ["python3", os.path.abspath(dhtnetwork.__file__), "-n", str(self.node_per_loc), '-I', self.ifname+str(i)+'.1']
            if self.remote_bootstrap:
                cmd.extend(['-b', self.remote_bootstrap, '-bp', "5000"])
            else:
                if not self.disable_ipv4 and self.local_bootstrap.ip4:
                    cmd.extend(['-b', self.local_bootstrap.ip4])
                if not self.disable_ipv6 and self.local_bootstrap.ip6:
                    cmd.extend(['-b6', self.local_bootstrap.ip6])
            lock = threading.Condition()
            def dcb(success):
                nonlocal lock
                if not success:
                    DhtNetwork.Log.err("Failed to initialize network...")
                with lock:
                    lock.notify()
            with lock:
                self.procs[i] = DhtNetworkSubProcess('node'+str(i), cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                self.procs[i].sendPing(done_cb=dcb)
                lock.wait()
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
    testArgs.add_argument('--bs-dht-log', action='store_true', default=False, help='Enables dht log in bootstrap.')
    testArgs.add_argument('-t', '--test', type=str, default=None, required=True, help='Specifies the test.')
    testArgs.add_argument('-o', '--opt', type=str, default=[], nargs='+',
            help='Options passed to tests routines.')
    testArgs.add_argument('-m', type=int, default=None, help='Generic size option passed to tests.')
    testArgs.add_argument('-e', type=int, default=None, help='Generic size option passed to tests.')

    featureArgs = parser.add_mutually_exclusive_group(required=True)
    featureArgs.add_argument('--performance', action='store_true', default=False,
            help='Launches performance benchmark test. Available args for "-t" are: gets.')
    featureArgs.add_argument('--pht', action='store_true', default=False,
            help='Launches PHT benchmark test. '\
                    'Available args for "-t" are: insert. '\
                    'Timer available by adding "timer" to "-o" args'\
                    'Use "-m" option for fixing number of keys to create during the test.')
    featureArgs.add_argument('--data-persistence', action='store_true', default=0,
            help='Launches data persistence benchmark test. '\
                 'Available args for "-t" are: delete, replace, mult_time. '\
                 'Available args for "-o" are : dump_str_log, keep_alive, trigger, traffic_plot, op_plot. '\
                 'Use "-m" to specify the number of producers on the DHT. '\
                 'Use "-e" to specify the number of values to put on the DHT.')

    args = parser.parse_args()
    test_opt = { o : True for o in args.opt }

    wb = WorkBench(args.ifname, args.virtual_locs, args.node_num, loss=args.loss,
            delay=args.delay, disable_ipv4=args.disable_ipv4,
            disable_ipv6=args.disable_ipv6)
    wb.create_virtual_net()
    bootstrap = wb.get_bootstrap()

    bs_dht_log_enabled = False
    def toggle_bs_dht_log(signum, frame):
        global bs_dht_log_enabled, bootstrap
        if bs_dht_log_enabled:
            bootstrap.front().disableLogging()
            bs_dht_log_enabled = False
        else:
            bootstrap.front().enableLogging()
            bs_dht_log_enabled = True
    signal.signal(signal.SIGUSR1, toggle_bs_dht_log)

    if args.bs_dht_log:
        bs_dht_log_enabled = True
        bootstrap.front().enableLogging()

    bootstrap.resize(1)
    print("Launching", wb.node_num, "nodes (", wb.clusters, "clusters of", wb.node_per_loc, "nodes)")

    try:
        for i in range(wb.clusters):
            wb.start_cluster(i)

        # recover -e and -m values.
        if args.e:
            test_opt.update({ 'num_values' : args.e })
        if args.m:
            test_opt.update({ 'num_producers' : args.m })

        # run the test
        if args.performance:
            PerformanceTest(args.test, wb, test_opt).run()
        elif args.data_persistence:
            PersistenceTest(args.test, wb, test_opt).run()
        elif args.pht:
            if args.m:
                test_opt.update({ 'num_keys' : args.m })
            PhtTest(args.test, wb, test_opt).run()

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
