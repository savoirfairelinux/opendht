#!/usr/bin/env python3
# Copyright (C) 2015 Savoir-Faire Linux Inc.
# Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>

import sys, subprocess, argparse, time, random, string, threading, signal
from pyroute2.netns.process.proxy import NSPopen
import numpy as np
import matplotlib.pyplot as plt
from dhtnetwork import DhtNetwork

sys.path.append('..')
from opendht import *

class WorkBench():
    """docstring for WorkBench"""
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
        self.procs            = [None for _ in range(self.clusters)]

    def get_bootstrap(self):
        if not self.local_bootstrap:
            self.local_bootstrap = DhtNetwork(iface='br'+self.ifname,
                    first_bootstrap=False if self.remote_bootstrap else True,
                    bootstrap=[(self.remote_bootstrap, "5000")] if self.remote_bootstrap else [])
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
            self.procs[i] = NSPopen('node'+str(i), cmd)
        else:
            raise Exception('First create bootstrap.')

    def stop_cluster(self, i):
        if self.procs[i]:
            try:
                self.procs[i].send_signal(signal.SIGINT);
                self.procs[i].wait()
                self.procs[i].release()
            except Exception as e:
                print(e)
            self.procs[i] = None

    def replace_cluster(self):
        n = random.randrange(0, self.clusters)
        self.stop_cluster(n)
        self.start_cluster(n)



def getsTimesTest():
    """TODO: Docstring for

    """

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
    done = 0

    lock = threading.Condition()

    def getcb(v):
        print("found", v)
        return True

    def donecb(ok, nodes):
        nonlocal lock, done, times
        t = time.time()-start
        with lock:
            if not ok:
                print("failed !")
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
        wb.replace_cluster()
        plt.pause(2)
        print("Getting 50 random hashes succesively.")
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

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Run, test and benchmark a DHT network on a local virtual network with simulated packet loss and latency.')
    parser.add_argument('-i', '--ifname', help='interface name', default='ethdht')
    parser.add_argument('-n', '--node-num', help='number of dht nodes to run', type=int, default=32)
    parser.add_argument('-v', '--virtual-locs', help='number of virtual locations (node clusters)', type=int, default=8)
    parser.add_argument('-l', '--loss', help='simulated cluster packet loss (percent)', type=int, default=0)
    parser.add_argument('-d', '--delay', help='simulated cluster latency (ms)', type=int, default=0)
    parser.add_argument('-b', '--bootstrap', help='Bootstrap node to use (if any)', default=None)
    parser.add_argument('-no4', '--disable-ipv4', help='Enable IPv4', action="store_true")
    parser.add_argument('-no6', '--disable-ipv6', help='Enable IPv6', action="store_true")
    parser.add_argument('--gets', action='store_true', help='Launches get calls timings benchmark test.', default=0)

    args = parser.parse_args()

    if args.gets < 1:
        print('No test specified... Quitting.', file=sys.stderr)
        sys.exit(1)

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

        if args.gets:
            getsTimesTest()

    except Exception as e:
        print(e)
    finally:
        for p in wb.procs:
            if p:
                p.send_signal(signal.SIGINT);
        bootstrap.resize(0)
        wb.destroy_virtual_net()
        for p in wb.procs:
            if p:
                try:
                    p.wait()
                    p.release()
                except Exception as e:
                    print(e)
