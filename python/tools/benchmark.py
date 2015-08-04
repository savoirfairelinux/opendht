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

def random_hash():
    return PyInfoHash.getRandom()

def start_cluster(i):
    global procs
    cmd = ["python3", "dhtnetwork.py", "-n", str(node_per_loc), '-I', args.ifname+str(i)+'.1']
    if not args.disable_ipv4 and bootstrap.ip4:
        cmd.extend(['-b', bootstrap.ip4])
    if not args.disable_ipv6 and bootstrap.ip6:
        cmd.extend(['-b6', bootstrap.ip6])
    procs[i] = NSPopen('node'+str(i), cmd)
    plt.pause(2)

def stop_cluster(i):
    global procs
    if procs[i]:
        try:
            procs[i].send_signal(signal.SIGINT);
            procs[i].wait()
            procs[i].release()
        except Exception as e:
            print(e)
        procs[i] = None

def replace_cluster():
    n = random.randrange(0, clusters)
    stop_cluster(n)
    start_cluster(n)

def getsTimesTest():
    """TODO: Docstring for

    """

    plt.ion()

    lines = plt.plot([])
    plt.ylabel('time (s)')
    #plt.show()

    # let the network stabilise
    plt.pause(5)

    start = time.time()
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

    plt.pause(5)

    plt.show()
    update_plot()

    times = []
    for n in range(10):
        #replace_cluster()
        plt.pause(2)
        print("Getting 50 random hashes succesively.")
        for i in range(50):
            with lock:
                done += 1
                start = time.time()
                bootstrap.front().get(random_hash(), getcb, donecb)
                while done > 0:
                    lock.wait()
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
    parser.add_argument('-no4', '--disable-ipv4', help='Enable IPv4', action="store_true")
    parser.add_argument('-no6', '--disable-ipv6', help='Enable IPv6', action="store_true")
    parser.add_argument('--gets', action='store_true', help='Launches get calls timings benchmark test.', default=0)

    args = parser.parse_args()

    if args.gets < 1:
        print('No test specified... Quitting.', file=sys.stderr)
        sys.exit(1)

    clusters = min(args.virtual_locs, args.node_num)
    node_per_loc = int(args.node_num / clusters)

    print("Launching", args.node_num, "nodes (", clusters, "clusters of", node_per_loc, "nodes)")

    if args.virtual_locs > 1:
        cmd = ["python3", "virtual_network_builder.py", "-i", args.ifname, "-n", str(clusters), '-l', str(args.loss), '-d', str(args.delay)]
        if not args.disable_ipv4:
            cmd.append('-4')
        if not args.disable_ipv6:
            cmd.append('-6')
        print(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        output, err = p.communicate()
        print(output.decode())

    bootstrap = DhtNetwork(iface='br'+args.ifname)
    bootstrap.resize(1)

    procs = [None for _ in range(clusters)]

    try:
        for i in range(clusters):
            start_cluster(i)

        if args.gets:
            getsTimesTest()

    except Exception as e:
        print(e)
    finally:
        for p in procs:
            if p:
                p.send_signal(signal.SIGINT);
        bootstrap.resize(0)
        print('Shuting down the virtual IP network.')
        subprocess.call(["python3", "virtual_network_builder.py", "-i", args.ifname, "-n", str(clusters), "-r"])
        for p in procs:
            if p:
                try:
                    p.wait()
                    p.release()
                except Exception as e:
                    print(e)
