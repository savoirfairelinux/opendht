#!/usr/bin/env python3
import sys, subprocess, argparse, time, random, string, math, ipaddress, threading, queue
from pyroute2.netns.process.proxy import NSPopen
import numpy as np
import matplotlib.pyplot as plt
from dhtnetwork import DhtNetwork

sys.path.append('..')
from opendht import *

def random_hash():
    return PyInfoHash(''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(40)).encode())

parser = argparse.ArgumentParser(description='Create a dummy network interface for testing')
parser.add_argument('-i', '--ifname', help='interface name', default='ethdht')
parser.add_argument('-n', '--node-num', help='number of dht nodes to run', type=int, default=32)
parser.add_argument('-v', '--virtual-locs', help='number of virtual locations', type=int, default=8)
parser.add_argument('-l', '--loss', help='simulated cluster packet loss (percent)', type=int, default=0)
parser.add_argument('-d', '--delay', help='simulated cluster latency (ms)', type=int, default=0)

args = parser.parse_args()

clusters = min(args.virtual_locs, args.node_num)
node_per_loc = int(args.node_num / clusters)

print("Launching", args.node_num, "nodes (", clusters, "clusters of", node_per_loc, "nodes)")

if args.virtual_locs > 1:
    p = subprocess.Popen(["/usr/bin/sudo", "python3", "dummy_if.py", "-i", args.ifname, "-n", str(clusters), '-l', str(args.loss), '-d', str(args.delay)], stdout=subprocess.PIPE)
    output, err = p.communicate()
    print(output.decode())

bootstrap = DhtNetwork(iface='br'+args.ifname)
bootstrap.resize(1)

procs = [None for _ in range(clusters)]

try:
    for i in range(clusters):
        procs[i] = NSPopen('node'+str(i), ["python3", "dhtnetwork.py", "-n", str(node_per_loc), "-b", bootstrap.ip4, "-b6", bootstrap.ip6, '-I', args.ifname+str(i)+'.1'])
        plt.pause(2)

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

    def donecb(ok, nodes):
        global lock, done, times
        t = time.time()-start
        with lock:
            if not ok:
                print("failed !")
            times.append(t)
            done -= 1
            lock.notify()

    def update_plot():
        global lines
        while lines:
            l = lines.pop()
            l.remove()
            del l
        lines = plt.plot(times, color='blue')
        plt.draw()

    def replace_cluster():
        n = random.randrange(0, clusters)
        if procs[n]:
            print("Terminating process...")
            try:
                procs[n].terminate()
                procs[n].release()
            except:
                pass
        procs[n] = NSPopen('node'+str(n), ["python3", "dhtnetwork.py", "-n", str(node_per_loc), "-b", bootstrap.ip4, "-b6", bootstrap.ip6, '-I', args.ifname+str(n)+'.1'])

    plt.pause(5)

    plt.show()
    update_plot()

    times = []
    for n in range(10):
        #nnodes = (n+1)*args.node_num
        #net.resize(nnodes)
        #time.sleep(2.5)
        replace_cluster()
        print("Getting 10 random hashes succesively.")
        for i in range(50):
            #net.replace_node()
            #if not (i % 10):
            #    net.replace_node()
            with lock:
                done += 1
                start = time.time()
                bootstrap.front().get(random_hash(), getcb, donecb)
                while done > 0:
                    lock.wait()
            update_plot()
        print("Took", np.sum(times), "mean", np.mean(times), "std", np.std(times), "min", np.min(times), "max", np.max(times))

    plt.ioff()
    plt.show()
except Exception as e:
    print(e)
finally:
    for p in procs:
        if p:
            print("Terminating process...")
            try:
                p.terminate()
                p.release()
            except:
                pass
    subprocess.call(["/usr/bin/sudo", "python3", "dummy_if.py", "-i", args.ifname, "-n", str(clusters), "-r"])
