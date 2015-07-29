#!/usr/bin/env python3
# Copyright (C) 2015 Savoir-Faire Linux Inc.
# Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>

import argparse, subprocess

from pyroute2 import IPDB, NetNS
from pyroute2.netns.process.proxy import NSPopen

parser = argparse.ArgumentParser(description='Creates a virtual network topology for testing')
parser.add_argument('-i', '--ifname', help='interface name', default='ethdht')
parser.add_argument('-n', '--ifnum', type=int, help='number of isolated interfaces to create', default=1)
parser.add_argument('-r', '--remove', help='remove instead of adding network interfaces', action="store_true")
parser.add_argument('-l', '--loss', help='simulated packet loss (percent)', type=int, default=0)
parser.add_argument('-d', '--delay', help='simulated latency (ms)', type=int, default=0)
parser.add_argument('-4', '--ipv4', help='Enable IPv4', action="store_true")
parser.add_argument('-6', '--ipv6', help='Enable IPv6', action="store_true")

args = parser.parse_args()

local_addr4 = '10.0.42.'
local_addr6 = '2001:db9::'
brige_name = 'br'+args.ifname

ip = None
try:
    ip = IPDB()
    if args.remove:
        # cleanup interfaces
        for ifn in range(args.ifnum):
            iface = args.ifname+str(ifn)
            if iface in ip.interfaces:
                with ip.interfaces[iface] as i:
                    i.remove()
        if 'tap'+args.ifname in ip.interfaces:
            with ip.interfaces['tap'+args.ifname] as i:
                i.remove()
        if brige_name in ip.interfaces:
            with ip.interfaces[brige_name] as i:
                i.remove()
        for ifn in range(args.ifnum):
            netns = NetNS('node'+str(ifn))
            netns.close()
            netns.remove()
    else:
        for ifn in range(args.ifnum):
            iface = args.ifname+str(ifn)
            if not iface in ip.interfaces:
                ip.create(kind='veth', ifname=iface, peer=iface+'.1').commit()

        ip.create(kind='tuntap', ifname='tap'+args.ifname, mode='tap').commit()

        with ip.create(kind='bridge', ifname=brige_name) as i:
            for ifn in range(args.ifnum):
                iface = args.ifname+str(ifn)
                i.add_port(ip.interfaces[iface])
            i.add_port(ip.interfaces['tap'+args.ifname])
            if args.ipv4:
                i.add_ip(local_addr4+'1/24')
            if args.ipv6:
                i.add_ip(local_addr6+'1/64')
            i.up()

        with ip.interfaces['tap'+args.ifname] as tap:
            tap.up()

        for ifn in range(args.ifnum):
            iface = args.ifname+str(ifn)

            nns = NetNS('node'+str(ifn))
            iface1 = iface+'.1'
            with ip.interfaces[iface1] as i:
                i.net_ns_fd = nns.netns

            with ip.interfaces[iface] as i:
                i.up()

            ip_ns = IPDB(nl=nns)
            try:
                with ip_ns.interfaces.lo as lo:
                    lo.up()
                with ip_ns.interfaces[iface1] as i:
                    if args.ipv4:
                        i.add_ip(local_addr4+str(ifn+8)+'/24')
                    if args.ipv6:
                        i.add_ip(local_addr6+str(ifn+8)+'/64')
                    i.up()
            finally:
                ip_ns.release()

            nsp = NSPopen(nns.netns, ["tc", "qdisc", "add", "dev", iface1, "root", "netem", "delay", str(args.delay)+"ms", str(int(args.delay/2))+"ms", "loss", str(args.loss)+"%", "25%"], stdout=subprocess.PIPE)
            #print(nsp.communicate()[0].decode())
            nsp.communicate()
            nsp.wait()
            nsp.release()

        if args.ipv4:
            subprocess.call(["sysctl", "-w", "net.ipv4.conf."+brige_name+".forwarding=1"])
        if args.ipv6:
            subprocess.call(["sysctl", "-w", "net.ipv6.conf."+brige_name+".forwarding=1"])

except Exception as e:
      print('Error',e)
finally:
    if ip:
        ip.release()
