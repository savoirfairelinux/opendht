#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2015-2023 Savoir-faire Linux Inc.
# Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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
import argparse
import os
import subprocess

from pyroute2 import NDB, NSPopen


def int_range(mini, maxi):
    def check_ifnum(arg):
        try:
            ret = int(arg)
        except ValueError:
            raise argparse.ArgumentTypeError('must be an integer')
        if ret > maxi or ret < mini:
            raise argparse.ArgumentTypeError(
                f'must be {mini} <= int <= {maxi}'
            )
        return ret

    return check_ifnum


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Creates a virtual network topology for testing'
    )
    parser.add_argument(
        '-i', '--ifname', help='interface name', default='ethdht'
    )
    parser.add_argument(
        '-n',
        '--ifnum',
        type=int_range(1, 245),
        help='number of isolated interfaces to create',
        default=1,
    )
    parser.add_argument(
        '-r',
        '--remove',
        help='remove instead of adding network interfaces',
        action='store_true',
    )
    parser.add_argument(
        '-l',
        '--loss',
        help='simulated packet loss (percent)',
        type=int,
        default=0,
    )
    parser.add_argument(
        '-d', '--delay', help='simulated latency (ms)', type=int, default=0
    )
    parser.add_argument(
        '-4', '--ipv4', help='Enable IPv4', action='store_true'
    )
    parser.add_argument(
        '-6', '--ipv6', help='Enable IPv6', action='store_true'
    )
    parser.add_argument(
        '-b',
        '--debug',
        help='Turn on debug logging and dump topology databases',
        action='store_true',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        help='Turn on verbose output on netns and interfaces operations',
        action='store_true',
    )

    args = parser.parse_args()

    local_addr4 = '10.0.42.'
    local_addr6 = '2001:db9::'
    bripv4 = f'{local_addr4}1/24'
    bripv6 = f'{local_addr6}1/64'
    bridge_name = f'br{args.ifname}'
    tap_name = f'tap{args.ifname}'
    veth_names = []
    namespaces = []
    ipv4addrs = []
    ipv6addrs = []
    for ifn in range(args.ifnum):
        namespaces.append(f'node{ifn}')
        veth_names.append(f'{args.ifname}{ifn}')
        ipv4addrs.append(f'{local_addr4}{ifn+8}/24' if args.ipv4 else None)
        ipv6addrs.append(f'{local_addr6}{ifn+8}/64' if args.ipv6 else None)

    with NDB(log='debug' if args.debug else None) as ndb:
        if args.remove:
            # cleanup interfaces in the main namespace
            for iface in veth_names + [bridge_name] + [tap_name]:
                if iface in ndb.interfaces:
                    ndb.interfaces[iface].remove().commit()
                    if args.verbose:
                        print(f'link: del main/{iface}')

            # cleanup namespaces
            for nsname in namespaces:
                try:
                    ndb.netns[nsname].remove().commit()
                    if args.verbose:
                        print(f'netns: del {nsname}')
                except KeyError:
                    pass
        else:
            # create ports
            for veth, nsname, ipv4addr, ipv6addr in zip(
                veth_names, namespaces, ipv4addrs, ipv6addrs
            ):
                # create a network namespace and launch NDB for it
                #
                # another possible solution could be simply to attach
                # the namespace to the main NDB instance, but it can
                # take a lot of memory in case of many interfaces, thus
                # launch and discard netns NDB instances
                netns = NDB(
                    log='debug' if args.debug else None,
                    sources=[
                        {
                            'target': 'localhost',
                            'netns': nsname,
                            'kind': 'netns',
                        }
                    ],
                )
                if args.verbose:
                    print(f'netns: add {nsname}')
                # create the port and push the peer into the namespace
                (
                    ndb.interfaces.create(
                        **{
                            'ifname': veth,
                            'kind': 'veth',
                            'state': 'up',
                            'peer': {'ifname': veth, 'net_ns_fd': nsname},
                        }
                    ).commit()
                )
                if args.verbose:
                    print(f'link: add main/{veth} <-> {nsname}/{veth}')
                # bring up namespace's loopback
                (
                    netns.interfaces.wait(ifname='lo', timeout=3)
                    .set('state', 'up')
                    .commit()
                )
                if args.verbose:
                    print(f'link: set {nsname}/lo')
                # bring up the peer
                with netns.interfaces.wait(ifname=veth, timeout=3) as i:
                    i.set('state', 'up')
                    if args.ipv4:
                        i.add_ip(ipv4addr)
                    if args.ipv6:
                        i.add_ip(ipv6addr)
                if args.verbose:
                    print(f'link: set {nsname}/{veth}, {ipv4addr}, {ipv6addr}')
                # disconnect the namespace NDB agent, not removing the NS
                if args.debug:
                    fname = f'{nsname}-ndb.db'
                    print(f'dump: netns topology database {fname}')
                    netns.schema.backup(fname)
                netns.close()
                # set up the emulation QDisc
                nsp = NSPopen(
                    nsname,
                    [
                        'tc',
                        'qdisc',
                        'add',
                        'dev',
                        veth,
                        'root',
                        'netem',
                        'delay',
                        f'{args.delay}ms',
                        f'{int(args.delay)/2}ms',
                        'loss',
                        f'{args.loss}%',
                        '25%',
                    ],
                    stdout=subprocess.PIPE,
                )
                nsp.communicate()
                nsp.wait()
                nsp.release()
                if args.verbose:
                    print(
                        f'netem: add {nsname}/{veth}, '
                        f'{args.delay}, {args.loss}'
                    )

            # create the tap
            #
            # for some reason we should create the tap inteface first,
            # and only then bring it up, thus two commit() calls
            (
                ndb.interfaces.create(
                    kind='tuntap', ifname=tap_name, mode='tap'
                )
                .commit()
                .set('state', 'up')
                .commit()
            )
            if args.verbose:
                print(f'link: add main/{tap_name}')

            # create the bridge and add all the ports
            with ndb.interfaces.create(
                ifname=bridge_name, kind='bridge', state='up'
            ) as i:
                if args.ipv4:
                    i.add_ip(bripv4)
                if args.ipv6:
                    i.add_ip(bripv6)
                for iface in veth_names + [tap_name]:
                    i.add_port(iface)
            if args.verbose:
                print(f'link: add main/{bridge_name}, {bripv4}, {bripv6}')

            with open(os.devnull, 'w') as fnull:
                if args.ipv4:
                    subprocess.call(
                        [
                            'sysctl',
                            '-w',
                            f'net.ipv4.conf.{bridge_name}.forwarding=1',
                        ],
                        stdout=fnull,
                    )
                if args.verbose:
                    print(f'sysctl: set {bridge_name} ipv4 forwarding')
                if args.ipv6:
                    subprocess.call(
                        [
                            'sysctl',
                            '-w',
                            f'net.ipv6.conf.{bridge_name}.forwarding=1',
                        ],
                        stdout=fnull,
                    )
                if args.verbose:
                    print(f'sysctl: set {bridge_name} ipv4 forwarding')

            if args.debug:
                fname = 'main-ndb.db'
                print('dump: the main netns topology database')
                ndb.schema.backup(fname)
