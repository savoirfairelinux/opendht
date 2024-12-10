#!/usr/bin/env python3
# Copyright (c) 2015-2019 Savoir-faire Linux Inc.
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

import time
import argparse
import time
import asyncio
from datetime import datetime

import opendht as dht

parser = argparse.ArgumentParser(description='Create a dht network of -n nodes')
parser.add_argument('-b', '--bootstrap', help='bootstrap address', default='bootstrap.ring.cx')
parser.add_argument('-n', '--num-ops', help='number of concurrent operations on the DHT', type=int, default=8)
parser.add_argument('-p', '--period', help='duration between each test (seconds)', type=int, default=60)
parser.add_argument('-t', '--timeout', help='timeout for a test to complete (seconds)', type=float, default=15)
args = parser.parse_args()

node1 = dht.DhtRunner()
node1.run()

node2 = dht.DhtRunner()
node2.run()

node1.bootstrap(args.bootstrap)
node2.bootstrap(args.bootstrap)
loop = asyncio.get_event_loop()

pending_tests = {}
keys = [dht.InfoHash.getRandom() for _ in range(args.num_ops)]

def listen_cb(key, val, expired):
    global pending_tests
    kstr = str(key)
    if kstr in pending_tests:
        if pending_tests[kstr]['v'].id == val.id:
            pending_tests.pop(kstr, None)
        else:
            print("Expected vid", val.id, "got", pending_tests[kstr]['v'].id)
    return True

def listen(key):
    node1.listen(key, lambda v, e: loop.call_soon_threadsafe(listen_cb, key, v, e))

for key in keys:
    listen(key)

next_test = time.time()
while True:
    start = time.time()
    #print(datetime.fromtimestamp(start).strftime('%Y-%m-%d %H:%M:%S'), 'Test started')
    for key in keys:
        val = dht.Value(str(dht.InfoHash.getRandom()).encode())
        pending_tests[str(key)] = {'v':val, 'c':0}
        node2.put(key, val, lambda ok, nodes: ok)
    while len(pending_tests):
        loop.stop()
        loop.run_forever()
        time.sleep(1)
        if time.time()-start > args.timeout:
            print('Test timeout !')
            exit(1)

    end = time.time()
    print(datetime.fromtimestamp(end).strftime('%Y-%m-%d %H:%M:%S'),
          'Test completed successfully in', end-start)
    next_test += args.period
    if next_test > end:
        time.sleep(next_test-end)
