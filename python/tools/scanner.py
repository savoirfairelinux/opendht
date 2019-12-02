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

import time, sys, os
from pprint import pprint
from math import cos, sin, pi
import urllib3
import gzip
import queue

sys.path.append('..')
from opendht import *

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import colorConverter
from matplotlib.collections import RegularPolyCollection
from matplotlib.widgets import Button
from mpl_toolkits.basemap import Basemap

import GeoIP

http = urllib3.PoolManager()

run = True
done = 0
all_nodes = NodeSet()
nodes_ip4s = {}
nodes_ip6s = {}
lats = []
lons = []
cities=[]
xys = []
colors = []
all_lines = []
points = []
not_found = []

plt.ion()
plt.figaspect(2.)

fig, axes = plt.subplots(2, 1)
fig.set_size_inches(8,16,forward=True)
fig.tight_layout()
fig.canvas.set_window_title('OpenDHT scanner')

mpx = axes[0]
mpx.set_title("Node GeoIP")

m = Basemap(projection='robin', resolution = 'l', area_thresh = 1000.0, lat_0=0, lon_0=0, ax=mpx)
m.fillcontinents(color='#cccccc',lake_color='white')
m.drawparallels(np.arange(-90.,120.,30.))
m.drawmeridians(np.arange(0.,420.,60.))
m.drawmapboundary(fill_color='white')
plt.show()

ringx = axes[1]
ringx.set_title("Node IDs")
ringx.set_autoscale_on(False)
ringx.set_aspect('equal', 'datalim')
ringx.set_xlim(-2.,2.)
ringx.set_ylim(-1.5,1.5)

exitax = plt.axes([0.92, 0.95, 0.07, 0.04])
exitbtn = Button(exitax, 'Exit')
reloadax = plt.axes([0.92, 0.90, 0.07, 0.04])
button = Button(reloadax, 'Reload')

collection = None
infos = [ringx.text(1.2, -0.8, ""),
         ringx.text(1.2, -0.9, "")]

def exitcb(arg):
    global run
    run = False
exitbtn.on_clicked(exitcb)

def check_dl(fname, url):
    if os.path.isfile(fname):
        return
    print('downloading', url)
    ghandle = gzip.GzipFile(fileobj=http.request('GET', url, headers={'User-Agent': 'Mozilla/5.0'}, preload_content=False))
    with open(fname, 'wb') as out:
        for line in ghandle:
            out.write(line)

check_dl("GeoLiteCity.dat", "http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz")
check_dl("GeoLiteCityv6.dat", "http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz")

gi = GeoIP.open("GeoLiteCity.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)
gi6 = GeoIP.open("GeoLiteCityv6.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)

def gcb(v):
    return True

r = DhtRunner()
r.run(port=4112)
r.bootstrap("bootstrap.ring.cx", "4222")

plt.pause(1)

q = queue.Queue()

def step(cur_h, cur_depth):
    global done
    done += 1
    a = 2.*pi*cur_h.toFloat()
    b = a + 2.*pi/(2**(cur_depth))
    arc = []
    lines = []
    q.put((stepUi, (cur_h, cur_depth, arc, lines)))
    print("step", cur_h, cur_depth)
    r.get(cur_h, gcb, lambda d, nodes: stepdone(cur_h, cur_depth, d, nodes, arc, lines))

def stepdone(cur_h, cur_depth, d, nodes, arc, lines):
    #print("stepdone", cur_h, cur_depth)
    q.put((nextstepUi, (nodes, arc, lines)))
    nextstep(cur_h, cur_depth, d, nodes)

def nextstep(cur_h, cur_depth, ok, nodes):
    global done
    if nodes:
        commonBits = 0
        if len(nodes) > 1:
            snodes = NodeSet()
            snodes.extend(nodes)
            commonBits = InfoHash.commonBits(snodes.first(), snodes.last())
        depth = min(8, commonBits+6)
        if cur_depth < depth:
            for b in range(cur_depth, depth):
                new_h = InfoHash(cur_h.toString());
                new_h.setBit(b, 1);
                step(new_h, b+1);
    else:
        print("step done with no nodes", ok, cur_h.toString().decode())
    done -= 1

def stepUi(cur_h, cur_depth, arc, lines):
    global all_lines
    a = 2.*pi*cur_h.toFloat()
    b = a + 2.*pi/(2**(cur_depth))
    arc.append(ringx.add_patch(mpatches.Wedge([0.,0,], 1., a*180/pi, b*180/pi, fill=True, color="blue", alpha=0.5)))
    lines.extend(ringx.plot([0, cos(a)], [0, sin(a)], 'k-', lw=1.2))
    all_lines.extend(lines)

def nextstepUi(nodes, arc=None, lines=[]):
    for a in arc:
        if a:
            a.remove()
            del a
    for l in lines:
        l.set_color('#aaaaaa')
    if nodes:
        appendNodes(nodes)

def appendNodes(nodes):
    global all_nodes
    for n in nodes:
        if all_nodes.insert(n):
            appendNewNode(n)

def appendNewNode(n):
    global nodes_ip4s, nodes_ip6s, colors, xys
    addr = b':'.join(n.getNode().getAddr().split(b':')[0:-1]).decode()
    colors.append('red' if n.getNode().isExpired() else 'blue')
    node_val = n.getId().toFloat()
    xys.append((cos(node_val*2*pi), sin(node_val*2*pi)))
    georecord = None
    if addr[0] == '[':
        addr = addr[1:-1]
        if addr in nodes_ip6s:
            nodes_ip6s[addr][1] += 1
        else:
            georecord = gi6.record_by_name_v6(addr)
            nodes_ip6s[addr] = [n, 1, georecord]
    else:
        if addr in nodes_ip4s:
            nodes_ip4s[addr][1] += 1
        else:
            georecord = gi.record_by_name(addr)
            nodes_ip4s[addr] = [n, 1, georecord]
    if georecord:
        appendMapPoint(georecord)

def appendMapPoint(res):
    global lons, lats, cities
    lons.append(res['longitude'])
    lats.append(res['latitude'])
    cities.append(res['city'] if res['city'] else (str(int(res['latitude']))+'-'+str(int(res['longitude']))))


def restart(arg):
    global collection, all_lines, all_nodes, points, done, nodes_ip4s, nodes_ip6s, lats, lons, cities, xys, colors
    if done:
        return
    for l in all_lines:
        l.remove()
        del l
    all_lines = []
    all_nodes = NodeSet()
    nodes_ip4s = {}
    nodes_ip6s = {}
    lats = []
    lons = []
    cities=[]
    xys = []
    colors = []
    if collection:
        collection.remove()
        del collection
        collection = None
    for p in points:
        p.remove()
        del p
    points = []

    print(arg)
    start_h = InfoHash()
    start_h.setBit(159, 1)
    step(start_h, 0)
    plt.draw()

def num_nodes(node_set):
    return sorted([x for x in node_set.items()], key=lambda ip: ip[1][1])

def update_plot():
    #print("update_plot", done)
    global m, collection, points
    for p in points:
        p.remove()
        del p
    points = []
    x,y = m(lons,lats)
    points.extend(m.plot(x,y,'bo'))
    for name, xpt, ypt in zip(cities, x, y):
        points.append(mpx.text(xpt+50000, ypt+50000, name))
    if collection:
        collection.remove()
        del collection
        collection = None
    collection = ringx.add_collection(RegularPolyCollection(
                int(fig.dpi), 6, sizes=(10,), facecolors=colors,
                offsets = xys, transOffset = ringx.transData))

    infos[0].set_text("{} different IPv4s".format(len(nodes_ip4s)))
    infos[1].set_text("{} different IPv6s".format(len(nodes_ip6s)))

def d(arg):
   pass

def handle_tasks():
    while True:
        try:
            f = q.get_nowait()
            f[0](*f[1])
            q.task_done()
        except Exception as e:
            break;
    update_plot()

if run:
    # start first step
    start_h = InfoHash()
    start_h.setBit(159, 1)
    step(start_h, 0)

while run:
    while run and done > 0:
        handle_tasks()
        plt.pause(.5)

    if not run:
        break

    button.on_clicked(restart)

    node_ip4s = num_nodes(nodes_ip4s)
    node_ip6s = num_nodes(nodes_ip6s)

    print(all_nodes.size(), " nodes found")
    print(all_nodes)
    #print(len(not_found), " nodes not geolocalized")
    #for n in not_found:
    #    print(n)
    print('')
    print(len(node_ip4s), " different IPv4s :")
    for ip in node_ip4s:
        print(ip[0], ":", str(ip[1][1]), "nodes",  ("(" + ip[1][2]['city'] + ")") if ip[1][2] and ip[1][2]['city'] else "")
    print('')
    print(len(node_ip6s), " different IPv6s :")
    for ip in node_ip6s:
        print(ip[0], ":", str(ip[1][1]), "nodes",  ("(" + ip[1][2]['city'] + ")") if ip[1][2] and ip[1][2]['city'] else "")

    handle_tasks()
    while run and done == 0:
        plt.pause(.5)
    button.on_clicked(d)
    plt.draw()

all_nodes = []
r.join()
