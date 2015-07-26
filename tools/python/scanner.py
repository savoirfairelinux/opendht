import time
from pprint import pprint
from math import cos, sin, pi

from opendht import *

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import colorConverter
from matplotlib.collections import RegularPolyCollection
from matplotlib.widgets import Button
from mpl_toolkits.basemap import Basemap

import GeoIP

done = 0
all_nodes = PyNodeSet()

plt.ion()
plt.figaspect(2.)

fig, axes = plt.subplots(2, 1)
fig.set_size_inches(12,16,forward=True)
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

gi = GeoIP.open("GeoLiteCity.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)
gi6 = GeoIP.open("GeoLiteCityv6.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)

def gcb(v):
    return True

r = PyDhtRunner()
i = PyIdentity()
i.generate(bits = 1024)

r.run(i, port=4112)
r.bootstrap("bootstrap.ring.cx", "4222")

all_lines = []

plt.pause(2)

def step(cur_h, cur_depth):
    global done, all_nodes, all_lines
    done += 1
    a = 2.*pi*cur_h.toFloat()
    b = a + 2.*pi/(2**(cur_depth))
    print("step", cur_h, cur_depth)
    arc = ringx.add_patch(mpatches.Wedge([0.,0,], 1., a*180/pi, b*180/pi, fill=True, color="blue", alpha=0.5))
    lines = ringx.plot([0, cos(a)], [0, sin(a)], 'k-', lw=1.2)
    all_lines.extend(lines)
    r.get(cur_h, gcb, lambda d, nodes: nextstep(cur_h, cur_depth, d, nodes, arc=arc, lines=lines))

def nextstep(cur_h, cur_depth, ok, nodes, arc=None, lines=[]):
    global done, all_nodes
    if arc:
        arc.remove()
        del arc
    for l in lines:
        l.set_color('#444444')
    snodes = PyNodeSet()
    snodes.extend(nodes)
    all_nodes.extend(nodes)
    depth = min(6, PyInfoHash.commonBits(snodes.first(), snodes.last())+4)
    if cur_depth < depth:
        for b in range(cur_depth, depth):
            new_h = PyInfoHash(cur_h.toString());
            new_h.setBit(b, 1);
            step(new_h, b+1);
    done -= 1

run = True
def exitcb(arg):
    global run
    run = False
exitbtn.on_clicked(exitcb)

def restart(arg):
    global collection, all_lines, points
    for l in all_lines:
        l.remove()
        del l
    all_lines = []
    if collection:
        collection.remove()
        del collection
        collection = None
    for p in points:
        p.remove()
        del p
    points = []

    print(arg)
    start_h = PyInfoHash()
    start_h.setBit(159, 1)
    step(start_h, 0)
    plt.draw()

collection = None
points = []
not_found = []

def generate_set():
    node_ipv4 = {}
    node_ipv6 = {}
    for n in all_nodes:
        addr = b''.join(n.getNode().getAddr().split(b':')[0:-1]).decode()
        if addr[0] == '[':
            addr = addr[1:-1]
            if addr in node_ipv6:
                node_ipv6[addr][1] = 1
            else:
                node_ipv6[addr] = [n, 1]
        else:
            if addr in node_ipv4:
                node_ipv4[addr][1] += 1
            else:
                node_ipv4[addr] = [n, 1]
    return node_ipv4, node_ipv6

def update_plot():
    global done, m, collection, not_found, points
    for p in points:
        p.remove()
        del p
    points = []
    lats = []
    lons = []
    cities=[]
    colors=[]
    not_found.clear()
    ip4s, ip6s = generate_set()
    ares = []
    for addr, n in ip4s.items():
        ares.append((addr, n[0].getNode(), gi.record_by_name(addr)))
    for addr, n in ip6s.items():
        ares.append((addr, n[0].getNode(), gi6.record_by_name_v6(addr)))
    for r in ares:
        res = r[2]
        n = r[1]
        if res:
            lats.append(res['latitude'])
            lons.append(res['longitude'])
            cities.append(res['city'] if res['city'] else (str(int(res['latitude']))+'-'+str(int(res['longitude']))))
            colors.append('red' if n.isExpired() else 'blue')
        else:
            not_found.append(r[0])

    x,y = m(lons,lats)
    points.extend(m.plot(x,y,'bo'))
    for name, xpt, ypt in zip(cities, x, y):
        points.append(mpx.text(xpt+50000, ypt+50000, name))
    node_val = [n.getId().toFloat() for n in all_nodes]
    xys = [(cos(d*2*pi), sin(d*2*pi)) for d in node_val]
    if collection:
        collection.remove()
        del collection
        collection = None
    collection = ringx.add_collection(RegularPolyCollection(
                fig.dpi, 6, sizes=(10,), facecolors=colors,
                offsets = xys, transOffset = ringx.transData))

if run:
    # start first step
    start_h = PyInfoHash()
    start_h.setBit(159, 1)
    step(start_h, 0)

def d(arg):
   pass

while run:
    while run and done > 0:
        update_plot()
        plt.draw()
        plt.pause(.5)

    if not run:
        break

    button.on_clicked(restart)

    node_ip4s, node_ip6s = generate_set()

    print(all_nodes.size(), " nodes found")
    print(all_nodes)
    print(len(not_found), " nodes not geolocalized")
    for n in not_found:
        print(n)
    print('')
    print(len(node_ip4s), " different IPv4s :")
    for ip in node_ip4s.items():
        print(ip[0] + " : " + str(ip[1][1]) + " nodes")
    print('')
    print(len(node_ip6s), " different IPv6s :")
    for ip in node_ip6s.items():
        print(ip[0] + " : " + str(ip[1][1]) + " nodes")

    while run and done == 0:
        plt.pause(.5)
    button.on_clicked(d)
    plt.draw()

all_nodes = []
r.join()
