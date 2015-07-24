import time
from pprint import pprint
from math import cos, sin, pi

from opendht import *

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import colorConverter
from matplotlib.collections import RegularPolyCollection
from mpl_toolkits.basemap import Basemap

import GeoIP

done = 0
all_nodes = PyNodeSet()

gi = GeoIP.open("GeoLiteCity.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)
gi6 = GeoIP.open("GeoLiteCityv6.dat", GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)

plt.ion()
plt.figaspect(2.)

fig, axes = plt.subplots(2, 1)
fig.set_size_inches(12,16,forward=True)
fig.tight_layout()

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

def gcb(v):
    return True

r = PyDhtRunner()
i = PyIdentity()
i.generate()

r.run(i, port=4112)
r.bootstrap("bootstrap.ring.cx", "4222")

plt.pause(2)

def step(cur_h, cur_depth):
    global done, all_nodes
    done += 1
    a = 2.*pi*cur_h.toFloat()
    b = a + 2.*pi/(2**(cur_depth))
    print("step", cur_h, cur_depth)
    arc = ringx.add_patch(mpatches.Wedge([0.,0,], 1., a*180/pi, b*180/pi, fill=True, color="blue", alpha=0.5))
    lines = ringx.plot([0, cos(a)], [0, sin(a)], 'k-', lw=1.2)
    r.get(cur_h, gcb, lambda d, nodes: nextstep(cur_h, cur_depth, d, nodes, arc=arc, lines=lines))

def nextstep(cur_h, cur_depth, ok, nodes, arc=None, lines=[]):
    global done, all_nodes
    if arc:
        arc.remove()
    for l in lines:
        l.set_color('#444444')
    snodes = PyNodeSet()
    snodes.extend(nodes)
    all_nodes.extend(nodes)
    depth = min(8, PyInfoHash.commonBits(snodes.first(), snodes.last())+6)
    if cur_depth < depth:
        for b in range(cur_depth, depth):
            new_h = PyInfoHash(cur_h.toString());
            new_h.setBit(b, 1);
            step(new_h, b+1);
    done -= 1

# start first step
start_h = PyInfoHash()
start_h.setBit(159, 1)
step(start_h, 0)

collection = None
not_found = []

def update_plot():
    global done, m, collection, not_found
    lats = []
    lons = []
    cities=[]
    not_found.clear()
    for n in all_nodes:
        addr = n.getNode().getAddr().decode().split(':')[0]
        if addr[0] == '[':
            res = gi6.record_by_name_v6(addr[1:-1])
        else:
            res = gi.record_by_name(addr)
        if res:
            #pprint(res)
            lats.append(res['latitude'])
            lons.append(res['longitude'])
            cities.append(res['city'] if res['city'] else (str(int(res['latitude']))+'-'+str(int(res['longitude']))))
        else:
            not_found.append(n)

    x,y = m(lons,lats)
    m.plot(x,y,'bo')
    for name, xpt, ypt in zip(cities, x, y):
        mpx.text(xpt+50000, ypt+50000, name)
    node_val = [n.getId().toFloat() for n in all_nodes]
    xys = [(cos(d*2*pi), sin(d*2*pi)) for d in node_val]
    if collection:
        collection.remove()
    collection = ringx.add_collection(RegularPolyCollection(
                fig.dpi, 6, sizes=(10,), facecolors=colorConverter.to_rgba('blue'),
                offsets = xys, transOffset = ringx.transData))

while done > 0:
    update_plot()
    plt.draw()
    plt.pause(.25)
plt.draw()

print(all_nodes.size(), " nodes found")
print(all_nodes)
print(len(not_found), " nodes not geolocalized")
for n in not_found:
    print(n.getNode().getId().toString().decode(), n.getNode().getAddr().decode())

plt.ioff()
plt.show()

all_nodes = []
r.join()

