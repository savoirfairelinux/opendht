# distutils: language = c++
# distutils: extra_compile_args = -std=c++11
# distutils: include_dirs = ../../include
# distutils: library_dirs = ../../src
# distutils: libraries = opendht gnutls
# cython: language_level=3
#
# Copyright (c) 2015 Savoir-Faire Linux Inc.
# Author: Guillaume Roguez <guillaume.roguez@savoirfairelinux.com>
# Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
#
# This wrapper is written for Cython 0.22
#
# This file is part of OpenDHT Python Wrapper.
#
#    OpenDHT Python Wrapper is free software:  you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    OpenDHT Python Wrapper is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with OpenDHT Python Wrapper. If not, see <http://www.gnu.org/licenses/>.
#

from libcpp.map cimport map as map
from libcpp cimport bool
from libcpp.utility cimport pair
from libcpp.string cimport string

from cython.parallel import parallel, prange
from cython.operator cimport dereference as deref, preincrement as inc, predecrement as dec
from cpython cimport ref

cimport opendht_cpp as cpp

import threading

cdef inline void shutdown_callback(void* user_data) with gil:
    cbs = <object>user_data
    if 'shutdown' in cbs and cbs['shutdown']:
        cbs['shutdown']()
    ref.Py_DECREF(cbs)

cdef inline bool get_callback(cpp.shared_ptr[cpp.Value] value, void *user_data) with gil:
    cb = (<object>user_data)['get']
    pv = Value()
    pv._value = value
    return cb(pv)

cdef inline void done_callback(bool done, cpp.vector[cpp.shared_ptr[cpp.Node]]* nodes, void *user_data) with gil:
    node_ids = []
    for n in deref(nodes):
        h = NodeEntry()
        h._v.first = n.get().getId()
        h._v.second = n
        node_ids.append(h)
    cbs = <object>user_data
    if 'done' in cbs and cbs['done']:
        cbs['done'](done, node_ids)
    ref.Py_DECREF(cbs)

cdef class _WithID(object):
    def __repr__(self):
        return "<%s '%s'>" % (self.__class__.__name__, str(self))
    def __str__(self):
        return self.getId().toString().decode()

cdef class InfoHash(_WithID):
    cdef cpp.InfoHash _infohash
    def __init__(self, bytes str=b''):
        self._infohash = cpp.InfoHash(str)
    def __bool__(InfoHash self):
        return not (self._infohash == cpp.InfoHash())
    def __richcmp__(InfoHash self, InfoHash other, int op):
        if op == 0:
            return self._infohash < other._infohash
        if op == 1:
            return self._infohash < other._infohash or self._infohash == other._infohash
        if op == 2:
            return self._infohash == other._infohash
        return NotImplemented
    def __hash__(self):
        cdef cpp.hash[cpp.InfoHash] hash_fn
        return hash_fn.get(self._infohash)
    def getBit(InfoHash self, bit):
        return self._infohash.getBit(bit)
    def setBit(InfoHash self, bit, b):
        self._infohash.setBit(bit, b)
    def getId(InfoHash self):
        return self
    def toString(InfoHash self):
        return self._infohash.toString()
    def toFloat(InfoHash self):
        return self._infohash.toFloat()
    @staticmethod
    def commonBits(InfoHash a, InfoHash b):
        return cpp.InfoHash.commonBits(a._infohash, b._infohash)
    @staticmethod
    def get(str key):
        h = InfoHash()
        h._infohash = cpp.InfoHash.get(key.encode())
        return h
    @staticmethod
    def getRandom():
        h = InfoHash()
        h._infohash = cpp.InfoHash.getRandom()
        return h

cdef class Node(_WithID):
    cdef cpp.shared_ptr[cpp.Node] _node
    def getId(self):
        h = InfoHash()
        h._infohash = self._node.get().getId()
        return h
    def getAddr(self):
        return self._node.get().getAddrStr()
    def isExpired(self):
        return self._node.get().isExpired()

cdef class NodeEntry(_WithID):
    cdef cpp.pair[cpp.InfoHash, cpp.shared_ptr[cpp.Node]] _v
    def getId(self):
        h = InfoHash()
        h._infohash = self._v.first
        return h
    def getNode(self):
        n = Node()
        n._node = self._v.second
        return n

cdef class Value(object):
    cdef cpp.shared_ptr[cpp.Value] _value
    def __init__(self, bytes val=b''):
        self._value.reset(new cpp.Value(val, len(val)))
    def __str__(self):
        return self._value.get().toString().decode()
    property owner:
        def __get__(self):
            h = InfoHash()
            h._infohash = self._value.get().owner.getId()
            return h
    property recipient:
        def __get__(self):
            h = InfoHash()
            h._infohash = self._value.get().recipient
            return h
        def __set__(self, InfoHash h):
            self._value.get().recipient = h._infohash
    property data:
        def __get__(self):
            return string(<char*>self._value.get().data.data(), self._value.get().data.size())
        def __set__(self, bytes value):
            self._value.get().data = value

cdef class NodeSetIter(object):
    cdef map[cpp.InfoHash, cpp.shared_ptr[cpp.Node]]* _nodes
    cdef map[cpp.InfoHash, cpp.shared_ptr[cpp.Node]].iterator _curIter
    def __init__(self, NodeSet s):
        self._nodes = &s._nodes
        self._curIter = self._nodes.begin()
    def __next__(self):
        if self._curIter == self._nodes.end():
            raise StopIteration
        h = NodeEntry()
        h._v = deref(self._curIter)
        inc(self._curIter)
        return h

cdef class NodeSet(object):
    cdef map[cpp.InfoHash, cpp.shared_ptr[cpp.Node]] _nodes
    def size(self):
        return self._nodes.size()
    def insert(self, NodeEntry l):
        self._nodes.insert(l._v)
    def extend(self, li):
        for n in li:
            self.insert(n)
    def first(self):
        if self._nodes.empty():
            raise IndexError()
        h = InfoHash()
        h._infohash = deref(self._nodes.begin()).first
        return h
    def last(self):
        if self._nodes.empty():
            raise IndexError()
        h = InfoHash()
        h._infohash = deref(dec(self._nodes.end())).first
        return h
    def __str__(self):
        s = ''
        cdef map[cpp.InfoHash, cpp.shared_ptr[cpp.Node]].iterator it = self._nodes.begin()
        while it != self._nodes.end():
            s += deref(it).first.toString().decode() + ' ' + deref(it).second.get().getAddrStr().decode() + '\n'
            inc(it)
        return s
    def __iter__(self):
        return NodeSetIter(self)

cdef class PublicKey(_WithID):
    cdef cpp.PublicKey _key
    def getId(self):
        h = InfoHash()
        h._infohash = self._key.getId()
        return h

cdef class Certificate(_WithID):
    cdef cpp.shared_ptr[cpp.Certificate] _cert
    def getId(self):
        h = InfoHash()
        h._infohash = self._cert.get().getId()
        return h

cdef class ListenToken(object):
    cdef cpp.InfoHash _h
    cdef cpp.shared_future[size_t] _t
    _cb = dict()

cdef class Identity(object):
    cdef cpp.Identity _id
    def generate(self, str name = "pydht", Identity ca = Identity(), unsigned bits = 4096):
        self._id = cpp.generateIdentity(name.encode(), ca._id, bits)
    property PublicKey:
        def __get__(self):
            k = PublicKey()
            k._key = self._id.first.get().getPublicKey()
            return k
    property Certificate:
        def __get__(self):
            c = Certificate()
            c._cert = self._id.second
            return c

cdef class DhtConfig(object):
    cdef cpp.Config _config
    def __init__(self):
        self._config = cpp.Config()
        self._config.threaded = True;
    def setIdentity(self, Identity id):
        self._config.dht_config.id = id._id
    def setBootstrapMode(self, bool bootstrap):
        self._config.dht_config.node_config.is_bootstrap = bootstrap
    def setNodeId(self, InfoHash id):
        self._config.dht_config.node_config.node_id = id._infohash

cdef class DhtRunner(_WithID):
    cdef cpp.DhtRunner* thisptr
    def __cinit__(self):
        self.thisptr = new cpp.DhtRunner()
    def getId(self):
        h = InfoHash()
        h._infohash = self.thisptr.getId()
        return h
    def getNodeId(self):
        return self.thisptr.getNodeId().toString()
    def bootstrap(self, str host, str port):
        self.thisptr.bootstrap(host.encode(), port.encode())
    def run(self, Identity id=None, is_bootstrap=False, cpp.in_port_t port=0, str ipv4="", str ipv6="", DhtConfig config=DhtConfig()):
        if id:
            config.setIdentity(id)
        if ipv4 or ipv6:
            bind4 = ipv4.encode() if ipv4 else b''
            bind6 = ipv6.encode() if ipv6 else b''
            self.thisptr.run(bind4, bind6, str(port).encode(), config._config)
        else:
            self.thisptr.run(port, config._config)
    def join(self):
        self.thisptr.join()
    def shutdown(self, shutdown_cb=None):
        cb_obj = {'shutdown':shutdown_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.shutdown(cpp.Dht.bindShutdownCb(shutdown_callback, <void*>cb_obj))
    def isRunning(self):
        return self.thisptr.isRunning()
    def getStorageLog(self):
        return self.thisptr.getStorageLog().decode()
    def getRoutingTablesLog(self, cpp.sa_family_t af):
        return self.thisptr.getRoutingTablesLog(af).decode()
    def getSearchesLog(self, cpp.sa_family_t af):
        return self.thisptr.getSearchesLog(af).decode()
    def getNodeMessageStats(self):
        stats = []
        cdef cpp.vector[unsigned] res = self.thisptr.getNodeMessageStats(False)
        for n in res:
            stats.append(n)
        return stats

    def get(self, InfoHash key, get_cb=None, done_cb=None):
        """Retreive values associated with a key on the DHT.

        key -- the key for which to search
        get_cb -- is set, makes the operation non-blocking. Called when a value is found on the DHT.
        done_cb -- optional callback used when get_cb is set. Called when the operation is completed.
        """
        if get_cb:
            cb_obj = {'get':get_cb, 'done':done_cb}
            ref.Py_INCREF(cb_obj)
            self.thisptr.get(key._infohash, cpp.Dht.bindGetCb(get_callback, <void*>cb_obj), cpp.Dht.bindDoneCb(done_callback, <void*>cb_obj))
        else:
            lock = threading.Condition()
            pending = 0
            res = []
            def tmp_get(v):
                nonlocal res
                res.append(v)
                return True
            def tmp_done(ok, nodes):
                nonlocal pending, lock
                with lock:
                    pending -= 1
                    lock.notify()
            with lock:
                pending += 1
                self.get(key, get_cb=tmp_get, done_cb=tmp_done)
                while pending > 0:
                    lock.wait()
            return res
    def put(self, InfoHash key, Value val, done_cb=None):
        """Publish a new value on the DHT at key.

        key -- the DHT key where to put the value
        val -- the value to put on the DHT
        done_cb -- optional callback called when the operation is completed.
        """
        cb_obj = {'done':done_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.put(key._infohash, val._value, cpp.Dht.bindDoneCb(done_callback, <void*>cb_obj))
    def listen(self, InfoHash key, get_cb):
        t = ListenToken()
        t._h = key._infohash
        cb_obj = {'get':get_cb}
        t._cb['cb'] = cb_obj
        # avoid the callback being destructed if the token is destroyed
        ref.Py_INCREF(cb_obj)
        t._t = self.thisptr.listen(t._h, cpp.Dht.bindGetCb(get_callback, <void*>cb_obj)).share()
        return t
    def cancelListen(self, ListenToken token):
        self.thisptr.cancelListen(token._h, token._t)
        ref.Py_DECREF(<object>token._cb['cb'])
        # fixme: not thread safe
