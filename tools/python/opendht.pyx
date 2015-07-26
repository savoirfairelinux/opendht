# distutils: language = c++
# distutils: extra_compile_args = -std=c++11
# distutils: include_dirs = ../../include
# distutils: library_dirs = ../../src
# distutils: libraries = opendht gnutls
# cython: language_level=3
#
# opendht.pyx - Copyright 2015 by Guillaume Roguez <yomgui1 AT gmail DOT com>
# A Python3 wrapper to access to OpenDHT API
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


from libc.stdint cimport *
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.map cimport map as map
from libcpp cimport bool
from libcpp.utility cimport pair

from cython.parallel import parallel, prange
from cython.operator cimport dereference as deref, preincrement as inc, predecrement as dec
from cpython cimport ref

ctypedef uint16_t in_port_t
ctypedef unsigned short int sa_family_t;

cdef extern from "<memory>" namespace "std" nogil:
    cdef cppclass shared_ptr[T]:
        shared_ptr() except +
        T* get()
        T operator*()
        void reset(T*);

cdef extern from "opendht/infohash.h" namespace "dht":
    cdef cppclass InfoHash:
        InfoHash() except +
        InfoHash(string s) except +
        string toString() const
        bool getBit(unsigned bit) const
        void setBit(unsigned bit, bool b)
        double toFloat() const
        @staticmethod
        unsigned commonBits(InfoHash a, InfoHash b)
        @staticmethod
        InfoHash get(string s)

cdef extern from "opendht/value.h" namespace "dht":
    cdef cppclass Value:
        Value() except +
        Value(vector[uint8_t]) except +
        Value(const uint8_t* dat_ptr, size_t dat_len) except +
        string toString() const

cdef extern from "opendht/dht.h" namespace "dht":
    cdef cppclass Node:
        Node() except +
        InfoHash getId() const
        string getAddrStr() const
        bool isExpired() const
    ctypedef bool (*GetCallbackRaw)(shared_ptr[Value] values, void *user_data)
    ctypedef void (*DoneCallbackRaw)(bool done, vector[shared_ptr[Node]]* nodes, void *user_data)
    cdef cppclass Dht:
        cppclass GetCallback:
            GetCallback() except +
            #GetCallback(GetCallbackRaw cb, void *user_data) except +
        cppclass DoneCallback:
            DoneCallback() except +
            #DoneCallback(DoneCallbackRaw, void *user_data) except +
        Dht() except +
        InfoHash getNodeId() const
        @staticmethod
        GetCallback bindGetCb(GetCallbackRaw cb, void *user_data)
        @staticmethod
        DoneCallback bindDoneCb(DoneCallbackRaw cb, void *user_data)

cdef extern from "opendht/crypto.h" namespace "dht::crypto":
    ctypedef pair[shared_ptr[PrivateKey], shared_ptr[Certificate]] Identity
    cdef Identity generateIdentity(string name, Identity ca, unsigned bits)

    cdef cppclass PrivateKey:
        PrivateKey()
        PublicKey getPublicKey() const

    cdef cppclass PublicKey:
        PublicKey()
        InfoHash getId() const

    cdef cppclass Certificate:
        Certificate()
        InfoHash getId() const

cdef class _WithID(object):
    def __repr__(self):
        return "<%s '%s'>" % (self.__class__.__name__, str(self))
    def __str__(self):
        return self.getId().toString().decode()

cdef class PyInfoHash(_WithID):
    cdef InfoHash _infohash
    def __init__(self, bytes str=b''):
        self._infohash = InfoHash(str)
    def getBit(self, bit):
        return self._infohash.getBit(bit)
    def setBit(self, bit, b):
        self._infohash.setBit(bit, b)
    def getId(self):
        return self
    def toString(self):
        return self._infohash.toString()
    def toFloat(self):
        return self._infohash.toFloat()
    @staticmethod
    def commonBits(PyInfoHash a, PyInfoHash b):
        return InfoHash.commonBits(a._infohash, b._infohash)
    @staticmethod
    def get(str key):
        h = PyInfoHash()
        h._infohash = InfoHash.get(key.encode())
        return h

cdef class PyNode(_WithID):
    cdef shared_ptr[Node] _node
    def getId(self):
        h = PyInfoHash()
        h._infohash = self._node.get().getId()
        return h
    def getAddr(self):
        return self._node.get().getAddrStr()
    def isExpired(self):
        return self._node.get().isExpired()

cdef class PyNodeEntry(_WithID):
    cdef pair[InfoHash, shared_ptr[Node]] _v
    def getId(self):
        h = PyInfoHash()
        h._infohash = self._v.first
        return h
    def getNode(self):
        n = PyNode()
        n._node = self._v.second
        return n

cdef class PyValue(object):
    cdef shared_ptr[Value] _value
    def __init__(self, bytes val=b''):
        self._value.reset(new Value(val, len(val)))
    def __str__(self):
        return self._value.get().toString().decode()

cdef class PyNodeSetIter(object):
    cdef map[InfoHash, shared_ptr[Node]]* _nodes
    cdef map[InfoHash, shared_ptr[Node]].iterator _curIter
    def __init__(self, PyNodeSet s):
        self._nodes = &s._nodes
        self._curIter = self._nodes.begin()
    def __next__(self):
        if self._curIter == self._nodes.end():
            raise StopIteration
        h = PyNodeEntry()
        h._v = deref(self._curIter)
        inc(self._curIter)
        return h

cdef class PyNodeSet(object):
    cdef map[InfoHash, shared_ptr[Node]] _nodes
    def size(self):
        return self._nodes.size()
    def insert(self, PyNodeEntry l):
        self._nodes.insert(l._v)
    def extend(self, li):
        for n in li:
            self.insert(n)
    def first(self):
        if self._nodes.empty():
            raise IndexError()
        h = PyInfoHash()
        h._infohash = deref(self._nodes.begin()).first
        return h
    def last(self):
        if self._nodes.empty():
            raise IndexError()
        h = PyInfoHash()
        h._infohash = deref(dec(self._nodes.end())).first
        return h
    def __str__(self):
        s = ''
        cdef map[InfoHash, shared_ptr[Node]].iterator it = self._nodes.begin()
        while it != self._nodes.end():
            s += deref(it).first.toString().decode() + ' ' + deref(it).second.get().getAddrStr().decode() + '\n'
            inc(it)
        return s
    def __iter__(self):
        return PyNodeSetIter(self)

cdef class PyPublicKey(_WithID):
    cdef PublicKey _key
    def getId(self):
        h = PyInfoHash()
        h._infohash = self._key.getId()
        return h

cdef class PySharedCertificate(_WithID):
    cdef shared_ptr[Certificate] _cert
    def getId(self):
        h = PyInfoHash()
        h._infohash = self._cert.get().getId()
        return h

cdef class PyIdentity(object):
    cdef Identity _id;
    def generate(self, str name = "pydht", PyIdentity ca = PyIdentity(), unsigned bits = 4096):
        self._id = generateIdentity(name.encode(), ca._id, bits)
    property PublicKey:
        def __get__(self):
            k = PyPublicKey()
            k._key = self._id.first.get().getPublicKey()
            return k
    property Certificate:
        def __get__(self):
            c = PySharedCertificate()
            c._cert = self._id.second
            return c

cdef extern from "opendht/dhtrunner.h" namespace "dht":
    cdef cppclass DhtRunner:
        DhtRunner() except +
        InfoHash getId() const
        InfoHash getNodeId() const
        void bootstrap(const char*, const char*)
        void run(in_port_t, const Identity, bool)
        #void run(const sockaddr_in*, const sockaddr_in6*, const Identity, bool)
        void run(const char*, const char*, const char*, const Identity, bool)
        void join()
        bool isRunning()
        string getStorageLog() const
        string getRoutingTablesLog(sa_family_t af) const
        string getSearchesLog(sa_family_t af) const
        void get(InfoHash key, Dht.GetCallback get_cb, Dht.DoneCallback done_cb)
        void put(InfoHash key, shared_ptr[Value] val, Dht.DoneCallback done_cb)

cdef bool py_get_callback(shared_ptr[Value] value, void *user_data) with gil:
    cb = (<object>user_data)['get']
    pv = PyValue()
    pv._value = value
    return cb(pv)

cdef void py_done_callback(bool done, vector[shared_ptr[Node]]* nodes, void *user_data) with gil:
    node_ids = []
    for n in deref(nodes):
        h = PyNodeEntry()
        h._v.first = n.get().getId()
        h._v.second = n
        node_ids.append(h)
    (<object>user_data)['done'](done, node_ids)
    ref.Py_DECREF(<object>user_data)

cdef class PyDhtRunner(_WithID):
    cdef DhtRunner* thisptr;
    def __cinit__(self):
        self.thisptr = new DhtRunner()
    def getId(self):
        h = PyInfoHash()
        h._infohash = self.thisptr.getId()
        return h
    def getNodeId(self):
        return self.thisptr.getNodeId().toString()
    def bootstrap(self, str host, str port):
        self.thisptr.bootstrap(host.encode(), port.encode())
    def run(self, PyIdentity id, bool threaded=True, in_port_t port=0, str ipv4="", str ipv6=""):
        if ipv4 or ipv6:
            self.thisptr.run(ipv4.encode(), ipv6.encode(), str(port).encode(), id._id, threaded)
        else:
            self.thisptr.run(port, id._id, threaded)
    def join(self):
        self.thisptr.join()
    def isRunning(self):
        return self.thisptr.isRunning()
    def getStorageLog(self):
        return self.thisptr.getStorageLog().decode()
    def getRoutingTablesLog(self, sa_family_t af):
        return self.thisptr.getRoutingTablesLog(af).decode()
    def getSearchesLog(self, sa_family_t af):
        return self.thisptr.getSearchesLog(af).decode()
    def get(self, PyInfoHash key, get_cb, done_cb):
        cb_obj = {'get':get_cb, 'done':done_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.get(key._infohash, Dht.bindGetCb(py_get_callback, <void*>cb_obj), Dht.bindDoneCb(py_done_callback, <void*>cb_obj))
    def get(self, str key, get_cb, done_cb):
        cb_obj = {'get':get_cb, 'done':done_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.get(InfoHash.get(key.encode()), Dht.bindGetCb(py_get_callback, <void*>cb_obj), Dht.bindDoneCb(py_done_callback, <void*>cb_obj))
    def put(self, PyInfoHash key, PyValue val, done_cb):
        cb_obj = {'done':done_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.put(key._infohash, val._value, Dht.bindDoneCb(py_done_callback, <void*>cb_obj))
    def put(self, str key, PyValue val, done_cb):
        cb_obj = {'done':done_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.put(InfoHash.get(key.encode()), val._value, Dht.bindDoneCb(py_done_callback, <void*>cb_obj))
