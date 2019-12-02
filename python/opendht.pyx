# distutils: language = c++
# distutils: extra_compile_args = -std=c++14
# distutils: include_dirs = ../../include
# distutils: library_dirs = ../../src
# distutils: libraries = opendht gnutls
# cython: language_level=3
#
# Copyright (c) 2015-2019 Savoir-faire Linux Inc.
# Author(s): Guillaume Roguez <guillaume.roguez@savoirfairelinux.com>
#            Adrien Béraud <adrien.beraud@savoirfairelinux.com>
#            Simon Désaulniers <sim.desaulniers@gmail.com>
#
# This wrapper is written for Cython 0.22
#
# This file is part of OpenDHT Python Wrapper.
#
# OpenDHT Python Wrapper is free software:  you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OpenDHT Python Wrapper is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenDHT Python Wrapper. If not, see <https://www.gnu.org/licenses/>.

from libcpp.map cimport map as map
from libcpp cimport bool
from libcpp.utility cimport pair
from libcpp.string cimport string
from libcpp.memory cimport shared_ptr

from cython.parallel import parallel, prange
from cython.operator cimport dereference as deref, preincrement as inc, predecrement as dec
from cpython cimport ref

cimport opendht_cpp as cpp

import threading

cdef inline void lookup_callback(cpp.vector[cpp.shared_ptr[cpp.IndexValue]]* values, cpp.Prefix* p, void *user_data) with gil:
    cbs = <object>user_data
    if 'lookup' in cbs and cbs['lookup']:
        vals = []
        for val in deref(values):
            v = IndexValue()
            v._value = val
            vals.append(v)
        cbs['lookup'](vals, p.toString())

cdef inline void shutdown_callback(void* user_data) with gil:
    cbs = <object>user_data
    if 'shutdown' in cbs and cbs['shutdown']:
        cbs['shutdown']()
    ref.Py_DECREF(cbs)

cdef inline bool get_callback(shared_ptr[cpp.Value] value, void *user_data) with gil:
    cbs = <object>user_data
    cb = cbs['get']
    f = cbs['filter'] if 'filter' in cbs else None
    pv = Value()
    pv._value = value
    return cb(pv) if not f or f(pv) else True

cdef inline bool value_callback(shared_ptr[cpp.Value] value, bool expired, void *user_data) with gil:
    cbs = <object>user_data
    cb = cbs['valcb']
    f = cbs['filter'] if 'filter' in cbs else None
    pv = Value()
    pv._value = value
    return cb(pv, expired) if not f or f(pv) else True

cdef inline void done_callback(bool done, cpp.vector[shared_ptr[cpp.Node]]* nodes, void *user_data) with gil:
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

cdef inline void done_callback_simple(bool done, void *user_data) with gil:
    cbs = <object>user_data
    if 'done' in cbs and cbs['done']:
        cbs['done'](done)
    ref.Py_DECREF(cbs)

cdef class _WithID(object):
    def __repr__(self):
        return "<%s '%s'>" % (self.__class__.__name__, str(self))
    def __str__(self):
        return self.getId().toString().decode()

cdef class InfoHash(_WithID):
    cdef cpp.InfoHash _infohash
    def __cinit__(self, bytes str=b''):
        self._infohash = cpp.InfoHash(str) if str else cpp.InfoHash()
    def __bool__(InfoHash self):
        return <bool>self._infohash
    def __richcmp__(InfoHash self, InfoHash other, int op):
        if op == 0:
            return self._infohash < other._infohash
        if op == 1:
            return self._infohash < other._infohash or self._infohash == other._infohash
        if op == 2:
            return self._infohash == other._infohash
        return NotImplemented
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

cdef class SockAddr(object):
    cdef cpp.SockAddr _addr
    def toString(SockAddr self):
        return self._addr.toString()
    def getPort(SockAddr self):
        return self._addr.getPort()
    def getFamily(SockAddr self):
        return self._addr.getFamily()
    def setPort(SockAddr self, cpp.in_port_t port):
        return self._addr.setPort(port)
    def setFamily(SockAddr self, cpp.sa_family_t af):
        return self._addr.setFamily(af)
    def isLoopback(SockAddr self):
        return self._addr.isLoopback()
    def isPrivate(SockAddr self):
        return self._addr.isPrivate()
    def isUnspecified(SockAddr self):
        return self._addr.isUnspecified()
    def __str__(self):
        return self.toString().decode()
    def __repr__(self):
        return "<%s '%s'>" % (self.__class__.__name__, str(self))

cdef class Node(_WithID):
    cdef shared_ptr[cpp.Node] _node
    def getId(self):
        h = InfoHash()
        h._infohash = self._node.get().getId()
        return h
    def getAddr(self):
        return self._node.get().getAddrStr()
    def isExpired(self):
        return self._node.get().isExpired()

cdef class NodeEntry(_WithID):
    cdef cpp.pair[cpp.InfoHash, shared_ptr[cpp.Node]] _v
    def getId(self):
        h = InfoHash()
        h._infohash = self._v.first
        return h
    def getNode(self):
        n = Node()
        n._node = self._v.second
        return n

cdef class Query(object):
    cdef cpp.Query _query
    def __cinit__(self, str q_str=''):
        self._query = cpp.Query(q_str.encode())
    def __str__(self):
        return self._query.toString().decode()
    def buildFrom(self, Select s, Where w):
        self._query = cpp.Query(s._select, w._where)
    def isSatisfiedBy(self, Query q):
        return self._query.isSatisfiedBy(q._query)

cdef class Select(object):
    cdef cpp.Select _select
    def __cinit__(self, str q_str=None):
        if q_str:
            self._select = cpp.Select(q_str.encode())
        else:
            self._select = cpp.Select()
    def __str__(self):
        return self._select.toString().decode()
    def isSatisfiedBy(self, Select os):
        return self._select.isSatisfiedBy(os._select)
    def field(self, int field):
        self._select.field(<cpp.Field> field)
        return self

cdef class Where(object):
    cdef cpp.Where _where
    def __cinit__(self, str q_str=None):
        if q_str:
            self._where = cpp.Where(q_str.encode())
        else:
            self._where = cpp.Where()
    def __str__(self):
        return self._where.toString().decode()
    def isSatisfiedBy(self, Where where):
        return self._where.isSatisfiedBy(where._where)
    def id(self, cpp.uint64_t id):
        self._where.id(id)
        return self
    def valueType(self, cpp.uint16_t type):
        self._where.valueType(type)
        return self
    def owner(self, InfoHash owner_pk_hash):
        self._where.owner(owner_pk_hash._infohash)
        return self
    def seq(self, cpp.uint16_t seq_no):
        self._where.seq(seq_no)
        return self
    def userType(self, str user_type):
        self._where.userType(user_type.encode())
        return self

cdef class Value(object):
    cdef shared_ptr[cpp.Value] _value
    def __init__(self, bytes val=b''):
        self._value.reset(new cpp.Value(val, len(val)))
    def __str__(self):
        return self._value.get().toString().decode()
    property owner:
        def __get__(self):
            h = InfoHash()
            h._infohash = self._value.get().owner.get().getId()
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
    property user_type:
        def __get__(self):
            return self._value.get().user_type.decode()
        def __set__(self, str t):
            self._value.get().user_type = t.encode()
    property id:
        def __get__(self):
            return self._value.get().id
        def __set__(self, cpp.uint64_t value):
            self._value.get().id = value
    property size:
        def __get__(self):
            return self._value.get().size()

cdef class NodeSetIter(object):
    cdef map[cpp.InfoHash, shared_ptr[cpp.Node]]* _nodes
    cdef map[cpp.InfoHash, shared_ptr[cpp.Node]].iterator _curIter
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
    cdef map[cpp.InfoHash, shared_ptr[cpp.Node]] _nodes
    def size(self):
        return self._nodes.size()
    def insert(self, NodeEntry l):
        return self._nodes.insert(l._v).second
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
        cdef map[cpp.InfoHash, shared_ptr[cpp.Node]].iterator it = self._nodes.begin()
        while it != self._nodes.end():
            s += deref(it).first.toString().decode() + ' ' + deref(it).second.get().getAddrStr().decode() + '\n'
            inc(it)
        return s
    def __iter__(self):
        return NodeSetIter(self)

cdef class PrivateKey(_WithID):
    cdef shared_ptr[cpp.PrivateKey] _key
    def getId(self):
        h = InfoHash()
        h._infohash = self._key.get().getPublicKey().getId()
        return h
    def getPublicKey(self):
        pk = PublicKey()
        pk._key = self._key.get().getPublicKey()
        return pk
    def decrypt(self, bytes dat):
        cdef size_t d_len = len(dat)
        cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>dat
        cdef cpp.Blob indat
        indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
        cdef cpp.Blob decrypted = self._key.get().decrypt(indat)
        cdef char* decrypted_c_str = <char *>decrypted.data()
        cdef Py_ssize_t length = decrypted.size()
        return decrypted_c_str[:length]
    def __str__(self):
        return self.getId().toString().decode()
    @staticmethod
    def generate():
        k = PrivateKey()
        k._key = cpp.make_shared[cpp.PrivateKey](cpp.PrivateKey.generate())
        return k
    @staticmethod
    def generateEC():
        k = PrivateKey()
        k._key = cpp.make_shared[cpp.PrivateKey](cpp.PrivateKey.generateEC())
        return k

cdef class PublicKey(_WithID):
    cdef cpp.PublicKey _key
    def getId(self):
        h = InfoHash()
        h._infohash = self._key.getId()
        return h
    def encrypt(self, bytes dat):
        cdef size_t d_len = len(dat)
        cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>dat
        cdef cpp.Blob indat
        indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
        cdef cpp.Blob encrypted = self._key.encrypt(indat)
        cdef char* encrypted_c_str = <char *>encrypted.data()
        cdef Py_ssize_t length = encrypted.size()
        return encrypted_c_str[:length]

cdef class Certificate(_WithID):
    cdef shared_ptr[cpp.Certificate] _cert
    def __init__(self, bytes dat = None):
        if dat:
            self._cert = cpp.make_shared[cpp.Certificate](<cpp.string>dat)
    def getId(self):
        h = InfoHash()
        if self._cert:
            h._infohash = self._cert.get().getId()
        return h
    def toString(self):
        return self._cert.get().toString().decode()
    def getName(self):
        return self._cert.get().getName()
    def revoke(self, PrivateKey k, Certificate c):
        self._cert.get().revoke(deref(k._key.get()), deref(c._cert.get()));
    def __bytes__(self):
        return self._cert.get().toString() if self._cert else b''
    property issuer:
        def __get__(self):
            c = Certificate()
            c._cert = self._cert.get().issuer
            return c;
    @staticmethod
    def generate(PrivateKey k, str name, Identity i = Identity(), bool is_ca = False):
        c = Certificate()
        c._cert = cpp.make_shared[cpp.Certificate](cpp.Certificate.generate(deref(k._key.get()), name.encode(), i._id, is_ca))
        return c

cdef class VerifyResult(object):
    cdef cpp.TrustListVerifyResult _result
    def __bool__(self):
        return self._result.isValid()
    def __str(self):
        return self._result.toString()

cdef class TrustList(object):
    cdef cpp.TrustList _trust
    def add(self, Certificate cert):
        self._trust.add(deref(cert._cert.get()))
    def remove(self, Certificate cert):
        self._trust.remove(deref(cert._cert.get()))
    def verify(self, Certificate cert):
        r = VerifyResult()
        r._result = self._trust.verify(deref(cert._cert.get()))
        return r

cdef class ListenToken(object):
    cdef cpp.InfoHash _h
    cdef cpp.shared_future[size_t] _t
    _cb = dict()

cdef class Identity(object):
    cdef cpp.Identity _id
    def __init__(self, PrivateKey k = None, Certificate c = None):
        if k:
            self._id.first = k._key
        if c:
            self._id.second = c._cert
    @staticmethod
    def generate(str name = "pydht", Identity ca = Identity(), unsigned bits = 4096):
        i = Identity()
        i._id = cpp.generateIdentity(name.encode(), ca._id, bits)
        return i
    property publickey:
        def __get__(self):
            k = PublicKey()
            k._key = self._id.first.get().getPublicKey()
            return k
    property certificate:
        def __get__(self):
            c = Certificate()
            c._cert = self._id.second
            return c
    property key:
        def __get__(self):
            k = PrivateKey()
            k._key = self._id.first
            return k

cdef class DhtConfig(object):
    cdef cpp.DhtRunnerConfig _config
    def __init__(self):
        self._config = cpp.DhtRunnerConfig()
        self._config.threaded = True;
    def setIdentity(self, Identity id):
        self._config.dht_config.id = id._id
    def setBootstrapMode(self, bool bootstrap):
        self._config.dht_config.node_config.is_bootstrap = bootstrap
    def setNodeId(self, InfoHash id):
        self._config.dht_config.node_config.node_id = id._infohash
    def setNetwork(self, unsigned netid):
        self._config.dht_config.node_config.network = netid
    def setMaintainStorage(self, bool maintain_storage):
        self._config.dht_config.node_config.maintain_storage = maintain_storage
    def setRateLimit(self, ssize_t max_req_per_sec, ssize_t max_peer_req_per_sec):
        self._config.dht_config.node_config.max_req_per_sec = max_req_per_sec
        self._config.dht_config.node_config.max_peer_req_per_sec = max_peer_req_per_sec

cdef class DhtRunner(_WithID):
    cdef cpp.shared_ptr[cpp.DhtRunner] thisptr
    def __cinit__(self):
        self.thisptr.reset(new cpp.DhtRunner())
    def getId(self):
        h = InfoHash()
        if self.thisptr:
            h._infohash = self.thisptr.get().getId()
        return h
    def getNodeId(self):
        return self.thisptr.get().getNodeId().toString()
    def ping(self, SockAddr addr, done_cb=None):
        if done_cb:
            cb_obj = {'done':done_cb}
            ref.Py_INCREF(cb_obj)
            self.thisptr.get().bootstrap(addr._addr, cpp.bindDoneCbSimple(done_callback_simple, <void*>cb_obj))
        else:
            lock = threading.Condition()
            pending = 0
            ok = False
            def tmp_done(ok_ret):
                nonlocal pending, ok, lock
                with lock:
                    ok = ok_ret
                    pending -= 1
                    lock.notify()
            with lock:
                pending += 1
                self.ping(addr, done_cb=tmp_done)
                while pending > 0:
                    lock.wait()
            return ok
    def bootstrap(self, str host, str port=None):
        host_bytes = host.encode()
        port_bytes = port.encode() if port else b'4222'
        self.thisptr.get().bootstrap(<cpp.const_char*>host_bytes, <cpp.const_char*>port_bytes)
    def run(self, Identity id=None, is_bootstrap=False, cpp.in_port_t port=0, str ipv4="", str ipv6="", DhtConfig config=DhtConfig()):
        if id:
            config.setIdentity(id)
        if ipv4 or ipv6:
            bind4 = ipv4.encode() if ipv4 else b''
            bind6 = ipv6.encode() if ipv6 else b''
            self.thisptr.get().run(bind4, bind6, str(port).encode(), config._config)
        else:
            self.thisptr.get().run(port, config._config)
    def join(self):
        self.thisptr.get().join()
    def shutdown(self, shutdown_cb=None):
        cb_obj = {'shutdown':shutdown_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.get().shutdown(cpp.bindShutdownCb(shutdown_callback, <void*>cb_obj))
    def enableLogging(self):
        cpp.enableLogging(self.thisptr.get()[0])
    def disableLogging(self):
        cpp.disableLogging(self.thisptr.get()[0])
    def enableFileLogging(self, str path):
        cpp.enableFileLogging(self.thisptr.get()[0], path.encode())
    def isRunning(self):
        return self.thisptr.get().isRunning()
    def getBound(self, cpp.sa_family_t af = 0):
        s = SockAddr()
        s._addr = self.thisptr.get().getBound(af)
        return s
    def getStorageLog(self):
        return self.thisptr.get().getStorageLog().decode()
    def getRoutingTablesLog(self, cpp.sa_family_t af):
        return self.thisptr.get().getRoutingTablesLog(af).decode()
    def getSearchesLog(self, cpp.sa_family_t af):
        return self.thisptr.get().getSearchesLog(af).decode()
    def getNodeMessageStats(self):
        stats = []
        cdef cpp.vector[unsigned] res = self.thisptr.get().getNodeMessageStats(False)
        for n in res:
            stats.append(n)
        return stats

    def get(self, InfoHash key, get_cb=None, done_cb=None, filter=None, Where where=None):
        """Retreive values associated with a key on the DHT.

        key     -- the key for which to search
        get_cb  -- is set, makes the operation non-blocking. Called when a value
                   is found on the DHT.
        done_cb -- optional callback used when get_cb is set. Called when the
                   operation is completed.
        """
        if get_cb:
            cb_obj = {'get':get_cb, 'done':done_cb, 'filter':filter}
            ref.Py_INCREF(cb_obj)
            if where is None:
                where = Where()
            self.thisptr.get().get(key._infohash, cpp.bindGetCb(get_callback, <void*>cb_obj),
                    cpp.bindDoneCb(done_callback, <void*>cb_obj),
                    cpp.nullptr, #filter implemented in the get_callback
                    where._where)
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
                self.get(key, get_cb=tmp_get, done_cb=tmp_done, filter=filter, where=where)
                while pending > 0:
                    lock.wait()
            return res
    def put(self, InfoHash key, Value val, done_cb=None):
        """Publish a new value on the DHT at key.

        key     -- the DHT key where to put the value
        val     -- the value to put on the DHT
        done_cb -- optional callback called when the operation is completed.
        """
        if done_cb:
            cb_obj = {'done':done_cb}
            ref.Py_INCREF(cb_obj)
            self.thisptr.get().put(key._infohash, val._value, cpp.bindDoneCb(done_callback, <void*>cb_obj))
        else:
            lock = threading.Condition()
            pending = 0
            ok = False
            def tmp_done(ok_ret, nodes):
                nonlocal pending, ok, lock
                with lock:
                    ok = ok_ret
                    pending -= 1
                    lock.notify()
            with lock:
                pending += 1
                self.put(key, val, done_cb=tmp_done)
                while pending > 0:
                    lock.wait()
            return ok
    def listen(self, InfoHash key, value_cb):
        t = ListenToken()
        t._h = key._infohash
        cb_obj = {'valcb':value_cb}
        t._cb['cb'] = cb_obj
        # avoid the callback being destructed if the token is destroyed
        ref.Py_INCREF(cb_obj)
        t._t = self.thisptr.get().listen(t._h, cpp.bindValueCb(value_callback, <void*>cb_obj)).share()
        return t
    def cancelListen(self, ListenToken token):
        self.thisptr.get().cancelListen(token._h, token._t)
        ref.Py_DECREF(<object>token._cb['cb'])
        # fixme: not thread safe

cdef class IndexValue(object):
    cdef cpp.shared_ptr[cpp.IndexValue] _value
    def __init__(self, InfoHash h=None, cpp.uint64_t vid=0):
       cdef cpp.InfoHash hh = h._infohash
       self._value.reset(new cpp.IndexValue(hh, vid))
    def __str__(self):
        return "(" + self.getKey().toString().decode() +", "+ str(self.getValueId()) +")"
    def getKey(self):
        h = InfoHash()
        h._infohash = self._value.get().first
        return h
    def getValueId(self):
        return self._value.get().second

cdef class Pht(object):
    cdef cpp.Pht* thisptr
    def __cinit__(self, bytes name, key_spec, DhtRunner dht):
        cdef cpp.IndexKeySpec cpp_key_spec
        for kk, size in key_spec.items():
            cpp_key_spec[bytes(kk, 'utf-8')] = size
        self.thisptr = new cpp.Pht(name, cpp_key_spec, dht.thisptr)
    property MAX_NODE_ENTRY_COUNT:
        def __get__(self):
            return cpp.PHT_MAX_NODE_ENTRY_COUNT
    def lookup(self, key, lookup_cb=None, done_cb=None):
        """Query the Index with a specified key.

        key       -- the key for to the entry in the index.
        lookup_cb -- function called when the operation is completed. This
                     function takes a list of IndexValue objects and a string
                     representation of the prefix where the value was indexed in
                     the PHT.
        """
        cb_obj = {'lookup':lookup_cb, 'done':done_cb} # TODO: donecallback is to be removed
        ref.Py_INCREF(cb_obj)
        cdef cpp.IndexKey cppk
        for kk, v in key.items():
            cppk[bytes(kk, 'utf-8')] = bytes(v)
        self.thisptr.lookup(
                cppk,
                cpp.Pht.bindLookupCb(lookup_callback, <void*>cb_obj),
                cpp.bindDoneCbSimple(done_callback_simple, <void*>cb_obj)
        )
    def insert(self, key, IndexValue value, done_cb=None):
        """Add an index entry to the Index.

        key     -- the key for to the entry in the index.
        value   -- an IndexValue object describing the indexed value.
        done_cb -- Called when the operation is completed.
        """
        cb_obj = {'done':done_cb}
        ref.Py_INCREF(cb_obj)
        cdef cpp.IndexKey cppk
        for kk, v in key.items():
            cppk[bytes(kk, 'utf-8')] = bytes(v)
        cdef cpp.IndexValue val
        val.first = (<InfoHash>value.getKey())._infohash
        val.second = value.getValueId()
        self.thisptr.insert(
                cppk,
                val,
                cpp.bindDoneCbSimple(done_callback_simple, <void*>cb_obj)
        )
