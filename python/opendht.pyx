# distutils: language = c++
# distutils: extra_compile_args = -std=c++17
# distutils: include_dirs = ../../include
# distutils: library_dirs = ../../src
# distutils: libraries = opendht gnutls
# cython: language_level=3
#
# Copyright (c) 2014-2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: MIT

from libcpp.map cimport map as map
from libcpp cimport bool
from libcpp.utility cimport pair
from libcpp.string cimport string
from libcpp.memory cimport shared_ptr, unique_ptr

from cython.operator cimport dereference as deref, preincrement as inc, predecrement as dec
from cpython cimport ref
from datetime import timedelta
from enum import IntEnum as _IntEnum
from operator import index as _index

cimport opendht_cpp as cpp

ctypedef cpp.Pht* _PhtPtr

import threading
import socket as _socket
import weakref as _weakref

cdef inline void _initialize_gnutls():
    cdef int err = cpp.gnutls_global_init()
    if err != 0:
        print(f"Failed to initialize GnuTLS: {cpp.gnutls_strerror(err).decode()}")
    else:
        import atexit
        atexit.register(_deinitialize_gnutls)

cdef inline _deinitialize_gnutls():
    cpp.gnutls_global_deinit()

# Initialize GnuTLS when this module is imported
_initialize_gnutls()

def version() -> str:
    return cpp.version().decode()

class NodeStatus(_IntEnum):
    Disconnected = 0
    Connecting = 1
    Connected = 2

class ValueField(_IntEnum):
    Id = 1
    ValueType = 2
    OwnerPk = 3
    SeqNum = 4
    UserType = 5

class _StatusCallbackState:
    __slots__ = ("callback", "__weakref__")
    def __init__(self):
        self.callback = None

cdef inline void status_callback(int ipv4, int ipv6, void* user_data) noexcept with gil:
    state = (<object>user_data)()
    if state is None:
        return
    callback = state.callback
    if callback is not None:
        callback(NodeStatus(ipv4), NodeStatus(ipv6))

cdef inline bool query_callback(shared_ptr[cpp.FieldValueIndex] value, void* user_data) noexcept with gil:
    cdef cpp.Blob blob
    row = {}
    for entry in value.get().index:
        field = ValueField(<int>entry.first)
        if field == ValueField.OwnerPk:
            owner = InfoHash()
            owner._infohash = entry.second.getHash()
            row[field] = owner
        elif field == ValueField.UserType:
            blob = entry.second.getBlob()
            row[field] = (<char*>blob.data())[:blob.size()].decode()
        else:
            row[field] = entry.second.getInt()
    return (<object>user_data)['query'](row)

cdef inline void query_done_callback(bool done, cpp.vector[shared_ptr[cpp.Node]]* nodes, void* user_data) noexcept with gil:
    callback = (<object>user_data)['done']
    if callback is not None:
        entries = []
        for node in deref(nodes):
            entry = NodeEntry()
            entry._v.first = node.get().getId()
            entry._v.second = node
            entries.append(entry)
        callback(done, entries)

cdef inline void lookup_callback(cpp.vector[cpp.shared_ptr[cpp.IndexValue]]* values, cpp.Prefix* p, void *user_data) noexcept with gil:
    cbs = <object>user_data
    if 'lookup' in cbs and cbs['lookup']:
        vals = []
        for val in deref(values):
            v = IndexValue()
            v._value = val
            vals.append(v)
        cbs['lookup'](vals, p.toString())

cdef inline void shutdown_callback(void* user_data) noexcept with gil:
    cbs = <object>user_data
    try:
        if 'shutdown' in cbs and cbs['shutdown']:
            cbs['shutdown']()
    finally:
        ref.Py_DECREF(cbs)

cdef inline bool get_callback(shared_ptr[cpp.Value] value, void *user_data) noexcept with gil:
    cbs = <object>user_data
    cb = cbs['get']
    f = cbs['filter'] if 'filter' in cbs else None
    pv = Value()
    pv._value = value
    return cb(pv) if not f or f(pv) else True

cdef inline bool value_callback(shared_ptr[cpp.Value] value, bool expired, void *user_data) noexcept with gil:
    cbs = <object>user_data
    cb = cbs['valcb']
    f = cbs['filter'] if 'filter' in cbs else None
    pv = Value()
    pv._value = value
    return cb(pv, expired) if not f or f(pv) else True

cdef inline void done_callback(bool done, cpp.vector[shared_ptr[cpp.Node]]* nodes, void *user_data) noexcept with gil:
    cbs = <object>user_data
    try:
        node_ids = []
        for n in deref(nodes):
            h = NodeEntry()
            h._v.first = n.get().getId()
            h._v.second = n
            node_ids.append(h)
        if 'done' in cbs and cbs['done']:
            cbs['done'](done, node_ids)
    finally:
        ref.Py_DECREF(cbs)

cdef inline void done_callback_simple(bool done, void *user_data) noexcept with gil:
    cbs = <object>user_data
    try:
        if 'done' in cbs and cbs['done']:
            cbs['done'](done)
    finally:
        ref.Py_DECREF(cbs)

cdef class _WithID(object):
    def __repr__(self):
        return "<%s '%s'>" % (self.__class__.__name__, str(self))
    def __str__(self):
        return self.getId().toString().decode()

cdef class _WithPk(object):
    def __repr__(self):
        return "<%s '%s'>" % (self.__class__.__name__, str(self))
    def __str__(self):
        return self.getLongId().toString().decode()

cdef inline unsigned _checked_bit_index(bit, unsigned bit_count) except *:
    bit = _index(bit)
    if bit < 0 or bit >= bit_count:
        raise IndexError("bit index out of range")
    return bit

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
        return self._infohash.getBit(_checked_bit_index(bit, 160))
    def setBit(InfoHash self, bit, b):
        self._infohash.setBit(_checked_bit_index(bit, 160), b)
    def getId(InfoHash self):
        return self
    def toString(InfoHash self):
        return self._infohash.toString()
    def toFloat(InfoHash self):
        return self._infohash.toFloat()
    @staticmethod
    def commonBits(InfoHash a, InfoHash b) -> int:
        return cpp.InfoHash.commonBits(a._infohash, b._infohash)
    @staticmethod
    def get(str key) -> InfoHash:
        h = InfoHash()
        h._infohash = cpp.InfoHash.get(key.encode())
        return h
    @staticmethod
    def getRandom() -> InfoHash:
        h = InfoHash()
        h._infohash = cpp.InfoHash.getRandom()
        return h

cdef class PkId(_WithPk):
    cdef cpp.PkId _pkid
    def __cinit__(self, bytes str=b''):
        self._pkid = cpp.PkId(str) if str else cpp.PkId()
    def __bool__(PkId self):
        return <bool>self._pkid
    def __richcmp__(PkId self, PkId other, int op):
        if op == 0:
            return self._pkid < other._pkid
        if op == 1:
            return self._pkid < other._pkid or self._pkid == other._pkid
        if op == 2:
            return self._pkid == other._pkid
        return NotImplemented
    def getBit(PkId self, bit):
        return self._pkid.getBit(_checked_bit_index(bit, 256))
    def setBit(PkId self, bit, b):
        self._pkid.setBit(_checked_bit_index(bit, 256), b)
    def getLongId(PkId self):
        return self
    def toString(PkId self):
        return self._pkid.toString()
    def toFloat(PkId self) -> float:
        return self._pkid.toFloat()
    @staticmethod
    def commonBits(PkId a, PkId b) -> int:
        return cpp.PkId.commonBits(a._pkid, b._pkid)
    @staticmethod
    def get(str key) -> PkId:
        h = PkId()
        h._pkid = cpp.PkId.get(key.encode())
        return h
    @staticmethod
    def getRandom() -> PkId:
        h = PkId()
        h._pkid = cpp.PkId.getRandom()
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
    @staticmethod
    def resolve(str host, str service=None):
        vals = []
        result = cpp.SockAddr.resolve(host.encode(), service.encode() if service else b'')
        for val in result:
            a = SockAddr()
            a._addr = val
            vals.append(a)
        return vals

cdef class Node(_WithID):
    cdef shared_ptr[cpp.Node] _node
    def getId(self):
        if not self._node:
            raise ValueError("Node is not initialized")
        h = InfoHash()
        h._infohash = self._node.get().getId()
        return h
    def getAddr(self):
        if not self._node:
            raise ValueError("Node is not initialized")
        return self._node.get().getAddrStr()
    def isExpired(self):
        if not self._node:
            raise ValueError("Node is not initialized")
        return self._node.get().isExpired()

cdef class NodeStats(object):
    cdef cpp.NodeStats _stats
    @property
    def good_nodes(self):
        return self._stats.good_nodes
    @property
    def dubious_nodes(self):
        return self._stats.dubious_nodes
    @property
    def cached_nodes(self):
        return self._stats.cached_nodes
    @property
    def incoming_nodes(self):
        return self._stats.incoming_nodes
    @property
    def table_depth(self):
        return self._stats.table_depth
    @property
    def searches(self):
        return self._stats.searches
    @property
    def node_cache_size(self):
        return self._stats.node_cache_size
    def getKnownNodes(self):
        return self._stats.getKnownNodes()
    def getNetworkSizeEstimation(self):
        return self._stats.getNetworkSizeEstimation()

cdef class NodeInfo(object):
    cdef cpp.NodeInfo _info
    @property
    def id(self):
        result = InfoHash()
        result._infohash = self._info.id
        return result
    @property
    def node_id(self):
        result = InfoHash()
        result._infohash = self._info.node_id
        return result
    @property
    def ipv4(self):
        result = NodeStats()
        result._stats = self._info.ipv4
        return result
    @property
    def ipv6(self):
        result = NodeStats()
        result._stats = self._info.ipv6
        return result
    @property
    def ongoing_ops(self):
        return self._info.ongoing_ops
    @property
    def storage_values(self):
        return self._info.storage_values
    @property
    def storage_size(self):
        return self._info.storage_size
    @property
    def local_storage_values(self):
        return self._info.local_storage_values
    @property
    def local_storage_size(self):
        return self._info.local_storage_size
    @property
    def bound4(self):
        return self._info.bound4
    @property
    def bound6(self):
        return self._info.bound6

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
    def field(self, field):
        cdef int field_id = ValueField(_index(field))
        if field_id == ValueField.SeqNum:
            raise ValueError("The native wire format does not support sequence-number projections")
        self._select.field(<cpp.Field>field_id)
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
    def isSatisfiedBy(self, Where where) -> bool:
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
    def __init__(self, bytes val=b'', cpp.uint16_t id=0):
        self._value.reset(new cpp.Value(id, val, len(val)))
    def __str__(self):
        return self._value.get().toString().decode()
    @property
    def owner(self) -> PublicKey:
        h = PublicKey()
        h._key = self._value.get().owner
        return h
    @property
    def recipient(self) -> InfoHash:
        h = InfoHash()
        h._infohash = self._value.get().recipient
        return h
    @recipient.setter
    def recipient(self, InfoHash h):
        self._value.get().recipient = h._infohash
    @property
    def data(self) -> bytes:
        cdef char* data_ptr = <char*>self._value.get().data.data()
        cdef int data_size = self._value.get().data.size()
        return data_ptr[:data_size]
    @data.setter
    def data(self, bytes value):
        self._value.get().data = value
    @property
    def user_type(self) -> str:
        return self._value.get().user_type.decode()
    @user_type.setter
    def user_type(self, str t):
        self._value.get().user_type = t.encode()
    @property
    def id(self):
        return self._value.get().id
    @id.setter
    def id(self, cpp.uint64_t value):
        self._value.get().id = value
    @property
    def type(self) -> int:
        return self._value.get().type
    @type.setter
    def type(self, cpp.uint16_t value):
        self._value.get().type = value
    @property
    def seq(self) -> int:
        return self._value.get().seq
    @seq.setter
    def seq(self, cpp.uint16_t value):
        self._value.get().seq = value
    @property
    def priority(self) -> int:
        return self._value.get().priority
    @priority.setter
    def priority(self, unsigned value):
        self._value.get().priority = value
    @property
    def pushType(self) -> str:
        return self._value.get().pushType.decode()
    @pushType.setter
    def pushType(self, str value):
        self._value.get().pushType = value.encode()
    @property
    def size(self) -> int:
        return self._value.get().size()

cdef class ValueType(object):
    cdef unique_ptr[cpp.ValueType] _value
    def __init__(self, cpp.uint16_t id, str name, expiration: timedelta):
        if not isinstance(expiration, timedelta):
            raise TypeError("expiration argument must be of type timedelta")
        cdef cpp.seconds duration = cpp.seconds(int(expiration.total_seconds()))
        self._value.reset(new cpp.ValueType(id, name.encode(), duration))

cdef class NodeSetIter(object):
    cdef NodeSet _owner
    cdef map[cpp.InfoHash, shared_ptr[cpp.Node]].iterator _curIter
    def __init__(self, NodeSet s not None):
        self._owner = s
        self._curIter = self._owner._nodes.begin()
    def __iter__(self):
        return self
    def __next__(self):
        if self._curIter == self._owner._nodes.end():
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
            if not deref(it).second:
                raise ValueError("Node is not initialized")
            s += deref(it).first.toString().decode() + ' ' + deref(it).second.get().getAddrStr().decode() + '\n'
            inc(it)
        return s
    def __iter__(self):
        return NodeSetIter(self)

cdef class PrivateKey(_WithPk):
    cdef shared_ptr[cpp.PrivateKey] _key

    def __init__(self, bytes data=None, str password=""):
        cdef cpp.Blob encoded
        if '\0' in password:
            raise ValueError("Password must not contain NUL characters")
        if data is not None:
            if not data:
                raise ValueError("Private key data must not be empty")
            encoded = data
            self._key = cpp.make_shared[cpp.PrivateKey](encoded, <cpp.string>password.encode())

    def serialize(self, str password="") -> bytes:
        """Export PKCS#8 PEM, encrypted when a nonempty password is supplied."""
        if not self._key:
            raise ValueError("PrivateKey is not initialized")
        if '\0' in password:
            raise ValueError("Password must not contain NUL characters")
        cdef cpp.Blob encoded = self._key.get().serialize(password.encode())
        if encoded.empty():
            raise RuntimeError("Could not export private key")
        return (<char*>encoded.data())[:encoded.size()]

    def __bytes__(self):
        return self.serialize()

    def getId(self) -> InfoHash:
        if not self._key:
            raise ValueError("PrivateKey is not initialized")
        h = InfoHash()
        h._infohash = self._key.get().getSharedPublicKey().get().getId()
        return h

    def getLongId(self) -> PkId:
        if not self._key:
            raise ValueError("PrivateKey is not initialized")
        id = PkId()
        id._pkid = self._key.get().getSharedPublicKey().get().getLongId()
        return id

    def getPublicKey(self) -> PublicKey:
        if not self._key:
            raise ValueError("PrivateKey is not initialized")
        pk = PublicKey()
        pk._key = self._key.get().getSharedPublicKey()
        return pk

    def decrypt(self, bytes dat) -> bytes:
        if not self._key:
            raise ValueError("PrivateKey is not initialized")
        cdef size_t d_len = len(dat)
        cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>dat
        cdef cpp.Blob indat
        indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
        cdef cpp.Blob decrypted = self._key.get().decrypt(indat)
        cdef char* decrypted_c_str = <char *>decrypted.data()
        cdef Py_ssize_t length = decrypted.size()
        return decrypted_c_str[:length]

    def sign(self, bytes dat) -> bytes:
        if not self._key:
            raise ValueError("PrivateKey is not initialized")
        cdef size_t d_len = len(dat)
        cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>dat
        cdef cpp.Blob indat
        indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
        cdef cpp.Blob signature = self._key.get().sign(indat)
        cdef char* signature_c_str = <char *>signature.data()
        cdef Py_ssize_t length = signature.size()
        return signature_c_str[:length]

    @staticmethod
    def generate() -> PrivateKey:
        k = PrivateKey()
        k._key = cpp.make_shared[cpp.PrivateKey](cpp.PrivateKey.generate())
        return k
    @staticmethod
    def generateEC() -> PrivateKey:
        k = PrivateKey()
        k._key = cpp.make_shared[cpp.PrivateKey](cpp.PrivateKey.generateEC())
        return k

cdef class PublicKey(_WithPk):
    cdef cpp.shared_ptr[cpp.PublicKey] _key
    def __init__(self, bytes data=None):
        cdef cpp.Blob encoded
        if data is not None:
            if not data:
                raise ValueError("Public key data must not be empty")
            encoded = data
            self._key = cpp.make_shared[cpp.PublicKey](encoded)

    def serialize(self) -> bytes:
        """Export the public key as DER bytes."""
        if not self._key:
            raise ValueError("PublicKey is not initialized")
        cdef cpp.Blob encoded
        self._key.get().pack(encoded)
        return (<char*>encoded.data())[:encoded.size()]

    def __bytes__(self):
        return self.serialize()

    def getId(self) -> InfoHash:
        if not self._key:
            raise ValueError("PublicKey is not initialized")
        h = InfoHash()
        h._infohash = self._key.get().getId()
        return h

    def getLongId(self) -> PkId:
        if not self._key:
            raise ValueError("PublicKey is not initialized")
        id = PkId()
        id._pkid = self._key.get().getLongId()
        return id

    def encrypt(self, bytes dat) -> bytes:
        if not self._key:
            raise ValueError("PublicKey is not initialized")
        cdef size_t d_len = len(dat)
        cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>dat
        cdef cpp.Blob indat
        indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
        cdef cpp.Blob encrypted = self._key.get().encrypt(indat)
        cdef char* encrypted_c_str = <char *>encrypted.data()
        cdef Py_ssize_t length = encrypted.size()
        return encrypted_c_str[:length]

    def checkSignature(self, bytes dat, bytes signature) -> bool:
        if not self._key:
            raise ValueError("PublicKey is not initialized")
        cdef size_t d_len = len(dat)
        cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>dat
        cdef cpp.Blob indat
        indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
        cdef size_t s_len = len(signature)
        cdef cpp.uint8_t* s_ptr = <cpp.uint8_t*>signature
        cdef cpp.Blob sig
        sig.assign(s_ptr, <cpp.uint8_t*>(s_ptr + s_len))
        return self._key.get().checkSignature(indat, sig)

cdef class Certificate(_WithPk):
    cdef shared_ptr[cpp.Certificate] _cert
    def __init__(self, bytes dat = None):
        if dat:
            self._cert = cpp.make_shared[cpp.Certificate](<cpp.string>dat)
    def getId(self) -> InfoHash:
        if not self._cert:
            raise ValueError("Certificate is not initialized")
        h = InfoHash()
        h._infohash = self._cert.get().getId()
        return h
    def getLongId(self) -> PkId:
        if not self._cert:
            raise ValueError("Certificate is not initialized")
        id = PkId()
        id._pkid = self._cert.get().getLongId()
        return id
    def toString(self) -> str:
        if not self._cert:
            return ""
        return self._cert.get().toString().decode()
    def getName(self) -> str:
        if not self._cert:
            raise ValueError("Certificate is not initialized")
        return self._cert.get().getName().decode()
    def revoke(self, PrivateKey k, Certificate c):
        if not self._cert or c is None or not c._cert:
            raise ValueError("Certificate is not initialized")
        if k is None or not k._key:
            raise ValueError("PrivateKey is not initialized")
        self._cert.get().revoke(deref(k._key.get()), deref(c._cert.get()));
    def __bytes__(self):
        return self._cert.get().toString() if self._cert else b''
    @property
    def issuer(self) -> Certificate|None:
        if self._cert and self._cert.get().issuer:
            c = Certificate()
            c._cert = self._cert.get().issuer
            return c
        return None
    @staticmethod
    def generate(PrivateKey k, str name, Identity i = Identity(), bool is_ca = False):
        if k is None or not k._key:
            raise ValueError("PrivateKey is not initialized")
        if i is None:
            i = Identity()
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
        if cert is None or not cert._cert:
            raise ValueError("Certificate is not initialized")
        self._trust.add(deref(cert._cert.get()))
    def remove(self, Certificate cert):
        if cert is None or not cert._cert:
            raise ValueError("Certificate is not initialized")
        self._trust.remove(deref(cert._cert.get()))
    def verify(self, Certificate cert):
        if cert is None or not cert._cert:
            raise ValueError("Certificate is not initialized")
        r = VerifyResult()
        r._result = self._trust.verify(deref(cert._cert.get()))
        return r

cdef class ListenToken(object):
    cdef cpp.InfoHash _h
    cdef cpp.shared_future[size_t] _t
    cdef bool _cancelled

cdef class Identity(object):
    cdef cpp.Identity _id
    def __init__(self, PrivateKey k = None, Certificate c = None):
        if k:
            self._id.first = k._key
        if c:
            self._id.second = c._cert
    @staticmethod
    def generate(str name = "pydht", Identity ca = Identity(), unsigned bits = 4096):
        if ca is None:
            ca = Identity()
        i = Identity()
        i._id = cpp.generateIdentity(name.encode(), ca._id, bits)
        return i
    @property
    def publickey(self) -> PublicKey|None:
        if not self._id.first:
            return None
        k = PublicKey()
        k._key = self._id.first.get().getSharedPublicKey()
        return k
    @property
    def certificate(self) -> Certificate|None:
        if not self._id.second:
            return None
        c = Certificate()
        c._cert = self._id.second
        return c
    @property
    def key(self) -> PrivateKey|None:
        if not self._id.first:
            return None
        k = PrivateKey()
        k._key = self._id.first
        return k

def aesEncrypt(bytes data, str password) -> bytes :
    cdef size_t d_len = len(data)
    cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>data
    cdef cpp.Blob indat
    indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
    cdef cpp.Blob encrypted = cpp.aesEncrypt(indat, password.encode())
    cdef char* encrypted_c_str = <char *>encrypted.data()
    cdef Py_ssize_t length = encrypted.size()
    return encrypted_c_str[:length]

def aesDecrypt(bytes data, str password) -> bytes :
    cdef size_t d_len = len(data)
    cdef cpp.uint8_t* d_ptr = <cpp.uint8_t*>data
    cdef cpp.Blob indat
    indat.assign(d_ptr, <cpp.uint8_t*>(d_ptr + d_len))
    cdef cpp.Blob decrypted = cpp.aesDecrypt(indat, password.encode())
    cdef char* decrypted_c_str = <char *>decrypted.data()
    cdef Py_ssize_t length = decrypted.size()
    return decrypted_c_str[:length]

cdef class DhtConfig(object):
    cdef cpp.DhtRunnerConfig _config
    def __init__(self):
        self._config = cpp.DhtRunnerConfig()
        self._config.threaded = True
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
    def setPersistPath(self, str path):
        """Set the native state file path; an empty string disables persistence."""
        if path is None:
            raise TypeError("path must be a string")
        if '\0' in path:
            raise ValueError("path must not contain NUL characters")
        self._config.dht_config.node_config.persist_path = path.encode()
    def setRateLimit(self, ssize_t max_req_per_sec, ssize_t max_peer_req_per_sec):
        self._config.dht_config.node_config.max_req_per_sec = max_req_per_sec
        self._config.dht_config.node_config.max_peer_req_per_sec = max_peer_req_per_sec
    def setProxyInfo(self, str proxy_server, str push_node_id="", str push_token="", str push_topic="", str push_platform="", str user_agent="", Certificate server_ca = Certificate()):
        self._config.proxy_server = proxy_server.encode()
        self._config.push_node_id = push_node_id.encode()
        self._config.push_token = push_token.encode()
        self._config.push_topic = push_topic.encode()
        self._config.push_platform = push_platform.encode()
        self._config.proxy_user_agent = user_agent.encode()
        self._config.server_ca = server_ca._cert
    def setPeerDiscovery(self, bool peer_discovery, bool peer_publish):
        self._config.peer_discovery = peer_discovery
        self._config.peer_publish = peer_publish
    def setBound(self, SockAddr bind4, SockAddr bind6):
        self._config.bind4 = bind4._addr
        self._config.bind6 = bind6._addr

cdef class DhtRunner(_WithID):
    cdef cpp.shared_ptr[cpp.DhtRunner] thisptr
    cdef map[_PhtPtr, shared_ptr[cpp.Pht]] _indexes
    cdef object _status_callback
    def __cinit__(self):
        self.thisptr.reset(new cpp.DhtRunner())
        self._status_callback = _StatusCallbackState()
    def __dealloc__(self):
        with nogil:
            if self.thisptr:
                self.thisptr.get().join()
            self._indexes.clear()
            self.thisptr.reset()
    def getId(self) -> InfoHash:
        h = InfoHash()
        if self.thisptr:
            with nogil:
                h._infohash = self.thisptr.get().getId()
        return h
    def getPublicKey(self) -> PublicKey:
        if not self.thisptr:
            raise ValueError("DhtRunner is not initialized")
        pk = PublicKey()
        with nogil:
            pk._key = self.thisptr.get().getPublicKey()
        return pk
    def getNodeId(self) -> InfoHash:
        h = InfoHash()
        if self.thisptr:
            with nogil:
                h._infohash = self.thisptr.get().getNodeId()
        return h
    def getNodeInfo(self) -> NodeInfo:
        result = NodeInfo()
        with nogil:
            result._info = self.thisptr.get().getNodeInfo()
        return result
    def getNodesStats(self, af=_socket.AF_INET) -> NodeStats:
        if af not in (_socket.AF_INET, _socket.AF_INET6):
            raise ValueError("af must be AF_INET or AF_INET6")
        info = self.getNodeInfo()
        return info.ipv4 if af == _socket.AF_INET else info.ipv6
    def getPublicAddress(self, cpp.sa_family_t af=0):
        if af not in (0, _socket.AF_INET, _socket.AF_INET6):
            raise ValueError("af must be AF_UNSPEC, AF_INET or AF_INET6")
        cdef cpp.vector[cpp.SockAddr] addresses
        with nogil:
            addresses = self.thisptr.get().getPublicAddress(af)
        result = []
        for address in addresses:
            value = SockAddr()
            value._addr = address
            result.append(value)
        return result
    def getPublicAddressStr(self, cpp.sa_family_t af=0):
        return [str(address) for address in self.getPublicAddress(af)]
    def setOnStatusChanged(self, callback=None):
        """Replace the DHT-thread status callback, or disable it with None."""
        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable or None")
        self._status_callback.callback = callback
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
    def run(self, Identity id=None, is_bootstrap=False, cpp.in_port_t port=0, str ipv4="", str ipv6="", DhtConfig config=None):
        cdef cpp.DhtRunnerConfig run_config = config._config if config is not None else cpp.DhtRunnerConfig()
        if id is not None:
            run_config.dht_config.id = id._id
        if is_bootstrap:
            run_config.dht_config.node_config.is_bootstrap = True
        if ipv4 or ipv6:
            bind4 = ipv4.encode() if ipv4 else b''
            bind6 = ipv6.encode() if ipv6 else b''
            cpp.runPythonRunnerAddress(deref(self.thisptr.get()), bind4, bind6,
                                       str(port).encode(), run_config,
                                       status_callback, _weakref.ref(self._status_callback))
        else:
            cpp.runPythonRunner(deref(self.thisptr.get()), port, run_config,
                                status_callback, _weakref.ref(self._status_callback))
    def join(self):
        with nogil:
            self.thisptr.get().join()
        self._indexes.clear()
    def shutdown(self, shutdown_cb=None):
        cb_obj = {'shutdown':shutdown_cb}
        ref.Py_INCREF(cb_obj)
        self.thisptr.get().shutdown(cpp.bindShutdownCb(shutdown_callback, <void*>cb_obj))
    def registerType(self, ValueType type):
        self.thisptr.get().registerType(deref(type._value.get()))
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
        with nogil:
            s._addr = self.thisptr.get().getBound(af)
        return s
    def getStorageLog(self):
        cdef cpp.string result
        with nogil:
            result = self.thisptr.get().getStorageLog()
        return result.decode()
    def getRoutingTablesLog(self, cpp.sa_family_t af):
        cdef cpp.string result
        with nogil:
            result = self.thisptr.get().getRoutingTablesLog(af)
        return result.decode()
    def getSearchesLog(self, cpp.sa_family_t af):
        cdef cpp.string result
        with nogil:
            result = self.thisptr.get().getSearchesLog(af)
        return result.decode()
    def getNodeMessageStats(self, bool incoming=False):
        stats = []
        cdef cpp.vector[unsigned] res
        with nogil:
            res = self.thisptr.get().getNodeMessageStats(incoming)
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

    def query(self, InfoHash key not None, query_cb=None, done_cb=None, Query query=None):
        """Return projected metadata rows, or stream them through query_cb."""
        if query is None:
            query = Query("SELECT id,value_type,owner_pk,user_type")
        if query_cb is None:
            completed = threading.Event()
            rows = []
            def on_row(row):
                rows.append(row)
                return True
            self.query(key, on_row, lambda ok, nodes: completed.set(), query)
            completed.wait()
            return rows
        if not callable(query_cb) or (done_cb is not None and not callable(done_cb)):
            raise TypeError("query callbacks must be callable")
        callbacks = {'query': query_cb, 'done': done_cb}
        cpp.queryPython(deref(self.thisptr.get()), key._infohash, query_callback,
                        query_done_callback, callbacks, query._query)

    def put(self, InfoHash key, Value val, done_cb=None, permanent=False):
        """Publish a new value on the DHT at key.

        key     -- the DHT key where to put the value
        val     -- the value to put on the DHT
        done_cb -- optional callback called when the operation is completed.
        """
        if done_cb:
            cb_obj = {'done':done_cb}
            ref.Py_INCREF(cb_obj)
            self.thisptr.get().put(key._infohash, val._value, cpp.bindDoneCb(done_callback, <void*>cb_obj), cpp.time_point.max(), permanent)
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
                self.put(key, val, done_cb=tmp_done, permanent=permanent)
                while pending > 0:
                    lock.wait()
            return ok

    def putSigned(self, InfoHash key, Value val, done_cb=None, permanent=False):
        if done_cb:
            cb_obj = {'done':done_cb}
            ref.Py_INCREF(cb_obj)
            self.thisptr.get().putSigned(key._infohash, val._value, cpp.bindDoneCb(done_callback, <void*>cb_obj), permanent)
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
                self.putSigned(key, val, done_cb=tmp_done, permanent=permanent)
                while pending > 0:
                    lock.wait()
            return ok

    def putEncrypted(self, InfoHash key, Value val, to, done_cb=None, bool permanent=False):
        if to is None:
            raise ValueError("'to' must be provided")
        if done_cb:
            cb_obj = {'done':done_cb}
            ref.Py_INCREF(cb_obj)
            try:
                if isinstance(to, PublicKey):
                    self.thisptr.get().putEncrypted(
                        key._infohash, (<PublicKey>to)._key, val._value,
                        cpp.bindDoneCb(done_callback, <void*>cb_obj), permanent
                    )
                elif isinstance(to, PkId):
                    self.thisptr.get().putEncrypted(
                        key._infohash, (<PkId>to)._pkid, val._value,
                        cpp.bindDoneCb(done_callback, <void*>cb_obj), permanent
                    )
                else:
                    raise TypeError("'to' must be PublicKey or PkId")
            except:
                ref.Py_DECREF(cb_obj)
                raise
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
                self.putEncrypted(key, val, to=to, done_cb=tmp_done, permanent=permanent)
                while pending > 0:
                    lock.wait()
            return ok

    def cancelPut(self, InfoHash key, Value val):
        self.thisptr.get().cancelPut(key._infohash, val._value)

    def listen(self, InfoHash key not None, value_cb, filter=None, Where where=None):
        if not callable(value_cb) or (filter is not None and not callable(filter)):
            raise TypeError("listener callbacks must be callable")
        if where is None:
            where = Where()
        t = ListenToken()
        t._h = key._infohash
        cb_obj = {'valcb':value_cb, 'filter':filter}
        t._t = self.thisptr.get().listen(t._h, cpp.bindPythonValueCb(value_callback, cb_obj),
                                       cpp.nullptr, where._where).share()
        return t
    def cancelListen(self, ListenToken token):
        if token is None:
            raise TypeError("token must be a ListenToken")
        if not token._cancelled and token._t.valid():
            self.thisptr.get().cancelListen(token._h, token._t)
            token._cancelled = True

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
    """PHT index; active native indexes live until the runner is joined."""
    cdef shared_ptr[cpp.Pht] thisptr
    cdef DhtRunner _runner
    def __cinit__(self, bytes name, key_spec, DhtRunner dht not None):
        cdef cpp.IndexKeySpec cpp_key_spec
        for kk, size in key_spec.items():
            cpp_key_spec[bytes(kk, 'utf-8')] = size
        self._runner = dht
        self.thisptr.reset(new cpp.Pht(name, cpp_key_spec, dht.thisptr))
    def __dealloc__(self):
        with nogil:
            self.thisptr.reset()
    @property
    def MAX_NODE_ENTRY_COUNT(self):
        return cpp.PHT_MAX_NODE_ENTRY_COUNT
    def lookup(self, key, lookup_cb=None, done_cb=None):
        """Query the Index with a specified key.

        key       -- the key for to the entry in the index.
        lookup_cb -- function called when the operation is completed. This
                     function takes a list of IndexValue objects and a string
                     representation of the prefix where the value was indexed in
                     the PHT.
        """
        cdef cpp.IndexKey cppk
        for kk, v in key.items():
            cppk[bytes(kk, 'utf-8')] = bytes(v)
        self._runner._indexes[self.thisptr.get()] = self.thisptr
        cb_obj = {'lookup':lookup_cb, 'done':done_cb} # TODO: donecallback is to be removed
        ref.Py_INCREF(cb_obj)
        try:
            self.thisptr.get().lookup(
                    cppk,
                    cpp.Pht.bindLookupCb(lookup_callback, <void*>cb_obj),
                    cpp.bindDoneCbSimple(done_callback_simple, <void*>cb_obj)
            )
        except:
            ref.Py_DECREF(cb_obj)
            raise
    def insert(self, key, IndexValue value, done_cb=None):
        """Add an index entry to the Index.

        key     -- the key for to the entry in the index.
        value   -- an IndexValue object describing the indexed value.
        done_cb -- Called when the operation is completed.
        """
        cdef cpp.IndexKey cppk
        for kk, v in key.items():
            cppk[bytes(kk, 'utf-8')] = bytes(v)
        cdef cpp.IndexValue val
        val.first = (<InfoHash>value.getKey())._infohash
        val.second = value.getValueId()
        self._runner._indexes[self.thisptr.get()] = self.thisptr
        cb_obj = {'done':done_cb}
        ref.Py_INCREF(cb_obj)
        try:
            self.thisptr.get().insert(
                    cppk,
                    val,
                    cpp.bindDoneCbSimple(done_callback_simple, <void*>cb_obj)
            )
        except:
            ref.Py_DECREF(cb_obj)
            raise
