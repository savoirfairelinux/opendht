# Copyright (c) 2015-2019 Savoir-faire Linux Inc.
# Author(s): Adrien Béraud <adrien.beraud@savoirfairelinux.com>
#            Simon Désaulniers <sim.desaulniers@gmail.com>
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
# along with this program; If not, see <https://www.gnu.org/licenses/>.

from libc.stdint cimport *
from libcpp cimport bool, nullptr_t, nullptr
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.utility cimport pair
from libcpp.map cimport map
from libc.string cimport const_char, const_uchar

ctypedef uint16_t in_port_t
ctypedef unsigned short int sa_family_t;

cdef extern from "<memory>" namespace "std" nogil:
    cdef cppclass shared_ptr[T]:
        shared_ptr() except +
        shared_ptr(T*) except +
        T* get()
        T operator*()
        bool operator bool() const
        void reset(T*)
    shared_ptr[T] make_shared[T](...) except +

cdef extern from "<functional>" namespace "std" nogil:
    cdef cppclass hash[T]:
        hash() except +
        size_t get "operator()"(T)

cdef extern from "<future>" namespace "std" nogil:
    cdef cppclass shared_future[T]:
        shared_future() except +
        bool valid() const

    cdef cppclass future[T]:
        future() except +
        bool valid() const
        shared_future[T] share()

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
        @staticmethod
        InfoHash getRandom()
        bool operator==(InfoHash) const
        bool operator<(InfoHash) const
        bool operator bool() const

cdef extern from "opendht/sockaddr.h" namespace "dht":
    cdef cppclass SockAddr:
        SockAddr() except +
        string toString() const
        in_port_t getPort() const
        void setPort(in_port_t p)
        sa_family_t getFamily() const
        void setFamily(sa_family_t f)
        bool isLoopback() const
        bool isPrivate() const
        bool isUnspecified() const

ctypedef vector[uint8_t] Blob

cdef extern from "opendht/crypto.h" namespace "dht::crypto":
    ctypedef pair[shared_ptr[PrivateKey], shared_ptr[Certificate]] Identity
    cdef Identity generateIdentity(string name, Identity ca, unsigned bits)

    cdef cppclass PrivateKey:
        PrivateKey()
        PublicKey getPublicKey() const
        Blob decrypt(Blob data) const
        @staticmethod
        PrivateKey generate()
        @staticmethod
        PrivateKey generateEC()

    cdef cppclass PublicKey:
        PublicKey()
        InfoHash getId() const
        Blob encrypt(Blob data) const

    cdef cppclass Certificate:
        Certificate()
        Certificate(string pem)
        InfoHash getId() const
        string toString() const
        string getName() const
        void revoke(PrivateKey key, Certificate cert)
        @staticmethod
        Certificate generate(PrivateKey key, string name, Identity ca, bool is_ca)
        shared_ptr[Certificate] issuer

    cdef cppclass TrustList:
        cppclass VerifyResult:
            bool operator bool() const
            bool isValid() const
            string toString() const
        TrustList()
        void add(Certificate)
        void remove(Certificate)
        VerifyResult verify(Certificate);

ctypedef TrustList.VerifyResult TrustListVerifyResult

cdef extern from "opendht/value.h" namespace "dht::Value":
    cdef cppclass Field:
        pass

cdef extern from "opendht/value.h" namespace "dht::Value::Field":
    cdef Field None
    cdef Field Id
    cdef Field ValueType
    cdef Field OwnerPk
    cdef Field SeqNum
    cdef Field UserType
    cdef Field COUNT

cdef extern from "opendht/value.h" namespace "dht":
    cdef cppclass Value:
        Value() except +
        Value(vector[uint8_t]) except +
        Value(const uint8_t* dat_ptr, size_t dat_len) except +
        string toString() const
        size_t size() const
        uint64_t id
        shared_ptr[PublicKey] owner
        InfoHash recipient
        vector[uint8_t] data
        string user_type

    cdef cppclass Query:
        Query() except +
        Query(Select s, Where w) except +
        Query(string q_str) except +
        bool isSatisfiedBy(const Query& q) const
        string toString() const

    cdef cppclass Select:
        Select() except +
        Select(const string& q_str) except +
        bool isSatisfiedBy(const Select& os) const
        Select& field(Field field)
        string toString() const

    cdef cppclass Where:
        Where() except +
        Where(const string& q_str)
        bool isSatisfiedBy(const Where& where) const
        Where& id(uint64_t id)
        Where& valueType(uint16_t type)
        Where& owner(InfoHash owner_pk_hash)
        Where& seq(uint16_t seq_no)
        Where& userType(string user_type)
        string toString() const

cdef extern from "opendht/node.h" namespace "dht":
    cdef cppclass Node:
        Node() except +
        InfoHash getId() const
        string getAddrStr() const
        bool isExpired() const

cdef extern from "opendht/callbacks.h" namespace "dht":
    ctypedef void (*ShutdownCallbackRaw)(void *user_data)
    ctypedef bool (*GetCallbackRaw)(shared_ptr[Value] values, void *user_data)
    ctypedef bool (*ValueCallbackRaw)(shared_ptr[Value] values, bool expired, void *user_data)
    ctypedef void (*DoneCallbackRaw)(bool done, vector[shared_ptr[Node]]* nodes, void *user_data)
    ctypedef void (*DoneCallbackSimpleRaw)(bool done, void *user_data)

    cppclass ShutdownCallback:
        ShutdownCallback() except +
    cppclass GetCallback:
        GetCallback() except +
    cppclass ValueCallback:
        ValueCallback() except +
    cppclass DoneCallback:
        DoneCallback() except +
    cppclass DoneCallbackSimple:
        DoneCallbackSimple() except +

    cdef ShutdownCallback bindShutdownCb(ShutdownCallbackRaw cb, void *user_data)
    cdef GetCallback bindGetCb(GetCallbackRaw cb, void *user_data)
    cdef ValueCallback bindValueCb(ValueCallbackRaw cb, void *user_data)
    cdef DoneCallback bindDoneCb(DoneCallbackRaw cb, void *user_data)
    cdef DoneCallbackSimple bindDoneCbSimple(DoneCallbackSimpleRaw cb, void *user_data)

    cppclass Config:
        InfoHash node_id
        uint32_t network
        bool is_bootstrap
        bool maintain_storage
        string persist_path
        size_t max_req_per_sec
        size_t max_peer_req_per_sec
    cppclass SecureDhtConfig:
        Config node_config
        Identity id

cdef extern from "opendht/dhtrunner.h" namespace "dht":
    ctypedef future[size_t] ListenToken
    ctypedef shared_future[size_t] SharedListenToken
    cdef cppclass DhtRunner:
        DhtRunner() except +
        cppclass Config:
            SecureDhtConfig dht_config
            bool threaded
        InfoHash getId() const
        InfoHash getNodeId() const
        void bootstrap(const_char*, const_char*)
        void bootstrap(const SockAddr&, DoneCallbackSimple done_cb)
        void run(in_port_t, Config config)
        void run(const_char*, const_char*, const_char*, Config config)
        void join()
        void shutdown(ShutdownCallback)
        bool isRunning()
        SockAddr getBound(sa_family_t af) const
        string getStorageLog() const
        string getRoutingTablesLog(sa_family_t af) const
        string getSearchesLog(sa_family_t af) const
        void get(InfoHash key, GetCallback get_cb, DoneCallback done_cb, nullptr_t f, Where w)
        void put(InfoHash key, shared_ptr[Value] val, DoneCallback done_cb)
        ListenToken listen(InfoHash key, ValueCallback get_cb)
        void cancelListen(InfoHash key, SharedListenToken token)
        vector[unsigned] getNodeMessageStats(bool i)

ctypedef DhtRunner.Config DhtRunnerConfig

cdef extern from "opendht/log.h" namespace "dht::log":
    void enableLogging(DhtRunner& dht)
    void disableLogging(DhtRunner& dht)
    void enableFileLogging(DhtRunner& dht, const string& path)

cdef extern from "opendht/indexation/pht.h" namespace "dht::indexation":
    size_t PHT_MAX_NODE_ENTRY_COUNT "dht::indexation::Pht::MAX_NODE_ENTRY_COUNT"
    cdef cppclass Prefix:
        Prefix() except +
        Prefix(vector[uint8_t]) except +
        string toString() const
    ctypedef pair[InfoHash, uint64_t] IndexValue "dht::indexation::Value"
    ctypedef map[string, vector[uint8_t]] IndexKey "dht::indexation::Pht::Key"
    ctypedef map[string, uint32_t] IndexKeySpec "dht::indexation::Pht::KeySpec"
    ctypedef void (*LookupCallbackRaw)(vector[shared_ptr[IndexValue]]* values, Prefix* p, void* user_data);
    cdef cppclass Pht:
        cppclass LookupCallback:
            LookupCallback() except +
        Pht(string, IndexKeySpec, shared_ptr[DhtRunner]) except +
        void lookup(IndexKey k, LookupCallback cb, DoneCallbackSimple doneCb);
        void insert(IndexKey k, IndexValue v, DoneCallbackSimple cb)
        @staticmethod
        LookupCallback bindLookupCb(LookupCallbackRaw cb, void *user_data)
