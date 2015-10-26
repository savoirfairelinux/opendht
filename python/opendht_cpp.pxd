from libc.stdint cimport *
from libcpp cimport bool
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.utility cimport pair

ctypedef uint16_t in_port_t
ctypedef unsigned short int sa_family_t;

cdef extern from "<memory>" namespace "std" nogil:
    cdef cppclass shared_ptr[T]:
        shared_ptr() except +
        T* get()
        T operator*()
        void reset(T*)

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
        bool operator==(InfoHash)
        bool operator<(InfoHash)

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

cdef extern from "opendht/value.h" namespace "dht":
    cdef cppclass Value:
        Value() except +
        Value(vector[uint8_t]) except +
        Value(const uint8_t* dat_ptr, size_t dat_len) except +
        string toString() const
        uint64_t id
        PublicKey owner
        InfoHash recipient
        vector[uint8_t] data
        string user_type

cdef extern from "opendht/dht.h" namespace "dht":
    cdef cppclass Node:
        Node() except +
        InfoHash getId() const
        string getAddrStr() const
        bool isExpired() const
    ctypedef void (*ShutdownCallbackRaw)(void *user_data)
    ctypedef bool (*GetCallbackRaw)(shared_ptr[Value] values, void *user_data)
    ctypedef void (*DoneCallbackRaw)(bool done, vector[shared_ptr[Node]]* nodes, void *user_data)
    cdef cppclass Dht:
        cppclass Config:
            InfoHash node_id
            bool is_bootstrap
        cppclass ShutdownCallback:
            ShutdownCallback() except +
        cppclass GetCallback:
            GetCallback() except +
            #GetCallback(GetCallbackRaw cb, void *user_data) except +
        cppclass DoneCallback:
            DoneCallback() except +
            #DoneCallback(DoneCallbackRaw, void *user_data) except +
        Dht() except +
        InfoHash getNodeId() const
        @staticmethod
        ShutdownCallback bindShutdownCb(ShutdownCallbackRaw cb, void *user_data)
        @staticmethod
        GetCallback bindGetCb(GetCallbackRaw cb, void *user_data)
        @staticmethod
        DoneCallback bindDoneCb(DoneCallbackRaw cb, void *user_data)

cdef extern from "opendht/dht.h" namespace "dht":
    cdef cppclass SecureDht:
        cppclass Config:
            Dht.Config node_config
            Identity id

cdef extern from "opendht/dhtrunner.h" namespace "dht":
    ctypedef future[size_t] ListenToken
    ctypedef shared_future[size_t] SharedListenToken
    cdef cppclass DhtRunner:
        DhtRunner() except +
        cppclass Config:
            SecureDht.Config dht_config
            bool threaded
        InfoHash getId() const
        InfoHash getNodeId() const
        void bootstrap(const char*, const char*)
        void run(in_port_t, Config config)
        void run(const char*, const char*, const char*, Config config)
        void join()
        void shutdown(Dht.ShutdownCallback)
        bool isRunning()
        string getStorageLog() const
        string getRoutingTablesLog(sa_family_t af) const
        string getSearchesLog(sa_family_t af) const
        void get(InfoHash key, Dht.GetCallback get_cb, Dht.DoneCallback done_cb)
        void put(InfoHash key, shared_ptr[Value] val, Dht.DoneCallback done_cb)
        ListenToken listen(InfoHash key, Dht.GetCallback get_cb)
        void cancelListen(InfoHash key, SharedListenToken token)
        vector[unsigned] getNodeMessageStats(bool i)

ctypedef DhtRunner.Config Config
