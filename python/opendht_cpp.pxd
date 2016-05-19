# Copyright (c) 2015-2016 Savoir-faire Linux Inc.
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
# along with this program; If not, see <http://www.gnu.org/licenses/>.

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
        size_t size() const
        uint64_t id
        shared_ptr[PublicKey] owner
        InfoHash recipient
        vector[uint8_t] data
        string user_type

cdef extern from "opendht/node.h" namespace "dht":
    cdef cppclass Node:
        Node() except +
        InfoHash getId() const
        string getAddrStr() const
        bool isExpired() const

cdef extern from "opendht/callbacks.h" namespace "dht":
    ctypedef void (*ShutdownCallbackRaw)(void *user_data)
    ctypedef bool (*GetCallbackRaw)(shared_ptr[Value] values, void *user_data)
    ctypedef void (*DoneCallbackRaw)(bool done, vector[shared_ptr[Node]]* nodes, void *user_data)

    cppclass ShutdownCallback:
        ShutdownCallback() except +
    cppclass GetCallback:
        GetCallback() except +
        #GetCallback(GetCallbackRaw cb, void *user_data) except +
    cppclass DoneCallback:
        DoneCallback() except +
        #DoneCallback(DoneCallbackRaw, void *user_data) except +

    cdef ShutdownCallback bindShutdownCb(ShutdownCallbackRaw cb, void *user_data)
    cdef GetCallback bindGetCb(GetCallbackRaw cb, void *user_data)
    cdef DoneCallback bindDoneCb(DoneCallbackRaw cb, void *user_data)

    cppclass Config:
        InfoHash node_id
        bool is_bootstrap
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
        void bootstrap(const char*, const char*)
        void run(in_port_t, Config config)
        void run(const char*, const char*, const char*, Config config)
        void join()
        void shutdown(ShutdownCallback)
        bool isRunning()
        string getStorageLog() const
        string getRoutingTablesLog(sa_family_t af) const
        string getSearchesLog(sa_family_t af) const
        void get(InfoHash key, GetCallback get_cb, DoneCallback done_cb)
        void put(InfoHash key, shared_ptr[Value] val, DoneCallback done_cb)
        ListenToken listen(InfoHash key, GetCallback get_cb)
        void cancelListen(InfoHash key, SharedListenToken token)
        vector[unsigned] getNodeMessageStats(bool i)

ctypedef DhtRunner.Config DhtRunnerConfig

cdef extern from "opendht/log.h" namespace "dht::log":
    void enableLogging(DhtRunner& dht)
    void disableLogging(DhtRunner& dht)
    void enableFileLogging(DhtRunner& dht, const string& path)

