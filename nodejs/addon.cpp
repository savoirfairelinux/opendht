#include <napi.h>
#include <opendht.h>
#include <gnutls/gnutls.h>
#include "crypto.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace {

constexpr size_t maxQueuedEvents = 1024;
constexpr size_t maxResultBytes = 16 * 1024 * 1024;

struct GnuTlsContext
{
    const int result = gnutls_global_init();

    ~GnuTlsContext()
    {
        if (result == GNUTLS_E_SUCCESS)
            gnutls_global_deinit();
    }
};

using opendht_node::guarded;

uint32_t
unsignedNumber(Napi::Value value, uint32_t maximum, const char* name)
{
    if (!value.IsNumber())
        throw Napi::TypeError::New(value.Env(), std::string(name) + " must be a number");
    const auto number = value.As<Napi::Number>().DoubleValue();
    if (!std::isfinite(number) || number < 0 || number > maximum || std::floor(number) != number)
        throw Napi::RangeError::New(value.Env(), std::string(name) + " is out of range");
    return static_cast<uint32_t>(number);
}

uint64_t
unsignedBigInt(Napi::Value value)
{
    if (!value.IsBigInt())
        throw Napi::TypeError::New(value.Env(), "id must be a bigint");
    int sign = 0;
    size_t count = 1;
    uint64_t word = 0;
    value.As<Napi::BigInt>().ToWords(&sign, &count, &word);
    if (sign || count > 1)
        throw Napi::RangeError::New(value.Env(), "id must fit in an unsigned 64-bit integer");
    return word;
}

std::string
text(Napi::Value value, const char* name)
{
    if (!value.IsString())
        throw Napi::TypeError::New(value.Env(), std::string(name) + " must be a string");
    auto result = value.As<Napi::String>().Utf8Value();
    if (result.find('\0') != std::string::npos)
        throw Napi::TypeError::New(value.Env(), std::string(name) + " must not contain NUL bytes");
    return result;
}

dht::InfoHash
infoHash(Napi::Value value)
{
    const auto result = text(value, "hash");
    if (result.size() != 40 || result.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        throw Napi::TypeError::New(value.Env(), "Expected a 40-character hexadecimal hash");
    return dht::InfoHash(result);
}

Napi::Object
optionsObject(Napi::Value value)
{
    if (!value.IsObject() || value.IsArray() || value.IsNull())
        throw Napi::TypeError::New(value.Env(), "options must be an object");
    return value.As<Napi::Object>();
}

struct ValueData
{
    explicit ValueData(const dht::Value& value)
        : id(value.id)
        , type(value.type)
        , seq(value.seq)
        , data(value.data)
        , userType(value.user_type)
        , owner(value.owner ? value.owner->getLongId().toString() : "")
        , isSigned(value.isSigned())
        , isEncrypted(value.isEncrypted())
    {}

    Napi::Object toJS(Napi::Env env) const
    {
        auto result = Napi::Object::New(env);
        result.Set("id", Napi::BigInt::New(env, id));
        result.Set("type", Napi::Number::New(env, type));
        result.Set("seq", Napi::Number::New(env, seq));
        result.Set("data", Napi::Buffer<uint8_t>::Copy(env, data.data(), data.size()));
        result.Set("userType", Napi::String::New(env, userType));
        result.Set("owner", owner.empty() ? Napi::Value(env.Null()) : Napi::Value(Napi::String::New(env, owner)));
        result.Set("isSigned", Napi::Boolean::New(env, isSigned));
        result.Set("isEncrypted", Napi::Boolean::New(env, isEncrypted));
        return result;
    }

    size_t size() const { return sizeof(ValueData) + data.size() + userType.size() + owner.size(); }

    uint64_t id;
    uint16_t type;
    uint16_t seq;
    dht::Blob data;
    std::string userType;
    std::string owner;
    bool isSigned;
    bool isEncrypted;
};

struct Event
{
    enum class Kind { Value, Done, Overflow, Status };
    Kind kind;
    uint64_t operation;
    bool flag;
    std::optional<ValueData> value;
    dht::NodeStatus ipv4 = dht::NodeStatus::Disconnected;
    dht::NodeStatus ipv6 = dht::NodeStatus::Disconnected;

    size_t size() const { return sizeof(Event) + (value ? value->size() : 0); }
};

struct PendingOperation
{
    Napi::Promise::Deferred deferred;
    bool get;
    std::vector<ValueData> values;
    size_t bytes = 0;
};

struct Subscription
{
    dht::InfoHash key;
    std::shared_future<size_t> token;
    Napi::FunctionReference callback;
};

struct RunnerState
{
    explicit RunnerState(Napi::Env environment)
        : env(environment)
    {}

    static std::shared_ptr<RunnerState> create(Napi::Env env)
    {
        auto state = std::make_shared<RunnerState>(env);
        auto dispatchOwner = std::make_unique<std::shared_ptr<RunnerState>>(state);
        napi_threadsafe_function function;
        if (napi_create_threadsafe_function(env,
                                            nullptr,
                                            nullptr,
                                            Napi::String::New(env, "OpenDHT callbacks"),
                                            0,
                                            1,
                                            dispatchOwner.get(),
                                            finalizeDispatcher,
                                            state.get(),
                                            dispatch,
                                            &function)
            != napi_ok)
            throw Napi::Error::New(env, "Could not create OpenDHT callback dispatcher");
        dispatchOwner.release();
        state->dispatcher = Napi::ThreadSafeFunction(function);
        state->dispatcher.Unref(env);
        auto closeOwner = std::make_unique<std::shared_ptr<RunnerState>>(state);
        if (napi_create_async_work(env,
                                   nullptr,
                                   Napi::String::New(env, "OpenDHT close"),
                                   executeClose,
                                   completeClose,
                                   closeOwner.get(),
                                   &state->closeWork)
            != napi_ok) {
            state->dispatcher.Release();
            throw Napi::Error::New(env, "Could not create OpenDHT cleanup work");
        }
        if (napi_add_async_cleanup_hook(env, cleanup, state.get(), &state->cleanupHook) != napi_ok) {
            napi_delete_async_work(env, state->closeWork);
            state->dispatcher.Release();
            throw Napi::Error::New(env, "Could not register OpenDHT cleanup hook");
        }
        state->closeOwner = closeOwner.release();
        return state;
    }

    void requireRunning() const
    {
        if (closing)
            throw Napi::Error::New(env, "DHT runner is closed");
        if (!started)
            throw Napi::Error::New(env, "DHT runner is not running");
    }

    void startClose()
    {
        if (closing.exchange(true))
            return;
        if (napi_queue_async_work(env, closeWork) != napi_ok) {
            executeClose(env, closeOwner);
            completeClose(env, napi_ok, closeOwner);
        }
    }

    void send(std::unique_ptr<Event> event)
    {
        if (closing || overflowed)
            return;
        const auto eventSize = event->size();
        const auto previousCount = queuedEvents.fetch_add(1);
        const auto previousBytes = queuedBytes.fetch_add(eventSize);
        if (previousCount >= maxQueuedEvents || eventSize > maxResultBytes
            || previousBytes > maxResultBytes - eventSize) {
            queuedEvents--;
            queuedBytes -= eventSize;
            signalOverflow();
            return;
        }
        if (dispatcher.NonBlockingCall(static_cast<void*>(event.get())) == napi_ok) {
            event.release();
        } else {
            queuedEvents--;
            queuedBytes -= eventSize;
        }
    }

    void sendValue(uint64_t operation, const dht::Value& value, bool expired = false)
    {
        if (closing || overflowed)
            return;
        if (value.data.size() > maxResultBytes || value.user_type.size() > maxResultBytes) {
            signalOverflow();
            return;
        }
        send(std::make_unique<Event>(Event {Event::Kind::Value, operation, expired, ValueData(value)}));
    }

    void signalOverflow()
    {
        if (overflowed.exchange(true))
            return;
        auto event = std::make_unique<Event>(Event {Event::Kind::Overflow, 0, false, {}});
        if (dispatcher.NonBlockingCall(static_cast<void*>(event.get())) == napi_ok)
            event.release();
    }

    void handle(Event& event)
    {
        if (closing)
            return;
        if (event.kind == Event::Kind::Status) {
            status4 = event.ipv4;
            status6 = event.ipv6;
            if (!onStatus.IsEmpty())
                onStatus.Call({status()});
            return;
        }
        if (event.kind == Event::Kind::Overflow) {
            overflowed = true;
            startClose();
            if (!onError.IsEmpty())
                onError.Call({makeCloseError().Value()});
            return;
        }
        if (event.kind == Event::Kind::Value) {
            const auto listener = listeners.find(event.operation);
            if (listener != listeners.end()) {
                listener->second.callback.Call({event.value->toJS(env), Napi::Boolean::New(env, event.flag)});
            } else if (const auto pending = operations.find(event.operation); pending != operations.end()) {
                auto& operation = pending->second;
                operation.bytes += event.value->size();
                if (operation.bytes > maxResultBytes || operation.values.size() >= 65536) {
                    overflowed = true;
                    startClose();
                    if (!onError.IsEmpty())
                        onError.Call({makeCloseError().Value()});
                    return;
                }
                operation.values.emplace_back(std::move(*event.value));
            }
            return;
        }
        const auto pending = operations.find(event.operation);
        if (pending == operations.end())
            return;
        auto operation = std::move(pending->second);
        operations.erase(pending);
        if (!operation.get) {
            operation.deferred.Resolve(Napi::Boolean::New(env, event.flag));
        } else if (!event.flag) {
            auto error = Napi::Error::New(env, "DHT get failed");
            error.Set("code", "ERR_DHT_GET_FAILED");
            operation.deferred.Reject(error.Value());
        } else {
            auto values = Napi::Array::New(env, operation.values.size());
            for (size_t index = 0; index < operation.values.size(); ++index)
                values.Set(static_cast<uint32_t>(index), operation.values[index].toJS(env));
            operation.deferred.Resolve(values);
        }
    }

    Napi::Object status() const
    {
        auto result = Napi::Object::New(env);
        result.Set("ipv4",
                   Napi::String::New(env,
                                     std::string(dht::statusToStr(closing ? dht::NodeStatus::Disconnected : status4))));
        result.Set("ipv6",
                   Napi::String::New(env,
                                     std::string(dht::statusToStr(closing ? dht::NodeStatus::Disconnected : status6))));
        return result;
    }

    static void dispatch(napi_env environment, napi_value, void* context, void* data)
    {
        auto state = static_cast<RunnerState*>(context);
        std::unique_ptr<Event> event(static_cast<Event*>(data));
        if (event->kind != Event::Kind::Overflow) {
            state->queuedEvents--;
            state->queuedBytes -= event->size();
        }
        if (!environment || state->envClosing)
            return;
        try {
            state->handle(*event);
        } catch (const Napi::Error& error) {
            napi_fatal_exception(environment, error.Value());
        } catch (const std::exception& error) {
            napi_fatal_exception(environment, Napi::Error::New(environment, error.what()).Value());
        }
    }

    static void finalizeDispatcher(napi_env, void* data, void*)
    {
        delete static_cast<std::shared_ptr<RunnerState>*>(data);
    }

    static void cleanup(napi_async_cleanup_hook_handle, void* data)
    {
        auto state = static_cast<RunnerState*>(data);
        state->envClosing = true;
        state->startClose();
    }

    static void executeClose(napi_env, void* data)
    {
        auto state = *static_cast<std::shared_ptr<RunnerState>*>(data);
        struct ShutdownSignal
        {
            std::mutex mutex;
            std::condition_variable condition;
            bool done = false;
        };
        try {
            auto signal = std::make_shared<ShutdownSignal>();
            state->runner.shutdown(
                [signal] {
                    std::lock_guard lock(signal->mutex);
                    signal->done = true;
                    signal->condition.notify_one();
                },
                true);
            std::unique_lock lock(signal->mutex);
            signal->condition.wait_for(lock, std::chrono::seconds(2), [&] { return signal->done; });
        } catch (const std::exception& error) {
            state->closeError = error.what();
        }
        state->runner.join();
    }

    Napi::Error makeCloseError() const
    {
        auto error = Napi::Error::New(env,
                                      overflowed           ? "OpenDHT result queue exceeded its limit"
                                      : closeError.empty() ? "DHT runner is closed"
                                                           : closeError);
        error.Set("code", overflowed ? "ERR_DHT_OVERFLOW" : "ERR_DHT_CLOSED");
        return error;
    }

    static void completeClose(napi_env environment, napi_status, void* data)
    {
        std::unique_ptr<std::shared_ptr<RunnerState>> owner(static_cast<std::shared_ptr<RunnerState>*>(data));
        auto state = *owner;
        state->finished = true;
        if (!state->envClosing) {
            state->dispatcher.Release();
            auto error = state->makeCloseError();
            for (auto& pending : state->operations)
                pending.second.deferred.Reject(error.Value());
            if (state->closeDeferred) {
                if (!state->overflowed && state->closeError.empty())
                    state->closeDeferred->Resolve(Napi::Env(environment).Undefined());
                else
                    state->closeDeferred->Reject(error.Value());
            }
        }
        state->operations.clear();
        state->listeners.clear();
        state->closeDeferred.reset();
        state->closePromise.Reset();
        state->onError.Reset();
        state->onStatus.Reset();
        state->owner.Reset();
        napi_delete_async_work(environment, state->closeWork);
        napi_remove_async_cleanup_hook(state->cleanupHook);
        state->closeOwner = nullptr;
    }

    Napi::Env env;
    dht::DhtRunner runner;
    Napi::ThreadSafeFunction dispatcher;
    napi_async_work closeWork {};
    napi_async_cleanup_hook_handle cleanupHook {};
    std::shared_ptr<RunnerState>* closeOwner {};
    std::atomic_bool closing {false};
    std::atomic_bool overflowed {false};
    std::atomic_size_t queuedEvents {0};
    std::atomic_size_t queuedBytes {0};
    bool envClosing = false;
    bool started = false;
    bool hasIdentity = false;
    bool finished = false;
    uint64_t nextOperation = 1;
    std::string closeError;
    std::unordered_map<uint64_t, PendingOperation> operations;
    std::unordered_map<uint64_t, Subscription> listeners;
    std::optional<Napi::Promise::Deferred> closeDeferred;
    Napi::Reference<Napi::Promise> closePromise;
    Napi::FunctionReference onError;
    Napi::FunctionReference onStatus;
    Napi::ObjectReference owner;
    dht::NodeStatus status4 = dht::NodeStatus::Disconnected;
    dht::NodeStatus status6 = dht::NodeStatus::Disconnected;
};

class Runner : public Napi::ObjectWrap<Runner>
{
public:
    explicit Runner(const Napi::CallbackInfo& info)
        : Napi::ObjectWrap<Runner>(info)
        , state_(RunnerState::create(info.Env()))
    {
        if (info.Length() && info[0].IsFunction())
            state_->onError = Napi::Persistent(info[0].As<Napi::Function>());
        if (info.Length() > 1 && info[1].IsFunction())
            state_->onStatus = Napi::Persistent(info[1].As<Napi::Function>());
    }

    ~Runner() override { state_->startClose(); }

    static Napi::Function define(Napi::Env env)
    {
        return DefineClass(env,
                           "NativeRunner",
                           {
                               InstanceMethod("run", &Runner::run),
                               InstanceMethod("close", &Runner::close),
                               InstanceMethod("isRunning", &Runner::isRunning),
                               InstanceMethod("getBoundPort", &Runner::getBoundPort),
                               InstanceMethod("getNodeId", &Runner::getNodeId),
                               InstanceMethod("getStatus", &Runner::getStatus),
                               InstanceMethod("bootstrap", &Runner::bootstrap),
                               InstanceMethod("get", &Runner::get),
                               InstanceMethod("put", &Runner::put),
                               InstanceMethod("putSigned", &Runner::putSigned),
                               InstanceMethod("putEncrypted", &Runner::putEncrypted),
                               InstanceMethod("listen", &Runner::listen),
                               InstanceMethod("cancelListen", &Runner::cancelListen),
                               InstanceMethod("ref", &Runner::ref),
                               InstanceMethod("unref", &Runner::unref),
                               InstanceMethod("setOwner", &Runner::setOwner),
                           });
    }

private:
    Napi::Value run(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            if (state_->closing)
                throw Napi::Error::New(info.Env(), "DHT runner is closed");
            if (state_->started)
                throw Napi::Error::New(info.Env(), "DHT runner is already running");
            auto options = info.Length() && !info[0].IsUndefined() ? optionsObject(info[0])
                                                                   : Napi::Object::New(info.Env());
            const auto port = options.Has("port") ? unsignedNumber(options.Get("port"), 65535, "port") : 0;
            const auto ipv4 = options.Has("ipv4") ? text(options.Get("ipv4"), "ipv4") : "0.0.0.0";
            const auto ipv6 = options.Has("ipv6") ? text(options.Get("ipv6"), "ipv6") : "::";
            dht::DhtRunner::Config config;
            if (options.Has("network"))
                config.dht_config.node_config.network = unsignedNumber(options.Get("network"), UINT32_MAX, "network");
            if (options.Has("persistPath"))
                config.dht_config.node_config.persist_path = text(options.Get("persistPath"), "persistPath");
            if (options.Has("identity"))
                config.dht_config.id = opendht_node::readIdentity(options.Get("identity"));
            dht::DhtRunner::Context context;
            const std::weak_ptr<RunnerState> state = state_;
            context.statusChangedCallback = [state](dht::NodeStatus ipv4, dht::NodeStatus ipv6) {
                if (auto owner = state.lock())
                    owner->send(std::make_unique<Event>(Event {Event::Kind::Status, 0, false, {}, ipv4, ipv6}));
            };
            const auto service = std::to_string(port);
            state_->runner.run(ipv4.c_str(), ipv6.c_str(), service.c_str(), config, std::move(context));
            state_->started = true;
            state_->hasIdentity = bool(config.dht_config.id.first);
            state_->dispatcher.Ref(info.Env());
            return info.Env().Undefined();
        });
    }

    Napi::Value close(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            if (!state_->closePromise.IsEmpty())
                return state_->closePromise.Value();
            auto deferred = Napi::Promise::Deferred::New(info.Env());
            if (state_->finished) {
                if (state_->overflowed || !state_->closeError.empty())
                    deferred.Reject(state_->makeCloseError().Value());
                else
                    deferred.Resolve(info.Env().Undefined());
            } else {
                state_->closeDeferred = deferred;
                state_->closePromise = Napi::Persistent(deferred.Promise());
                state_->startClose();
            }
            return deferred.Promise();
        });
    }

    Napi::Value isRunning(const Napi::CallbackInfo& info)
    {
        return Napi::Boolean::New(info.Env(), !state_->closing && !state_->overflowed && state_->runner.isRunning());
    }

    Napi::Value getStatus(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value { return state_->status(); });
    }

    Napi::Value getBoundPort(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            const auto family = info.Length() ? unsignedNumber(info[0], 6, "family") : 4;
            if (family != 4 && family != 6)
                throw Napi::RangeError::New(info.Env(), "family must be 4 or 6");
            return Napi::Number::New(info.Env(), state_->runner.getBoundPort(family == 4 ? AF_INET : AF_INET6));
        });
    }

    Napi::Value getNodeId(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            return Napi::String::New(info.Env(), state_->runner.getNodeId().toString());
        });
    }

    Napi::Value bootstrap(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            const auto host = text(info[0], "host");
            const auto port = unsignedNumber(info[1], 65535, "port");
            if (host.empty() || !port)
                throw Napi::RangeError::New(info.Env(), "bootstrap requires a host and nonzero port");
            state_->runner.bootstrap(host, std::to_string(port));
            return info.Env().Undefined();
        });
    }

    Napi::Value get(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            const auto key = infoHash(info[0]);
            const auto operation = state_->nextOperation++;
            auto deferred = Napi::Promise::Deferred::New(info.Env());
            state_->operations.emplace(operation, PendingOperation {deferred, true, {}});
            const std::weak_ptr<RunnerState> state = state_;
            try {
                state_->runner.get(key,
                                   dht::GetCallback(
                                       [state, operation](const std::vector<std::shared_ptr<dht::Value>>& values) {
                                           const auto owner = state.lock();
                                           if (!owner || owner->closing || owner->overflowed)
                                               return false;
                                           for (const auto& value : values)
                                               owner->sendValue(operation, *value);
                                           return !owner->closing && !owner->overflowed;
                                       }),
                                   dht::DoneCallbackSimple([state, operation](bool ok) {
                                       if (const auto owner = state.lock())
                                           owner->send(
                                               std::make_unique<Event>(Event {Event::Kind::Done, operation, ok, {}}));
                                   }));
            } catch (...) {
                state_->operations.erase(operation);
                throw;
            }
            return deferred.Promise();
        });
    }

    Napi::Value put(const Napi::CallbackInfo& info) { return putValue(info, PutMode::Plain); }

    Napi::Value putSigned(const Napi::CallbackInfo& info) { return putValue(info, PutMode::Signed); }

    Napi::Value putEncrypted(const Napi::CallbackInfo& info) { return putValue(info, PutMode::Encrypted); }

    enum class PutMode { Plain, Signed, Encrypted };

    Napi::Value putValue(const Napi::CallbackInfo& info, PutMode mode)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            if (mode != PutMode::Plain && !state_->hasIdentity)
                throw Napi::Error::New(info.Env(), "Signed and encrypted puts require an identity");
            std::shared_ptr<dht::crypto::PublicKey> recipient;
            if (mode == PutMode::Encrypted) {
                recipient = opendht_node::readEncryptionKey(info[3]);
            }
            const auto key = infoHash(info[0]);
            if (!info[1].IsTypedArray() || info[1].As<Napi::TypedArray>().TypedArrayType() != napi_uint8_array)
                throw Napi::TypeError::New(info.Env(), "data must be a Uint8Array");
            const auto data = info[1].As<Napi::Uint8Array>();
            dht::Blob bytes(data.ElementLength());
            if (!bytes.empty())
                std::copy_n(data.Data(), bytes.size(), bytes.data());
            auto value = std::make_shared<dht::Value>(std::move(bytes));
            auto options = info.Length() > 2 && !info[2].IsUndefined() ? optionsObject(info[2])
                                                                       : Napi::Object::New(info.Env());
            if (options.Has("id"))
                value->id = unsignedBigInt(options.Get("id"));
            if (options.Has("type"))
                value->type = unsignedNumber(options.Get("type"), 65535, "type");
            if (options.Has("userType")) {
                if (!options.Get("userType").IsString())
                    throw Napi::TypeError::New(info.Env(), "userType must be a string");
                value->user_type = options.Get("userType").As<Napi::String>().Utf8Value();
            }
            bool permanent = false;
            if (options.Has("permanent")) {
                if (!options.Get("permanent").IsBoolean())
                    throw Napi::TypeError::New(info.Env(), "permanent must be a boolean");
                permanent = options.Get("permanent").As<Napi::Boolean>().Value();
            }
            const auto operation = state_->nextOperation++;
            auto deferred = Napi::Promise::Deferred::New(info.Env());
            state_->operations.emplace(operation, PendingOperation {deferred, false, {}});
            const std::weak_ptr<RunnerState> state = state_;
            try {
                dht::DoneCallbackSimple done = [state, operation](bool ok) {
                    if (const auto owner = state.lock())
                        owner->send(std::make_unique<Event>(Event {Event::Kind::Done, operation, ok, {}}));
                };
                if (mode == PutMode::Signed)
                    state_->runner.putSigned(key, value, std::move(done), permanent);
                else if (mode == PutMode::Encrypted)
                    state_->runner.putEncrypted(key, recipient, value, std::move(done), permanent);
                else
                    state_->runner.put(key, value, std::move(done), dht::time_point::max(), permanent);
            } catch (...) {
                state_->operations.erase(operation);
                throw;
            }
            return deferred.Promise();
        });
    }

    Napi::Value listen(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            const auto key = infoHash(info[0]);
            if (!info[1].IsFunction())
                throw Napi::TypeError::New(info.Env(), "callback must be a function");
            const auto operation = state_->nextOperation++;
            const std::weak_ptr<RunnerState> state = state_;
            auto token = state_->runner
                             .listen(key,
                                     dht::ValueCallback(
                                         [state, operation](const std::vector<std::shared_ptr<dht::Value>>& values,
                                                            bool expired) {
                                             const auto owner = state.lock();
                                             if (!owner || owner->closing || owner->overflowed)
                                                 return false;
                                             for (const auto& value : values)
                                                 owner->sendValue(operation, *value, expired);
                                             return !owner->closing && !owner->overflowed;
                                         }))
                             .share();
            state_->listeners.emplace(operation,
                                      Subscription {key,
                                                    std::move(token),
                                                    Napi::Persistent(info[1].As<Napi::Function>())});
            return Napi::BigInt::New(info.Env(), operation);
        });
    }

    Napi::Value cancelListen(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            if (state_->closing)
                return info.Env().Undefined();
            const auto listener = state_->listeners.find(unsignedBigInt(info[0]));
            if (listener != state_->listeners.end()) {
                state_->runner.cancelListen(listener->second.key, listener->second.token);
                state_->listeners.erase(listener);
            }
            return info.Env().Undefined();
        });
    }

    Napi::Value ref(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            state_->dispatcher.Ref(info.Env());
            return info.This();
        });
    }

    Napi::Value unref(const Napi::CallbackInfo& info)
    {
        return guarded(info, [&]() -> Napi::Value {
            state_->requireRunning();
            state_->dispatcher.Unref(info.Env());
            return info.This();
        });
    }

    Napi::Value setOwner(const Napi::CallbackInfo& info)
    {
        if (!state_->closing) {
            state_->owner.Reset();
            if (info[0].IsObject())
                state_->owner = Napi::Persistent(info[0].As<Napi::Object>());
        }
        return info.Env().Undefined();
    }

    std::shared_ptr<RunnerState> state_;
};

Napi::Value
hash(const Napi::CallbackInfo& info)
{
    const auto env = info.Env();
    dht::InfoHash result;
    if (info.Length() == 1 && info[0].IsString()) {
        result = dht::InfoHash::get(info[0].As<Napi::String>().Utf8Value());
    } else if (info.Length() == 1 && info[0].IsTypedArray()
               && info[0].As<Napi::TypedArray>().TypedArrayType() == napi_uint8_array) {
        const auto data = info[0].As<Napi::Uint8Array>();
        result = dht::InfoHash::get(data.Data(), data.ElementLength());
    } else {
        throw Napi::TypeError::New(env, "Expected a string or Uint8Array");
    }
    return Napi::String::New(env, result.toString());
}

Napi::Object
initialize(Napi::Env env, Napi::Object exports)
{
    static const GnuTlsContext crypto;
    if (crypto.result != GNUTLS_E_SUCCESS)
        throw Napi::Error::New(env, std::string("Unable to initialize GnuTLS: ") + gnutls_strerror(crypto.result));
    opendht_node::initializeCrypto(env, exports);
    exports.Set("NativeRunner", Runner::define(env));
    exports.Set("hash", Napi::Function::New(env, hash));
    exports.Set("version", Napi::String::New(env, dht::version()));
    return exports;
}

} // namespace

NODE_API_MODULE(opendht, initialize)