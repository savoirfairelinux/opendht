#include "crypto.h"

#include <algorithm>
#include <cmath>
#include <variant>

namespace opendht_node {
namespace {

using PublicKey = std::shared_ptr<dht::crypto::PublicKey>;
using PrivateKey = std::shared_ptr<dht::crypto::PrivateKey>;
using Certificate = std::shared_ptr<dht::crypto::Certificate>;
using Identity = dht::crypto::Identity;
using Handle = std::variant<PublicKey, PrivateKey, Certificate, Identity>;

constexpr napi_type_tag cryptoTag {0x37cdf3e4648e4cb5ULL, 0x964fb031062c245aULL};

Handle&
handle(Napi::Value value)
{
    bool matches = false;
    if (!value.IsExternal() || napi_check_object_type_tag(value.Env(), value, &cryptoTag, &matches) != napi_ok
        || !matches)
        throw Napi::TypeError::New(value.Env(), "Invalid OpenDHT crypto handle");
    return *value.As<Napi::External<Handle>>().Data();
}

template<typename Type>
Type
read(Napi::Value value)
{
    if (auto result = std::get_if<Type>(&handle(value)))
        return *result;
    throw Napi::TypeError::New(value.Env(), "Wrong OpenDHT crypto handle type");
}

Napi::Value
wrap(Napi::Env env, Handle value)
{
    auto owner = std::make_unique<Handle>(std::move(value));
    auto result = Napi::External<Handle>::New(env, owner.get(), [](Napi::Env, Handle* data) { delete data; });
    owner.release();
    if (napi_type_tag_object(env, result, &cryptoTag) != napi_ok)
        throw Napi::Error::New(env, "Could not tag OpenDHT crypto handle");
    return result;
}

dht::Blob
bytes(Napi::Value value)
{
    if (!value.IsTypedArray() || value.As<Napi::TypedArray>().TypedArrayType() != napi_uint8_array)
        throw Napi::TypeError::New(value.Env(), "Expected a Uint8Array");
    auto array = value.As<Napi::Uint8Array>();
    dht::Blob result(array.ElementLength());
    if (!result.empty())
        std::copy_n(array.Data(), result.size(), result.data());
    return result;
}

std::string
string(Napi::Value value)
{
    if (!value.IsString())
        throw Napi::TypeError::New(value.Env(), "Expected a string");
    auto result = value.As<Napi::String>().Utf8Value();
    if (result.find('\0') != std::string::npos)
        throw Napi::TypeError::New(value.Env(), "Crypto strings must not contain NUL bytes");
    return result;
}

Napi::Buffer<uint8_t>
buffer(Napi::Env env, const dht::Blob& value)
{
    return Napi::Buffer<uint8_t>::Copy(env, value.data(), value.size());
}

PublicKey
publicKey(const Handle& value)
{
    if (auto key = std::get_if<PublicKey>(&value))
        return *key;
    if (auto key = std::get_if<PrivateKey>(&value))
        return (*key)->getSharedPublicKey();
    if (auto certificate = std::get_if<Certificate>(&value))
        return (*certificate)->getSharedPublicKey();
    return std::get<Identity>(value).second->getSharedPublicKey();
}

class GenerateWorker : public Napi::AsyncWorker
{
public:
    GenerateWorker(Napi::Env env, bool identity, std::string name, bool rsa, unsigned bits)
        : Napi::AsyncWorker(env, "OpenDHT crypto generation")
        , deferred_(Napi::Promise::Deferred::New(env))
        , identity_(identity)
        , name_(std::move(name))
        , rsa_(rsa)
        , bits_(bits)
    {}

    Napi::Promise promise() const { return deferred_.Promise(); }

    void Execute() override
    {
        try {
            if (identity_)
                result_ = rsa_ ? dht::crypto::generateIdentity(name_, {}, bits_)
                               : dht::crypto::generateEcIdentity(name_);
            else
                result_ = std::make_shared<dht::crypto::PrivateKey>(rsa_ ? dht::crypto::PrivateKey::generate(bits_)
                                                                         : dht::crypto::PrivateKey::generateEC());
        } catch (const std::exception& error) {
            SetError(error.what());
        }
    }

    void OnOK() override { deferred_.Resolve(wrap(Env(), std::move(result_))); }
    void OnError(const Napi::Error& error) override { deferred_.Reject(error.Value()); }

private:
    Napi::Promise::Deferred deferred_;
    bool identity_;
    std::string name_;
    bool rsa_;
    unsigned bits_;
    Handle result_;
};

Napi::Value
generate(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        const auto kind = string(info[0]);
        const auto name = string(info[1]);
        const auto algorithm = string(info[2]);
        if (algorithm != "rsa" && algorithm != "ec")
            throw Napi::TypeError::New(info.Env(), "algorithm must be rsa or ec");
        if (!info[3].IsNumber())
            throw Napi::TypeError::New(info.Env(), "bits must be a number");
        const auto bits = info[3].As<Napi::Number>().DoubleValue();
        if (!std::isfinite(bits) || std::floor(bits) != bits || bits < 2048 || bits > 8192)
            throw Napi::RangeError::New(info.Env(), "RSA bits must be an integer between 2048 and 8192");
        if (kind != "private" && kind != "identity")
            throw Napi::TypeError::New(info.Env(), "Invalid crypto generation type");
        auto worker = std::make_unique<GenerateWorker>(info.Env(), kind == "identity", name, algorithm == "rsa", bits);
        auto promise = worker->promise();
        worker->Queue();
        worker.release();
        return promise;
    });
}

Napi::Value
import(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        const auto kind = string(info[0]);
        auto data = bytes(info[1]);
        if (data.empty())
            throw Napi::TypeError::New(info.Env(), "Crypto imports must not be empty");
        if (kind == "private")
            return wrap(info.Env(), std::make_shared<dht::crypto::PrivateKey>(data, string(info[2])));
        if (kind == "public")
            return wrap(info.Env(), std::make_shared<dht::crypto::PublicKey>(data));
        if (kind == "certificate")
            return wrap(info.Env(), std::make_shared<dht::crypto::Certificate>(data));
        throw Napi::TypeError::New(info.Env(), "Invalid crypto import type");
    });
}

Napi::Value
serialize(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        auto& value = handle(info[0]);
        if (auto key = std::get_if<PrivateKey>(&value))
            return buffer(info.Env(), (*key)->serialize(string(info[1])));
        if (auto certificate = std::get_if<Certificate>(&value))
            return buffer(info.Env(), (*certificate)->getPacked());
        dht::Blob result;
        readPublicKey(info[0])->pack(result);
        return buffer(info.Env(), result);
    });
}

Napi::Value
getPublicKey(const Napi::CallbackInfo& info)
{
    return guarded(info, [&] { return wrap(info.Env(), publicKey(handle(info[0]))); });
}

Napi::Value
getId(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        const auto key = publicKey(handle(info[0]));
        if (!info[1].IsBoolean())
            throw Napi::TypeError::New(info.Env(), "Expected a boolean");
        return Napi::String::New(info.Env(),
                                 info[1].As<Napi::Boolean>().Value() ? key->getLongId().toString()
                                                                     : key->getId().toString());
    });
}

Napi::Value
sign(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        return buffer(info.Env(), read<PrivateKey>(info[0])->sign(bytes(info[1])));
    });
}

Napi::Value
verify(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        return Napi::Boolean::New(info.Env(), readPublicKey(info[0])->checkSignature(bytes(info[1]), bytes(info[2])));
    });
}

Napi::Value
encrypt(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        const auto key = readEncryptionKey(info[0]);
        return buffer(info.Env(), key->encrypt(bytes(info[1])));
    });
}

Napi::Value
decrypt(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        return buffer(info.Env(), read<PrivateKey>(info[0])->decrypt(bytes(info[1])));
    });
}

Napi::Value
identity(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        auto key = read<PrivateKey>(info[0]);
        auto certificate = read<Certificate>(info[1]);
        if (key->getPublicKey().getLongId() != certificate->getLongId())
            throw Napi::TypeError::New(info.Env(), "Identity key and certificate do not match");
        return wrap(info.Env(), Identity {std::move(key), std::move(certificate)});
    });
}

Napi::Value
identityPart(const Napi::CallbackInfo& info)
{
    return guarded(info, [&]() -> Napi::Value {
        const auto value = readIdentity(info[0]);
        if (!info[1].IsBoolean())
            throw Napi::TypeError::New(info.Env(), "Expected a boolean");
        return info[1].As<Napi::Boolean>().Value() ? wrap(info.Env(), value.first) : wrap(info.Env(), value.second);
    });
}

} // namespace

dht::crypto::Identity
readIdentity(Napi::Value value)
{
    return read<Identity>(value);
}
std::shared_ptr<dht::crypto::PublicKey>
readPublicKey(Napi::Value value)
{
    return read<PublicKey>(value);
}

std::shared_ptr<dht::crypto::PublicKey>
readEncryptionKey(Napi::Value value)
{
    const auto key = readPublicKey(value);
    const auto algorithm = gnutls_pubkey_get_pk_algorithm(key->pk, nullptr);
    if (algorithm != GNUTLS_PK_RSA
#if GNUTLS_VERSION_NUMBER >= 0x030804
        && algorithm != GNUTLS_PK_RSA_OAEP
#endif
    )
        throw Napi::TypeError::New(value.Env(), "Encryption requires an RSA public key");
    return key;
}

void
initializeCrypto(Napi::Env env, Napi::Object exports)
{
    exports.Set("cryptoGenerate", Napi::Function::New(env, generate));
    exports.Set("cryptoImport", Napi::Function::New(env, import));
    exports.Set("cryptoSerialize", Napi::Function::New(env, serialize));
    exports.Set("cryptoPublicKey", Napi::Function::New(env, getPublicKey));
    exports.Set("cryptoId", Napi::Function::New(env, getId));
    exports.Set("cryptoSign", Napi::Function::New(env, sign));
    exports.Set("cryptoVerify", Napi::Function::New(env, verify));
    exports.Set("cryptoEncrypt", Napi::Function::New(env, encrypt));
    exports.Set("cryptoDecrypt", Napi::Function::New(env, decrypt));
    exports.Set("cryptoIdentity", Napi::Function::New(env, identity));
    exports.Set("cryptoIdentityPart", Napi::Function::New(env, identityPart));
}

} // namespace opendht_node