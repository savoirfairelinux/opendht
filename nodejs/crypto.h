#pragma once

#include <napi.h>
#include <opendht/crypto.h>

namespace opendht_node {

template<typename Callback>
Napi::Value
guarded(const Napi::CallbackInfo& info, Callback&& callback)
{
    try {
        return callback();
    } catch (const Napi::Error&) {
        throw;
    } catch (const std::exception& error) {
        throw Napi::Error::New(info.Env(), error.what());
    }
}

dht::crypto::Identity readIdentity(Napi::Value value);
std::shared_ptr<dht::crypto::PublicKey> readPublicKey(Napi::Value value);
std::shared_ptr<dht::crypto::PublicKey> readEncryptionKey(Napi::Value value);
void initializeCrypto(Napi::Env env, Napi::Object exports);

} // namespace opendht_node