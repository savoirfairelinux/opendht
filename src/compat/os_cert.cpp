// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "os_cert.h"
#include "logger.h"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif
#include <openssl/ssl.h>

#ifdef TARGET_OS_OSX
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif /*TARGET_OS_OSX*/

namespace dht {
namespace http {

PEMCache::PEMCache(const std::shared_ptr<Logger>& l)
    : logger(l)
{
#ifdef _WIN32
    PCCERT_CONTEXT pContext = NULL;
    HCERTSTORE hSystemStore;
    hSystemStore = CertOpenSystemStore(NULL, "ROOT");
    if (!hSystemStore) {
        if (logger)
            logger->e("couldn't open the system cert store");
        return;
    }
    while (pContext = CertEnumCertificatesInStore(hSystemStore, pContext)) {
        const uint8_t* encoded_cert = pContext->pbCertEncoded;
        X509Ptr x509cert(d2i_X509(nullptr, &encoded_cert, pContext->cbCertEncoded), &X509_free);
        if (x509cert)
            pems_.emplace_back(std::move(x509cert));
    }
    CertCloseStore(hSystemStore, 0);
#elif TARGET_OS_OSX
    CFArrayRef result = NULL;
    OSStatus osStatus;

    if ((osStatus = SecTrustCopyAnchorCertificates(&result)) != 0) {
        if (logger) {
            CFStringRef statusString = SecCopyErrorMessageString(osStatus, NULL);
            logger->d("Error enumerating certificates: %s", CFStringGetCStringPtr(statusString, kCFStringEncodingASCII));
            CFRelease(statusString);
        }
        if (result != NULL) {
            CFRelease(result);
        }
        return;
    }
    CFDataRef rawData = NULL;
    for (CFIndex i = 0; i < CFArrayGetCount(result); i++) {
        SecCertificateRef cert = (SecCertificateRef) CFArrayGetValueAtIndex(result, i);
        rawData = SecCertificateCopyData(cert);
        if (!rawData) {
            if (logger)
                logger->e("couldn't copy raw certificate data");
            break;
        }
        const uint8_t* rawDataPtr = CFDataGetBytePtr(rawData);
        X509Ptr x509cert(d2i_X509(nullptr, &rawDataPtr, CFDataGetLength(rawData)), &X509_free);
        if (x509cert)
            pems_.emplace_back(std::move(x509cert));
        CFRelease(rawData);
        rawData = NULL;
    }
    if (result != NULL) {
        CFRelease(result);
    }
    if (rawData != NULL) {
        CFRelease(rawData);
    }
#endif /*TARGET_OS_OSX, _WIN32*/
}

void
PEMCache::fillX509Store(SSL_CTX* ctx)
{
    if (logger)
        logger->d("adding %d decoded certs to X509 store", pems_.size());
    if (X509_STORE* store = SSL_CTX_get_cert_store(ctx)) {
        for (const auto& pem : pems_) {
            if (X509_STORE_add_cert(store, pem.get()) != 1)
                if (logger)
                    logger->w("couldn't add local certificate");
        }
    } else if (logger)
        logger->e("couldn't get the context cert store");
}

} /*namespace http*/
} /*namespace dht*/
