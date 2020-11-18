/*
 *  Copyright (C) 2020 Savoir-faire Linux Inc.
 *  Author: Andreas Traczyk <andreas.traczyk@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "os_cert.h"

#include "log_enable.h"

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

#if EMBEDDED_ASN1_TIME_PARSE
#undef X509_NAME
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#define GENTIME_LENGTH 15
#define UTCTIME_LENGTH 13
#define ATOI2(ar)      ((ar) += 2, ((ar)[-2] - '0') * 10 + ((ar)[-1] - '0'))
extern "C" {
// Taken from libressl/src/crypto/asn1/a_time_tm.c
int
ASN1_time_parse(const char* bytes, size_t len, struct tm* tm, int mode)
{
    size_t i;
    int type = 0;
    struct tm ltm;
    struct tm* lt;
    const char* p;

    if (bytes == NULL)
        return (-1);

    /* Constrain to valid lengths. */
    if (len != UTCTIME_LENGTH && len != GENTIME_LENGTH)
        return (-1);

    lt = tm;
    if (lt == NULL) {
        memset(&ltm, 0, sizeof(ltm));
        lt = &ltm;
    }

    /* Timezone is required and must be GMT (Zulu). */
    if (bytes[len - 1] != 'Z')
        return (-1);

    /* Make sure everything else is digits. */
    for (i = 0; i < len - 1; i++) {
        if (isdigit((unsigned char) bytes[i]))
            continue;
        return (-1);
    }

    /*
     * Validate and convert the time
     */
    p = bytes;
    switch (len) {
    case GENTIME_LENGTH:
        if (mode == V_ASN1_UTCTIME)
            return (-1);
        lt->tm_year = (ATOI2(p) * 100) - 1900; /* cc */
        type = V_ASN1_GENERALIZEDTIME;
        /* FALLTHROUGH */
    case UTCTIME_LENGTH:
        if (type == 0) {
            if (mode == V_ASN1_GENERALIZEDTIME)
                return (-1);
            type = V_ASN1_UTCTIME;
        }
        lt->tm_year += ATOI2(p); /* yy */
        if (type == V_ASN1_UTCTIME) {
            if (lt->tm_year < 50)
                lt->tm_year += 100;
        }
        lt->tm_mon = ATOI2(p) - 1; /* mm */
        if (lt->tm_mon < 0 || lt->tm_mon > 11)
            return (-1);
        lt->tm_mday = ATOI2(p); /* dd */
        if (lt->tm_mday < 1 || lt->tm_mday > 31)
            return (-1);
        lt->tm_hour = ATOI2(p); /* HH */
        if (lt->tm_hour < 0 || lt->tm_hour > 23)
            return (-1);
        lt->tm_min = ATOI2(p); /* MM */
        if (lt->tm_min < 0 || lt->tm_min > 59)
            return (-1);
        lt->tm_sec = ATOI2(p); /* SS */
        /* Leap second 60 is not accepted. Reconsider later? */
        if (lt->tm_sec < 0 || lt->tm_sec > 59)
            return (-1);
        break;
    default:
        return (-1);
    }

    return type;
}
}
#endif /* EMBEDDED_ASN1_TIME_PARSE */

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
            logger->d("Error enumerating certificates: %s",
                    CFStringGetCStringPtr(statusString, kCFStringEncodingASCII));
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
        logger->w("adding %d decoded certs to X509 store", pems_.size());
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (store == nullptr) {
        if (logger)
            logger->e("couldn't get the context cert store");
        return;
    }
    for (const auto& pem : pems_) {
        if (X509_STORE_add_cert(store, pem.get()) == 1)
            continue;
        if (logger)
            logger->d("couldn't add local certificate");
    }
}

} /*namespace http*/
} /*namespace dht*/
