/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author: Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#include "http.h"
#include "log_enable.h"
#include "crypto.h"
#include "base64.h"
#include "compat/os_cert.h"

#include <asio.hpp>
#include <restinio/impl/tls_socket.hpp>
#include <http_parser.h>
#include <json/json.h>

#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define MAXAGE_SEC (14*24*60*60)
#define JITTER_SEC (60)
#define OCSP_MAX_RESPONSE_SIZE (20480)
#ifdef _WIN32
#define timegm                 _mkgmtime
#endif

namespace dht {
namespace http {

constexpr const char HTTP_HEADER_CONTENT_TYPE_JSON[] = "application/json";
constexpr const char HTTP_HEADER_DELIM[] = "\r\n\r\n";
constexpr const char HTTP_PROTOCOL[] = "http://";
constexpr const char HTTPS_PROTOCOL[] = "https://";
constexpr const char ORIGIN_PROTOCOL[] = "//";
constexpr unsigned MAX_REDIRECTS {5};

Url::Url(const std::string& url): url(url)
{
    size_t addr_begin = 0;
    // protocol
    const size_t proto_end = url.find("://");
    if (proto_end != std::string::npos){
        addr_begin = proto_end + 3;
        if (url.substr(0, proto_end) == "https"){
            protocol = "https";
        }
    }
    // host and service
    size_t addr_size = url.substr(addr_begin).find("/");
    if (addr_size == std::string::npos)
        addr_size = url.size() - addr_begin;
    auto host_service = splitPort(url.substr(addr_begin, addr_size));
    host = host_service.first;
    if (!host_service.second.empty())
        service = host_service.second;
    // target, query and fragment
    size_t query_begin = url.find("?");
    auto addr_end = addr_begin + addr_size;
    if (addr_end < url.size())
        target = url.substr(addr_end);
    size_t fragment_begin = url.find("#");
    if (fragment_begin == std::string::npos){
        query = url.substr(query_begin + 1);
    } else {
        target = url.substr(addr_end, fragment_begin - addr_end);
        query = url.substr(query_begin + 1, fragment_begin - query_begin - 1);
        fragment = url.substr(fragment_begin);
    }
}

std::string
Url::toString() const
{
    std::stringstream ss;
    if (not protocol.empty()) {
        ss << protocol << "://";
    }
    ss << host;
    if (not service.empty()) {
        ss << ':' << service;
    }
    ss << target;
    return ss.str();
}

// connection

std::atomic_uint Connection::ids_ {1};

std::shared_ptr<asio::ssl::context>
newTlsClientContext(const std::shared_ptr<dht::Logger>& logger)
{
    auto ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_client);
    ctx->set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);

    if (char* path = getenv("CA_ROOT_FILE")) {
        if (logger)
            logger->d("Using CA file: %s", path);
        ctx->load_verify_file(path);
    } else if (char* path = getenv("CA_ROOT_PATH")) {
        if (logger)
            logger->d("Using CA path: %s", path);
        ctx->add_verify_path(path);
    } else {
#ifdef __ANDROID__
        if (logger)
            logger->d("Using CA path: /system/etc/security/cacerts");
        ctx->add_verify_path("/system/etc/security/cacerts");
#elif defined(WIN32) || defined(TARGET_OS_OSX)
        PEMCache::instance(logger).fillX509Store(ctx->native_handle());
#else
        if (logger)
            logger->d("Using default CA path");
        ctx->set_default_verify_paths();
#endif
    }
    return ctx;
}

Connection::Connection(asio::io_context& ctx, const bool ssl, std::shared_ptr<dht::Logger> l)
    : id_(Connection::ids_++), ctx_(ctx), istream_(&read_buf_), logger_(l)
{
    if (ssl) {
        ssl_ctx_ = newTlsClientContext(l);
        ssl_socket_ = std::make_unique<ssl_socket_t>(ctx_, ssl_ctx_);
        if (logger_)
            logger_->d("[connection:%i] start https session", id_);
    }
    else {
        socket_ = std::make_unique<socket_t>(ctx);
        if (logger_)
            logger_->d("[connection:%i] start http session", id_);
    }
}

Connection::Connection(asio::io_context& ctx, std::shared_ptr<dht::crypto::Certificate> server_ca,
                       const dht::crypto::Identity& identity, std::shared_ptr<dht::Logger> l)
    : id_(Connection::ids_++), ctx_(ctx), istream_(&read_buf_), logger_(l)
{
    asio::error_code ec;
    if (server_ca) {
        ssl_ctx_ = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_client);
        ssl_ctx_->set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
        auto ca = server_ca->toString(false/*chain*/);
        ssl_ctx_->add_certificate_authority(asio::const_buffer{ca.data(), ca.size()}, ec);
        if (ec)
            throw std::runtime_error("Error adding certificate authority: " + ec.message());
        else if (logger_)
            logger_->d("[connection:%i] certficate authority %s", id_, server_ca->getUID().c_str());
    } else {
        ssl_ctx_ = newTlsClientContext(l);
    }
    if (identity.first){
        auto key = identity.first->serialize();
        ssl_ctx_->use_private_key(asio::const_buffer{key.data(), key.size()},
                                  asio::ssl::context::file_format::pem, ec);
        if (ec)
            throw std::runtime_error("Error setting client private key: " + ec.message());
    }
    if (identity.second){
        auto cert = identity.second->toString(true/*chain*/);
        ssl_ctx_->use_certificate_chain(asio::const_buffer{cert.data(), cert.size()}, ec);
        if (ec)
            throw std::runtime_error("Error adding client certificate: " + ec.message());
        else if (logger_)
            logger_->d("[connection:%i] client certificate %s", id_, identity.second->getUID().c_str());
    }
    ssl_socket_ = std::make_unique<ssl_socket_t>(ctx_, ssl_ctx_);
}

Connection::~Connection() {
    close();
}

void
Connection::close()
{
    std::lock_guard<std::mutex> lock(mutex_);
    asio::error_code ec;
    if (ssl_socket_) {
        if (ssl_socket_->is_open())
            ssl_socket_->close(ec);
    }
    else if (socket_) {
        if (socket_->is_open())
            socket_->close(ec);
    }
    if (ec and logger_)
        logger_->e("[connection:%i] error closing: %s", id_, ec.message().c_str());
}

bool
Connection::is_open() const
{
    if  (ssl_socket_) return ssl_socket_->is_open();
    else if (socket_) return socket_->is_open();
    else              return false;
}

bool
Connection::is_ssl() const
{
    return ssl_ctx_ ? true : false;
}

static time_t
parse_ocsp_time(ASN1_GENERALIZEDTIME* gt)
{
    struct tm tm;
    time_t rv = -1;

    if (gt == nullptr)
        return -1;
    // RFC 6960 specifies that all times in OCSP must be GENERALIZEDTIME
    if (ASN1_time_parse((const char*)gt->data, gt->length, &tm, V_ASN1_GENERALIZEDTIME) == -1)
        return -1;
    if ((rv = timegm(&tm)) == -1)
        return -1;
    return rv;
}

static inline X509*
cert_from_chain(STACK_OF(X509)* fullchain)
{
    return sk_X509_value(fullchain, 0);
}

static X509*
issuer_from_chain(STACK_OF(X509)* fullchain)
{
    X509 *cert, *issuer;
    X509_NAME *issuer_name;

    cert = cert_from_chain(fullchain);
    if ((issuer_name = X509_get_issuer_name(cert)) == nullptr)
        return nullptr;

    issuer = X509_find_by_subject(fullchain, issuer_name);
    return issuer;
}

using OscpRequestPtr = std::unique_ptr<OCSP_REQUEST, decltype(&OCSP_REQUEST_free)>;
struct OscpRequestInfo {
    OscpRequestPtr req {nullptr, &OCSP_REQUEST_free};
    std::string data;
    std::string url;
};

static std::unique_ptr<OscpRequestInfo>
ocspRequestFromCert(STACK_OF(X509)* fullchain, const std::shared_ptr<Logger>& logger, bool nonce = false)
{
    if (fullchain == nullptr)
        return {};

    if (sk_X509_num(fullchain) <= 1) {
        if (logger)
            logger->e("Cert does not contain a cert chain");
        return {};
    }
    X509* cert = cert_from_chain(fullchain);
    if (cert == nullptr) {
        if (logger)
            logger->e("No certificate found");
        return {};
    }
    X509* issuer = issuer_from_chain(fullchain);
    if (issuer == nullptr) {
        if (logger)
            logger->e("Unable to find issuer for cert");
        return {};
    }

    auto urls = X509_get1_ocsp(cert);
    if (urls == nullptr || sk_OPENSSL_STRING_num(urls) <= 0) {
        if (logger)
            logger->e("Certificate contains no OCSP url");
        return {};
    }
    auto url = sk_OPENSSL_STRING_value(urls, 0);
    if (url == nullptr)
        return {};

    auto request = std::make_unique<OscpRequestInfo>();
    request->req = OscpRequestPtr(OCSP_REQUEST_new(), &OCSP_REQUEST_free);
    request->url = strdup(url);
    X509_email_free(urls);

    OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if (id == nullptr) {
        if (logger)
            logger->e("Unable to get certificate id from cert");
        return {};
    }
    if (OCSP_request_add0_id(request->req.get(), id) == nullptr) {
        if (logger)
            logger->e("Unable to add certificate id to request");
        return {};
    }

    if (nonce)
        OCSP_request_add1_nonce(request->req.get(), nullptr, -1);

    int size;
    uint8_t* data {nullptr};
    if ((size = i2d_OCSP_REQUEST(request->req.get(), &data)) <= 0) {
        if (logger)
            logger->e("Unable to encode ocsp request");
        return {};
    }
    if (data == nullptr) {
        if (logger)
            logger->e("Unable to allocte memory");
        return {};
    }
    request->data = std::string((char*)data, (char*)data+size);
    free(data);
    return request;
}

bool
ocspValidateResponse(const OscpRequestInfo& info, STACK_OF(X509)* fullchain, const std::string& response, X509_STORE *store, const std::shared_ptr<Logger>& logger)
{
    ASN1_GENERALIZEDTIME *revtime = nullptr, *thisupd = nullptr, *nextupd = nullptr;
    const uint8_t* p = (const uint8_t*)response.data();
    int status, cert_status=0, crl_reason=0;
    time_t now, rev_t = -1, this_t, next_t;
    OCSP_RESPONSE *resp;
    OCSP_BASICRESP *bresp;
    OCSP_CERTID *cid;

    X509* cert = cert_from_chain(fullchain);
    if (cert == nullptr) {
        if (logger)
            logger->e("No certificate found");
        return false;
    }
    X509* issuer = issuer_from_chain(fullchain);
    if (issuer == nullptr) {
        if (logger)
            logger->e("Unable to find issuer for cert");
        return false;
    }
    if ((cid = OCSP_cert_to_id(nullptr, cert, issuer)) == nullptr) {
        if (logger)
            logger->e("Unable to get issuer cert/CID");
        return false;
    }

    if ((resp = d2i_OCSP_RESPONSE(nullptr, &p, response.size())) == nullptr) {
        if (logger)
            logger->e("OCSP response unserializable");
        return false;
    }

    if ((bresp = OCSP_response_get1_basic(resp)) == nullptr) {
        if (logger)
            logger->e("Failed to load OCSP response");
        return false;
    }

    if (OCSP_basic_verify(bresp, fullchain, store, OCSP_TRUSTOTHER) != 1) {
        if (logger)
            logger->w("OCSP verify failed");
        return false;
    }
    printf("OCSP response signature validated\n");

    status = OCSP_response_status(resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        if (logger)
            logger->w("OCSP Failure: code %d (%s)", status, OCSP_response_status_str(status));
        return false;
    }

    // Check the nonce if we sent one
    if (OCSP_check_nonce(info.req.get(), bresp) <= 0) {
        if (logger)
            logger->w("No OCSP nonce, or mismatch");
        return false;
    }

    if (OCSP_resp_find_status(bresp, cid, &cert_status, &crl_reason,
        &revtime, &thisupd, &nextupd) != 1) {
        if (logger)
            logger->w("OCSP verify failed: no result for cert");
        return false;
    }

    if (revtime && (rev_t = parse_ocsp_time(revtime)) == -1) {
        if (logger)
            logger->w("Unable to parse revocation time in OCSP reply");
        return false;
    }
    // Belt and suspenders, Treat it as revoked if there is either
    // a revocation time, or status revoked.
    if (rev_t != -1 || cert_status == V_OCSP_CERTSTATUS_REVOKED) {
        if (logger)
            logger->w("Invalid OCSP reply: certificate is revoked");
        if (rev_t != -1) {
            if (logger)
                logger->w("Certificate revoked at: %s", ctime(&rev_t));
        }
        return false;
    }
    if ((this_t = parse_ocsp_time(thisupd)) == -1) {
        if (logger)
            logger->w("unable to parse this update time in OCSP reply");
        return false;
    }
    if ((next_t = parse_ocsp_time(nextupd)) == -1) {
        if (logger)
            logger->w("unable to parse next update time in OCSP reply");
        return false;
    }

    // Don't allow this update to precede next update
    if (this_t >= next_t) {
        if (logger)
            logger->w("Invalid OCSP reply: this update >= next update");
        return false;
    }

    now = time(nullptr);
    // Check that this update is not more than JITTER seconds in the future.
    if (this_t > now + JITTER_SEC) {
        if (logger)
            logger->e("Invalid OCSP reply: this update is in the future (%s)", ctime(&this_t));
        return false;
    }

    // Check that this update is not more than MAXSEC in the past.
    if (this_t < now - MAXAGE_SEC) {
        if (logger)
            logger->e("Invalid OCSP reply: this update is too old (%s)", ctime(&this_t));
        return false;
    }

    // Check that next update is still valid
    if (next_t < now - JITTER_SEC) {
        if (logger)
            logger->w("Invalid OCSP reply: reply has expired (%s)", ctime(&next_t));
        return false;
    }

    if (logger) {
        logger->d("OCSP response validated");
        logger->d("	   This Update: %s", ctime(&this_t));
        logger->d("	   Next Update: %s", ctime(&next_t));
    }
    return true;
}

void
Connection::set_ssl_verification(const std::string& hostname, const asio::ssl::verify_mode verify_mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ssl_socket_) {
        // Set SNI Hostname (many hosts need this to handshake successfully)
        SSL_set_tlsext_host_name(ssl_socket_->asio_ssl_stream().native_handle(), hostname.c_str());
        ssl_socket_->asio_ssl_stream().set_verify_mode(verify_mode);
        if (verify_mode != asio::ssl::verify_none) {
            ssl_socket_->asio_ssl_stream().set_verify_callback([
                    id = id_, logger = logger_, hostname
                ] (bool preverified, asio::ssl::verify_context& ctx) -> bool {
                    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
                    if (logger) {
                        char subject_name[1024];
                        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 1024);
                        logger->d("[connection:%i] verify %s compliance to RFC 2818:\n%s", id, hostname.c_str(), subject_name);
                    }

                    // starts from CA and goes down the presented chain
                    auto verifier = asio::ssl::rfc2818_verification(hostname);
                    bool verified = verifier(preverified, ctx);
                    auto verify_ec = X509_STORE_CTX_get_error(ctx.native_handle());
                    if (verify_ec != 0 /*X509_V_OK*/ and logger)
                        logger->e("[http::connection:%i] ssl verification error=%i %d", id, verify_ec, verified);
                    if (verified) {
                        auto chain = X509_STORE_CTX_get1_chain(ctx.native_handle());
                        if (auto ocspInfo = ocspRequestFromCert(chain, logger)) {
                            if (logger)
                                logger->w("[http::connection:%i] TLS OCSP server: %s, request size: %zu", id, ocspInfo->url.c_str(), ocspInfo->data.size());
                            bool ocspVerified = false;
                            asio::io_context io_ctx;
                            auto ocspReq = std::make_shared<Request>(io_ctx, ocspInfo->url, [&](const Response& ocspResp){
                                if (ocspResp.status_code == 200) {
                                    ocspVerified = ocspValidateResponse(*ocspInfo, chain, ocspResp.body, X509_STORE_CTX_get0_store(ctx.native_handle()), logger);
                                } else {
                                    if (logger)
                                        logger->w("[http::connection:%i] TLS OCSP check error", id);
                                }
                            }, logger);
                            ocspReq->set_method(restinio::http_method_post());
                            ocspReq->set_header_field(restinio::http_field_t::content_type, "application/ocsp-request");
                            ocspReq->set_body(ocspInfo->data);
                            ocspReq->send();
                            io_ctx.run();
                            if (not ocspVerified)
                                return false;
                        }
                    }
                    return verified;
                }
            );
        }
    }
}

asio::streambuf&
Connection::input()
{
    return write_buf_;
}

std::string
Connection::read_bytes(size_t bytes)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (bytes == 0)
        bytes = read_buf_.in_avail();
    std::string content;
    content.resize(bytes);
    auto rb = istream_.readsome(&content[0], bytes);
    content.resize(rb);
    return content;
}

std::string
Connection::read_until(const char delim)
{
    std::string content;
    std::getline(istream_, content, delim);
    return content;
}

void
Connection::async_connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, ConnectHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ssl_socket_)
        asio::async_connect(ssl_socket_->lowest_layer(), std::move(endpoints), wrapCallabck(std::move(cb)));
    else if (socket_)
        asio::async_connect(*socket_, std::move(endpoints), wrapCallabck(std::move(cb)));
    else if (cb)
        cb(asio::error::operation_aborted, {});
}

void
Connection::async_handshake(HandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ssl_socket_) {
        std::weak_ptr<Connection> wthis = shared_from_this();
        ssl_socket_->async_handshake(asio::ssl::stream<asio::ip::tcp::socket>::client,
                                    [wthis, cb](const asio::error_code& ec)
        {
            if (ec == asio::error::operation_aborted)
                return;
            if (auto sthis = wthis.lock()) {
                auto& this_ = *sthis;
                auto verify_ec = SSL_get_verify_result(this_.ssl_socket_->asio_ssl_stream().native_handle());
                if (this_.logger_) {
                    if (verify_ec == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT /*18*/
                        || verify_ec == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN /*19*/)
                        this_.logger_->d("[connection:%i] self-signed certificate in handshake: %i", this_.id_, verify_ec);
                    else if (verify_ec != X509_V_OK)
                        this_.logger_->e("[connection:%i] verify handshake error: %i", this_.id_, verify_ec);
                    else
                        this_.logger_->w("[connection:%i] verify handshake success", this_.id_);
                }
            }
            if (cb)
                cb(ec);
        });
    }
    else if (socket_)
        cb(asio::error::no_protocol_option);
    else if (cb)
        cb(asio::error::operation_aborted);
}

void
Connection::async_write(BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) ctx_.post([cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_write(*ssl_socket_, write_buf_, wrapCallabck(std::move(cb)));
    else if (socket_) asio::async_write(*socket_, write_buf_, wrapCallabck(std::move(cb)));
    else if (cb)      ctx_.post([cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read_until(const char* delim, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) ctx_.post([cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_read_until(*ssl_socket_, read_buf_, delim, wrapCallabck(std::move(cb)));
    else if (socket_) asio::async_read_until(*socket_, read_buf_, delim, wrapCallabck(std::move(cb)));
    else if (cb)      ctx_.post([cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read_until(char delim, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) ctx_.post([cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_read_until(*ssl_socket_, read_buf_, delim, wrapCallabck(std::move(cb)));
    else if (socket_) asio::async_read_until(*socket_, read_buf_, delim, wrapCallabck(std::move(cb)));
    else if (cb)      ctx_.post([cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read(size_t bytes, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) ctx_.post([cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_read(*ssl_socket_, read_buf_, asio::transfer_exactly(bytes), wrapCallabck(std::move(cb)));
    else if (socket_) asio::async_read(*socket_, read_buf_, asio::transfer_exactly(bytes), wrapCallabck(std::move(cb)));
    else if (cb)      ctx_.post([cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read_some(size_t bytes, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) ctx_.post([cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    auto buf = read_buf_.prepare(bytes);
    auto onEnd = [this_=shared_from_this(), cb=std::move(cb)](const asio::error_code& ec, size_t t){
        this_->read_buf_.commit(t);
        cb(ec, t);
    };
    if (ssl_socket_)  ssl_socket_->async_read_some(buf, onEnd);
    else              socket_->async_read_some(buf, onEnd);
}

void
Connection::timeout(const std::chrono::seconds timeout, HandlerCb cb)
{
    if (!is_open()){
        if (logger_)
            logger_->e("[connection:%i] closed, can't timeout", id_);
        if (cb)
            cb(asio::error::operation_aborted);
        return;
    }
    if (!timeout_timer_)
        timeout_timer_ = std::make_unique<asio::steady_timer>(ctx_);
    timeout_timer_->expires_at(std::chrono::steady_clock::now() + timeout);
    timeout_timer_->async_wait([id=id_, logger=logger_, cb](const asio::error_code &ec){
        if (ec == asio::error::operation_aborted)
            return;
        else if (ec){
            if (logger)
                logger->e("[connection:%i] timeout error: %s", id, ec.message().c_str());
        }
        if (cb)
            cb(ec);
    });
}

// Resolver

Resolver::Resolver(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger)
    : url_(url), resolver_(ctx), destroyed_(std::make_shared<bool>(false)), logger_(logger)
{
    resolve(url_.host, url_.service.empty() ? url_.protocol : url_.service);
}

Resolver::Resolver(asio::io_context& ctx, const std::string& host, const std::string& service,
                   const bool ssl, std::shared_ptr<dht::Logger> logger)
    : resolver_(ctx), destroyed_(std::make_shared<bool>(false)), logger_(logger)
{
    url_.host = host;
    url_.service = service;
    url_.protocol = (ssl ? "https" : "http");
    resolve(url_.host, url_.service.empty() ? url_.protocol : url_.service);
}

Resolver::Resolver(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint> endpoints, const bool ssl,
                   std::shared_ptr<dht::Logger> logger)
    : resolver_(ctx), destroyed_(std::make_shared<bool>(false)), logger_(logger)
{
    url_.protocol = (ssl ? "https" : "http");
    endpoints_ = std::move(endpoints);
    completed_ = true;
}

Resolver::~Resolver()
{
    decltype(cbs_) cbs;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cbs = std::move(cbs_);
    }
    while (not cbs.empty()){
        auto cb = cbs.front();
        if (cb)
            cb(asio::error::operation_aborted, {});
        cbs.pop();
    }
    *destroyed_ = true;
}

inline
std::vector<asio::ip::tcp::endpoint>
filter(const std::vector<asio::ip::tcp::endpoint>& epts, sa_family_t family)
{
    if (family == AF_UNSPEC)
        return epts;
    std::vector<asio::ip::tcp::endpoint> ret;
    for (const auto& ep : epts) {
        if (family == AF_INET && ep.address().is_v4())
            ret.emplace_back(ep);
        else if (family == AF_INET6 && ep.address().is_v6())
            ret.emplace_back(ep);
    }
    return ret;
}

void
Resolver::add_callback(ResolverCb cb, sa_family_t family)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!completed_)
        cbs_.emplace(family == AF_UNSPEC ? std::move(cb) : [cb, family](const asio::error_code& ec, const std::vector<asio::ip::tcp::endpoint>& endpoints){
            if (ec)
                cb(ec, endpoints);
            else
                cb(ec, filter(endpoints, family));
        });
    else
        cb(ec_, family == AF_UNSPEC ? endpoints_ : filter(endpoints_, family));
}

void
Resolver::resolve(const std::string& host, const std::string& service)
{
    asio::ip::tcp::resolver::query query_(host, service);
    resolver_.async_resolve(query_, [this, host, service, destroyed = destroyed_]
        (const asio::error_code& ec, asio::ip::tcp::resolver::results_type endpoints)
    {
        if (ec == asio::error::operation_aborted or *destroyed)
            return;
        if (logger_) {
            if (ec)
                logger_->e("[http:client] [resolver] error for %s:%s: %s",
                           host.c_str(), service.c_str(), ec.message().c_str());
        }
        decltype(cbs_) cbs;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ec_ = ec;
            endpoints_ = std::vector<asio::ip::tcp::endpoint>{endpoints.begin(), endpoints.end()};
            completed_ = true;
            cbs = std::move(cbs_);
        }
        while (not cbs.empty()){
            auto cb = cbs.front();
            if (cb)
                cb(ec, endpoints_);
            cbs.pop();
        }
    });
}

// Request

std::atomic_uint Request::ids_ {1};


Request::Request(asio::io_context& ctx, const std::string& url, const Json::Value& json, OnJsonCb jsoncb,
                 std::shared_ptr<dht::Logger> logger)
    : logger_(std::move(logger)), id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, url, logger))
{
    init_default_headers();
    set_header_field(restinio::http_field_t::content_type, HTTP_HEADER_CONTENT_TYPE_JSON);
    set_header_field(restinio::http_field_t::accept, HTTP_HEADER_CONTENT_TYPE_JSON);
    Json::StreamWriterBuilder wbuilder;
    set_method(restinio::http_method_post());
    set_body(Json::writeString(wbuilder, json));
    add_on_done_callback([this, jsoncb](const Response& response){
        Json::Value json;
        if (response.status_code != 0) {
            std::string err;
            Json::CharReaderBuilder rbuilder;
            auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
            if (!reader->parse(response.body.data(), response.body.data() + response.body.size(), &json, &err) and logger_)
                logger_->e("[http:request:%i] can't parse response to json", id_, err.c_str());
        }
        if (jsoncb)
            jsoncb(std::move(json), response);
    });
}

Request::Request(asio::io_context& ctx, const std::string& url, OnJsonCb jsoncb, std::shared_ptr<dht::Logger> logger)
    : logger_(std::move(logger)), id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, url, logger))
{
    init_default_headers();
    set_header_field(restinio::http_field_t::accept, HTTP_HEADER_CONTENT_TYPE_JSON);
    Json::StreamWriterBuilder wbuilder;
    set_method(restinio::http_method_get());
    add_on_done_callback([this, jsoncb](const Response& response) {
        Json::Value json;
        if (response.status_code != 0) {
            std::string err;
            Json::CharReaderBuilder rbuilder;
            auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
            if (!reader->parse(response.body.data(), response.body.data() + response.body.size(), &json, &err) and logger_)
                logger_->e("[http:request:%i] can't parse response to json", id_, err.c_str());
        }
        if (jsoncb)
            jsoncb(std::move(json), response);
    });
}

Request::Request(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger)
    : logger_(logger), id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, url, logger))
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, const std::string& url, OnDoneCb onDone, std::shared_ptr<dht::Logger> logger)
    : logger_(logger), id_(Request::ids_++), ctx_(ctx), resolver_(std::make_shared<Resolver>(ctx, url, logger))
{
    init_default_headers();
    add_on_done_callback(std::move(onDone));
}

Request::Request(asio::io_context& ctx, const std::string& host, const std::string& service,
                 const bool ssl, std::shared_ptr<dht::Logger> logger)
    : logger_(logger), id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, host, service, ssl, logger))
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, sa_family_t family)
    : logger_(resolver->getLogger()), id_(Request::ids_++), ctx_(ctx), family_(family), resolver_(resolver)
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint>&& endpoints, const bool ssl,
                 std::shared_ptr<dht::Logger> logger)
    : logger_(logger), id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, std::move(endpoints), ssl, logger))
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, const std::string& target, sa_family_t family)
    : logger_(resolver->getLogger()), id_(Request::ids_++), ctx_(ctx), family_(family), resolver_(resolver)
{
    set_header_field(restinio::http_field_t::host, get_url().host + ":" + get_url().service);
    set_target(Url(target).target);
}

Request::~Request()
{
    resolver_.reset();
    terminate(asio::error::connection_aborted);
}

void
Request::init_default_headers()
{
    const auto& url = resolver_->get_url();
    set_header_field(restinio::http_field_t::user_agent, "Mozilla/5.0");
    set_header_field(restinio::http_field_t::accept, "text/html");
    set_target(url.target);
}

void
Request::cancel()
{
    if (auto c = conn_)
        c->close();
}

void
Request::set_connection(std::shared_ptr<Connection> connection) {
    conn_ = std::move(connection);
}

std::shared_ptr<Connection>
Request::get_connection() const {
    return conn_;
}

void
Request::set_certificate_authority(std::shared_ptr<dht::crypto::Certificate> certificate) {
    server_ca_ = certificate;
}

void
Request::set_identity(const dht::crypto::Identity& identity) {
    client_identity_ = identity;
}

void
Request::set_logger(std::shared_ptr<dht::Logger> logger) {
    logger_ = logger;
}

void
Request::set_header(restinio::http_request_header_t header)
{
    header_ = header;
}

void
Request::set_method(restinio::http_method_id_t method) {
    header_.method(method);
}

void
Request::set_target(std::string target) {
    header_.request_target(target.empty() ? "/" : std::move(target));
}

void
Request::set_header_field(restinio::http_field_t field, std::string value) {
    headers_[field] = std::move(value);
}

void
Request::set_connection_type(restinio::http_connection_header_t connection) {
    connection_type_ = connection;
}

void
Request::set_body(std::string body) {
    body_ = std::move(body);
}

void
Request::set_auth(const std::string& username, const std::string& password)
{
    std::vector<uint8_t> creds;
    creds.reserve(username.size() + password.size() + 1);
    creds.insert(creds.end(), username.begin(), username.end());
    creds.emplace_back(':');
    creds.insert(creds.end(), password.begin(), password.end());
    set_header_field(restinio::http_field_t::authorization, "Basic " + base64_encode(creds));
}

void
Request::build()
{
    std::stringstream request;
    bool append_body = !body_.empty();

    // first header
    request << header_.method().c_str() << " " << header_.request_target() << " " <<
               "HTTP/" << header_.http_major() << "." << header_.http_minor() << "\r\n";

    // other headers
    for (auto header: headers_){
        request << restinio::field_to_string(header.first) << ": " << header.second << "\r\n";
        if (header.first == restinio::http_field_t::expect and header.second == "100-continue")
            append_body = false;
    }

    // last connection header
    const char* conn_str = nullptr;
    switch (connection_type_){
    case restinio::http_connection_header_t::keep_alive:
        conn_str = "keep-alive";
        break;
    case restinio::http_connection_header_t::upgrade:
        if (logger_)
            logger_->e("Unsupported connection type 'upgrade', fallback to 'close'");
    // fallthrough
    case restinio::http_connection_header_t::close:
        conn_str = "close"; // default
        break;
    }
    if (conn_str)
        request << "Connection: " << conn_str << "\r\n";

    // body & content-length
    if (append_body) {
        request << "Content-Length: " << body_.size() << "\r\n\r\n"
                << body_;
    } else
        request << "\r\n";
    request_ = request.str();
}

void
Request::add_on_status_callback(OnStatusCb cb) {
    cbs_.on_status = std::move(cb);
}

void
Request::add_on_body_callback(OnDataCb cb) {
    cbs_.on_body = std::move(cb);
}

void
Request::add_on_state_change_callback(OnStateChangeCb cb) {
    cbs_.on_state_change = std::move(cb);
}

void
Request::add_on_done_callback(OnDoneCb cb) {
    add_on_state_change_callback([onDone=std::move(cb)](State state, const Response& response){
        if (state == Request::State::DONE)
            onDone(response);
    });
}

void
Request::notify_state_change(State state) {
    state_ = state;
    if (cbs_.on_state_change)
        cbs_.on_state_change(state, response_);
}

void
Request::init_parser()
{
    response_.request = shared_from_this();

    if (!parser_)
        parser_ = std::make_unique<http_parser>();
    http_parser_init(parser_.get(), HTTP_RESPONSE);
    parser_->data = static_cast<void*>(this);

    if (!parser_s_)
        parser_s_ = std::make_unique<http_parser_settings>();
    http_parser_settings_init(parser_s_.get());

    cbs_.on_status = [this, statusCb = std::move(cbs_.on_status)](unsigned int status_code){
        response_.status_code = status_code;
        if (statusCb)
            statusCb(status_code);
    };
    auto header_field = std::make_shared<std::string>();
    cbs_.on_header_field = [header_field](const char* at, size_t length) {
        *header_field = std::string(at, length);
    };
    cbs_.on_header_value = [this, header_field](const char* at, size_t length) {
        response_.headers[*header_field] = std::string(at, length);
    };

    // http_parser raw c callback (note: no context can be passed into them)
    parser_s_->on_status = [](http_parser* parser, const char* /*at*/, size_t /*length*/) -> int {
        static_cast<Request*>(parser->data)->cbs_.on_status(parser->status_code);
        return 0;
    };
    parser_s_->on_header_field = [](http_parser* parser, const char* at, size_t length) -> int {
        static_cast<Request*>(parser->data)->cbs_.on_header_field(at, length);
        return 0;
    };
    parser_s_->on_header_value = [](http_parser* parser, const char* at, size_t length) -> int {
        static_cast<Request*>(parser->data)->cbs_.on_header_value(at, length);
        return 0;
    };
    parser_s_->on_body = [](http_parser* parser, const char* at, size_t length) -> int {
        static_cast<Request*>(parser->data)->onBody(at, length);
        return 0;
    };
    parser_s_->on_headers_complete = [](http_parser* parser) -> int {
        static_cast<Request*>(parser->data)->onHeadersComplete();
        return 0;
    };
    parser_s_->on_message_complete = [](http_parser* parser) -> int {
        static_cast<Request*>(parser->data)->onComplete();
        return 0;
    };
}

void
Request::connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, HandlerCb cb)
{
    if (endpoints.empty()){
        if (logger_)
            logger_->e("[http:request:%i] connect: no endpoints provided", id_);
        if (cb)
            cb(asio::error::connection_aborted);
        return;
    }
    if (logger_){
        std::string eps = "";
        for (const auto& endpoint : endpoints)
            eps.append(endpoint.address().to_string() + ":" + std::to_string(endpoint.port()) + " ");
        logger_->d("[http:request:%i] connect begin: %s", id_, eps.c_str());
    }
    bool isHttps = get_url().protocol == "https";
    if (isHttps) {
        if (server_ca_ or client_identity_.first)
            conn_ = std::make_shared<Connection>(ctx_, server_ca_, client_identity_, logger_);
        else
            conn_ = std::make_shared<Connection>(ctx_, true/*ssl*/, logger_);
        conn_->set_ssl_verification(get_url().host, asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    }
    else
        conn_ = std::make_shared<Connection>(ctx_, false/*ssl*/, logger_);

    // try to connect to any until one works
    std::weak_ptr<Request> wthis = shared_from_this();
    conn_->async_connect(std::move(endpoints), [wthis, cb, isHttps]
                        (const asio::error_code& ec, const asio::ip::tcp::endpoint& endpoint){
        auto sthis = wthis.lock();
        if (not sthis)
            return;
        auto& this_ = *sthis;
        std::lock_guard<std::mutex> lock(this_.mutex_);
        if (ec == asio::error::operation_aborted){
            this_.terminate(ec);
            return;
        }
        else if (ec) {
            if (this_.logger_)
                this_.logger_->e("[http:request:%i] connect failed with all endpoints: %s", this_.id_, ec.message().c_str());
        } else {
            const auto& url = this_.get_url();
            auto port = endpoint.port();
            if ((!isHttps && port == (in_port_t)80)
             || (isHttps && port == (in_port_t)443))
                this_.set_header_field(restinio::http_field_t::host, url.host);
            else
                this_.set_header_field(restinio::http_field_t::host, url.host + ":" + std::to_string(port));

            if (isHttps) {
                if (this_.conn_ and this_.conn_->is_open() and this_.conn_->is_ssl()) {
                    this_.conn_->async_handshake([id = this_.id_, cb, logger = this_.logger_](const asio::error_code& ec){
                        if (ec == asio::error::operation_aborted)
                            return;
                        if (ec and logger)
                            logger->e("[http:request:%i] handshake error: %s", id, ec.message().c_str());
                        //else if (logger)
                        //    logger->d("[http:request:%i] handshake success", id);
                        if (cb)
                            cb(ec);
                    });
                }
                else if (cb)
                    cb(asio::error::operation_aborted);
                return;
            }
        }
        if (cb)
            cb(ec);
    });
}

void
Request::send()
{
    notify_state_change(State::CREATED);

    std::weak_ptr<Request> wthis = shared_from_this();
    resolver_->add_callback([wthis](const asio::error_code& ec,
                                   std::vector<asio::ip::tcp::endpoint> endpoints) {
        if (auto sthis = wthis.lock()) {
            auto& this_ = *sthis;
            std::lock_guard<std::mutex> lock(this_.mutex_);
            if (ec){
                if (this_.logger_)
                    this_.logger_->e("[http:request:%i] resolve error: %s", this_.id_, ec.message().c_str());
                this_.terminate(asio::error::connection_aborted);
            }
            else if (!this_.conn_ or !this_.conn_->is_open()) {
                this_.connect(std::move(endpoints), [wthis](const asio::error_code &ec) {
                    if (auto sthis = wthis.lock()) {
                        if (ec)
                            sthis->terminate(asio::error::not_connected);
                        else
                            sthis->post();
                    }
                });
            }
            else
                this_.post();
        }
    }, family_);
}

void
Request::post()
{
    if (!conn_ or !conn_->is_open()){
        terminate(asio::error::not_connected);
        return;
    }
    build();
    init_parser();

    if (logger_)
        logger_->d("[http:request:%i] sending %zu bytes", id_, request_.size());

    // write the request to buffer
    std::ostream request_stream(&conn_->input());
    request_stream << request_;

    // send the request
    notify_state_change(State::SENDING);

    std::weak_ptr<Request> wthis = shared_from_this();
    conn_->async_write([wthis](const asio::error_code& ec, size_t) {
        if (auto sthis = wthis.lock())
            sthis->handle_request(ec);
    });
}

void
Request::terminate(const asio::error_code& ec)
{
    if (finishing_.exchange(true))
        return;

    response_.aborted = ec == asio::error::operation_aborted;

    if (logger_) {
        if (ec and ec != asio::error::eof and ec != asio::error::operation_aborted)
            logger_->e("[http:request:%i] end with error: %s", id_, ec.message().c_str());
        else
            logger_->d("[http:request:%i] done with status code %u", id_, response_.status_code);
    }

    if (!parser_ or !http_should_keep_alive(parser_.get()))
        if (auto c = conn_)
            c->close();
    notify_state_change(State::DONE);
}

void
Request::handle_request(const asio::error_code& ec)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ec and ec != asio::error::eof){
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        terminate(asio::error::not_connected);
        return;
    }
    // if (logger_)
    //    logger_->d("[http:request:%i] send success", id_);
    // read response
    notify_state_change(State::RECEIVING);

    std::weak_ptr<Request> wthis = shared_from_this();
    conn_->async_read_until(HTTP_HEADER_DELIM, [wthis](const asio::error_code& ec, size_t n_bytes){
        if (auto sthis = wthis.lock())
            sthis->handle_response(ec, n_bytes);
    });
}

void
Request::handle_response(const asio::error_code& ec, size_t /* n_bytes */)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ec && ec != asio::error::eof){
        terminate(ec);
        return;
    }
    auto request = (ec == asio::error::eof) ? std::string{} : conn_->read_bytes();
    size_t ret = http_parser_execute(parser_.get(), parser_s_.get(), request.c_str(), request.size());
    if (ret != request.size()) {
        if (logger_)
            logger_->e("Error parsing HTTP: %zu %s %s", ret,
                http_errno_name(HTTP_PARSER_ERRNO(parser_)),
                http_errno_description(HTTP_PARSER_ERRNO(parser_)));
        terminate(asio::error::basic_errors::broken_pipe);
        return;
    }

    if (state_ != State::DONE and parser_ and not http_body_is_final(parser_.get())) {
        auto toRead = parser_->content_length ? std::min<uint64_t>(parser_->content_length, 64 * 1024) : 64 * 1024;
        std::weak_ptr<Request> wthis = shared_from_this();
        conn_->async_read_some(toRead, [wthis](const asio::error_code& ec, size_t bytes){
            if (auto sthis = wthis.lock())
                sthis->handle_response(ec, bytes);
        });
    }
}

void
Request::onBody(const char* at, size_t length)
{
    if (cbs_.on_body)
        cbs_.on_body(at, length);
    else
        response_.body.insert(response_.body.end(), at, at+length);
}

void
Request::onComplete() {
    terminate(asio::error::eof);
}

void
Request::onHeadersComplete() {
    notify_state_change(State::HEADER_RECEIVED);

    if (response_.status_code == restinio::status_code::moved_permanently.raw_code() or
        response_.status_code == restinio::status_code::found.raw_code())
    {
        auto location_it = response_.headers.find(restinio::field_to_string(restinio::http_field_t::location));
        if (location_it == response_.headers.end()){
            if (logger_)
                logger_->e("[http:client] [request:%i] got redirect without location", id_);
            terminate(asio::error::connection_aborted);
        }

        if (follow_redirect and num_redirect < MAX_REDIRECTS) {
            auto newUrl = getRelativePath(get_url(), location_it->second);
            if (logger_)
                logger_->w("[http:client] [request:%i] redirect to %s", id_, newUrl.c_str());
            auto next = std::make_shared<Request>(ctx_, newUrl, logger_);
            next->set_method(header_.method());
            next->headers_ = std::move(headers_);
            next->body_ = std::move(body_);
            next->cbs_ = std::move(cbs_);
            next->num_redirect = num_redirect + 1;
            next_ = next;
            next->prev_ = shared_from_this();
            next->send();
        } else {
            if (logger_)
                logger_->e("[http:client] [request:%i] got redirect without location", id_);
            terminate(asio::error::connection_aborted);
        }
    } else {
        auto expect_it = headers_.find(restinio::http_field_t::expect);
        if (expect_it != headers_.end() and (expect_it->second == "100-continue") and response_.status_code != 200){
            notify_state_change(State::SENDING);
            request_.append(body_);
            std::ostream request_stream(&conn_->input());
            request_stream << body_ << "\r\n";
            std::weak_ptr<Request> wthis = shared_from_this();
            conn_->async_write([wthis](const asio::error_code& ec, size_t) {
                if (auto sthis = wthis.lock())
                    sthis->handle_request(ec);
            });
        }
    }
}

bool startsWith(const std::string& haystack, const std::string& needle) {
    return needle.length() <= haystack.length() 
        && std::equal(needle.begin(), needle.end(), haystack.begin());
}

std::string
Request::getRelativePath(const Url& origin, const std::string& path)
{
    if (startsWith(path, HTTP_PROTOCOL)
    || startsWith(path, HTTPS_PROTOCOL)
    || startsWith(path, ORIGIN_PROTOCOL)) {
        // Absolute path
        return path;
    }
    Url newPath = origin;
    if (not path.empty() and path[0] == '/') {
        newPath.target = path;
    } else {
        if (newPath.target.empty())
            newPath.target.push_back('/');
        newPath.target += path;
    }
    return newPath.toString();
}

const Response&
Request::await()
{
    std::mutex mtx;
    std::unique_lock<std::mutex> lock(mtx);
    std::condition_variable cv;
    bool ok {false};
    add_on_done_callback([&](const Response& resp){
        std::lock_guard<std::mutex> lk(mtx);
        ok = true;
        cv.notify_all();
    });
    cv.wait(lock, [&]{ return ok; });
    return response_;
}

} // namespace http
} // namespace dht
