/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
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
#include "logger.h"
#include "crypto.h"
#include "base64.h"
#include "compat/os_cert.h"

#include <asio.hpp>
#include <restinio/impl/tls_socket.hpp>
#include <llhttp.h>
#include <json/json.h>

#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <cctype>
#include <iomanip>
#include <sstream>

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

Url::Url(std::string_view url): url(url)
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
    auto [h, s] = splitPort(url.substr(addr_begin, addr_size));
    host = std::move(h);
    service = std::move(s);
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
    std::ostringstream ss;
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
            logger->debug("Using CA file: {}", path);
        ctx->load_verify_file(path);
    } else if (char* path = getenv("CA_ROOT_PATH")) {
        if (logger)
            logger->debug("Using CA path: {}", path);
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
            logger_->debug("[connection:{:d}] start https session with system CA", id_);
    }
    else {
        socket_ = std::make_unique<socket_t>(ctx);
        if (logger_)
            logger_->debug("[connection:{:d}] start http session", id_);
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
            logger_->debug("[connection:{:d}] start https with custom CA {:s}", id_, server_ca->getUID());
    } else {
        ssl_ctx_ = newTlsClientContext(l);
        if (logger_)
            logger_->debug("[connection:{:d}] start https session with system CA", id_);
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
            logger_->debug("[connection:{:d}] client certificate {:s}", id_, identity.second->getUID());
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
        logger_->error("[connection:{:d}] error closing: {:s}", id_, ec.message());
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

std::string asn1ToString(ASN1_GENERALIZEDTIME* time) {
    if (!time) {
        return "(null)";
    }
    BIO* memBio = BIO_new(BIO_s_mem());
    if (!memBio) {
        throw std::runtime_error("Failed to create BIO");
    }

    if (ASN1_GENERALIZEDTIME_print(memBio, time) <= 0) {
        BIO_free(memBio);
        throw std::runtime_error("Failed to print ASN1_GENERALIZEDTIME");
    }

    char* bioData;
    long bioLength = BIO_get_mem_data(memBio, &bioData);
    std::string result(bioData, bioLength);
    BIO_free(memBio);
    return result;
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
            logger->error("Cert does not contain a cert chain");
        return {};
    }
    X509* cert = cert_from_chain(fullchain);
    if (cert == nullptr) {
        if (logger)
            logger->error("No certificate found");
        return {};
    }
    X509* issuer = issuer_from_chain(fullchain);
    if (issuer == nullptr) {
        if (logger)
            logger->error("Unable to find issuer for cert");
        return {};
    }

    auto urls = X509_get1_ocsp(cert);
    if (urls == nullptr || sk_OPENSSL_STRING_num(urls) <= 0) {
        if (logger)
            logger->error("Certificate contains no OCSP url");
        return {};
    }
    auto url = sk_OPENSSL_STRING_value(urls, 0);
    if (url == nullptr)
        return {};

    auto request = std::make_unique<OscpRequestInfo>();
    request->req = OscpRequestPtr(OCSP_REQUEST_new(), &OCSP_REQUEST_free);
    request->url = url;
    X509_email_free(urls);

    OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if (id == nullptr) {
        if (logger)
            logger->error("Unable to get certificate id from cert");
        return {};
    }
    if (OCSP_request_add0_id(request->req.get(), id) == nullptr) {
        if (logger)
            logger->error("Unable to add certificate id to request");
        return {};
    }

    if (nonce)
        OCSP_request_add1_nonce(request->req.get(), nullptr, -1);

    int size;
    uint8_t* data {nullptr};
    if ((size = i2d_OCSP_REQUEST(request->req.get(), &data)) <= 0) {
        if (logger)
            logger->error("Unable to encode ocsp request");
        return {};
    }
    if (data == nullptr) {
        if (logger)
            logger->error("Unable to allocte memory");
        return {};
    }
    request->data = std::string((char*)data, (char*)data+size);
    free(data);
    return request;
}

bool
ocspValidateResponse(const OscpRequestInfo& info, STACK_OF(X509)* fullchain, const std::string& response, X509_STORE *store, const std::shared_ptr<Logger>& logger)
{
    X509* cert = cert_from_chain(fullchain);
    if (cert == nullptr) {
        if (logger)
            logger->error("ocsp: no certificate found");
        return false;
    }
    X509* issuer = issuer_from_chain(fullchain);
    if (issuer == nullptr) {
        if (logger)
            logger->error("ocsp: unable to find issuer for cert");
        return false;
    }

    OCSP_CERTID *cidr;
    if ((cidr = OCSP_cert_to_id(nullptr, cert, issuer)) == nullptr) {
        if (logger)
            logger->error("ocsp: unable to get issuer cert/CID");
        return false;
    }
    std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)> cid(cidr, &OCSP_CERTID_free);

    const uint8_t* resp_data = (const uint8_t*)response.data();
    OCSP_RESPONSE *r;
    if ((r = d2i_OCSP_RESPONSE(nullptr, &resp_data, response.size())) == nullptr) {
        if (logger)
            logger->error("OCSP response unserializable");
        return false;
    }
    std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)> resp(r, &OCSP_RESPONSE_free);

    OCSP_BASICRESP *brespr;
    if ((brespr = OCSP_response_get1_basic(resp.get())) == nullptr) {
        if (logger)
            logger->error("Failed to load OCSP response");
        return false;
    }
    std::unique_ptr<OCSP_BASICRESP, decltype(&OCSP_BASICRESP_free)> bresp(brespr, &OCSP_BASICRESP_free);

    if (OCSP_basic_verify(bresp.get(), fullchain, store, OCSP_TRUSTOTHER) != 1) {
        if (logger)
            logger->warn("OCSP verify failed");
        return false;
    }

    int status = OCSP_response_status(resp.get());
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        if (logger)
            logger->warn("OCSP Failure: code {:d} ({:s})", status, OCSP_response_status_str(status));
        return false;
    }

    // Check the nonce if we sent one
    if (OCSP_check_nonce(info.req.get(), bresp.get()) <= 0) {
        if (logger)
            logger->warn("No OCSP nonce, or mismatch");
        return false;
    }

    ASN1_GENERALIZEDTIME *revtime = nullptr, *thisupd = nullptr, *nextupd = nullptr;
    int cert_status=0, crl_reason=0;
    if (OCSP_resp_find_status(bresp.get(), cid.get(), &cert_status, &crl_reason,
        &revtime, &thisupd, &nextupd) != 1) {
        if (logger)
            logger->warn("OCSP verify failed: no result for cert");
        return false;
    }

    // Belt and suspenders, Treat it as revoked if there is either
    // a revocation time, or status revoked.
    if (revtime || cert_status == V_OCSP_CERTSTATUS_REVOKED) {
        if (logger) {
            logger->warn("OCSP verify failed: certificate revoked since {}", asn1ToString(revtime));
        }
        return false;
    }

    if (OCSP_check_validity(thisupd, nextupd, 1, -1) == 0) {
        if (logger)
            logger->warn("OCSP reply is expired or not yet valid");
        return false;
    }

    if (logger) {
        logger->debug("OCSP response validated");
        logger->debug("	   This Update: {}", asn1ToString(thisupd));
        logger->debug("	   Next Update: {}", asn1ToString(nextupd));
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
                    id = id_, logger = logger_, hostname, checkOcsp = checkOcsp_
                ] (bool preverified, asio::ssl::verify_context& ctx) -> bool {
                    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
                    if (logger) {
                        char subject_name[1024];
                        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 1024);
                        logger->debug("[connection:{:d}] verify {:s} compliance to RFC 2818:\n{:s}", id, hostname, subject_name);
                    }

                    // starts from CA and goes down the presented chain
                    auto verifier = asio::ssl::host_name_verification(hostname);
                    bool verified = verifier(preverified, ctx);
                    auto verify_ec = X509_STORE_CTX_get_error(ctx.native_handle());
                    if (verify_ec != 0 /*X509_V_OK*/ and logger)
                        logger->error("[http::connection:{:d}] ssl verification error={:d} {}", id, verify_ec, verified);
                    if (verified and checkOcsp) {
                        std::unique_ptr<stack_st_X509, void(*)(stack_st_X509*)> chain(
                            X509_STORE_CTX_get1_chain(ctx.native_handle()),
                            [](stack_st_X509* c){ sk_X509_pop_free(c, X509_free); });
                        if (auto ocspInfo = ocspRequestFromCert(chain.get(), logger)) {
                            if (logger)
                                logger->warn("[http::connection:{:d}] TLS OCSP server: {:s}, request size: {:d}", id, ocspInfo->url, ocspInfo->data.size());
                            bool ocspVerified = false;
                            asio::io_context io_ctx;
                            auto ocspReq = std::make_shared<Request>(io_ctx, ocspInfo->url, [&](const Response& ocspResp){
                                if (ocspResp.status_code == 200) {
                                    ocspVerified = ocspValidateResponse(*ocspInfo, chain.get(), ocspResp.body, X509_STORE_CTX_get0_store(ctx.native_handle()), logger);
                                } else {
                                    if (logger)
                                        logger->warn("[http::connection:{:d}] TLS OCSP check error", id);
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
    if (!ssl_socket_ && !socket_) {
        cb(asio::error::operation_aborted, {});
        return;
    }
    auto& base = ssl_socket_? ssl_socket_->lowest_layer() : *socket_;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
    ConnectHandlerCb wcb = [this, &base, cb=std::move(cb)](const asio::error_code& ec, const asio::ip::tcp::endpoint& endpoint) {
        if (!ec) {
            local_address_ = base.local_endpoint().address();
            // Once connected, set a keep alive on the TCP socket with 30 seconds delay
            // This will generate broken pipes as soon as possible.
            // Note this needs to be done once connected to have a valid native_handle()
            this->set_keepalive(30);
        }
        if (cb)
            cb(ec, endpoint);
    };
#pragma GCC diagnostic pop

    if (ssl_socket_)
        asio::async_connect(ssl_socket_->lowest_layer(), std::move(endpoints), wrapCallback(std::move(wcb)));
    else
        asio::async_connect(*socket_, std::move(endpoints), wrapCallback(std::move(wcb)));
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
                        this_.logger_->debug("[connection:{:d}] self-signed certificate in handshake: {:d}", this_.id_, verify_ec);
                    else if (verify_ec != X509_V_OK)
                        this_.logger_->error("[connection:{:d}] verify handshake error: {:d}", this_.id_, verify_ec);
                    else
                        this_.logger_->warn("[connection:{:d}] verify handshake success", this_.id_);
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
        if (cb) asio::post(ctx_, [cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_write(*ssl_socket_, write_buf_, wrapCallback(std::move(cb)));
    else if (socket_) asio::async_write(*socket_, write_buf_, wrapCallback(std::move(cb)));
    else if (cb)      asio::post(ctx_, [cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read_until(const char* delim, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) asio::post(ctx_, [cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_read_until(*ssl_socket_, read_buf_, delim, wrapCallback(std::move(cb)));
    else if (socket_) asio::async_read_until(*socket_, read_buf_, delim, wrapCallback(std::move(cb)));
    else if (cb)      asio::post(ctx_, [cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read_until(char delim, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) asio::post(ctx_, [cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_read_until(*ssl_socket_, read_buf_, delim, wrapCallback(std::move(cb)));
    else if (socket_) asio::async_read_until(*socket_, read_buf_, delim, wrapCallback(std::move(cb)));
    else if (cb)      asio::post(ctx_, [cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read(size_t bytes, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) asio::post(ctx_, [cb](){ cb(asio::error::broken_pipe, 0); });
        return;
    }
    if (ssl_socket_)  asio::async_read(*ssl_socket_, read_buf_, asio::transfer_exactly(bytes), wrapCallback(std::move(cb)));
    else if (socket_) asio::async_read(*socket_, read_buf_, asio::transfer_exactly(bytes), wrapCallback(std::move(cb)));
    else if (cb)      asio::post(ctx_, [cb](){ cb(asio::error::operation_aborted, 0); });
}

void
Connection::async_read_some(size_t bytes, BytesHandlerCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open()) {
        if (cb) asio::post(ctx_, [cb](){ cb(asio::error::broken_pipe, 0); });
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
Connection::set_keepalive(uint32_t seconds)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ssl_socket_ && !socket_) return;

    auto& base = ssl_socket_? ssl_socket_->lowest_layer() : *socket_;
    auto socket = base.native_handle();

    uint32_t interval = 1;
    uint32_t cnt = 10;
#ifdef _WIN32
    // TCP_KEEPIDLE and TCP_KEEPINTVL are available since Win 10 version 1709
    // TCP_KEEPCNT since Win 10 version 1703
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
    std::string val = "1";
    setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, val.c_str(), sizeof(val));
    std::string seconds_str = std::to_string(seconds);
    setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE,
        seconds_str.c_str(), sizeof(seconds_str));
    std::string interval_str = std::to_string(interval);
    setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL,
        interval_str.c_str(), sizeof(interval_str));
    std::string cnt_str = std::to_string(cnt);
    setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT,
        cnt_str.c_str(), sizeof(cnt_str));
#else
    struct {
        uint32_t onoff;
        uint32_t keepalivetime;
        uint32_t keepaliveinterval;
    } keepalive;
    keepalive.onoff = 1;
    keepalive.keepalivetime = seconds * 1000;
    keepalive.keepaliveinterval = interval * 1000;
    int32_t out = 0;
    WSAIoctl(socket, SIO_KEEPALIVE_VALS, keepalive, sizeof(tcp_keepalive),
        nullptr, 0, &out, nullptr, nullptr);
#endif
#else
    uint32_t val = 1;
    setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(uint32_t));
#ifdef __APPLE__
    // Old Apple devices only have one parameter
    setsockopt(socket, IPPROTO_TCP, TCP_KEEPALIVE, &seconds, sizeof(uint32_t));
#if defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
    setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(uint32_t));
    setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(uint32_t));
#endif
#else
    // Linux based systems
    setsockopt(socket, SOL_TCP, TCP_KEEPIDLE, &seconds, sizeof(uint32_t));
    setsockopt(socket, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(uint32_t));
    setsockopt(socket, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(uint32_t));
#endif
#endif
}

const asio::ip::address&
Connection::local_address() const
{
    return local_address_;
}

void
Connection::timeout(const std::chrono::seconds& timeout, HandlerCb cb)
{
    if (!timeout_timer_)
        timeout_timer_ = std::make_unique<asio::steady_timer>(ctx_);
    timeout_timer_->expires_at(std::chrono::steady_clock::now() + timeout);
    timeout_timer_->async_wait([id=id_, logger=logger_, cb](const asio::error_code &ec){
        if (ec == asio::error::operation_aborted)
            return;
        else if (ec){
            if (logger)
                logger->error("[connection:{:d}] timeout error: {:s}", id, ec.message());
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

void
Resolver::cancel()
{
    resolver_.cancel();
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
Resolver::resolve(const std::string& host, const std::string& serviceName)
{
    auto service = serviceName;
    // The async_resolve function used below typically relies on the contents of the
    // /etc/services (Linux/POSIX) or c:\windows\system32\drivers\etc\services (Windows)
    // file in order to resolve a descriptive service name into a port number. A
    // resolution attempt that would otherwise succeed can therefore fail if the file
    // is inaccessible or corrupted (which is rare but can happen in practice). We
    // hardcode the port numbers for http and https to prevent this failure mode.
    if (service == "http") {
        service = "80";
    } else if (service == "https") {
        service = "443";
    }
    resolver_.async_resolve(host, service, [this, host, service, destroyed = destroyed_]
        (const asio::error_code& ec, asio::ip::tcp::resolver::results_type endpoints)
    {
        if (ec == asio::error::operation_aborted or *destroyed)
            return;
        if (logger_) {
            logger_->debug("[http:client] [resolver] result for {:s}:{:s}: {:s}",
                        host, service, ec.message());
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
                logger_->error("[http:request:{:d}] can't parse response to json: {:s}", id_, err);
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
                logger_->error("[http:request:{:d}] can't parse response to json: {:s}", id_, err);
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
    if (auto r = resolver_)
        r->cancel();
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
    std::ostringstream request;
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
            logger_->error("Unsupported connection type 'upgrade', fallback to 'close'");
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

// https://stackoverflow.com/a/17708801
std::string
Request::url_encode(std::string_view value)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (const char& c : value) {
        // Keep alphanumeric and other accepted characters intact
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        escaped << std::nouppercase;
    }

    return escaped.str();
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
        parser_ = std::make_unique<llhttp_t>();

    if (!parser_s_)
        parser_s_ = std::make_unique<llhttp_settings_t>();
    llhttp_settings_init(parser_s_.get());

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

    // llhttp raw c callback (note: no context can be passed into them)
    parser_s_->on_status = [](llhttp_t* parser, const char* /*at*/, size_t /*length*/) -> int {
        static_cast<Request*>(parser->data)->cbs_.on_status(parser->status_code);
        return 0;
    };
    parser_s_->on_header_field = [](llhttp_t* parser, const char* at, size_t length) -> int {
        static_cast<Request*>(parser->data)->cbs_.on_header_field(at, length);
        return 0;
    };
    parser_s_->on_header_value = [](llhttp_t* parser, const char* at, size_t length) -> int {
        static_cast<Request*>(parser->data)->cbs_.on_header_value(at, length);
        return 0;
    };
    parser_s_->on_body = [](llhttp_t* parser, const char* at, size_t length) -> int {
        static_cast<Request*>(parser->data)->onBody(at, length);
        return 0;
    };
    parser_s_->on_headers_complete = [](llhttp_t* parser) -> int {
        static_cast<Request*>(parser->data)->onHeadersComplete();
        return 0;
    };
    parser_s_->on_message_complete = [](llhttp_t* parser) -> int {
        static_cast<Request*>(parser->data)->onComplete();
        return 0;
    };
    llhttp_init(parser_.get(), HTTP_RESPONSE, parser_s_.get());
    parser_->data = static_cast<void*>(this);
}

void
Request::connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, HandlerCb cb)
{
    if (endpoints.empty()){
        if (logger_)
            logger_->error("[http:request:{:d}] connect: no endpoints provided", id_);
        if (cb)
            cb(asio::error::connection_aborted);
        return;
    }
    if (logger_){
        std::string eps = "";
        for (const auto& endpoint : endpoints)
            eps.append(endpoint.address().to_string() + ":" + std::to_string(endpoint.port()) + " ");
        logger_->debug("[http:request:{:d}] connect begin: {:s}", id_, eps);
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

    if (conn_ && timeoutCb_)
        conn_->timeout(timeout_, std::move(timeoutCb_));

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
                this_.logger_->error("[http:request:{:d}] connect failed with all endpoints: {:s}", this_.id_, ec.message());
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
                            logger->error("[http:request:{:d}] handshake error: {:s}", id, ec.message());
                        //else if (logger)
                        //    logger->d("[http:request:{:d}] handshake success", id);
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
                    this_.logger_->error("[http:request:{:d}] resolve error: {:s}", this_.id_, ec.message());
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
        logger_->debug("[http:request:{}] sending {} bytes", id_, request_.size());

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
    if (ec == asio::error::basic_errors::broken_pipe)
        response_.status_code = 0U; // Avoid to give a successful answer (happen with a broken pipe, takes the last status)

    if (logger_) {
        if (ec and ec != asio::error::eof and !response_.aborted)
            logger_->error("[http:request:{:d}] end with error: {:s}", id_, ec.message());
        else
            logger_->debug("[http:request:{:d}] done with status code {:d}", id_, response_.status_code);
    }

    if (!parser_ or !llhttp_should_keep_alive(parser_.get()))
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
    enum llhttp_errno ret = llhttp_execute(parser_.get(), request.c_str(), request.size());
    if (ret != HPE_OK && ret != HPE_PAUSED) {
        if (logger_)
            logger_->e("Error parsing HTTP: %zu %s %d", (int)ret, llhttp_errno_name(ret), llhttp_get_error_reason(parser_.get()));
        terminate(asio::error::basic_errors::broken_pipe);
        return;
    }

    if (state_ != State::DONE and parser_ and not llhttp_message_needs_eof(parser_.get())) {
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
    add_on_done_callback([&](const Response&){
        std::lock_guard<std::mutex> lk(mtx);
        ok = true;
        cv.notify_all();
    });
    cv.wait(lock, [&]{ return ok; });
    return response_;
}

} // namespace http
} // namespace dht
