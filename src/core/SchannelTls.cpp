#include "SchannelTls.hpp"

#ifdef _WIN32
#include <wincrypt.h>
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace aifw {

SchannelTls::SchannelTls() = default;

SchannelTls::~SchannelTls() {
    disconnect();
}

bool SchannelTls::connect(SOCKET sock, const TlsConfig& config) {
#ifdef _WIN32
    socket_ = sock;
    config_ = config;

    // Acquire credentials
    SCHANNEL_CRED cred = {};
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = config.protocols;
    cred.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS;
    if (config.verifyCert) {
        cred.dwFlags |= SCH_CRED_AUTO_CRED_VALIDATION;
    } else {
        cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    TimeStamp expiry;
    SECURITY_STATUS status = AcquireCredentialsHandleA(
        nullptr, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
        nullptr, &cred, nullptr, nullptr, &credHandle_, &expiry);

    if (status != SEC_E_OK) return false;
    hasCred_ = true;

    // Perform handshake
    if (!performHandshake(config.hostname)) {
        disconnect();
        return false;
    }

    // Get stream sizes
    status = QueryContextAttributes(&ctxtHandle_, SECPKG_ATTR_STREAM_SIZES, &sizes_);
    if (status != SEC_E_OK) {
        disconnect();
        return false;
    }

    // Validate certificate
    if (config.verifyCert) {
        certValid_ = validateCertificate();
        if (!certValid_) {
            disconnect();
            return false;
        }
    } else {
        certValid_ = true;
    }

    connected_ = true;
    return true;
#else
    (void)sock; (void)config;
    return false;
#endif
}

bool SchannelTls::performHandshake(const std::string& hostname) {
#ifdef _WIN32
    DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                  ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                  ISC_REQ_STREAM;

    SecBuffer outBuf = {};
    SecBufferDesc outDesc = {SECBUFFER_VERSION, 1, &outBuf};

    // First call
    DWORD outFlags;
    SECURITY_STATUS status = InitializeSecurityContextA(
        &credHandle_, nullptr, const_cast<char*>(hostname.c_str()),
        flags, 0, 0, nullptr, 0, &ctxtHandle_, &outDesc, &outFlags, nullptr);

    if (status != SEC_I_CONTINUE_NEEDED) return false;
    hasCtxt_ = true;

    // Send ClientHello
    if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
        if (!sendRaw(outBuf.pvBuffer, outBuf.cbBuffer)) {
            FreeContextBuffer(outBuf.pvBuffer);
            return false;
        }
        FreeContextBuffer(outBuf.pvBuffer);
    }

    // Handshake loop
    std::vector<uint8_t> recvBuf(16384);
    size_t recvLen = 0;

    while (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE) {
        // Receive more data if needed
        if (status == SEC_E_INCOMPLETE_MESSAGE || recvLen == 0) {
            int n = recvRaw(recvBuf.data() + recvLen, recvBuf.size() - recvLen);
            if (n <= 0) return false;
            recvLen += n;
        }

        SecBuffer inBufs[2] = {};
        inBufs[0].BufferType = SECBUFFER_TOKEN;
        inBufs[0].pvBuffer = recvBuf.data();
        inBufs[0].cbBuffer = static_cast<ULONG>(recvLen);
        inBufs[1].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc inDesc = {SECBUFFER_VERSION, 2, inBufs};

        outBuf = {};
        outDesc = {SECBUFFER_VERSION, 1, &outBuf};

        status = InitializeSecurityContextA(
            &credHandle_, &ctxtHandle_, nullptr,
            flags, 0, 0, &inDesc, 0, nullptr, &outDesc, &outFlags, nullptr);

        // Send any output
        if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
            sendRaw(outBuf.pvBuffer, outBuf.cbBuffer);
            FreeContextBuffer(outBuf.pvBuffer);
        }

        // Handle extra data
        if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0) {
            memmove(recvBuf.data(),
                recvBuf.data() + recvLen - inBufs[1].cbBuffer,
                inBufs[1].cbBuffer);
            recvLen = inBufs[1].cbBuffer;
        } else {
            recvLen = 0;
        }

        if (status == SEC_E_OK) break;
        if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_INCOMPLETE_MESSAGE) {
            return false;
        }
    }

    return status == SEC_E_OK;
#else
    (void)hostname;
    return false;
#endif
}

bool SchannelTls::validateCertificate() {
#ifdef _WIN32
    PCCERT_CONTEXT cert = nullptr;
    SECURITY_STATUS status = QueryContextAttributes(
        &ctxtHandle_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert);

    if (status != SEC_E_OK || !cert) return false;

    // Get subject name
    char subject[256] = {};
    CertNameToStrA(cert->dwCertEncodingType, &cert->pCertInfo->Subject,
        CERT_X500_NAME_STR, subject, sizeof(subject));
    certSubject_ = subject;

    // Verify certificate chain
    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(nullptr, cert, nullptr, cert->hCertStore,
            &chainPara, 0, nullptr, &chain)) {
        CertFreeCertificateContext(cert);
        return false;
    }

    // Check trust status
    bool trusted = (chain->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);

    // Verify hostname
    if (trusted && !config_.hostname.empty()) {
        // Simple CN check (production should use SAN)
        std::string cn;
        size_t pos = certSubject_.find("CN=");
        if (pos != std::string::npos) {
            cn = certSubject_.substr(pos + 3);
            size_t end = cn.find(',');
            if (end != std::string::npos) cn = cn.substr(0, end);
        }
        if (cn != config_.hostname && cn.find("*.") != 0) {
            trusted = false;
        }
    }

    CertFreeCertificateChain(chain);
    CertFreeCertificateContext(cert);
    return trusted;
#else
    return false;
#endif
}

bool SchannelTls::send(const uint8_t* data, size_t len) {
#ifdef _WIN32
    if (!connected_) return false;

    // Encrypt and send in chunks
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = std::min(len - offset, static_cast<size_t>(sizes_.cbMaximumMessage));

        std::vector<uint8_t> buf(sizes_.cbHeader + chunk + sizes_.cbTrailer);
        memcpy(buf.data() + sizes_.cbHeader, data + offset, chunk);

        SecBuffer bufs[4] = {};
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer = buf.data();
        bufs[0].cbBuffer = sizes_.cbHeader;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = buf.data() + sizes_.cbHeader;
        bufs[1].cbBuffer = static_cast<ULONG>(chunk);
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer = buf.data() + sizes_.cbHeader + chunk;
        bufs[2].cbBuffer = sizes_.cbTrailer;
        bufs[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc = {SECBUFFER_VERSION, 4, bufs};

        SECURITY_STATUS status = EncryptMessage(&ctxtHandle_, 0, &desc, 0);
        if (status != SEC_E_OK) return false;

        size_t total = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        if (!sendRaw(buf.data(), total)) return false;

        offset += chunk;
    }
    return true;
#else
    (void)data; (void)len;
    return false;
#endif
}

std::optional<std::vector<uint8_t>> SchannelTls::recv(size_t maxLen) {
#ifdef _WIN32
    if (!connected_) return std::nullopt;

    std::vector<uint8_t> result;
    std::vector<uint8_t> buf(16384);
    size_t bufLen = 0;

    while (result.size() < maxLen) {
        // Receive more data
        int n = recvRaw(buf.data() + bufLen, buf.size() - bufLen);
        if (n <= 0 && result.empty()) return std::nullopt;
        if (n > 0) bufLen += n;

        // Decrypt
        SecBuffer bufs[4] = {};
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = buf.data();
        bufs[0].cbBuffer = static_cast<ULONG>(bufLen);
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc = {SECBUFFER_VERSION, 4, bufs};

        SECURITY_STATUS status = DecryptMessage(&ctxtHandle_, &desc, 0, nullptr);

        if (status == SEC_E_OK) {
            // Find data buffer
            for (int i = 0; i < 4; ++i) {
                if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                    result.insert(result.end(),
                        static_cast<uint8_t*>(bufs[i].pvBuffer),
                        static_cast<uint8_t*>(bufs[i].pvBuffer) + bufs[i].cbBuffer);
                }
            }
            // Handle extra
            for (int i = 0; i < 4; ++i) {
                if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer > 0) {
                    memmove(buf.data(), bufs[i].pvBuffer, bufs[i].cbBuffer);
                    bufLen = bufs[i].cbBuffer;
                    break;
                }
            }
            if (result.size() >= maxLen) break;
        } else if (status == SEC_E_INCOMPLETE_MESSAGE) {
            continue;  // Need more data
        } else {
            break;
        }
    }

    return result.empty() ? std::nullopt : std::optional(result);
#else
    (void)maxLen;
    return std::nullopt;
#endif
}

void SchannelTls::disconnect() {
#ifdef _WIN32
    if (hasCtxt_) {
        DeleteSecurityContext(&ctxtHandle_);
        hasCtxt_ = false;
    }
    if (hasCred_) {
        FreeCredentialsHandle(&credHandle_);
        hasCred_ = false;
    }
#endif
    connected_ = false;
    socket_ = INVALID_SOCKET;
}

bool SchannelTls::sendRaw(const void* data, size_t len) {
#ifdef _WIN32
    const char* p = static_cast<const char*>(data);
    size_t sent = 0;
    while (sent < len) {
        int n = ::send(socket_, p + sent, static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
#else
    (void)data; (void)len;
    return false;
#endif
}

int SchannelTls::recvRaw(void* data, size_t len) {
#ifdef _WIN32
    return ::recv(socket_, static_cast<char*>(data), static_cast<int>(len), 0);
#else
    (void)data; (void)len;
    return -1;
#endif
}

} // namespace aifw
