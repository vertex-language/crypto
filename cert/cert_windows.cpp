// The system's certificate trust on Windows: see cert.cpp.
module;
#include <stdint.h>
#include <string.h>
#include <string_view>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "crypt32")
#pragma comment(lib, "bcrypt")
module crypto.cert;

namespace {

thread_local char lastError[512];

void setError(const char* text) noexcept {
    strncpy(lastError, text, sizeof lastError - 1);
    lastError[sizeof lastError - 1] = 0;
}

void setErrorFrom(DWORD code) noexcept {
    lastError[0] = 0;
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
                             lastError, sizeof lastError, nullptr);
    while (n > 0 && (lastError[n - 1] == '\r' || lastError[n - 1] == '\n' || lastError[n - 1] == '.')) {
        lastError[--n] = 0;
    }
}

int32_t codeOf(DWORD error) noexcept {
    switch (error) {
    case CERT_E_EXPIRED:
    case CERT_E_VALIDITYPERIODNESTING:
        return Code::expired;
    case CERT_E_CN_NO_MATCH:
        return Code::nameMismatch;
    }
    return Code::untrusted;
}

// A hash CNG knows, by the TLS scheme's hash.
struct Hash {
    LPCWSTR algorithm;
    ULONG length;
};

bool hashFor(int32_t scheme, Hash* h) noexcept {
    switch (scheme >> 8) {
    case 0x04: *h = {BCRYPT_SHA256_ALGORITHM, 32}; return true;
    case 0x05: *h = {BCRYPT_SHA384_ALGORITHM, 48}; return true;
    case 0x06: *h = {BCRYPT_SHA512_ALGORITHM, 64}; return true;
    case 0x08:
        switch (scheme & 0xff) {
        case 0x04: *h = {BCRYPT_SHA256_ALGORITHM, 32}; return true;
        case 0x05: *h = {BCRYPT_SHA384_ALGORITHM, 48}; return true;
        case 0x06: *h = {BCRYPT_SHA512_ALGORITHM, 64}; return true;
        }
    }
    return false;
}

bool digest(const Hash& h, const uint8_t* data, int64_t length, uint8_t* out) noexcept {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, h.algorithm, nullptr, 0) != 0) {
        return false;
    }
    NTSTATUS status = BCryptHash(alg, nullptr, 0, (PUCHAR)data, (ULONG)length, out, h.length);
    BCryptCloseAlgorithmProvider(alg, 0);
    return status == 0;
}

// derLength reads a DER length at *p, moving past it.
bool derLength(const uint8_t*& p, const uint8_t* end, size_t* n) noexcept {
    if (p >= end) {
        return false;
    }
    uint8_t b = *p++;
    if (b < 0x80) {
        *n = b;
        return true;
    }
    int bytes = b & 0x7f;
    if (bytes == 0 || bytes > 2 || end - p < bytes) {
        return false;
    }
    size_t v = 0;
    while (bytes-- > 0) {
        v = v << 8 | *p++;
    }
    *n = v;
    return true;
}

// rawECDSA turns an X9.62 signature, SEQUENCE { r INTEGER, s INTEGER }, into
// the fixed-width r || s CNG verifies.
bool rawECDSA(const uint8_t* sig, int64_t length, size_t width, uint8_t* out) noexcept {
    const uint8_t* p = sig;
    const uint8_t* end = sig + length;
    size_t n;
    if (p >= end || *p++ != 0x30 || !derLength(p, end, &n) || (size_t)(end - p) != n) {
        return false;
    }
    for (int i = 0; i < 2; i++) {
        if (p >= end || *p++ != 0x02 || !derLength(p, end, &n) || (size_t)(end - p) < n) {
            return false;
        }
        const uint8_t* v = p;
        p += n;
        while (n > 0 && *v == 0) {
            v++;
            n--;
        }
        if (n > width) {
            return false;
        }
        memset(out + i * width, 0, width - n);
        memcpy(out + i * width + (width - n), v, n);
    }
    return p == end;
}

} // namespace

int32_t certVerifyChain(const uint8_t* ders, const int64_t* lengths, int32_t count,
                        std::string_view host) noexcept {
    if (count <= 0) {
        setError("no certificates");
        return Code::invalid;
    }
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    PCCERT_CONTEXT leaf = nullptr;
    const uint8_t* at = ders;
    for (int32_t i = 0; i < count; i++) {
        PCCERT_CONTEXT added = nullptr;
        if (!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, at, (DWORD)lengths[i],
                                              CERT_STORE_ADD_ALWAYS, i == 0 ? &leaf : &added)) {
            if (leaf) {
                CertFreeCertificateContext(leaf);
            }
            CertCloseStore(store, 0);
            setError("a certificate in the chain does not parse");
            return Code::invalid;
        }
        if (added) {
            CertFreeCertificateContext(added);
        }
        at += lengths[i];
    }

    CERT_CHAIN_PARA para = {};
    para.cbSize = sizeof para;
    PCCERT_CHAIN_CONTEXT chain = nullptr;
    int32_t result = Code::ok;
    if (!CertGetCertificateChain(nullptr, leaf, nullptr, store, &para, 0, nullptr, &chain)) {
        setErrorFrom(GetLastError());
        result = Code::untrusted;
    } else {
        wchar_t name[256] = {};
        if (!host.empty()) {
            MultiByteToWideChar(CP_UTF8, 0, host.data(), (int)host.size(), name, 255);
        }
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl = {};
        ssl.cbSize = sizeof ssl;
        ssl.dwAuthType = AUTHTYPE_SERVER;
        ssl.pwszServerName = host.empty() ? nullptr : name;
        CERT_CHAIN_POLICY_PARA policy = {};
        policy.cbSize = sizeof policy;
        policy.pvExtraPolicyPara = &ssl;
        CERT_CHAIN_POLICY_STATUS status = {};
        status.cbSize = sizeof status;
        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy, &status)) {
            setErrorFrom(GetLastError());
            result = Code::untrusted;
        } else if (status.dwError != 0) {
            setErrorFrom(status.dwError);
            result = codeOf(status.dwError);
        }
        CertFreeCertificateChain(chain);
    }
    CertFreeCertificateContext(leaf);
    CertCloseStore(store, 0);
    return result;
}

int32_t certVerifySignature(const uint8_t* der, int64_t derLength, int32_t scheme,
                            const uint8_t* data, int64_t dataLength,
                            const uint8_t* signature, int64_t signatureLength) noexcept {
    Hash h;
    if (!hashFor(scheme, &h)) {
        setError("the signature scheme is not supported");
        return Code::unsupported;
    }
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, der, (DWORD)derLength);
    if (!cert) {
        setError("the certificate does not parse");
        return Code::invalid;
    }
    BCRYPT_KEY_HANDLE key = nullptr;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, &key)) {
        CertFreeCertificateContext(cert);
        setError("the certificate's public key is not one the system reads");
        return Code::unsupported;
    }
    CertFreeCertificateContext(cert);

    uint8_t hashed[64];
    int32_t result = Code::ok;
    NTSTATUS status = 0;
    if (!digest(h, data, dataLength, hashed)) {
        setError("the system could not hash the message");
        result = Code::unsupported;
    } else if ((scheme & 0xff) == 0x03) {
        size_t width = scheme == 0x0403 ? 32 : scheme == 0x0503 ? 48 : 66;
        uint8_t raw[132];
        if (!rawECDSA(signature, signatureLength, width, raw)) {
            setError("the ECDSA signature does not parse");
            result = Code::badSignature;
        } else {
            status = BCryptVerifySignature(key, nullptr, hashed, h.length, raw, (ULONG)(2 * width), 0);
        }
    } else if ((scheme >> 8) == 0x08) {
        BCRYPT_PSS_PADDING_INFO pss = {h.algorithm, h.length};
        status = BCryptVerifySignature(key, &pss, hashed, h.length, (PUCHAR)signature,
                                       (ULONG)signatureLength, BCRYPT_PAD_PSS);
    } else {
        BCRYPT_PKCS1_PADDING_INFO pkcs1 = {h.algorithm};
        status = BCryptVerifySignature(key, &pkcs1, hashed, h.length, (PUCHAR)signature,
                                       (ULONG)signatureLength, BCRYPT_PAD_PKCS1);
    }
    if (result == Code::ok && status != 0) {
        setError("the signature does not verify");
        result = Code::badSignature;
    }
    BCryptDestroyKey(key);
    return result;
}

int64_t certLastError(uint8_t* out, int64_t capacity) noexcept {
    int64_t n = (int64_t)strlen(lastError);
    if (n > capacity) {
        n = capacity;
    }
    memcpy(out, lastError, (size_t)n);
    return n;
}
