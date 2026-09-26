// The system's certificate trust on Darwin: see cert.cpp.
module;
#include <stdint.h>
#include <string.h>
#include <string_view>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#pragma vertex framework("CoreFoundation")
#pragma vertex framework("Security")
module crypto.cert;

namespace {

thread_local char lastError[512];

void setError(const char* text) noexcept {
    strncpy(lastError, text, sizeof lastError - 1);
    lastError[sizeof lastError - 1] = 0;
}

// setErrorFrom keeps the system's description of err.
void setErrorFrom(CFErrorRef err) noexcept {
    lastError[0] = 0;
    if (!err) {
        return;
    }
    CFStringRef desc = CFErrorCopyDescription(err);
    if (desc) {
        CFStringGetCString(desc, lastError, sizeof lastError, kCFStringEncodingUTF8);
        CFRelease(desc);
    }
}

SecCertificateRef certificateOf(const uint8_t* der, int64_t length) noexcept {
    CFDataRef data = CFDataCreate(nullptr, der, (CFIndex)length);
    if (!data) {
        return nullptr;
    }
    SecCertificateRef cert = SecCertificateCreateWithData(nullptr, data);
    CFRelease(data);
    return cert;
}

// codeOf reads a trust failure's OSStatus as one of Code's.
int32_t codeOf(CFErrorRef err) noexcept {
    switch (CFErrorGetCode(err)) {
    case errSecCertificateExpired:
    case errSecCertificateNotValidYet:
        return Code::expired;
    case errSecHostNameMismatch:
        return Code::nameMismatch;
    default:
        return Code::untrusted;
    }
}

SecKeyAlgorithm algorithmFor(int32_t scheme) noexcept {
    switch (scheme) {
    case 0x0401: return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    case 0x0501: return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
    case 0x0601: return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
    case 0x0804: return kSecKeyAlgorithmRSASignatureMessagePSSSHA256;
    case 0x0805: return kSecKeyAlgorithmRSASignatureMessagePSSSHA384;
    case 0x0806: return kSecKeyAlgorithmRSASignatureMessagePSSSHA512;
    case 0x0403: return kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
    case 0x0503: return kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
    case 0x0603: return kSecKeyAlgorithmECDSASignatureMessageX962SHA512;
    }
    return nullptr;
}

} // namespace

int32_t certVerifyChain(const uint8_t* ders, const int64_t* lengths, int32_t count,
                        std::string_view host) noexcept {
    if (count <= 0) {
        setError("no certificates");
        return Code::invalid;
    }
    CFMutableArrayRef chain = CFArrayCreateMutable(nullptr, count, &kCFTypeArrayCallBacks);
    const uint8_t* at = ders;
    for (int32_t i = 0; i < count; i++) {
        SecCertificateRef cert = certificateOf(at, lengths[i]);
        if (!cert) {
            CFRelease(chain);
            setError("a certificate in the chain does not parse");
            return Code::invalid;
        }
        CFArrayAppendValue(chain, cert);
        CFRelease(cert);
        at += lengths[i];
    }
    CFStringRef name = nullptr;
    if (!host.empty()) {
        name = CFStringCreateWithBytes(nullptr, (const UInt8*)host.data(), (CFIndex)host.size(),
                                       kCFStringEncodingUTF8, false);
    }
    SecPolicyRef policy = SecPolicyCreateSSL(true, name);
    SecTrustRef trust = nullptr;
    OSStatus status = SecTrustCreateWithCertificates(chain, policy, &trust);
    int32_t result = Code::ok;
    if (status != errSecSuccess || !trust) {
        setError("the system could not evaluate the chain");
        result = Code::untrusted;
    } else {
        CFErrorRef err = nullptr;
        if (!SecTrustEvaluateWithError(trust, &err)) {
            setErrorFrom(err);
            result = err ? codeOf(err) : Code::untrusted;
            if (err) {
                CFRelease(err);
            }
        }
        CFRelease(trust);
    }
    CFRelease(policy);
    if (name) {
        CFRelease(name);
    }
    CFRelease(chain);
    return result;
}

int32_t certVerifySignature(const uint8_t* der, int64_t derLength, int32_t scheme,
                            const uint8_t* data, int64_t dataLength,
                            const uint8_t* signature, int64_t signatureLength) noexcept {
    SecKeyAlgorithm algorithm = algorithmFor(scheme);
    if (!algorithm) {
        setError("the signature scheme is not supported");
        return Code::unsupported;
    }
    SecCertificateRef cert = certificateOf(der, derLength);
    if (!cert) {
        setError("the certificate does not parse");
        return Code::invalid;
    }
    SecKeyRef key = SecCertificateCopyKey(cert);
    CFRelease(cert);
    if (!key) {
        setError("the certificate's public key is not one the system reads");
        return Code::unsupported;
    }
    int32_t result = Code::ok;
    if (!SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeVerify, algorithm)) {
        setError("the signature scheme does not fit the certificate's key");
        result = Code::badSignature;
    } else {
        CFDataRef message = CFDataCreate(nullptr, data, (CFIndex)dataLength);
        CFDataRef sig = CFDataCreate(nullptr, signature, (CFIndex)signatureLength);
        CFErrorRef err = nullptr;
        if (!SecKeyVerifySignature(key, algorithm, message, sig, &err)) {
            setErrorFrom(err);
            result = Code::badSignature;
            if (err) {
                CFRelease(err);
            }
        }
        CFRelease(sig);
        CFRelease(message);
    }
    CFRelease(key);
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
