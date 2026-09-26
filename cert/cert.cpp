// The system's certificate trust, for package cert.
//
// Two questions only, both answered by the operating system: does this
// chain lead to a root the system trusts, for this host name, today? And
// does this signature verify under this certificate's public key? The OS
// already builds paths, honours the user's and the administrator's trust
// settings, checks validity and names, and knows ECDSA, RSA-PSS and the
// rest, so none of that is written again here.
//
//   Darwin:  Security.framework (SecTrust, SecKey)
//   Windows: crypt32 (CertGetCertificateChain, the SSL chain policy) and
//            CNG (BCryptVerifySignature)
//   Android: not yet: its trust store is reached through Java
module;
#include <stdint.h>
#include <string_view>
export module crypto.cert;

// The results, as the Vertex side names them.
export namespace Code {
    constexpr int32_t ok = 0;
    constexpr int32_t untrusted = -1;    // no path to a trusted root
    constexpr int32_t nameMismatch = -2; // the leaf is not for this host
    constexpr int32_t expired = -3;      // outside its validity period
    constexpr int32_t badSignature = -4; // the signature does not verify
    constexpr int32_t unsupported = -5;  // this platform, or this scheme
    constexpr int32_t invalid = -6;      // a certificate that does not parse
}

// certVerifyChain checks a chain: count certificates, DER, concatenated in
// ders with their lengths in lengths, the server's own first. host is the
// name the client asked for; empty checks the chain without a name.
export int32_t certVerifyChain(const uint8_t* ders, const int64_t* lengths, int32_t count,
                               std::string_view host) noexcept;

// certVerifySignature checks signature over data with the public key of
// the DER certificate, by TLS SignatureScheme: 0x0401/0x0501/0x0601 RSA
// PKCS#1 v1.5 with SHA-256/384/512, 0x0804/0x0805/0x0806 RSA-PSS with
// SHA-256/384/512, 0x0403/0x0503/0x0603 ECDSA P-256/P-384/P-521.
export int32_t certVerifySignature(const uint8_t* der, int64_t derLength, int32_t scheme,
                                   const uint8_t* data, int64_t dataLength,
                                   const uint8_t* signature, int64_t signatureLength) noexcept;

// certLastError copies the system's words for the calling thread's last
// failure into out, up to capacity bytes, and returns how many it wrote.
export int64_t certLastError(uint8_t* out, int64_t capacity) noexcept;
