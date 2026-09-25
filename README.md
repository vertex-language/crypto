# crypto

[![package: vs-package](https://img.shields.io/badge/package-vs--package-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language)
[![crypto: tls1.3-ready](https://img.shields.io/badge/crypto-tls1.3--ready-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language/crypto)

Cryptographic library providing in-memory cryptographic primitives, secure random entropy, hash algorithms, authenticated ciphers, and key exchange up to TLS 1.3.

---

## Packages

All packages in this repository are organized as directory packages (`crypto/<pkg>`):

- **`crypto/subtle`**: Constant-time comparison routines to prevent timing side-channel attacks (`subtle.ConstantTimeCompare`).
- **`crypto/rand`**: Cryptographically secure pseudorandom entropy from the OS CSPRNG (`rand.Read`, `rand.Bytes`).
- **`crypto/sha256`**: SHA-256 and SHA-224 hash functions (`sha256.Sum256`, `sha256.New`, `sha256.ToHex`).
- **`crypto/sha512`**: SHA-384, SHA-512, and SHA-512/256 hash functions.
- **`crypto/hmac`**: Keyed-Hash Message Authentication Code (RFC 2104).
- **`crypto/hkdf`**: HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
- **`crypto/aes`**: Advanced Encryption Standard block cipher (FIPS 197).
- **`crypto/cipher`**: AEAD interfaces and cipher modes (GCM, CBC, CTR).
- **`crypto/chacha20`**: ChaCha20 stream cipher (RFC 8439).
- **`crypto/poly1305`**: Poly1305 128-bit one-time authenticator (RFC 8439).
- **`crypto/chacha20poly1305`**: ChaCha20-Poly1305 AEAD construction (RFC 8439).
- **`crypto/curve25519`**: X25519 Montgomery curve scalar multiplication (RFC 7748).
- **`crypto/ecdh`**: Elliptic Curve Diffie-Hellman key exchange (X25519, P-256, P-384).
- **`crypto/ed25519`**: Ed25519 digital signature algorithm (RFC 8032).
- **`crypto/ecdsa`**: Elliptic Curve Digital Signature Algorithm (FIPS 186-4).
- **`crypto/rsa`**: RSA PKCS #1 v1.5 and PSS signatures / OAEP encryption.
- **`crypto/tls`**: Transport Layer Security 1.3 client and server implementation (RFC 8446).
- **`crypto/x509`**: X.509 public key certificates, CRLs, and trust chain validation.

For the comprehensive design document and Golang equivalence map, see [docs/proposed.md](docs/proposed.md).

---

## Quick Start

Run any entry point with:

```bash
vsc run main.vs
```

### SHA-256 Digest

```swift
package main

import "crypto/sha256"

func main() -> int32 {
    let data = "hello vertex crypto"
    let digest = sha256.Sum256(data)
    print("SHA-256: \(sha256.ToHex(digest))")
    return 0
}
```

### HMAC-SHA256 & HKDF Key Derivation

```swift
package main

import "crypto/hmac"
import "crypto/hkdf"
import "crypto/sha256"

func main() -> int32 {
    let secret = [uint8](repeating: 0x42, count: 32)
    let message = "vertex authenticated data"

    let mac = hmac.Compute(key: secret, message: message, hash: .sha256)
    print("HMAC: \(sha256.ToHex(mac))")

    // Derive 32 bytes of TLS 1.3 traffic secret
    let prk = hkdf.Extract(hash: .sha256, secret: secret, salt: [])
    let derivedKey = hkdf.Expand(hash: .sha256, prk: prk, info: "tls13 client in", length: 32)
    print("Derived Key: \(sha256.ToHex(derivedKey))")
    return 0
}
```

---

## Testing

Run the test suite across all cryptographic packages:

```bash
# Run all crypto tests
vsc run tests/all/main.vs

# Run individual package test suites
vsc run tests/subtle/main.vs
vsc run tests/rand/main.vs
vsc run tests/sha256/main.vs
vsc run tests/hmac/main.vs
vsc run tests/hkdf/main.vs
```

---

## License

[MIT](LICENSE)
