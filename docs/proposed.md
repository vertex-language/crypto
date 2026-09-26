# Vertex Crypto: Standard Cryptographic Library

A unified architectural design and inventory for `vertex-language/crypto`, establishing a pure-memory, Golang-style directory package layout for Vertex cryptography leading to TLS 1.3 and `net/https`.

---

## 1. Core Architecture & Design Principles

### Single Domain Repository (`vertex-language/crypto`)
Rather than fracturing cryptography across 20+ micro-repositories, all standard cryptographic packages live in a **single domain repository**:
```
https://github.com/vertex-language/crypto
```

### Pure Folder-Based Packages (Golang Style)
Vertex supports folder-based package resolution without manifest files:
- **No manifest**: Because cryptographic algorithms are pure mathematical transformations on in-memory byte buffers (`[uint8]`), each folder is a package of pure `.vs` source, and a `vs.mod` at the repository root names the module.
- **Top-level package declarations**: Each folder contains `.vs` files starting with `package <name>`.
- **URL path mapping**:
  ```swift
  import "crypto/sha256"  // Resolves to crypto/sha256/
  import "crypto/aes"     // Resolves to crypto/aes/
  import "crypto/tls"     // Resolves to crypto/tls/
  ```

### Why Crypto is Purely Memory-Based
Cryptography does not manage operating system file descriptors, event queues (`kqueue`/`epoll`), or hardware devices. It is **purely in-memory**:
- **Inputs**: Byte buffers (`[uint8]`), keys, nonces, and parameters.
- **Operations**: Bitwise rotations (`ROTR`/`ROTL`), XOR, modular arithmetic, S-Box lookups, and finite field operations.
- **Outputs**: Hash digests, ciphertexts, authentication tags, and shared secrets.

The **only** operating system touchpoint in the entire hierarchy is gathering initial seed entropy for **`crypto/rand`** (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows). Once random bytes are gathered, everything else up to a complete TLS 1.3 handshake is 100% in-memory buffer processing.

---

## 2. Directory Layout of `vertex-language/crypto`

```
crypto/
├── README.md
├── LICENSE
├── docs/
│   └── proposed.md
│
├── subtle/                  # Constant-time comparison & operations
│   └── subtle.vs            # ConstantTimeCompare, ConstantTimeByteEq
│
├── rand/                    # CSPRNG secure random entropy
│   └── rand.vs              # Read(into buffer: inout [uint8])
│
├── sha256/                  # SHA-256 and SHA-224 (FIPS 180-4)
│   ├── sha256.vs
│   └── sha224.vs
│
├── sha512/                  # SHA-384, SHA-512, SHA-512/256
│   └── sha512.vs
│
├── hmac/                    # Keyed-Hash Message Authentication Code (RFC 2104)
│   └── hmac.vs
│
├── hkdf/                    # HMAC-based Key Derivation Function (RFC 5869)
│   └── hkdf.vs
│
├── aes/                     # Advanced Encryption Standard (FIPS 197)
│   ├── aes.vs
│   └── block.vs
│
├── cipher/                  # Stream ciphers & AEAD interfaces (GCM, CBC, CTR)
│   ├── cipher.vs
│   ├── gcm.vs
│   └── ctr.vs
│
├── chacha20/                # ChaCha20 stream cipher (RFC 8439)
│   └── chacha20.vs
│
├── poly1305/                # Poly1305 one-time authenticator (RFC 8439)
│   └── poly1305.vs
│
├── chacha20poly1305/        # Combined AEAD cipher suite for TLS 1.3
│   └── chacha20poly1305.vs
│
├── curve25519/              # Montgomery curve X25519 (RFC 7748)
│   └── curve25519.vs
│
├── ecdh/                    # Elliptic Curve Diffie-Hellman key agreement
│   └── ecdh.vs
│
├── ecdsa/                   # Elliptic Curve Digital Signatures (P-256, P-384)
│   └── ecdsa.vs
│
├── ed25519/                 # Ed25519 signature algorithm (RFC 8032)
│   └── ed25519.vs
│
├── rsa/                     # RSA signatures & OAEP encryption
│   └── rsa.vs
│
├── asn1/                    # ASN.1 DER parser & serializer
│   └── asn1.vs
│
├── pem/                     # PEM armor decoder (-----BEGIN CERTIFICATE-----)
│   └── pem.vs
│
├── x509/                    # X.509 certificate parsing & chain validation
│   ├── cert.vs
│   ├── chain.vs
│   └── roots.vs
│
└── tls/                     # TLS 1.3 & 1.2 client & server state machines
    ├── tls.vs
    ├── conn.vs
    ├── handshake.vs
    ├── record.vs
    └── key_schedule.vs
```

---

## 3. Go Standard Library Inventory & Vertex Mapping

All packages map to clean subdirectories inside `vertex-language/crypto`:

| Go Package | Vertex Import | Vertex Directory | Description | Role in `net/https` |
| :--- | :--- | :--- | :--- | :--- |
| `crypto/subtle` | `"crypto/subtle"` | `crypto/subtle/` | Constant-time slice/byte equality checks | **Required** (Prevents timing attacks) |
| `crypto/rand` | `"crypto/rand"` | `crypto/rand/` | Cryptographically secure random bytes | **Required** (Keys, nonces, IVs) |
| `crypto/sha256` | `"crypto/sha256"` | `crypto/sha256/` | SHA-256 and SHA-224 cryptographic hash | **Required** (TLS 1.3 & Certificates) |
| `crypto/sha512` | `"crypto/sha512"` | `crypto/sha512/` | SHA-384 and SHA-512 cryptographic hash | **Required** (TLS 1.3 Suite 2) |
| `crypto/hmac` | `"crypto/hmac"` | `crypto/hmac/` | Hash-based message authentication code | **Required** (Key derivation & Finished tags) |
| `golang.org/x/crypto/hkdf` | `"crypto/hkdf"` | `crypto/hkdf/` | Extract-and-Expand Key Derivation (RFC 5869) | **Required** (TLS 1.3 key schedule) |
| `crypto/aes` | `"crypto/aes"` | `crypto/aes/` | AES-128 and AES-256 block cipher | **Required** (Bulk record encryption) |
| `crypto/cipher` | `"crypto/cipher"` | `crypto/cipher/` | AEAD interface and GCM mode (GHASH) | **Required** (`TLS_AES_128_GCM_SHA256`) |
| `golang.org/x/crypto/chacha20` | `"crypto/chacha20"` | `crypto/chacha20/` | ChaCha20 stream cipher engine | **Required** |
| `golang.org/x/crypto/poly1305` | `"crypto/poly1305"` | `crypto/poly1305/` | Poly1305 128-bit MAC engine | **Required** |
| `crypto/chacha20poly1305` | `"crypto/chacha20poly1305"` | `crypto/chacha20poly1305/` | ChaCha20-Poly1305 AEAD cipher | **Required** (`TLS_CHACHA20_POLY1305_SHA256`) |
| `golang.org/x/crypto/curve25519`| `"crypto/curve25519"`| `crypto/curve25519/` | Montgomery curve X25519 scalar multiplication | **Required** (Modern TLS 1.3 Key Exchange) |
| `crypto/ecdh` | `"crypto/ecdh"` | `crypto/ecdh/` | ECDH key agreement over X25519 / P-256 | **Required** (Client/Server key share) |
| `crypto/ecdsa` | `"crypto/ecdsa"` | `crypto/ecdsa/` | ECDSA signature verification | **Required** (Web certificate validation) |
| `crypto/ed25519` | `"crypto/ed25519"` | `crypto/ed25519/` | Ed25519 signature algorithm | **Required** (Modern signatures) |
| `crypto/rsa` | `"crypto/rsa"` | `crypto/rsa/` | RSA PKCS#1 v1.5 and PSS signatures | **Required** (Legacy / enterprise certificates) |
| `encoding/asn1` | `"crypto/asn1"` | `crypto/asn1/` | ASN.1 DER parser for certificates | **Required** (X.509 decoding) |
| `encoding/pem` | `"crypto/pem"` | `crypto/pem/` | PEM block decoder (`-----BEGIN ...-----`) | **Required** (Certificate file reading) |
| `crypto/x509` | `"crypto/x509"` | `crypto/x509/` | X.509 certificate parsing & trust chain | **Required** (Server identity verification) |
| `crypto/tls` | `"crypto/tls"` | `crypto/tls/` | TLS 1.3 / 1.2 client & server engine | **Required** (Encrypted streams over `net/tcp`) |

---

## 4. The Phased Path to `net/https`

```
Phase 1: Bedrock Primitives
  crypto/subtle  ->  Constant-time operations
  crypto/rand    ->  CSPRNG system entropy

Phase 2: Hashes & Key Schedule
  crypto/sha256  ->  SHA-256 / SHA-224
  crypto/sha512  ->  SHA-384 / SHA-512
  crypto/hmac    ->  Keyed HMAC
  crypto/hkdf    ->  HKDF extract/expand (TLS 1.3 key schedule)

Phase 3: Symmetric AEAD Ciphers
  crypto/aes + crypto/cipher  ->  AES-GCM (GHASH)
  crypto/chacha20poly1305     ->  ChaCha20-Poly1305 AEAD

Phase 4: Key Agreement & Signatures
  crypto/curve25519 + ecdh    ->  X25519 key exchange
  crypto/ecdsa, rsa, ed25519  ->  Signature verification

Phase 5: Certificates & PKI
  crypto/asn1, crypto/pem     ->  DER / PEM decoding
  crypto/x509                 ->  Certificate chain verification

Phase 6: TLS Transport Security
  crypto/tls                  ->  TLS 1.3 client stream wrapping net.TcpStream

Phase 7: HTTPS Client & Server
  net/https                   ->  Full HTTPS client (net/tcp + crypto/tls + HTTP/1.1)
```

---

## 5. Security & Memory Safety Rules for Vertex Crypto

1. **No External Allocators in Inner Loops**: Ciphers and hashes operate on user-provided buffers (`inout [uint8]`) or fixed-size value arrays to prevent unnecessary heap allocation and GC churn.
2. **Constant-Time Verification**: Any check involving secrets (MAC verification, signature hashes, padding checks) MUST use `subtle.ConstantTimeCompare` to avoid timing side-channels.
3. **Sensitive Memory Zeroing**: Key buffers, secrets, and intermediate state structures should provide an explicit `.Wipe()` or `.Zero()` method executed via `defer`.
