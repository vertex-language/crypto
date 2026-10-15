# crypto/x509

Parses X.509 certificates (RFC 5280) and verifies chains of them to a pool of trusted roots, for a TLS client and RDP: RSA and ECDSA (P-256, P-384, P-521) keys and signatures, the validity window, the names, and the extensions a path validator needs.

```vertex
import "crypto/x509"
```

## Types

- **`X509Error`** (enum)
- **`SignatureAlgorithm`** (enum): SignatureAlgorithm identifies how a certificate was signed.
- **`Certificate`** (struct): Certificate holds the parsed fields a TLS/RDP client uses.
- **`CertPool`** (struct): CertPool is a set of trusted root certificates.
- **`VerifyOptions`** (struct): VerifyOptions is what Verify checks a certificate against.
- **`VerifyError`** (enum)

## Functions

- `func Parse(_ der: [uint8]) throws -> Certificate`: Parse reads one DER-encoded certificate.
- `func Verify(_ leaf: Certificate, _ opts: VerifyOptions) throws -> [Certificate]`: Verify checks leaf against opts and returns the path it verified, leaf first and the root last.
- `func VerifyHostname(_ c: Certificate, _ host: string) throws`: VerifyHostname checks that c is for host: one of its DNS names matches it, or for an IP address, one of its IP address names is it.
- `func CheckSignatureFrom(_ cert: Certificate, _ parent: Certificate) throws`: CheckSignatureFrom checks that parent's key signed cert, by an algorithm fit for the web today.
- `func VerifySignedBy(_ cert: Certificate, _ issuerKey: rsa.PublicKey) throws`: VerifySignedBy checks this certificate's signature against an issuer's RSA public key.
- `func FingerprintSHA256(_ der: [uint8]) -> [uint8]`: FingerprintSHA256 is the SHA-256 of the whole certificate DER, for pinning and trust-on-first-use display.
- and 1 more

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
