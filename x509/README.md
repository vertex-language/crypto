# crypto/x509

Parses X.509 certificates (RFC 5280) far enough for a TLS client and RDP: the RSA public key, the validity window, the subject common name and DNS SANs, and the pieces needed to verify the certificate's signature.

```vertex
import "crypto/x509"
```

## Types

- **`X509Error`** (enum)
- **`SignatureAlgorithm`** (enum): SignatureAlgorithm identifies how a certificate was signed.
- **`Certificate`** (struct): Certificate holds the parsed fields a TLS/RDP client uses.

## Functions

- `func Parse(_ der: [uint8]) throws -> Certificate`: Parse reads one DER-encoded certificate.
- `func VerifySignedBy(_ cert: Certificate, _ issuerKey: rsa.PublicKey) throws`: VerifySignedBy checks this certificate's signature against an issuer's RSA public key. For a self-signed certificate the issuer is itself.
- `func FingerprintSHA256(_ der: [uint8]) -> [uint8]`: FingerprintSHA256 is the SHA-256 of the whole certificate DER, for pinning and trust-on-first-use display.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
