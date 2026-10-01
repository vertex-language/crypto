# crypto/cert

Answers two questions with the operating system's own certificate trust: does a server's chain lead to a root this machine trusts, for the host the client asked for; and does a signature verify under a certificate's public key.

```vertex
import "crypto/cert"
```

## Types

- **`CertError`** (enum): CertError is why a chain or a signature was refused, with the system's own words for it.
- **`Scheme`** (enum): Scheme is a TLS SignatureScheme (RFC 8446 §4.2.3): what a signature is and the hash it is over.

## Functions

- `func VerifyChain(_ chain: [[uint8]], host: string) throws`: VerifyChain checks a certificate chain, DER-encoded and the server's own certificate first, against the system's trusted roots and today's date, and that the first is for host.
- `func VerifySignature(certificate: [uint8], scheme: uint16, data: [uint8], signature: [uint8]) throws`: VerifySignature checks signature over data with the public key of certificate, a DER certificate, by TLS signature scheme (see Scheme).

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
