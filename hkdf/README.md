# crypto/hkdf

HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).

```vertex
import "crypto/hkdf"
```

## Functions

- `func Extract(hash: hmac.HashAlgorithm = .sha256, secret: [uint8], salt: [uint8] = []) -> [uint8]`: Extract generates a pseudorandom key (PRK) from the input keying material (secret) and an optional salt according to RFC 5869 Section 2.2.
- `func Expand(hash: hmac.HashAlgorithm = .sha256, prk: [uint8], info: [uint8], length: int) -> [uint8]`: Expand expands the pseudorandom key (PRK) using info and requested output length according to RFC 5869 Section 2.3.
- `func Expand(hash: hmac.HashAlgorithm = .sha256, prk: [uint8], info: string, length: int) -> [uint8]`: Expand expands the pseudorandom key (PRK) using a string info.
- `func DeriveKey(hash: hmac.HashAlgorithm = .sha256, secret: [uint8], salt: [uint8] = [], info: [uint8] = [], length: int) -> [uint8]`: DeriveKey combines Extract and Expand into a single step.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
