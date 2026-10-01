# crypto/hmac

Keyed-Hash Message Authentication Code (RFC 2104).

```vertex
import "crypto/hmac"
```

## Types

- **`HashAlgorithm`** (enum)

## Functions

- `func Compute(key: [uint8], message: [uint8], hash: HashAlgorithm = .sha256) -> [uint8]`: Compute calculates the HMAC of a message with the given key and hash algorithm.
- `func Compute(key: [uint8], message: string, hash: HashAlgorithm = .sha256) -> [uint8]`: Compute calculates the HMAC of a string message with the given key.
- `func Equal(_ mac1: [uint8], _ mac2: [uint8]) -> bool`: Equal compares two MACs for equality without leaking timing information.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
