# crypto/curve25519

X25519 Montgomery curve scalar multiplication (RFC 7748).

```vertex
import "crypto/curve25519"
```

## Types

- **`Curve25519Error`** (enum)

## Functions

- `func ScalarMult(scalar: [uint8], point: [uint8]) throws -> [uint8]`: ScalarMult calculates the scalar product of scalar and point on Curve25519 (RFC 7748).
- `func ScalarBaseMult(scalar: [uint8]) throws -> [uint8]`: ScalarBaseMult calculates the public key corresponding to a private scalar.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
