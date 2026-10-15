# crypto/ecdsa

Verifies ECDSA signatures (FIPS 186-5, SEC 1 §4.1.4) on the NIST curves P-256, P-384 and P-521, which web certificates and TLS handshakes are signed with.

```vertex
import "crypto/ecdsa"
```

## Types

- **`Curve`** (enum): Curve is a NIST prime curve, y² = x³ - 3x + b over GF(p).
- **`PublicKey`** (struct): PublicKey is a point on Curve, checked to be on it.
- **`EcdsaError`** (enum)

## Functions

- `func Size(_ c: Curve) -> int`: Size is the byte length of a field element (and of a scalar) on c.
- `func ParsePublicKey(curve: Curve, point: [uint8]) throws -> PublicKey`: ParsePublicKey reads an uncompressed SEC 1 point, 0x04 || X || Y, and checks that it is on the curve.
- `func ParseSignature(_ sig: [uint8]) -> (r: big.Nat, s: big.Nat)?`: ParseSignature reads an X9.62 signature, SEQUENCE { r INTEGER, s INTEGER }, strictly as DER.
- `func Verify(key: PublicKey, digest: [uint8], signature: [uint8]) throws`: Verify checks an X9.62 DER signature over digest, the hash of the message, with key.
- and 2 more

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
