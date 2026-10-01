# crypto/rsa

Implements RSA public-key operations needed by a TLS client and RDP: PKCS#1 v1.5 and PSS signature verification, and the raw public operation.

```vertex
import "crypto/rsa"
```

## Types

- **`PublicKey`** (struct): PublicKey is an RSA public key: modulus N and exponent E.
- **`RsaError`** (enum)
- **`Hash`** (enum): Hash names the digest a signature was made with.

## Functions

- `func PublicOp(_ key: PublicKey, _ sig: [uint8]) -> [uint8]`: PublicOp is the raw RSA public operation: signature^E mod N, returned left-padded to the modulus size.
- `func VerifyPKCS1v15(key: PublicKey, hash: Hash, data: [uint8], signature: [uint8]) throws`: VerifyPKCS1v15 checks an RSASSA-PKCS1-v1_5 signature over data.
- `func VerifyPSS(key: PublicKey, hash: Hash, data: [uint8], signature: [uint8]) throws`: VerifyPSS checks an RSASSA-PSS signature over data (MGF1 with the same hash, salt length equal to the hash length -- the TLS profile).

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
