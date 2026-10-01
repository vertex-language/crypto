# crypto/cipher

Provides AEAD cipher modes over a block cipher. GCM (Galois/Counter Mode, NIST SP 800-38D) is what the TLS 1.2 AES-GCM cipher suites Windows negotiates use to protect records.

```vertex
import "crypto/cipher"
```

## Types

- **`CipherError`** (enum)
- **`GCM`** (struct): GCM wraps an AES block cipher in Galois/Counter Mode with a 96-bit nonce and 128-bit tag, the profile TLS uses.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
