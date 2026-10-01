# crypto/aes

Implements the AES block cipher (FIPS 197) for 128- and 256-bit keys. It is the block primitive under crypto/cipher's GCM, which is what the TLS 1.2 AES-GCM cipher suites Windows negotiates use.

```vertex
import "crypto/aes"
```

## Types

- **`AesError`** (enum)
- **`Block`** (struct): Block is an AES cipher set up with one key. It encrypts and decrypts single 16-byte blocks; modes of operation live in crypto/cipher.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
