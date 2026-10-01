# crypto/chacha20poly1305

ChaCha20-Poly1305 AEAD construction (RFC 8439).

```vertex
import "crypto/chacha20poly1305"
```

## Types

- **`AeadError`** (enum)
- **`AEAD`** (struct): AEAD represents a ChaCha20-Poly1305 Authenticated Encryption with Associated Data instance (RFC 8439).

## Functions

- `func Seal(key: [uint8], nonce: [uint8], plaintext: [uint8], additionalData: [uint8] = []) throws -> [uint8]`: Seal encrypts and authenticates plaintext with key and nonce.
- `func Open(key: [uint8], nonce: [uint8], ciphertextAndTag: [uint8], additionalData: [uint8] = []) throws -> [uint8]`: Open authenticates and decrypts ciphertextAndTag with key and nonce.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
