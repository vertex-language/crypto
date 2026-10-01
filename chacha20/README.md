# crypto/chacha20

ChaCha20 stream cipher (RFC 8439).

```vertex
import "crypto/chacha20"
```

## Types

- **`ChaCha20Error`** (enum)
- **`Cipher`** (struct): Cipher is a stateful ChaCha20 stream cipher instance (RFC 8439).

## Functions

- `func Encrypt(key: [uint8], nonce: [uint8], plaintext: [uint8], counter: uint32 = 1) throws -> [uint8]`: Encrypt encrypts plaintext with key and nonce using ChaCha20 (RFC 8439).
- `func Decrypt(key: [uint8], nonce: [uint8], ciphertext: [uint8], counter: uint32 = 1) throws -> [uint8]`: Decrypt decrypts ciphertext with key and nonce using ChaCha20 (RFC 8439).

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
