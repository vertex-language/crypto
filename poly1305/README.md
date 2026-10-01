# crypto/poly1305

Poly1305 128-bit one-time authenticator (RFC 8439).

```vertex
import "crypto/poly1305"
```

## Types

- **`Poly1305Error`** (enum)

## Functions

- `func Sum(_ msg: [uint8], key: [uint8]) -> [uint8]`: Sum calculates the 16-byte Poly1305 authenticator tag of msg using a 32-byte one-time key.
- `func Verify(mac: [uint8], msg: [uint8], key: [uint8]) -> bool`: Verify returns true if mac matches the Poly1305 tag of msg.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
