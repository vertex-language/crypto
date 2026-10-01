# crypto/sha512

Implements SHA-512 and SHA-384 (FIPS 180-4). SHA-384 is SHA-512 with a different initial state, truncated to 48 bytes.

```vertex
import "crypto/sha512"
```

## Types

- **`Digest`** (struct)

## Functions

- `func New() -> Digest`
- `func New384() -> Digest`
- `func Sum512(_ data: [uint8]) -> [uint8]`
- `func Sum384(_ data: [uint8]) -> [uint8]`
- `func ToHex(_ bytes: [uint8]) -> string`

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
