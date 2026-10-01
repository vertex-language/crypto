# crypto/sha1

The SHA-1 hash, one-shot or incremental. SHA-1 no longer resists collisions; use it for older formats and protocols that require it.

```vertex
import "crypto/sha1"
```

## Types

- **`Digest`** (struct): Digest represents the partial evaluation of a SHA-1 checksum.

## Functions

- `func New() -> Digest`: Creates a new Digest instance.
- `func Sum1(_ data: [uint8]) -> [uint8]`: Computes the SHA-1 checksum of the given data.
- `func Sum1String(_ s: string) -> [uint8]`: Computes the SHA-1 checksum of a string.
- `func ToHex(_ d: [uint8]) -> string`: Converts a byte array to its lowercase hexadecimal string representation.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
