# crypto/sha256

SHA-256 and SHA-224 hash functions (`sha256.Sum256`, `sha256.New`, `sha256.ToHex`).

## Example

```vertex
import "crypto/sha256"

print(sha256.ToHex(sha256.Sum256("hello")))
```

## Types

- **`Digest`** (struct): Digest represents the partial evaluation of a SHA-256 or SHA-224 checksum.

## Functions

- `func New() -> Digest`: New returns a new Digest computing the SHA-256 checksum.
- `func New224() -> Digest`: New224 returns a new Digest computing the SHA-224 checksum.
- `func Sum256(_ data: [uint8]) -> [uint8]`: Sum256 returns the SHA-256 checksum of the data.
- `func Sum256(_ text: string) -> [uint8]`: Sum256 returns the SHA-256 checksum of the UTF-8 string.
- `func Sum224(_ data: [uint8]) -> [uint8]`: Sum224 returns the SHA-224 checksum of the data.
- `func Sum224(_ text: string) -> [uint8]`: Sum224 returns the SHA-224 checksum of the UTF-8 string.
- `func ToHex(_ bytes: [uint8]) -> string`: ToHex converts a byte slice into a lowercase hexadecimal string.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
