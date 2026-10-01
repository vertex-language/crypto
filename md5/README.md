# crypto/md5

The MD5 hash, one-shot or incremental. MD5 is broken as a security hash; use it for checksums and older formats.

```vertex
import "crypto/md5"
```

## Types

- **`Digest`** (struct): Digest represents the partial evaluation of an MD5 checksum.

## Functions

- `func New() -> Digest`: Creates a new Digest instance.
- `func Sum(_ data: [uint8]) -> [uint8]`: Computes the MD5 checksum of the given data.
- `func SumString(_ s: string) -> [uint8]`: Computes the MD5 checksum of a string.
- `func ToHex(_ d: [uint8]) -> string`: Converts a byte array to its lowercase hexadecimal string representation.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
