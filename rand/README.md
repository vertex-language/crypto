# crypto/rand

Cryptographically secure pseudorandom entropy from the OS CSPRNG (`rand.Read`, `rand.Bytes`).

```vertex
import "crypto/rand"
```

## Types

- **`RandError`** (enum)

## Functions

- `func Read(into buffer: inout [uint8]) throws -> int`: Read fills buffer with cryptographically secure random bytes from the platform CSPRNG.
- `func Bytes(_ count: int) throws -> [uint8]`: Bytes allocates and returns a buffer of count cryptographically secure random bytes.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
