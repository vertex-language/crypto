# crypto/md4

Implements the MD4 message digest (RFC 1320). It is cryptographically broken and used only where a legacy protocol requires it: the NTLM "NT hash" is MD4 of the UTF-16LE password.

```vertex
import "crypto/md4"
```

## Types

- **`Digest`** (struct)

## Functions

- `func New() -> Digest`
- `func Sum(_ data: [uint8]) -> [uint8]`

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
