# crypto/rc4

Implements the RC4 stream cipher. RC4 is insecure and used only where a legacy protocol requires it: NTLM sealing/signing and RDP licensing encryption run RC4 keystreams.

```vertex
import "crypto/rc4"
```

## Types

- **`Cipher`** (struct): Cipher is an RC4 keystream generator. XORStream applies it; a fresh Cipher is needed per independent stream.

## Functions

- `func Apply(key: [uint8], data: [uint8]) -> [uint8]`: Apply is a one-shot RC4 of data under key (for callers that need a single independent stream).

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
