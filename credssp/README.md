# crypto/credssp

Implements the client side of CredSSP / NLA (MS-CSSP) over an established TLS 1.2 channel.

```vertex
import "crypto/credssp"
```

## Types

- **`CredSSPError`** (enum)
- **`Credentials`** (struct): Credentials to delegate over CredSSP.

## Functions

- `func Authenticate(conn: inout tls.Conn12, creds: Credentials) async throws`: Authenticate runs the full CredSSP client exchange over an established TLS connection.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
