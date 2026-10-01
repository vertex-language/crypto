# crypto/ntlm

Implements the client side of NTLMv2 (MS-NLMP), enough for CredSSP/NLA: the NEGOTIATE and AUTHENTICATE messages, the NTLMv2 response and session-key hierarchy, the message integrity code (MIC), and the GSS-style Wrap/Unwrap (sign+seal) used to protect CredSSP's public-key and credential tokens.

```vertex
import "crypto/ntlm"
```

## Types

- **`NtlmError`** (enum)
- **`Context`** (struct): Context carries the negotiated session keys and running cipher state for signing and sealing after authentication (GSS Wrap/Unwrap).
- **`Client`** (struct): Client drives an NTLMv2 exchange and then protects tokens.

## Functions

- `func ChallengeNames(_ msg: [uint8]) -> (nbDomain: string, nbComputer: string)`: ChallengeNames returns the server's NetBIOS domain and computer names from a CHALLENGE_MESSAGE's target info (for choosing a logon domain).
- `func NTOWFv2(user: string, domain: string, password: [uint8]) -> [uint8]`: ntowfv2 computes the NTLMv2 one-way function.
- `func Client.Wrap(_ message: [uint8]) -> [uint8]`: Wrap signs and seals a message the way GSS_WrapEx does for NTLM: it returns the 16-byte signature followed by the sealed data.
- `func Client.Unwrap(_ token: [uint8]) throws -> [uint8]`: Unwrap verifies and decrypts a token the server produced (signature || sealed data), returning the plaintext.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
