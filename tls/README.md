# crypto/tls

Transport Layer Security 1.3 client and server implementation (RFC 8446).

```vertex
import "crypto/tls"
```

## Types

- **`Conn`** (struct): Conn represents an established or in-progress TLS 1.3 encrypted connection over TCP.
- **`ServerHelloInfo`** (struct)
- **`HandshakeMessage`** (struct)
- **`TrafficSecrets`** (struct)
- **`TrafficKeys`** (struct)
- **`Transcript`** (struct): Transcript tracks the running handshake hash using SHA-256.
- **`KeySchedule`** (struct): KeySchedule manages the derivation of TLS 1.3 secrets across handshake phases.
- **`DecryptedRecord`** (struct)
- **`RecordCipher`** (struct): RecordCipher manages encryption and decryption of TLS 1.3 records for one direction.
- **`ProtocolVersion`** (struct): TLS Protocol Versions
- and 12 more

## Functions

- `func Client(_ stream: tcp.TcpStream, config: Config = Config()) -> Conn`: Client wraps a connected TCP stream into a TLS client.
- `func Connect(host: string, port: uint16, config: Config = Config()) async throws -> Conn`: Connect connects to host and port over TCP, then performs the TLS 1.3 handshake.
- `func Dial(host: string, port: uint16, config: Config = Config()) async throws -> Conn`: Dial connects to host and port over TCP, then performs the TLS 1.3 handshake.
- `func BuildClientHello(serverName: string, clientRandom: [uint8], sessionId: [uint8], clientPublicKey: [uint8], alpnProtos: [string] = []) -> [uint8]`: BuildClientHello creates the RFC 8446 TLS 1.3 ClientHello message and wraps it in a TLS record.
- `func WrapInRecord(contentType: uint8, payload: [uint8], legacyVersion: uint16 = 0x0301) -> [uint8]`: WrapInRecord wraps a handshake message into a standard TLS record.
- `func ParseServerHello(_ msg: [uint8]) throws -> ServerHelloInfo`: ParseServerHello parses the ServerHello handshake message.
- `func ParseEncryptedExtensions(_ msg: [uint8]) -> string`: Parses the EncryptedExtensions handshake message and returns negotiated ALPN protocol if present.
- `func HkdfExpandLabel(secret: [uint8], label: string, context: [uint8], length: int) -> [uint8]`: HkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1).
- `func DeriveSecret(secret: [uint8], label: string, transcriptHash: [uint8]) -> [uint8]`: DeriveSecret implements TLS 1.3 Derive-Secret(Secret, Label, Messages) (RFC 8446 Section 7.1).
- `func KeyLength(_ cipherSuite: uint16) -> int`: KeyLength is the AEAD key size of a TLS 1.3 cipher suite.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
