# crypto/dtls

Building blocks for DTLS: handshake messages, the record layer, an anti-replay window, SRTP keying, and certificate fingerprints.

```vertex
import "crypto/dtls"
```

## Types

- **`DtlsHandshakeMessage`** (struct): DtlsHandshakeMessage represents a parsed DTLS handshake message.
- **`DtlsHandshakeResult`** (struct): DtlsHandshakeResult holds the result of parsing a handshake message.
- **`DtlsHelloInfo`** (struct): DtlsHelloInfo represents extracted key parameters from a ClientHello or ServerHello.
- **`DecryptedRecord`** (struct): DecryptedRecord represents a verified and opened DTLS record.
- **`RecordCipher`** (struct): RecordCipher manages datagram encryption, decryption, and replay protection (RFC 9147 Section 4).
- **`AntiReplayWindow`** (struct): AntiReplayWindow implements the 64-packet sliding window anti-replay protection specified in RFC 6347 Section 4.1.2.6 and RFC 9147 Section 4.1.
- **`SrtpKeys`** (struct): SrtpKeys holds the derived SRTP master keys and salts for both peers (RFC 5764 Section 4.2).
- **`ProtocolVersion`** (struct): DTLS Protocol Versions (RFC 6347 / RFC 9147)
- **`ContentType`** (struct): DTLS Content Types (RFC 9147 Section 4)
- **`HandshakeType`** (struct): DTLS Handshake Types (RFC 9147 Section 5)
- and 2 more

## Functions

- `func CalculateFingerprint(_ der: [uint8]) -> string`: Computes the uppercase colon-delimited SHA-256 fingerprint of a DER certificate (RFC 8122). E.g. "2B:04:D9:6A:..."
- `func VerifyFingerprint(_ der: [uint8], expectedFingerprint: string) -> bool`: Verifies whether a certificate's SHA-256 fingerprint matches an SDP fingerprint attribute value.
- `func WrapDtlsHandshake(type: uint8, body: [uint8], messageSeq: uint16 = 0) -> [uint8]`: WrapDtlsHandshake serializes a handshake message with the 12-byte DTLS handshake header.
- `func ParseDtlsHandshake(data: [uint8], offset: int = 0) -> DtlsHandshakeResult`: ParseDtlsHandshake parses a DTLS handshake message from buffer starting at offset.
- `func BuildDtlsClientHello(random: [uint8], sessionId: [uint8], cookie: [uint8], publicKey: [uint8], srtpProfiles: [uint16] = [0x0001, 0x0007]) -> [uint8]`: BuildDtlsClientHello constructs a DTLS 1.3 / DTLS 1.2 ClientHello handshake body.
- `func BuildDtlsServerHello(random: [uint8], sessionId: [uint8], cipherSuite: uint16, publicKey: [uint8], srtpProfile: uint16 = 0x0001) -> [uint8]`: BuildDtlsServerHello constructs a DTLS ServerHello handshake body.
- `func ParseDtlsServerHello(body: [uint8]) -> DtlsHelloInfo`: ParseDtlsServerHello extracts random, publicKey, cipherSuite, and srtpProfile from a ServerHello body.
- `func ParseDtlsClientHello(body: [uint8]) -> DtlsHelloInfo`: ParseDtlsClientHello extracts random, publicKey, and srtpProfile from a ClientHello body.
- `func DeriveSrtpKeys(exporterSecret: [uint8], keyLength: int = 16, saltLength: int = 14) -> SrtpKeys`: Derives SRTP encryption keys and salts from DTLS keying material according to RFC 5764 Section 4.2. E.g.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
