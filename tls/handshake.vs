package tls

import (
    "crypto/curve25519"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
)

public struct ServerHelloInfo {
    public var ServerRandom: [uint8]
    public var CipherSuite: uint16
    public var ServerPublicKey: [uint8]

    public init(serverRandom: [uint8], cipherSuite: uint16, serverPublicKey: [uint8]) {
        self.ServerRandom = serverRandom
        self.CipherSuite = cipherSuite
        self.ServerPublicKey = serverPublicKey
    }
}

public struct HandshakeMessage {
    public var Type: uint8
    public var Body: [uint8]
    public var FullBytes: [uint8]

    public init(type: uint8, body: [uint8], fullBytes: [uint8]) {
        self.Type = type
        self.Body = body
        self.FullBytes = fullBytes
    }
}

/// BuildClientHello creates the RFC 8446 TLS 1.3 ClientHello message and wraps it in a TLS record.
public func BuildClientHello(serverName: string,
                             clientRandom: [uint8],
                             sessionId: [uint8],
                             clientPublicKey: [uint8],
                             alpnProtos: [string] = []) -> [uint8] {
    var body: [uint8] = []

    // 1. Legacy version: TLS 1.2 (0x0303)
    body.append(0x03)
    body.append(0x03)

    // 2. Client random: 32 bytes
    var r = 0
    while r < clientRandom.count {
        body.append(clientRandom[r])
        r += 1
    }

    // 3. Legacy session ID: 32 bytes
    body.append(uint8(truncatingIfNeeded: sessionId.count))
    var s = 0
    while s < sessionId.count {
        body.append(sessionId[s])
        s += 1
    }

    // 4. Cipher suites: TLS_CHACHA20_POLY1305_SHA256 (0x1303) and TLS_AES_128_GCM_SHA256 (0x1301)
    body.append(0x00)
    body.append(0x04)
    body.append(0x13)
    body.append(0x03)
    body.append(0x13)
    body.append(0x01)

    // 5. Legacy compression methods: 1 byte length (1), 0x00 (null compression)
    body.append(0x01)
    body.append(0x00)

    // 6. Extensions
    var exts: [uint8] = []

    // 6a. supported_versions extension (0x002b): TLS 1.3 (0x0304)
    exts.append(0x00)
    exts.append(0x2b)
    exts.append(0x00)
    exts.append(0x03)
    exts.append(0x02)
    exts.append(0x03)
    exts.append(0x04)

    // 6b. supported_groups extension (0x000a): X25519 (0x001d)
    exts.append(0x00)
    exts.append(0x0a)
    exts.append(0x00)
    exts.append(0x04)
    exts.append(0x00)
    exts.append(0x02)
    exts.append(0x00)
    exts.append(0x1d)

    // 6c. key_share extension (0x0033): X25519 public key (32 bytes)
    exts.append(0x00)
    exts.append(0x33)
    exts.append(0x00)
    exts.append(0x26) // 38 bytes total
    exts.append(0x00)
    exts.append(0x24) // 36 bytes list length
    exts.append(0x00)
    exts.append(0x1d) // group X25519
    exts.append(0x00)
    exts.append(0x20) // key len: 32 bytes
    var k = 0
    while k < clientPublicKey.count {
        exts.append(clientPublicKey[k])
        k += 1
    }

    // 6d. signature_algorithms extension (0x000d)
    // The schemes crypto/cert verifies: what the system's own verifier knows.
    let schemes: [uint16] = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]
    exts.append(0x00)
    exts.append(0x0d)
    exts.append(0x00)
    exts.append(uint8(truncatingIfNeeded: 2 + 2 * schemes.count))
    exts.append(0x00)
    exts.append(uint8(truncatingIfNeeded: 2 * schemes.count))
    for scheme in schemes {
        exts.append(uint8(truncatingIfNeeded: scheme >> 8))
        exts.append(uint8(truncatingIfNeeded: scheme))
    }

    // 6e. server_name (SNI) extension (0x0000)
    if !serverName.isEmpty {
        let nameLen = serverName.utf8.count
        exts.append(0x00)
        exts.append(0x00)
        let extLen = nameLen + 5
        exts.append(uint8(truncatingIfNeeded: (extLen >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: extLen & 0xff))
        let listLen = nameLen + 3
        exts.append(uint8(truncatingIfNeeded: (listLen >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: listLen & 0xff))
        exts.append(0x00) // host_name type
        exts.append(uint8(truncatingIfNeeded: (nameLen >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: nameLen & 0xff))
        for b in serverName.utf8 {
            exts.append(b)
        }
    }

    // 6f. ALPN extension (0x0010)
    if !alpnProtos.isEmpty {
        var alpnList: [uint8] = []
        var p = 0
        while p < alpnProtos.count {
            let proto = alpnProtos[p]
            alpnList.append(uint8(truncatingIfNeeded: proto.utf8.count))
            for b in proto.utf8 {
                alpnList.append(b)
            }
            p += 1
        }
        exts.append(0x00)
        exts.append(0x10)
        let extLen = alpnList.count + 2
        exts.append(uint8(truncatingIfNeeded: (extLen >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: extLen & 0xff))
        exts.append(uint8(truncatingIfNeeded: (alpnList.count >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: alpnList.count & 0xff))
        var a = 0
        while a < alpnList.count {
            exts.append(alpnList[a])
            a += 1
        }
    }

    // Append extensions length and extensions body
    body.append(uint8(truncatingIfNeeded: (exts.count >> 8) & 0xff))
    body.append(uint8(truncatingIfNeeded: exts.count & 0xff))
    var e = 0
    while e < exts.count {
        body.append(exts[e])
        e += 1
    }

    // 7. Wrap into Handshake message header (Type 1, 3-byte length)
    var hsMsg: [uint8] = []
    hsMsg.append(HandshakeClientHello)
    hsMsg.append(uint8(truncatingIfNeeded: (body.count >> 16) & 0xff))
    hsMsg.append(uint8(truncatingIfNeeded: (body.count >> 8) & 0xff))
    hsMsg.append(uint8(truncatingIfNeeded: body.count & 0xff))
    var bIdx = 0
    while bIdx < body.count {
        hsMsg.append(body[bIdx])
        bIdx += 1
    }

    return hsMsg
}

/// WrapInRecord wraps a handshake message into a standard TLS record.
public func WrapInRecord(contentType: uint8, payload: [uint8], legacyVersion: uint16 = 0x0301) -> [uint8] {
    var record = [uint8](repeating: 0, count: 5 + payload.count)
    record[0] = contentType
    record[1] = uint8(truncatingIfNeeded: (legacyVersion >> 8) & 0xff)
    record[2] = uint8(truncatingIfNeeded: legacyVersion & 0xff)
    record[3] = uint8(truncatingIfNeeded: (payload.count >> 8) & 0xff)
    record[4] = uint8(truncatingIfNeeded: payload.count & 0xff)
    var i = 0
    while i < payload.count {
        record[5 + i] = payload[i]
        i += 1
    }
    return record
}

/// ParseServerHello parses the ServerHello handshake message.
public func ParseServerHello(_ msg: [uint8]) throws -> ServerHelloInfo {
    if msg.count < 38 {
        throw TlsError.handshakeFailed("server hello message too short")
    }
    if msg[0] != HandshakeServerHello {
        throw TlsError.unexpectedMessage("expected server hello (2), got \(msg[0])")
    }

    // Server random: 32 bytes at offset 6..37
    var serverRandom = [uint8](repeating: 0, count: 32)
    var r = 0
    while r < 32 {
        serverRandom[r] = msg[6 + r]
        r += 1
    }

    // Session ID
    let sessLen = int(msg[38])
    var offset = 39 + sessLen
    if msg.count < offset + 4 {
        throw TlsError.handshakeFailed("truncated server hello after session ID")
    }

    // CipherSuite
    let suite = (uint16(msg[offset]) << 8) | uint16(msg[offset + 1])
    if suite != TLS_AES_128_GCM_SHA256 && suite != TLS_CHACHA20_POLY1305_SHA256 {
        throw TlsError.unsupportedCipherSuite("server chose \(suite), which was not offered")
    }
    offset += 2

    // Legacy compression method
    offset += 1

    // Extensions
    if msg.count < offset + 2 {
        throw TlsError.handshakeFailed("missing server hello extensions")
    }
    let extsLen = (int(msg[offset]) << 8) | int(msg[offset + 1])
    offset += 2

    let endOffset = offset + extsLen
    if msg.count < endOffset {
        throw TlsError.handshakeFailed("truncated server hello extensions")
    }

    var serverPubKey: [uint8] = []
    var versionOk = false

    while offset + 4 <= endOffset {
        let extType = (uint16(msg[offset]) << 8) | uint16(msg[offset + 1])
        let extLen = (int(msg[offset + 2]) << 8) | int(msg[offset + 3])
        offset += 4

        if extType == ExtSupportedVersions {
            if extLen >= 2 {
                let ver = (uint16(msg[offset]) << 8) | uint16(msg[offset + 1])
                if ver == VersionTLS13 {
                    versionOk = true
                }
            }
        } else if extType == ExtKeyShare {
            if extLen >= 36 {
                let group = (uint16(msg[offset]) << 8) | uint16(msg[offset + 1])
                let kLen = (int(msg[offset + 2]) << 8) | int(msg[offset + 3])
                if group == GroupX25519 && kLen == 32 {
                    serverPubKey = [uint8](repeating: 0, count: 32)
                    var k = 0
                    while k < 32 {
                        serverPubKey[k] = msg[offset + 4 + k]
                        k += 1
                    }
                }
            }
        }

        offset += extLen
    }

    if !versionOk {
        throw TlsError.unsupportedVersion("server did not select TLS 1.3 (0x0304)")
    }
    if serverPubKey.count != 32 {
        throw TlsError.handshakeFailed("server did not provide valid X25519 key share")
    }

    return ServerHelloInfo(serverRandom: serverRandom, cipherSuite: suite, serverPublicKey: serverPubKey)
}

/// Parses the EncryptedExtensions handshake message and returns negotiated ALPN protocol if present.
public func ParseEncryptedExtensions(_ msg: [uint8]) -> string {
    if msg.count < 6 || msg[0] != HandshakeEncryptedExtensions {
        return ""
    }
    // msg[0] = type (8), msg[1..3] = length
    // Extensions start at offset 4: 2 bytes extsLen
    let extsLen = (int(msg[4]) << 8) | int(msg[5])
    var offset = 6
    let endOffset = (6 + extsLen <= msg.count) ? (6 + extsLen) : msg.count

    while offset + 4 <= endOffset {
        let extType = (uint16(msg[offset]) << 8) | uint16(msg[offset + 1])
        let extLen = (int(msg[offset + 2]) << 8) | int(msg[offset + 3])
        offset += 4
        if offset + extLen > endOffset {
            break
        }
        if extType == ExtALPN && extLen >= 3 {
            // ALPN extension: 2 bytes listLen, 1 byte protoLen, proto bytes
            let protoLen = int(msg[offset + 2])
            if offset + 3 + protoLen <= endOffset {
                var pBytes: [uint8] = []
                var pi = 0
                while pi < protoLen {
                    pBytes.append(msg[offset + 3 + pi])
                    pi += 1
                }
                return string(decoding: pBytes, as: UTF8.self)
            }
        }
        offset += extLen
    }
    return ""
}
