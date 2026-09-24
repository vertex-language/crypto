package dtls

import "crypto/curve25519"
import "crypto/hkdf"
import "crypto/hmac"
import "crypto/rand"
import "crypto/sha256"

/// DtlsHandshakeMessage represents a parsed DTLS handshake message.
public struct DtlsHandshakeMessage {
    public var Type: uint8
    public var Length: int
    public var MessageSeq: uint16
    public var FragmentOffset: int
    public var FragmentLength: int
    public var Body: [uint8]

    public init(type: uint8,
                length: int,
                messageSeq: uint16,
                fragmentOffset: int,
                fragmentLength: int,
                body: [uint8]) {
        self.Type = type
        self.Length = length
        self.MessageSeq = messageSeq
        self.FragmentOffset = fragmentOffset
        self.FragmentLength = fragmentLength
        self.Body = body
    }
}

/// DtlsHandshakeResult holds the result of parsing a handshake message.
public struct DtlsHandshakeResult {
    public var Ok: bool
    public var Message: DtlsHandshakeMessage
    public var BytesConsumed: int

    public init(ok: bool, message: DtlsHandshakeMessage, bytesConsumed: int) {
        self.Ok = ok
        self.Message = message
        self.BytesConsumed = bytesConsumed
    }
}

/// WrapDtlsHandshake serializes a handshake message with the 12-byte DTLS handshake header.
public func WrapDtlsHandshake(type: uint8, body: [uint8], messageSeq: uint16 = 0) -> [uint8] {
    let bodyLen = body.count
    var out = [uint8](repeating: 0, count: 12 + bodyLen)

    out[0] = type
    out[1] = uint8(truncatingIfNeeded: (bodyLen >> 16) & 0xff)
    out[2] = uint8(truncatingIfNeeded: (bodyLen >> 8) & 0xff)
    out[3] = uint8(truncatingIfNeeded: bodyLen & 0xff)

    out[4] = uint8(truncatingIfNeeded: (messageSeq >> 8) & 0xff)
    out[5] = uint8(truncatingIfNeeded: messageSeq & 0xff)

    // Fragment offset = 0
    out[6] = 0
    out[7] = 0
    out[8] = 0

    // Fragment length = bodyLen
    out[9] = uint8(truncatingIfNeeded: (bodyLen >> 16) & 0xff)
    out[10] = uint8(truncatingIfNeeded: (bodyLen >> 8) & 0xff)
    out[11] = uint8(truncatingIfNeeded: bodyLen & 0xff)

    var i = 0
    while i < bodyLen {
        out[12 + i] = body[i]
        i += 1
    }

    return out
}

/// ParseDtlsHandshake parses a DTLS handshake message from buffer starting at offset.
public func ParseDtlsHandshake(data: [uint8], offset: int = 0) -> DtlsHandshakeResult {
    let dummyMsg = DtlsHandshakeMessage(type: 0, length: 0, messageSeq: 0, fragmentOffset: 0, fragmentLength: 0, body: [])
    if data.count < offset + 12 {
        return DtlsHandshakeResult(ok: false, message: dummyMsg, bytesConsumed: 0)
    }

    let msgType = data[offset]
    let length = (int(data[offset + 1]) << 16) | (int(data[offset + 2]) << 8) | int(data[offset + 3])
    let msgSeq = (uint16(data[offset + 4]) << 8) | uint16(data[offset + 5])
    let fragOffset = (int(data[offset + 6]) << 16) | (int(data[offset + 7]) << 8) | int(data[offset + 8])
    let fragLength = (int(data[offset + 9]) << 16) | (int(data[offset + 10]) << 8) | int(data[offset + 11])

    if data.count < offset + 12 + fragLength {
        return DtlsHandshakeResult(ok: false, message: dummyMsg, bytesConsumed: 0)
    }

    var body = [uint8](repeating: 0, count: fragLength)
    var i = 0
    while i < fragLength {
        body[i] = data[offset + 12 + i]
        i += 1
    }

    let msg = DtlsHandshakeMessage(
        type: msgType,
        length: length,
        messageSeq: msgSeq,
        fragmentOffset: fragOffset,
        fragmentLength: fragLength,
        body: body
    )

    return DtlsHandshakeResult(ok: true, message: msg, bytesConsumed: 12 + fragLength)
}

/// DtlsHelloInfo represents extracted key parameters from a ClientHello or ServerHello.
public struct DtlsHelloInfo {
    public var Random: [uint8]
    public var PublicKey: [uint8]
    public var CipherSuite: uint16
    public var SrtpProfile: uint16

    public init(random: [uint8], publicKey: [uint8], cipherSuite: uint16, srtpProfile: uint16) {
        self.Random = random
        self.PublicKey = publicKey
        self.CipherSuite = cipherSuite
        self.SrtpProfile = srtpProfile
    }
}

/// BuildDtlsClientHello constructs a DTLS 1.3 / DTLS 1.2 ClientHello handshake body.
public func BuildDtlsClientHello(random: [uint8],
                                 sessionId: [uint8],
                                 cookie: [uint8],
                                 publicKey: [uint8],
                                 srtpProfiles: [uint16] = [0x0001, 0x0007]) -> [uint8] {
    var body: [uint8] = []

    // 1. Client version: DTLS 1.2 (0xfefd) for backwards compatibility
    body.append(0xfe)
    body.append(0xfd)

    // 2. Random: 32 bytes
    var r = 0
    while r < random.count && r < 32 {
        body.append(random[r])
        r += 1
    }
    while body.count < 34 {
        body.append(0)
    }

    // 3. Session ID
    body.append(uint8(truncatingIfNeeded: sessionId.count))
    var s = 0
    while s < sessionId.count {
        body.append(sessionId[s])
        s += 1
    }

    // 4. Cookie (RFC 6347 §4.2.1 / RFC 9147)
    body.append(uint8(truncatingIfNeeded: cookie.count))
    var c = 0
    while c < cookie.count {
        body.append(cookie[c])
        c += 1
    }

    // 5. Cipher Suites (TLS_CHACHA20_POLY1305_SHA256 = 0x1303, TLS_AES_128_GCM_SHA256 = 0x1301)
    body.append(0x00)
    body.append(0x04)
    body.append(0x13)
    body.append(0x03)
    body.append(0x13)
    body.append(0x01)

    // 6. Compression methods: 1 byte length (1), 0x00 (none)
    body.append(0x01)
    body.append(0x00)

    // 7. Extensions
    var exts: [uint8] = []

    // 7a. supported_versions: DTLS 1.3 (0xfefc)
    exts.append(0x00)
    exts.append(0x2b)
    exts.append(0x00)
    exts.append(0x03)
    exts.append(0x02)
    exts.append(0xfe)
    exts.append(0xfc)

    // 7b. supported_groups: X25519 (0x001d)
    exts.append(0x00)
    exts.append(0x0a)
    exts.append(0x00)
    exts.append(0x04)
    exts.append(0x00)
    exts.append(0x02)
    exts.append(0x00)
    exts.append(0x1d)

    // 7c. key_share: X25519 (0x001d), 32-byte public key
    exts.append(0x00)
    exts.append(0x33)
    let keyShareTotal = 6 + publicKey.count
    exts.append(uint8(truncatingIfNeeded: (keyShareTotal >> 8) & 0xff))
    exts.append(uint8(truncatingIfNeeded: keyShareTotal & 0xff))
    let keyShareList = 4 + publicKey.count
    exts.append(uint8(truncatingIfNeeded: (keyShareList >> 8) & 0xff))
    exts.append(uint8(truncatingIfNeeded: keyShareList & 0xff))
    exts.append(0x00)
    exts.append(0x1d)
    exts.append(uint8(truncatingIfNeeded: (publicKey.count >> 8) & 0xff))
    exts.append(uint8(truncatingIfNeeded: publicKey.count & 0xff))
    var pk = 0
    while pk < publicKey.count {
        exts.append(publicKey[pk])
        pk += 1
    }

    // 7d. use_srtp extension (0x000e - RFC 5764)
    if !srtpProfiles.isEmpty {
        exts.append(0x00)
        exts.append(0x0e)
        let srtpLen = 2 + (srtpProfiles.count * 2) + 1
        exts.append(uint8(truncatingIfNeeded: (srtpLen >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: srtpLen & 0xff))
        // Profiles length
        let profBytes = srtpProfiles.count * 2
        exts.append(uint8(truncatingIfNeeded: (profBytes >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: profBytes & 0xff))
        var sp = 0
        while sp < srtpProfiles.count {
            let p = srtpProfiles[sp]
            exts.append(uint8(truncatingIfNeeded: (p >> 8) & 0xff))
            exts.append(uint8(truncatingIfNeeded: p & 0xff))
            sp += 1
        }
        // MKI length (0)
        exts.append(0x00)
    }

    // Append extensions length and extensions body
    body.append(uint8(truncatingIfNeeded: (exts.count >> 8) & 0xff))
    body.append(uint8(truncatingIfNeeded: exts.count & 0xff))
    var e = 0
    while e < exts.count {
        body.append(exts[e])
        e += 1
    }

    return body
}

/// BuildDtlsServerHello constructs a DTLS ServerHello handshake body.
public func BuildDtlsServerHello(random: [uint8],
                                 sessionId: [uint8],
                                 cipherSuite: uint16,
                                 publicKey: [uint8],
                                 srtpProfile: uint16 = 0x0001) -> [uint8] {
    var body: [uint8] = []

    // 1. Server version: DTLS 1.2 (0xfefd)
    body.append(0xfe)
    body.append(0xfd)

    // 2. Random: 32 bytes
    var r = 0
    while r < random.count && r < 32 {
        body.append(random[r])
        r += 1
    }
    while body.count < 34 {
        body.append(0)
    }

    // 3. Session ID
    body.append(uint8(truncatingIfNeeded: sessionId.count))
    var s = 0
    while s < sessionId.count {
        body.append(sessionId[s])
        s += 1
    }

    // 4. Selected Cipher Suite
    body.append(uint8(truncatingIfNeeded: (cipherSuite >> 8) & 0xff))
    body.append(uint8(truncatingIfNeeded: cipherSuite & 0xff))

    // 5. Compression method: 0x00
    body.append(0x00)

    // 6. Extensions
    var exts: [uint8] = []

    // 6a. supported_versions: DTLS 1.3 (0xfefc)
    exts.append(0x00)
    exts.append(0x2b)
    exts.append(0x00)
    exts.append(0x02)
    exts.append(0xfe)
    exts.append(0xfc)

    // 6b. key_share
    exts.append(0x00)
    exts.append(0x33)
    let keyShareTotal = 4 + publicKey.count
    exts.append(uint8(truncatingIfNeeded: (keyShareTotal >> 8) & 0xff))
    exts.append(uint8(truncatingIfNeeded: keyShareTotal & 0xff))
    exts.append(0x00)
    exts.append(0x1d) // X25519
    exts.append(uint8(truncatingIfNeeded: (publicKey.count >> 8) & 0xff))
    exts.append(uint8(truncatingIfNeeded: publicKey.count & 0xff))
    var pk = 0
    while pk < publicKey.count {
        exts.append(publicKey[pk])
        pk += 1
    }

    // 6c. use_srtp (RFC 5764)
    if srtpProfile != 0 {
        exts.append(0x00)
        exts.append(0x0e)
        exts.append(0x00)
        exts.append(0x05)
        exts.append(0x00)
        exts.append(0x02)
        exts.append(uint8(truncatingIfNeeded: (srtpProfile >> 8) & 0xff))
        exts.append(uint8(truncatingIfNeeded: srtpProfile & 0xff))
        exts.append(0x00) // MKI len
    }

    // Extensions length + body
    body.append(uint8(truncatingIfNeeded: (exts.count >> 8) & 0xff))
    body.append(uint8(truncatingIfNeeded: exts.count & 0xff))
    var e = 0
    while e < exts.count {
        body.append(exts[e])
        e += 1
    }

    return body
}

/// ParseDtlsServerHello extracts random, publicKey, cipherSuite, and srtpProfile from a ServerHello body.
public func ParseDtlsServerHello(body: [uint8]) -> DtlsHelloInfo {
    var dummy = DtlsHelloInfo(random: [], publicKey: [], cipherSuite: 0, srtpProfile: 0)
    if body.count < 38 {
        return dummy
    }

    var randBytes: [uint8] = []
    var i = 2
    while i < 34 {
        randBytes.append(body[i])
        i += 1
    }

    let sessIdLen = int(body[34])
    var pos = 35 + sessIdLen
    if body.count < pos + 3 {
        return dummy
    }

    let cipherSuite = (uint16(body[pos]) << 8) | uint16(body[pos + 1])
    pos += 2 // skip cipherSuite
    pos += 1 // skip compression method

    if body.count < pos + 2 {
        return DtlsHelloInfo(random: randBytes, publicKey: [], cipherSuite: cipherSuite, srtpProfile: 0)
    }

    let extsLen = (int(body[pos]) << 8) | int(body[pos + 1])
    pos += 2
    let extsEnd = pos + extsLen

    var pubKey: [uint8] = []
    var srtpProf: uint16 = 0

    while pos + 4 <= extsEnd && pos + 4 <= body.count {
        let extType = (uint16(body[pos]) << 8) | uint16(body[pos + 1])
        let extDataLen = (int(body[pos + 2]) << 8) | int(body[pos + 3])
        pos += 4

        if extType == 0x0033 { // key_share
            if extDataLen >= 4 {
                let keyLen = (int(body[pos + 2]) << 8) | int(body[pos + 3])
                var k = 0
                while k < keyLen && pos + 4 + k < body.count {
                    pubKey.append(body[pos + 4 + k])
                    k += 1
                }
            }
        } else if extType == 0x000e { // use_srtp
            if extDataLen >= 4 {
                srtpProf = (uint16(body[pos + 2]) << 8) | uint16(body[pos + 3])
            }
        }

        pos += extDataLen
    }

    return DtlsHelloInfo(random: randBytes, publicKey: pubKey, cipherSuite: cipherSuite, srtpProfile: srtpProf)
}

/// ParseDtlsClientHello extracts random, publicKey, and srtpProfile from a ClientHello body.
public func ParseDtlsClientHello(body: [uint8]) -> DtlsHelloInfo {
    var dummy = DtlsHelloInfo(random: [], publicKey: [], cipherSuite: 0, srtpProfile: 0)
    if body.count < 34 {
        return dummy
    }

    var randBytes: [uint8] = []
    var i = 2
    while i < 34 {
        randBytes.append(body[i])
        i += 1
    }

    let sessIdLen = int(body[34])
    var pos = 35 + sessIdLen
    if body.count <= pos {
        return dummy
    }

    let cookieLen = int(body[pos])
    pos += 1 + cookieLen

    if body.count < pos + 2 {
        return dummy
    }
    let ciphersLen = (int(body[pos]) << 8) | int(body[pos + 1])
    pos += 2 + ciphersLen

    if body.count <= pos {
        return dummy
    }
    let compLen = int(body[pos])
    pos += 1 + compLen

    if body.count < pos + 2 {
        return DtlsHelloInfo(random: randBytes, publicKey: [], cipherSuite: 0, srtpProfile: 0)
    }
    let extsLen = (int(body[pos]) << 8) | int(body[pos + 1])
    pos += 2
    let extsEnd = pos + extsLen

    var pubKey: [uint8] = []
    var srtpProf: uint16 = 0

    while pos + 4 <= extsEnd && pos + 4 <= body.count {
        let extType = (uint16(body[pos]) << 8) | uint16(body[pos + 1])
        let extDataLen = (int(body[pos + 2]) << 8) | int(body[pos + 3])
        pos += 4

        if extType == 0x0033 { // key_share
            if extDataLen >= 6 {
                // client_shares list length: 2 bytes
                let keyLen = (int(body[pos + 4]) << 8) | int(body[pos + 5])
                var k = 0
                while k < keyLen && pos + 6 + k < body.count {
                    pubKey.append(body[pos + 6 + k])
                    k += 1
                }
            }
        } else if extType == 0x000e { // use_srtp
            if extDataLen >= 4 {
                srtpProf = (uint16(body[pos + 2]) << 8) | uint16(body[pos + 3])
            }
        }

        pos += extDataLen
    }

    return DtlsHelloInfo(random: randBytes, publicKey: pubKey, cipherSuite: 0x1303, srtpProfile: srtpProf)
}

