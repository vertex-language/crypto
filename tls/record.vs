package tls

import (
    "crypto/chacha20poly1305"
    "crypto/cipher"
    "crypto/subtle"
)

public struct DecryptedRecord {
    public var ContentType: uint8
    public var Data: [uint8]

    public init(contentType: uint8, data: [uint8]) {
        self.ContentType = contentType
        self.Data = data
    }
}

/// KeyLength is the AEAD key size of a TLS 1.3 cipher suite.
public func KeyLength(_ cipherSuite: uint16) -> int {
    return cipherSuite == TLS_AES_128_GCM_SHA256 ? 16 : 32
}

// The AEAD a record cipher seals and opens with, keyed once.
enum recordAead {
    case none
    case chacha(chacha20poly1305.AEAD)
    case gcm(cipher.GCM)
}

/// RecordCipher manages encryption and decryption of TLS 1.3 records for one direction.
public struct RecordCipher {
    public var Key: [uint8]
    public var IV: [uint8]
    public var SequenceNumber: uint64 = 0
    public var CipherSuite: uint16 = 0x1303
    var aead: recordAead = recordAead.none

    public init(key: [uint8], iv: [uint8], cipherSuite: uint16 = 0x1303) {
        self.Key = key
        self.IV = iv
        self.SequenceNumber = 0
        self.CipherSuite = cipherSuite
    }

    /// ComputeNonce calculates the per-record nonce: IV XOR SequenceNumber (RFC 8446 Section 5.3).
    public func ComputeNonce() -> [uint8] {
        var nonce = self.IV
        var s = self.SequenceNumber
        var i = 11
        while i >= 4 {
            nonce[i] ^= uint8(truncatingIfNeeded: s & 0xff)
            s >>= 8
            i -= 1
        }
        return nonce
    }

    mutating func seal(nonce: [uint8], plaintext: [uint8], additionalData: [uint8]) throws -> [uint8] {
        try self.keyAead()
        switch self.aead {
        case .gcm(let g): return try g.Seal(nonce: nonce, plaintext: plaintext, additionalData: additionalData)
        case .chacha(let c): return try c.Seal(nonce: nonce, plaintext: plaintext, additionalData: additionalData)
        case .none: throw TlsError.unsupportedCipherSuite("\(self.CipherSuite)")
        }
    }

    mutating func open(nonce: [uint8], ciphertextAndTag: [uint8], additionalData: [uint8]) throws -> [uint8] {
        try self.keyAead()
        switch self.aead {
        case .gcm(let g): return try g.Open(nonce: nonce, ciphertextAndTag: ciphertextAndTag, additionalData: additionalData)
        case .chacha(let c): return try c.Open(nonce: nonce, ciphertextAndTag: ciphertextAndTag, additionalData: additionalData)
        case .none: throw TlsError.unsupportedCipherSuite("\(self.CipherSuite)")
        }
    }

    mutating func keyAead() throws {
        if case .none = self.aead {
            if self.CipherSuite == TLS_AES_128_GCM_SHA256 {
                self.aead = .gcm(try cipher.GCM.New(key: self.Key))
            } else if self.CipherSuite == TLS_CHACHA20_POLY1305_SHA256 {
                self.aead = .chacha(try chacha20poly1305.AEAD.New(key: self.Key))
            }
        }
    }

    /// Encrypt wraps plaintext into a TLS 1.3 protected record.
    public mutating func Encrypt(contentType: uint8, plaintext: [uint8]) throws -> [uint8] {
        // Construct inner plaintext: plaintext || contentType
        var inner: [uint8] = []
        var p = 0
        while p < plaintext.count {
            inner.append(plaintext[p])
            p += 1
        }
        inner.append(contentType)

        let tagSize = 16
        let recordPayloadLen = inner.count + tagSize
        if recordPayloadLen > 16384 + 256 {
            throw TlsError.recordOverflow("plaintext too large for single record")
        }

        // Construct 5-byte record header: Type 23, Legacy Version 0x0303, Payload Length
        var header = [uint8](repeating: 0, count: 5)
        header[0] = RecordApplicationData
        header[1] = 0x03
        header[2] = 0x03
        header[3] = uint8(truncatingIfNeeded: (recordPayloadLen >> 8) & 0xff)
        header[4] = uint8(truncatingIfNeeded: recordPayloadLen & 0xff)

        let nonce = ComputeNonce()
        let ciphertext = try self.seal(nonce: nonce, plaintext: inner, additionalData: header)

        self.SequenceNumber &+= 1

        var record: [uint8] = []
        var h = 0
        while h < header.count {
            record.append(header[h])
            h += 1
        }
        var c = 0
        while c < ciphertext.count {
            record.append(ciphertext[c])
            c += 1
        }
        return record
    }

    /// Decrypt verifies and opens a TLS 1.3 protected record.
    public mutating func Decrypt(header: [uint8], payload: [uint8]) throws -> DecryptedRecord {
        if header.count != 5 {
            throw TlsError.unexpectedMessage("malformed record header")
        }
        if header[0] != RecordApplicationData {
            throw TlsError.unexpectedMessage("expected application data record (23), got \(header[0])")
        }

        let nonce = ComputeNonce()
        let inner = try self.open(nonce: nonce, ciphertextAndTag: payload, additionalData: header)

        self.SequenceNumber &+= 1

        // Scan from the end of inner plaintext to strip padding and find inner ContentType
        var idx = inner.count - 1
        while idx >= 0 && inner[idx] == 0 {
            idx -= 1
        }
        if idx < 0 {
            throw TlsError.unexpectedMessage("zero inner plaintext in protected record")
        }

        let innerType = inner[idx]
        let realData = Array(inner[0..<idx])

        return DecryptedRecord(contentType: innerType, data: realData)
    }
}
