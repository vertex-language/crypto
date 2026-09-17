package tls

import "crypto/chacha20poly1305"
import "crypto/subtle"

public struct DecryptedRecord {
    public var ContentType: uint8
    public var Data: [uint8]

    public init(contentType: uint8, data: [uint8]) {
        self.ContentType = contentType
        self.Data = data
    }
}

/// RecordCipher manages encryption and decryption of TLS 1.3 records for one direction.
public struct RecordCipher {
    public var Key: [uint8]
    public var IV: [uint8]
    public var SequenceNumber: uint64 = 0
    public var CipherSuite: uint16 = 0x1303

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
        let aead = try chacha20poly1305.AEAD.New(key: self.Key)
        let ciphertext = try aead.Seal(nonce: nonce, plaintext: inner, additionalData: header)

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
        let aead = try chacha20poly1305.AEAD.New(key: self.Key)
        let inner = try aead.Open(nonce: nonce, ciphertextAndTag: payload, additionalData: header)

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
        var realData = [uint8](repeating: 0, count: idx)
        var i = 0
        while i < idx {
            realData[i] = inner[i]
            i += 1
        }

        return DecryptedRecord(contentType: innerType, data: realData)
    }
}
