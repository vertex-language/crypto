package dtls

import "crypto/chacha20poly1305"

/// DecryptedRecord represents a verified and opened DTLS record.
public struct DecryptedRecord {
    public var ContentType: uint8
    public var Epoch: uint16
    public var SequenceNumber: uint64
    public var Data: [uint8]
}

/// RecordCipher manages datagram encryption, decryption, and replay protection (RFC 9147 Section 4).
public struct RecordCipher {
    public var Key: [uint8]
    public var IV: [uint8]
    public var Epoch: uint16
    public var SequenceNumber: uint64 = 0
    public var Window: AntiReplayWindow

    public init(key: [uint8], iv: [uint8], epoch: uint16 = 0) {
        self.Key = key
        self.IV = iv
        self.Epoch = epoch
        self.SequenceNumber = 0
        self.Window = AntiReplayWindow()
    }

    /// Calculates the 12-byte AEAD nonce by XORing the IV with the (Epoch || SequenceNumber)
    /// as specified in RFC 9147 Section 4.2.
    public func ComputeNonce(epoch: uint16, seq: uint64) -> [uint8] {
        var nonce = self.IV
        let combined: uint64 = (uint64(epoch) << 48) | (seq & 0x0000FFFFFFFFFFFF)
        var s = combined
        var i = 11
        while i >= 4 {
            nonce[i] ^= uint8(truncatingIfNeeded: s & 0xFF)
            s >>= 8
            i -= 1
        }
        return nonce
    }

    /// Encrypts plaintext into an authenticated DTLS protected datagram record.
    public mutating func Encrypt(contentType: uint8, plaintext: [uint8]) throws -> [uint8] {
        // Construct inner plaintext: plaintext || contentType (RFC 9147 Section 4.2.1)
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
            throw DtlsError.recordOverflow("plaintext too large for single DTLS record")
        }

        // Construct standard 13-byte DTLS record header
        var header = [uint8](repeating: 0, count: 13)
        header[0] = RecordApplicationData // Outer type
        header[1] = 0xFE
        header[2] = 0xFD                  // Version DTLS 1.2 legacy wire format
        header[3] = uint8(truncatingIfNeeded: self.Epoch >> 8)
        header[4] = uint8(truncatingIfNeeded: self.Epoch & 0xFF)

        // 48-bit sequence number (6 bytes)
        let seq = self.SequenceNumber
        header[5] = uint8(truncatingIfNeeded: (seq >> 40) & 0xFF)
        header[6] = uint8(truncatingIfNeeded: (seq >> 32) & 0xFF)
        header[7] = uint8(truncatingIfNeeded: (seq >> 24) & 0xFF)
        header[8] = uint8(truncatingIfNeeded: (seq >> 16) & 0xFF)
        header[9] = uint8(truncatingIfNeeded: (seq >> 8) & 0xFF)
        header[10] = uint8(truncatingIfNeeded: seq & 0xFF)

        // Payload length (2 bytes)
        header[11] = uint8(truncatingIfNeeded: (recordPayloadLen >> 8) & 0xFF)
        header[12] = uint8(truncatingIfNeeded: recordPayloadLen & 0xFF)

        let nonce = ComputeNonce(epoch: self.Epoch, seq: self.SequenceNumber)
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

    /// Decrypts and verifies an incoming DTLS datagram record, enforcing anti-replay.
    public mutating func Decrypt(record: [uint8]) throws -> DecryptedRecord {
        if record.count < 13 + 16 {
            throw DtlsError.recordTooSmall
        }

        var header = [uint8](repeating: 0, count: 13)
        var h = 0
        while h < 13 {
            header[h] = record[h]
            h += 1
        }

        let epoch = (uint16(header[3]) << 8) | uint16(header[4])
        let seq: uint64 = (uint64(header[5]) << 40) |
                          (uint64(header[6]) << 32) |
                          (uint64(header[7]) << 24) |
                          (uint64(header[8]) << 16) |
                          (uint64(header[9]) << 8)  |
                           uint64(header[10])

        // Verify Anti-Replay
        if epoch == self.Epoch {
            if !self.Window.Check(seq) {
                throw DtlsError.replayDetected(seq)
            }
        }

        var payload: [uint8] = []
        var p = 13
        while p < record.count {
            payload.append(record[p])
            p += 1
        }

        let nonce = ComputeNonce(epoch: epoch, seq: seq)
        let aead = try chacha20poly1305.AEAD.New(key: self.Key)
        let inner = try aead.Open(nonce: nonce, ciphertextAndTag: payload, additionalData: header)

        // Decryption succeeded: mark sequence number in replay window
        if epoch == self.Epoch {
            _ = self.Window.Update(seq)
        }

        // Scan from end of inner plaintext to strip padding and retrieve real ContentType
        var idx = inner.count - 1
        while idx >= 0 && inner[idx] == 0 {
            idx -= 1
        }
        if idx < 0 {
            throw DtlsError.unexpectedMessage("zero inner plaintext in DTLS record")
        }

        let innerType = inner[idx]
        var realData = [uint8](repeating: 0, count: idx)
        var i = 0
        while i < idx {
            realData[i] = inner[i]
            i += 1
        }

        return DecryptedRecord(
            ContentType: innerType,
            Epoch: epoch,
            SequenceNumber: seq,
            Data: realData
        )
    }
}
