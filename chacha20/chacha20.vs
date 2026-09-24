package chacha20

public let KeySize: int = 32
public let NonceSize: int = 12
public let BlockSize: int = 64

public enum ChaCha20Error: Error {
    case invalidKeySize
    case invalidNonceSize
    case counterOverflow
}

func rol(_ v: uint32, _ c: uint32) -> uint32 {
    return (v << c) | (v >> (32 &- c))
}

func qround(_ x: inout [uint32], _ a: int, _ b: int, _ c: int, _ d: int) {
    x[a] &+= x[b]; x[d] ^= x[a]; x[d] = rol(x[d], 16)
    x[c] &+= x[d]; x[b] ^= x[c]; x[b] = rol(x[b], 12)
    x[a] &+= x[b]; x[d] ^= x[a]; x[d] = rol(x[d], 8)
    x[c] &+= x[d]; x[b] ^= x[c]; x[b] = rol(x[b], 7)
}

/// Cipher is a stateful ChaCha20 stream cipher instance (RFC 8439).
public struct Cipher {
    var key: [uint32] = [uint32](repeating: 0, count: 8)
    var nonce: [uint32] = [uint32](repeating: 0, count: 3)
    public var counter: uint32 = 1

    public init(keyWords: [uint32], nonceWords: [uint32], counter: uint32 = 1) {
        self.key = keyWords
        self.nonce = nonceWords
        self.counter = counter
    }

    /// New creates a new ChaCha20 Cipher instance.
    public static func New(key: [uint8], nonce: [uint8], counter: uint32 = 1) throws -> Cipher {
        if key.count != KeySize {
            throw ChaCha20Error.invalidKeySize
        }
        if nonce.count != NonceSize {
            throw ChaCha20Error.invalidNonceSize
        }

        var keyWords = [uint32](repeating: 0, count: 8)
        var i = 0
        while i < 8 {
            let offset = i * 4
            keyWords[i] = uint32(key[offset]) |
                          (uint32(key[offset + 1]) << 8) |
                          (uint32(key[offset + 2]) << 16) |
                          (uint32(key[offset + 3]) << 24)
            i += 1
        }

        var nonceWords = [uint32](repeating: 0, count: 3)
        i = 0
        while i < 3 {
            let offset = i * 4
            nonceWords[i] = uint32(nonce[offset]) |
                            (uint32(nonce[offset + 1]) << 8) |
                            (uint32(nonce[offset + 2]) << 16) |
                            (uint32(nonce[offset + 3]) << 24)
            i += 1
        }

        return Cipher(keyWords: keyWords, nonceWords: nonceWords, counter: counter)
    }

    /// XORKeyStream encrypts or decrypts src into dst using the ChaCha20 keystream.
    public mutating func XORKeyStream(_ dst: inout [uint8], _ src: [uint8]) {
        var offset = 0
        while offset < src.count {
            var state: [uint32] = [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                key[0], key[1], key[2], key[3],
                key[4], key[5], key[6], key[7],
                counter, nonce[0], nonce[1], nonce[2]
            ]
            counter &+= 1

            var working = state
            var round = 0
            while round < 10 {
                // Column round
                qround(&working, 0, 4, 8, 12)
                qround(&working, 1, 5, 9, 13)
                qround(&working, 2, 6, 10, 14)
                qround(&working, 3, 7, 11, 15)
                // Diagonal round
                qround(&working, 0, 5, 10, 15)
                qround(&working, 1, 6, 11, 12)
                qround(&working, 2, 7, 8, 13)
                qround(&working, 3, 4, 9, 14)
                round += 1
            }

            var ks = [uint8](repeating: 0, count: 64)
            var w = 0
            while w < 16 {
                let sum = working[w] &+ state[w]
                let base = w * 4
                ks[base] = uint8(truncatingIfNeeded: sum)
                ks[base + 1] = uint8(truncatingIfNeeded: sum >> 8)
                ks[base + 2] = uint8(truncatingIfNeeded: sum >> 16)
                ks[base + 3] = uint8(truncatingIfNeeded: sum >> 24)
                w += 1
            }

            let chunkLen = src.count - offset < 64 ? src.count - offset : 64
            var j = 0
            while j < chunkLen {
                dst[offset + j] = src[offset + j] ^ ks[j]
                j += 1
            }
            offset += chunkLen
        }
    }
}

/// Encrypt encrypts plaintext with key and nonce using ChaCha20 (RFC 8439).
public func Encrypt(key: [uint8], nonce: [uint8], plaintext: [uint8], counter: uint32 = 1) throws -> [uint8] {
    var c = try Cipher.New(key: key, nonce: nonce, counter: counter)
    var ct = [uint8](repeating: 0, count: plaintext.count)
    c.XORKeyStream(&ct, plaintext)
    return ct
}

/// Decrypt decrypts ciphertext with key and nonce using ChaCha20 (RFC 8439).
public func Decrypt(key: [uint8], nonce: [uint8], ciphertext: [uint8], counter: uint32 = 1) throws -> [uint8] {
    return try Encrypt(key: key, nonce: nonce, plaintext: ciphertext, counter: counter)
}
