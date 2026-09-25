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
        // The state is sixteen locals, not an array: a block is then
        // arithmetic on registers, with nothing allocated.
        let k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3]
        let k4 = key[4], k5 = key[5], k6 = key[6], k7 = key[7]
        let n0 = nonce[0], n1 = nonce[1], n2 = nonce[2]
        let total = src.count
        var ctr = counter
        dst.withUnsafeMutableBufferPointer { out in
            src.withUnsafeBufferPointer { inp in
                var offset = 0
                while offset < total {
                    var x0: uint32 = 0x61707865, x1: uint32 = 0x3320646e
                    var x2: uint32 = 0x79622d32, x3: uint32 = 0x6b206574
                    var x4 = k0, x5 = k1, x6 = k2, x7 = k3
                    var x8 = k4, x9 = k5, x10 = k6, x11 = k7
                    var x12 = ctr, x13 = n0, x14 = n1, x15 = n2
                    var round = 0
                    while round < 10 {
                        // Column round
                        x0 &+= x4; x12 ^= x0; x12 = (x12 << 16) | (x12 >> 16)
                        x8 &+= x12; x4 ^= x8; x4 = (x4 << 12) | (x4 >> 20)
                        x0 &+= x4; x12 ^= x0; x12 = (x12 << 8) | (x12 >> 24)
                        x8 &+= x12; x4 ^= x8; x4 = (x4 << 7) | (x4 >> 25)
                        x1 &+= x5; x13 ^= x1; x13 = (x13 << 16) | (x13 >> 16)
                        x9 &+= x13; x5 ^= x9; x5 = (x5 << 12) | (x5 >> 20)
                        x1 &+= x5; x13 ^= x1; x13 = (x13 << 8) | (x13 >> 24)
                        x9 &+= x13; x5 ^= x9; x5 = (x5 << 7) | (x5 >> 25)
                        x2 &+= x6; x14 ^= x2; x14 = (x14 << 16) | (x14 >> 16)
                        x10 &+= x14; x6 ^= x10; x6 = (x6 << 12) | (x6 >> 20)
                        x2 &+= x6; x14 ^= x2; x14 = (x14 << 8) | (x14 >> 24)
                        x10 &+= x14; x6 ^= x10; x6 = (x6 << 7) | (x6 >> 25)
                        x3 &+= x7; x15 ^= x3; x15 = (x15 << 16) | (x15 >> 16)
                        x11 &+= x15; x7 ^= x11; x7 = (x7 << 12) | (x7 >> 20)
                        x3 &+= x7; x15 ^= x3; x15 = (x15 << 8) | (x15 >> 24)
                        x11 &+= x15; x7 ^= x11; x7 = (x7 << 7) | (x7 >> 25)
                        // Diagonal round
                        x0 &+= x5; x15 ^= x0; x15 = (x15 << 16) | (x15 >> 16)
                        x10 &+= x15; x5 ^= x10; x5 = (x5 << 12) | (x5 >> 20)
                        x0 &+= x5; x15 ^= x0; x15 = (x15 << 8) | (x15 >> 24)
                        x10 &+= x15; x5 ^= x10; x5 = (x5 << 7) | (x5 >> 25)
                        x1 &+= x6; x12 ^= x1; x12 = (x12 << 16) | (x12 >> 16)
                        x11 &+= x12; x6 ^= x11; x6 = (x6 << 12) | (x6 >> 20)
                        x1 &+= x6; x12 ^= x1; x12 = (x12 << 8) | (x12 >> 24)
                        x11 &+= x12; x6 ^= x11; x6 = (x6 << 7) | (x6 >> 25)
                        x2 &+= x7; x13 ^= x2; x13 = (x13 << 16) | (x13 >> 16)
                        x8 &+= x13; x7 ^= x8; x7 = (x7 << 12) | (x7 >> 20)
                        x2 &+= x7; x13 ^= x2; x13 = (x13 << 8) | (x13 >> 24)
                        x8 &+= x13; x7 ^= x8; x7 = (x7 << 7) | (x7 >> 25)
                        x3 &+= x4; x14 ^= x3; x14 = (x14 << 16) | (x14 >> 16)
                        x9 &+= x14; x4 ^= x9; x4 = (x4 << 12) | (x4 >> 20)
                        x3 &+= x4; x14 ^= x3; x14 = (x14 << 8) | (x14 >> 24)
                        x9 &+= x14; x4 ^= x9; x4 = (x4 << 7) | (x4 >> 25)
                        round += 1
                    }
                    x0 &+= 0x61707865; x1 &+= 0x3320646e; x2 &+= 0x79622d32; x3 &+= 0x6b206574
                    x4 &+= k0; x5 &+= k1; x6 &+= k2; x7 &+= k3
                    x8 &+= k4; x9 &+= k5; x10 &+= k6; x11 &+= k7
                    x12 &+= ctr; x13 &+= n0; x14 &+= n1; x15 &+= n2
                    ctr &+= 1

                    let chunkLen = total - offset < 64 ? total - offset : 64
                    var j = 0
                    while j < chunkLen {
                        var word: uint32 = 0
                        switch j >> 2 {
                        case 0: word = x0
                        case 1: word = x1
                        case 2: word = x2
                        case 3: word = x3
                        case 4: word = x4
                        case 5: word = x5
                        case 6: word = x6
                        case 7: word = x7
                        case 8: word = x8
                        case 9: word = x9
                        case 10: word = x10
                        case 11: word = x11
                        case 12: word = x12
                        case 13: word = x13
                        case 14: word = x14
                        default: word = x15
                        }
                        // Four bytes of the word at a time where they fit.
                        if j + 4 <= chunkLen {
                            out[offset + j] = inp[offset + j] ^ uint8(truncatingIfNeeded: word)
                            out[offset + j + 1] = inp[offset + j + 1] ^ uint8(truncatingIfNeeded: word >> 8)
                            out[offset + j + 2] = inp[offset + j + 2] ^ uint8(truncatingIfNeeded: word >> 16)
                            out[offset + j + 3] = inp[offset + j + 3] ^ uint8(truncatingIfNeeded: word >> 24)
                            j += 4
                        } else {
                            out[offset + j] = inp[offset + j] ^ uint8(truncatingIfNeeded: word >> uint32((j & 3) * 8))
                            j += 1
                        }
                    }
                    offset += chunkLen
                }
            }
        }
        counter = ctr
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
