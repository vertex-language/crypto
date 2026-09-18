package sha1

// The size of a SHA-1 checksum in bytes.
public let Size: int = 20

// The blocksize of SHA-1 in bytes.
public let BlockSize: int = 64

func rotl(_ x: uint32, _ n: uint32) -> uint32 {
    return (x << n) | (x &>> (32 &- n))
}

/// Digest represents the partial evaluation of a SHA-1 checksum.
public struct Digest {
    var h0: uint32 = 0x67452301
    var h1: uint32 = 0xEFCDAB89
    var h2: uint32 = 0x98BADCFE
    var h3: uint32 = 0x10325476
    var h4: uint32 = 0xC3D2E1F0

    var buf: [uint8] = []
    var length: uint64 = 0

    public init() {
        Reset()
    }

    public mutating func Reset() {
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
        buf = []
        length = 0
    }

    public mutating func Write(_ p: [uint8]) {
        length &+= uint64(p.count)
        var i = 0
        while i < p.count {
            buf.append(p[i])
            if buf.count == BlockSize {
                processBlock(buf)
                buf.removeAll()
            }
            i += 1
        }
    }

    public mutating func WriteString(_ s: string) {
        var bytes: [uint8] = []
        for b in s.utf8 {
            bytes.append(b)
        }
        Write(bytes)
    }

    mutating func processBlock(_ block: [uint8]) {
        var w = [uint32](repeating: 0, count: 80)
        var i = 0
        while i < 16 {
            let offset = i * 4
            w[i] = (uint32(block[offset]) << 24) |
                   (uint32(block[offset + 1]) << 16) |
                   (uint32(block[offset + 2]) << 8) |
                   uint32(block[offset + 3])
            i += 1
        }
        while i < 80 {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
            i += 1
        }

        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4

        var t = 0
        while t < 80 {
            var f: uint32 = 0
            var k: uint32 = 0
            if t < 20 {
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            } else if t < 40 {
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            } else if t < 60 {
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            } else {
                f = b ^ c ^ d
                k = 0xCA62C1D6
            }

            let temp = rotl(a, 5) &+ f &+ e &+ k &+ w[t]
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = temp
            t += 1
        }

        h0 &+= a
        h1 &+= b
        h2 &+= c
        h3 &+= d
        h4 &+= e
    }

    /// Finalize and return the 20-byte digest.
    public func Checksum() -> [uint8] {
        var clone = self
        var pad: [uint8] = []
        pad.append(0x80)

        let totalBits = clone.length &* 8
        let currentLen = (clone.buf.count + 1) % BlockSize
        let padLen = (currentLen <= 56) ? (56 - currentLen) : (BlockSize + 56 - currentLen)

        var p = 0
        while p < padLen {
            pad.append(0)
            p += 1
        }

        var shift: uint64 = 56
        while true {
            pad.append(uint8(truncatingIfNeeded: totalBits >> shift))
            if shift == 0 {
                break
            }
            shift &-= 8
        }

        clone.Write(pad)

        var result = [uint8](repeating: 0, count: Size)
        let state = [clone.h0, clone.h1, clone.h2, clone.h3, clone.h4]
        var si = 0
        while si < 5 {
            let offset = si * 4
            let val = state[si]
            result[offset] = uint8(truncatingIfNeeded: val >> 24)
            result[offset + 1] = uint8(truncatingIfNeeded: val >> 16)
            result[offset + 2] = uint8(truncatingIfNeeded: val >> 8)
            result[offset + 3] = uint8(truncatingIfNeeded: val)
            si += 1
        }
        return result
    }
}

/// Creates a new Digest instance.
public func New() -> Digest {
    return Digest()
}

/// Computes the SHA-1 checksum of the given data.
public func Sum1(_ data: [uint8]) -> [uint8] {
    var d = Digest()
    d.Write(data)
    return d.Checksum()
}

/// Computes the SHA-1 checksum of a string.
public func Sum1String(_ s: string) -> [uint8] {
    var d = Digest()
    d.WriteString(s)
    return d.Checksum()
}

/// Converts a byte array to its lowercase hexadecimal string representation.
public func ToHex(_ d: [uint8]) -> string {
    let digits: [uint8] = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]
    var hexBytes: [uint8] = []
    var i = 0
    while i < d.count {
        let b = d[i]
        hexBytes.append(digits[int(b >> 4)])
        hexBytes.append(digits[int(b & 0x0F)])
        i += 1
    }
    return string(decoding: hexBytes, as: UTF8.self)
}
