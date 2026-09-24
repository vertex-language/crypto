package md5

// The size of an MD5 checksum in bytes.
public let Size: int = 16

// The blocksize of MD5 in bytes.
public let BlockSize: int = 64

func rotl(_ x: uint32, _ n: uint32) -> uint32 {
    return (x << n) | (x &>> (32 &- n))
}

func ff(_ a: uint32, _ b: uint32, _ c: uint32, _ d: uint32, _ k: uint32, _ s: uint32, _ t: uint32) -> uint32 {
    let f = (b & c) | ((~b) & d)
    return b &+ rotl(a &+ f &+ k &+ t, s)
}

func gg(_ a: uint32, _ b: uint32, _ c: uint32, _ d: uint32, _ k: uint32, _ s: uint32, _ t: uint32) -> uint32 {
    let g = (b & d) | (c & (~d))
    return b &+ rotl(a &+ g &+ k &+ t, s)
}

func hh(_ a: uint32, _ b: uint32, _ c: uint32, _ d: uint32, _ k: uint32, _ s: uint32, _ t: uint32) -> uint32 {
    let h = b ^ c ^ d
    return b &+ rotl(a &+ h &+ k &+ t, s)
}

func ii(_ a: uint32, _ b: uint32, _ c: uint32, _ d: uint32, _ k: uint32, _ s: uint32, _ t: uint32) -> uint32 {
    let i = c ^ (b | (~d))
    return b &+ rotl(a &+ i &+ k &+ t, s)
}

/// Digest represents the partial evaluation of an MD5 checksum.
public struct Digest {
    var a: uint32 = 0x67452301
    var b: uint32 = 0xefcdab89
    var c: uint32 = 0x98badcfe
    var d: uint32 = 0x10325476

    var buf: [uint8] = []
    var length: uint64 = 0

    public init() {
        Reset()
    }

    public mutating func Reset() {
        a = 0x67452301
        b = 0xefcdab89
        c = 0x98badcfe
        d = 0x10325476
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
        var x = [uint32](repeating: 0, count: 16)
        var j = 0
        while j < 16 {
            let offset = j * 4
            let b0 = uint32(block[offset])
            let b1 = uint32(block[offset + 1])
            let b2 = uint32(block[offset + 2])
            let b3 = uint32(block[offset + 3])
            x[j] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            j += 1
        }

        var aa = a
        var bb = b
        var cc = c
        var dd = d

        // Round 1
        aa = ff(aa, bb, cc, dd, x[0], 7, 0xd76aa478)
        dd = ff(dd, aa, bb, cc, x[1], 12, 0xe8c7b756)
        cc = ff(cc, dd, aa, bb, x[2], 17, 0x242070db)
        bb = ff(bb, cc, dd, aa, x[3], 22, 0xc1bdceee)
        aa = ff(aa, bb, cc, dd, x[4], 7, 0xf57c0faf)
        dd = ff(dd, aa, bb, cc, x[5], 12, 0x4787c62a)
        cc = ff(cc, dd, aa, bb, x[6], 17, 0xa8304613)
        bb = ff(bb, cc, dd, aa, x[7], 22, 0xfd469501)
        aa = ff(aa, bb, cc, dd, x[8], 7, 0x698098d8)
        dd = ff(dd, aa, bb, cc, x[9], 12, 0x8b44f7af)
        cc = ff(cc, dd, aa, bb, x[10], 17, 0xffff5bb1)
        bb = ff(bb, cc, dd, aa, x[11], 22, 0x895cd7be)
        aa = ff(aa, bb, cc, dd, x[12], 7, 0x6b901122)
        dd = ff(dd, aa, bb, cc, x[13], 12, 0xfd987193)
        cc = ff(cc, dd, aa, bb, x[14], 17, 0xa679438e)
        bb = ff(bb, cc, dd, aa, x[15], 22, 0x49b40821)

        // Round 2
        aa = gg(aa, bb, cc, dd, x[1], 5, 0xf61e2562)
        dd = gg(dd, aa, bb, cc, x[6], 9, 0xc040b340)
        cc = gg(cc, dd, aa, bb, x[11], 14, 0x265e5a51)
        bb = gg(bb, cc, dd, aa, x[0], 20, 0xe9b6c7aa)
        aa = gg(aa, bb, cc, dd, x[5], 5, 0xd62f105d)
        dd = gg(dd, aa, bb, cc, x[10], 9, 0x02441453)
        cc = gg(cc, dd, aa, bb, x[15], 14, 0xd8a1e681)
        bb = gg(bb, cc, dd, aa, x[4], 20, 0xe7d3fbc8)
        aa = gg(aa, bb, cc, dd, x[9], 5, 0x21e1cde6)
        dd = gg(dd, aa, bb, cc, x[14], 9, 0xc33707d6)
        cc = gg(cc, dd, aa, bb, x[3], 14, 0xf4d50d87)
        bb = gg(bb, cc, dd, aa, x[8], 20, 0x455a14ed)
        aa = gg(aa, bb, cc, dd, x[13], 5, 0xa9e3e905)
        dd = gg(dd, aa, bb, cc, x[2], 9, 0xfcefa3f8)
        cc = gg(cc, dd, aa, bb, x[7], 14, 0x676f02d9)
        bb = gg(bb, cc, dd, aa, x[12], 20, 0x8d2a4c8a)

        // Round 3
        aa = hh(aa, bb, cc, dd, x[5], 4, 0xfffa3942)
        dd = hh(dd, aa, bb, cc, x[8], 11, 0x8771f681)
        cc = hh(cc, dd, aa, bb, x[11], 16, 0x6d9d6122)
        bb = hh(bb, cc, dd, aa, x[14], 23, 0xfde5380c)
        aa = hh(aa, bb, cc, dd, x[1], 4, 0xa4beea44)
        dd = hh(dd, aa, bb, cc, x[4], 11, 0x4bdecfa9)
        cc = hh(cc, dd, aa, bb, x[7], 16, 0xf6bb4b60)
        bb = hh(bb, cc, dd, aa, x[10], 23, 0xbebfbc70)
        aa = hh(aa, bb, cc, dd, x[13], 4, 0x289b7ec6)
        dd = hh(dd, aa, bb, cc, x[0], 11, 0xeaa127fa)
        cc = hh(cc, dd, aa, bb, x[3], 16, 0xd4ef3085)
        bb = hh(bb, cc, dd, aa, x[6], 23, 0x04881d05)
        aa = hh(aa, bb, cc, dd, x[9], 4, 0xd9d4d039)
        dd = hh(dd, aa, bb, cc, x[12], 11, 0xe6db99e5)
        cc = hh(cc, dd, aa, bb, x[15], 16, 0x1fa27cf8)
        bb = hh(bb, cc, dd, aa, x[2], 23, 0xc4ac5665)

        // Round 4
        aa = ii(aa, bb, cc, dd, x[0], 6, 0xf4292244)
        dd = ii(dd, aa, bb, cc, x[7], 10, 0x432aff97)
        cc = ii(cc, dd, aa, bb, x[14], 15, 0xab9423a7)
        bb = ii(bb, cc, dd, aa, x[5], 21, 0xfc93a039)
        aa = ii(aa, bb, cc, dd, x[12], 6, 0x655b59c3)
        dd = ii(dd, aa, bb, cc, x[3], 10, 0x8f0ccc92)
        cc = ii(cc, dd, aa, bb, x[10], 15, 0xffeff47d)
        bb = ii(bb, cc, dd, aa, x[1], 21, 0x85845dd1)
        aa = ii(aa, bb, cc, dd, x[8], 6, 0x6fa87e4f)
        dd = ii(dd, aa, bb, cc, x[15], 10, 0xfe2ce6e0)
        cc = ii(cc, dd, aa, bb, x[6], 15, 0xa3014314)
        bb = ii(bb, cc, dd, aa, x[13], 21, 0x4e0811a1)
        aa = ii(aa, bb, cc, dd, x[4], 6, 0xf7537e82)
        dd = ii(dd, aa, bb, cc, x[11], 10, 0xbd3af235)
        cc = ii(cc, dd, aa, bb, x[2], 15, 0x2ad7d2bb)
        bb = ii(bb, cc, dd, aa, x[9], 21, 0xeb86d391)

        a &+= aa
        b &+= bb
        c &+= cc
        d &+= dd
    }

    /// Checksum finalizes the MD5 hash and returns the 16-byte digest.
    public mutating func Checksum() -> [uint8] {
        let bitLen = length &* 8
        var pad: [uint8] = [0x80]
        let currentBlockLen = int(length % uint64(BlockSize))
        var padLen = 56 - currentBlockLen
        if padLen <= 0 {
            padLen += BlockSize
        }
        padLen -= 1 // account for 0x80
        var i = 0
        while i < padLen {
            pad.append(0)
            i += 1
        }

        // 64-bit length in bits in little-endian order
        pad.append(uint8(truncatingIfNeeded: bitLen))
        pad.append(uint8(truncatingIfNeeded: bitLen >> 8))
        pad.append(uint8(truncatingIfNeeded: bitLen >> 16))
        pad.append(uint8(truncatingIfNeeded: bitLen >> 24))
        pad.append(uint8(truncatingIfNeeded: bitLen >> 32))
        pad.append(uint8(truncatingIfNeeded: bitLen >> 40))
        pad.append(uint8(truncatingIfNeeded: bitLen >> 48))
        pad.append(uint8(truncatingIfNeeded: bitLen >> 56))

        Write(pad)

        // Little-endian output of a, b, c, d
        var result = [uint8](repeating: 0, count: Size)
        let state = [a, b, c, d]
        var si = 0
        while si < 4 {
            let val = state[si]
            let offset = si * 4
            result[offset] = uint8(truncatingIfNeeded: val)
            result[offset + 1] = uint8(truncatingIfNeeded: val >> 8)
            result[offset + 2] = uint8(truncatingIfNeeded: val >> 16)
            result[offset + 3] = uint8(truncatingIfNeeded: val >> 24)
            si += 1
        }
        return result
    }
}

/// Creates a new Digest instance.
public func New() -> Digest {
    return Digest()
}

/// Computes the MD5 checksum of the given data.
public func Sum(_ data: [uint8]) -> [uint8] {
    var d = Digest()
    d.Write(data)
    return d.Checksum()
}

/// Computes the MD5 checksum of a string.
public func SumString(_ s: string) -> [uint8] {
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
