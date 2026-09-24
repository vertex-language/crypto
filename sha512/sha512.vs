// Package sha512 implements SHA-512 and SHA-384 (FIPS 180-4). SHA-384 is
// SHA-512 with a different initial state, truncated to 48 bytes. RDP needs
// SHA-384 for the TLS_..._SHA384 cipher suites Schannel prefers and their
// HMAC/PRF.
package sha512

public let Size: int = 64
public let Size384: int = 48
public let BlockSize: int = 128

let K: [uint64] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

func rotr(_ x: uint64, _ n: uint64) -> uint64 { return (x >> n) | (x << (64 - n)) }
func ch(_ x: uint64, _ y: uint64, _ z: uint64) -> uint64 { return (x & y) ^ (~x & z) }
func maj(_ x: uint64, _ y: uint64, _ z: uint64) -> uint64 { return (x & y) ^ (x & z) ^ (y & z) }
func bs0(_ x: uint64) -> uint64 { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39) }
func bs1(_ x: uint64) -> uint64 { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41) }
func ss0(_ x: uint64) -> uint64 { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7) }
func ss1(_ x: uint64) -> uint64 { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6) }

public struct Digest {
    var h: [uint64] = [uint64](repeating: 0, count: 8)
    var buf: [uint8] = []
    var length: uint64 = 0
    public var is384: bool = false

    public init(is384: bool = false) {
        self.is384 = is384
        Reset()
    }

    public mutating func Reset() {
        if is384 {
            h = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]
        } else {
            h = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
        }
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
        for b in s.utf8 { bytes.append(b) }
        Write(bytes)
    }

    mutating func processBlock(_ block: [uint8]) {
        var w = [uint64](repeating: 0, count: 80)
        var i = 0
        while i < 16 {
            let o = i * 8
            w[i] = (uint64(block[o]) << 56) | (uint64(block[o+1]) << 48) |
                   (uint64(block[o+2]) << 40) | (uint64(block[o+3]) << 32) |
                   (uint64(block[o+4]) << 24) | (uint64(block[o+5]) << 16) |
                   (uint64(block[o+6]) << 8) | uint64(block[o+7])
            i += 1
        }
        while i < 80 {
            w[i] = ss1(w[i-2]) &+ w[i-7] &+ ss0(w[i-15]) &+ w[i-16]
            i += 1
        }
        var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
        var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]
        var t = 0
        while t < 80 {
            let t1 = hh &+ bs1(e) &+ ch(e, f, g) &+ K[t] &+ w[t]
            let t2 = bs0(a) &+ maj(a, b, c)
            hh = g; g = f; f = e; e = d &+ t1
            d = c; c = b; b = a; a = t1 &+ t2
            t += 1
        }
        h[0] &+= a; h[1] &+= b; h[2] &+= c; h[3] &+= d
        h[4] &+= e; h[5] &+= f; h[6] &+= g; h[7] &+= hh
    }

    public func Checksum() -> [uint8] {
        var d = self
        let bitLen = d.length &* 8
        // Pad: 0x80, zeros, then 128-bit big-endian length. We only track
        // the low 64 bits of the bit length (inputs are far below 2^64 bits).
        d.appendByte(0x80)
        while d.buf.count != 112 {
            d.appendByte(0x00)
        }
        var lenBytes = [uint8](repeating: 0, count: 16)
        var j = 15
        var bl = bitLen
        while j >= 8 {
            lenBytes[j] = uint8(truncatingIfNeeded: bl)
            bl >>= 8
            j -= 1
        }
        var k = 0
        while k < 16 {
            d.appendByte(lenBytes[k])
            k += 1
        }
        var out: [uint8] = []
        let n = d.is384 ? 6 : 8
        var i = 0
        while i < n {
            let v = d.h[i]
            out.append(uint8(truncatingIfNeeded: v >> 56))
            out.append(uint8(truncatingIfNeeded: v >> 48))
            out.append(uint8(truncatingIfNeeded: v >> 40))
            out.append(uint8(truncatingIfNeeded: v >> 32))
            out.append(uint8(truncatingIfNeeded: v >> 24))
            out.append(uint8(truncatingIfNeeded: v >> 16))
            out.append(uint8(truncatingIfNeeded: v >> 8))
            out.append(uint8(truncatingIfNeeded: v))
            i += 1
        }
        return out
    }

    mutating func appendByte(_ b: uint8) {
        buf.append(b)
        if buf.count == BlockSize {
            processBlock(buf)
            buf.removeAll()
        }
    }
}

public func New() -> Digest { return Digest(is384: false) }
public func New384() -> Digest { return Digest(is384: true) }

public func Sum512(_ data: [uint8]) -> [uint8] {
    var d = Digest(is384: false)
    d.Write(data)
    return d.Checksum()
}

public func Sum384(_ data: [uint8]) -> [uint8] {
    var d = Digest(is384: true)
    d.Write(data)
    return d.Checksum()
}

public func ToHex(_ bytes: [uint8]) -> string {
    let hexChars: [uint8] = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]
    var out: [uint8] = []
    var i = 0
    while i < bytes.count {
        out.append(hexChars[int(bytes[i] >> 4)])
        out.append(hexChars[int(bytes[i] & 0x0f)])
        i += 1
    }
    return string(decoding: out, as: UTF8.self)
}
