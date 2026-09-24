// Package md4 implements the MD4 message digest (RFC 1320). It is
// cryptographically broken and used only where a legacy protocol requires
// it: the NTLM "NT hash" is MD4 of the UTF-16LE password.
package md4

public let Size: int = 16
public let BlockSize: int = 64

public struct Digest {
    var a: uint32 = 0x67452301
    var b: uint32 = 0xefcdab89
    var c: uint32 = 0x98badcfe
    var d: uint32 = 0x10325476
    var buf: [uint8] = []
    var length: uint64 = 0

    public init() { Reset() }

    public mutating func Reset() {
        a = 0x67452301; b = 0xefcdab89; c = 0x98badcfe; d = 0x10325476
        buf = []; length = 0
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

    mutating func processBlock(_ block: [uint8]) {
        var x = [uint32](repeating: 0, count: 16)
        var i = 0
        while i < 16 {
            let o = i * 4
            x[i] = uint32(block[o]) | (uint32(block[o+1]) << 8) |
                   (uint32(block[o+2]) << 16) | (uint32(block[o+3]) << 24)
            i += 1
        }
        // MD4's three rounds use a fixed word/shift schedule, written out.
        var aa = a; var bb = b; var cc = c; var dd = d

        aa = ff(aa,bb,cc,dd,x[0],3);  dd = ff(dd,aa,bb,cc,x[1],7)
        cc = ff(cc,dd,aa,bb,x[2],11); bb = ff(bb,cc,dd,aa,x[3],19)
        aa = ff(aa,bb,cc,dd,x[4],3);  dd = ff(dd,aa,bb,cc,x[5],7)
        cc = ff(cc,dd,aa,bb,x[6],11); bb = ff(bb,cc,dd,aa,x[7],19)
        aa = ff(aa,bb,cc,dd,x[8],3);  dd = ff(dd,aa,bb,cc,x[9],7)
        cc = ff(cc,dd,aa,bb,x[10],11);bb = ff(bb,cc,dd,aa,x[11],19)
        aa = ff(aa,bb,cc,dd,x[12],3); dd = ff(dd,aa,bb,cc,x[13],7)
        cc = ff(cc,dd,aa,bb,x[14],11);bb = ff(bb,cc,dd,aa,x[15],19)

        aa = gg(aa,bb,cc,dd,x[0],3);  dd = gg(dd,aa,bb,cc,x[4],5)
        cc = gg(cc,dd,aa,bb,x[8],9);  bb = gg(bb,cc,dd,aa,x[12],13)
        aa = gg(aa,bb,cc,dd,x[1],3);  dd = gg(dd,aa,bb,cc,x[5],5)
        cc = gg(cc,dd,aa,bb,x[9],9);  bb = gg(bb,cc,dd,aa,x[13],13)
        aa = gg(aa,bb,cc,dd,x[2],3);  dd = gg(dd,aa,bb,cc,x[6],5)
        cc = gg(cc,dd,aa,bb,x[10],9); bb = gg(bb,cc,dd,aa,x[14],13)
        aa = gg(aa,bb,cc,dd,x[3],3);  dd = gg(dd,aa,bb,cc,x[7],5)
        cc = gg(cc,dd,aa,bb,x[11],9); bb = gg(bb,cc,dd,aa,x[15],13)

        aa = hh(aa,bb,cc,dd,x[0],3);  dd = hh(dd,aa,bb,cc,x[8],9)
        cc = hh(cc,dd,aa,bb,x[4],11); bb = hh(bb,cc,dd,aa,x[12],15)
        aa = hh(aa,bb,cc,dd,x[2],3);  dd = hh(dd,aa,bb,cc,x[10],9)
        cc = hh(cc,dd,aa,bb,x[6],11); bb = hh(bb,cc,dd,aa,x[14],15)
        aa = hh(aa,bb,cc,dd,x[1],3);  dd = hh(dd,aa,bb,cc,x[9],9)
        cc = hh(cc,dd,aa,bb,x[5],11); bb = hh(bb,cc,dd,aa,x[13],15)
        aa = hh(aa,bb,cc,dd,x[3],3);  dd = hh(dd,aa,bb,cc,x[11],9)
        cc = hh(cc,dd,aa,bb,x[7],11); bb = hh(bb,cc,dd,aa,x[15],15)

        a = a &+ aa; b = b &+ bb; c = c &+ cc; d = d &+ dd
    }

    public func Checksum() -> [uint8] {
        var d2 = self
        let bitLen = d2.length &* 8
        d2.appendByte(0x80)
        while d2.buf.count != 56 { d2.appendByte(0x00) }
        var i = 0
        var bl = bitLen
        while i < 8 { d2.appendByte(uint8(truncatingIfNeeded: bl)); bl >>= 8; i += 1 }
        var out: [uint8] = []
        appendLE(&out, d2.a); appendLE(&out, d2.b); appendLE(&out, d2.c); appendLE(&out, d2.d)
        return out
    }

    mutating func appendByte(_ x: uint8) {
        buf.append(x)
        if buf.count == BlockSize { processBlock(buf); buf.removeAll() }
    }
}

func appendLE(_ out: inout [uint8], _ v: uint32) {
    out.append(uint8(truncatingIfNeeded: v))
    out.append(uint8(truncatingIfNeeded: v >> 8))
    out.append(uint8(truncatingIfNeeded: v >> 16))
    out.append(uint8(truncatingIfNeeded: v >> 24))
}

func rol(_ x: uint32, _ n: int) -> uint32 { return (x << uint32(n)) | (x >> uint32(32 - n)) }
func f(_ x: uint32, _ y: uint32, _ z: uint32) -> uint32 { return (x & y) | (~x & z) }
func g(_ x: uint32, _ y: uint32, _ z: uint32) -> uint32 { return (x & y) | (x & z) | (y & z) }
func h(_ x: uint32, _ y: uint32, _ z: uint32) -> uint32 { return x ^ y ^ z }

func ff(_ a: uint32, _ b: uint32, _ c: uint32, _ d: uint32, _ xk: uint32, _ s: int) -> uint32 {
    return rol(a &+ f(b, c, d) &+ xk, s)
}
func gg(_ a: uint32, _ b: uint32, _ c: uint32, _ d: uint32, _ xk: uint32, _ s: int) -> uint32 {
    return rol(a &+ g(b, c, d) &+ xk &+ 0x5a827999, s)
}
func hh(_ a: uint32, _ b: uint32, _ c: uint32, _ d: uint32, _ xk: uint32, _ s: int) -> uint32 {
    return rol(a &+ h(b, c, d) &+ xk &+ 0x6ed9eba1, s)
}

public func New() -> Digest { return Digest() }

public func Sum(_ data: [uint8]) -> [uint8] {
    var d = Digest()
    d.Write(data)
    return d.Checksum()
}
