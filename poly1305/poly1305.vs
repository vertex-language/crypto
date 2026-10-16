package poly1305

import "crypto/subtle"

public let TagSize: int = 16
public let KeySize: int = 32

public enum Poly1305Error: Error {
    case invalidKeySize
}

func readU32Le(_ b: [uint8], _ offset: int) -> uint32 {
    return uint32(b[offset]) |
           (uint32(b[offset + 1]) << 8) |
           (uint32(b[offset + 2]) << 16) |
           (uint32(b[offset + 3]) << 24)
}

func le32(_ p: UnsafePointer<uint8>) -> uint32 {
    return uint32(p.pointee) |
           (uint32((p + 1).pointee) << 8) |
           (uint32((p + 2).pointee) << 16) |
           (uint32((p + 3).pointee) << 24)
}

/// State is a Poly1305 computation's arithmetic: r clamped, in five
/// 26-bit limbs, its multiples by 5, and the accumulator h.
struct State {
    var r0: uint64 = 0, r1: uint64 = 0, r2: uint64 = 0, r3: uint64 = 0, r4: uint64 = 0
    var s1: uint64 = 0, s2: uint64 = 0, s3: uint64 = 0, s4: uint64 = 0
    var h0: uint64 = 0, h1: uint64 = 0, h2: uint64 = 0, h3: uint64 = 0, h4: uint64 = 0
}

/// absorb adds the n / 16 blocks at p to st, each with hibit (1 << 24, the
/// 0x01 byte past a whole block, or 0 for a final block padded by hand).
/// The blocks are read where they are: no block is copied.
func absorb(_ st: inout State, _ p: UnsafePointer<uint8>, _ n: int, _ hibit: uint32) {
    let r0 = st.r0, r1 = st.r1, r2 = st.r2, r3 = st.r3, r4 = st.r4
    let s1 = st.s1, s2 = st.s2, s3 = st.s3, s4 = st.s4
    var h0 = st.h0, h1 = st.h1, h2 = st.h2, h3 = st.h3, h4 = st.h4
    var offset = 0
    while offset + 16 <= n {
        let b = p + offset
        h0 &+= uint64(le32(b) & 0x3ffffff)
        h1 &+= uint64((le32(b + 3) >> 2) & 0x3ffffff)
        h2 &+= uint64((le32(b + 6) >> 4) & 0x3ffffff)
        h3 &+= uint64((le32(b + 9) >> 6) & 0x3ffffff)
        h4 &+= uint64((le32(b + 12) >> 8) | hibit)

        let d0 = h0 &* r0 &+ h1 &* s4 &+ h2 &* s3 &+ h3 &* s2 &+ h4 &* s1
        let d1 = h0 &* r1 &+ h1 &* r0 &+ h2 &* s4 &+ h3 &* s3 &+ h4 &* s2
        let d2 = h0 &* r2 &+ h1 &* r1 &+ h2 &* r0 &+ h3 &* s4 &+ h4 &* s3
        let d3 = h0 &* r3 &+ h1 &* r2 &+ h2 &* r1 &+ h3 &* r0 &+ h4 &* s4
        let d4 = h0 &* r4 &+ h1 &* r3 &+ h2 &* r2 &+ h3 &* r1 &+ h4 &* r0

        var c = d0 >> 26
        h0 = d0 & 0x3ffffff
        let carry_d1 = d1 &+ c
        c = carry_d1 >> 26
        h1 = carry_d1 & 0x3ffffff
        let carry_d2 = d2 &+ c
        c = carry_d2 >> 26
        h2 = carry_d2 & 0x3ffffff
        let carry_d3 = d3 &+ c
        c = carry_d3 >> 26
        h3 = carry_d3 & 0x3ffffff
        let carry_d4 = d4 &+ c
        c = carry_d4 >> 26
        h4 = carry_d4 & 0x3ffffff

        h0 &+= c &* 5
        c = h0 >> 26
        h0 &= 0x3ffffff
        h1 &+= c

        offset += 16
    }
    st.h0 = h0
    st.h1 = h1
    st.h2 = h2
    st.h3 = h3
    st.h4 = h4
}

/// MAC computes a Poly1305 tag over a message written to it in pieces, as
/// an AEAD writes its additional data, ciphertext and lengths: nothing is
/// gathered into one message first. A key is used for one message only.
public struct MAC {
    var st = State()
    var sLo: uint64 = 0
    var sHi: uint64 = 0
    var buf = [uint8](repeating: 0, count: 16)
    var buffered = 0

    /// init starts a tag under key, which must be KeySize bytes.
    public init(key: [uint8]) {
        // Clamp r
        st.r0 = uint64(readU32Le(key, 0) & 0x3ffffff)
        st.r1 = uint64((readU32Le(key, 3) >> 2) & 0x3ffff03)
        st.r2 = uint64((readU32Le(key, 6) >> 4) & 0x3ffc0ff)
        st.r3 = uint64((readU32Le(key, 9) >> 6) & 0x3f03fff)
        st.r4 = uint64((readU32Le(key, 12) >> 8) & 0x00fffff)
        st.s1 = st.r1 &* 5
        st.s2 = st.r2 &* 5
        st.s3 = st.r3 &* 5
        st.s4 = st.r4 &* 5
        // Read s (key[16..31])
        sLo = uint64(readU32Le(key, 16)) | (uint64(readU32Le(key, 20)) << 32)
        sHi = uint64(readU32Le(key, 24)) | (uint64(readU32Le(key, 28)) << 32)
    }

    /// Write adds msg to the message.
    public mutating func Write(_ msg: [uint8]) {
        let n = msg.count
        var at = 0
        // A block left part-filled by the last write is filled first.
        if buffered > 0 {
            while buffered < 16 && at < n {
                buf[buffered] = msg[at]
                buffered += 1
                at += 1
            }
            if buffered < 16 {
                return
            }
            var st = self.st
            buf.withUnsafeBufferPointer { b in absorb(&st, b.baseAddress!, 16, 1 << 24) }
            self.st = st
            buffered = 0
        }
        let whole = (n - at) & ~15
        if whole > 0 {
            var st = self.st
            msg.withUnsafeBufferPointer { m in absorb(&st, m.baseAddress! + at, whole, 1 << 24) }
            self.st = st
            at += whole
        }
        while at < n {
            buf[buffered] = msg[at]
            buffered += 1
            at += 1
        }
    }

    /// Sum is the tag of everything written.
    public mutating func Sum() -> [uint8] {
        if buffered > 0 {
            // A final short block: its 0x01 byte is in the block.
            buf[buffered] = 1
            var i = buffered + 1
            while i < 16 {
                buf[i] = 0
                i += 1
            }
            var st = self.st
            buf.withUnsafeBufferPointer { b in absorb(&st, b.baseAddress!, 16, 0) }
            self.st = st
            buffered = 0
        }
        var h0 = st.h0, h1 = st.h1, h2 = st.h2, h3 = st.h3, h4 = st.h4

        // Fully carry
        var c = h0 >> 26
        h0 &= 0x3ffffff
        h1 &+= c
        c = h1 >> 26
        h1 &= 0x3ffffff
        h2 &+= c
        c = h2 >> 26
        h2 &= 0x3ffffff
        h3 &+= c
        c = h3 >> 26
        h3 &= 0x3ffffff
        h4 &+= c
        c = h4 >> 26
        h4 &= 0x3ffffff
        h0 &+= c &* 5
        c = h0 >> 26
        h0 &= 0x3ffffff
        h1 &+= c

        // Compute h - p to check if h >= 2^130 - 5
        var g0 = h0 &+ 5
        c = g0 >> 26
        g0 &= 0x3ffffff
        var g1 = h1 &+ c
        c = g1 >> 26
        g1 &= 0x3ffffff
        var g2 = h2 &+ c
        c = g2 >> 26
        g2 &= 0x3ffffff
        var g3 = h3 &+ c
        c = g3 >> 26
        g3 &= 0x3ffffff
        var g4 = h4 &+ c &- (1 << 26)

        // Select g only if h >= p (i.e. g4 did not underflow)
        if (g4 >> 63) == 0 {
            h0 = g0
            h1 = g1
            h2 = g2
            h3 = g3
            h4 = g4
        }

        // Pack into 128-bit integer limbs: lo 64-bit and hi 64-bit
        let hLo = (h0) | (h1 << 26) | ((h2 & 0xfff) << 52)
        let hHi = (h2 >> 12) | (h3 << 14) | (h4 << 40)

        // (h + s) mod 2^128
        let tagLo = hLo &+ sLo
        let carryLo = (tagLo < hLo) ? uint64(1) : uint64(0)
        let tagHi = hHi &+ sHi &+ carryLo

        var tag = [uint8](repeating: 0, count: 16)
        var shift: uint64 = 0
        var i = 0
        while i < 8 {
            tag[i] = uint8(truncatingIfNeeded: tagLo >> shift)
            tag[8 + i] = uint8(truncatingIfNeeded: tagHi >> shift)
            shift &+= 8
            i += 1
        }
        return tag
    }
}

/// Sum calculates the 16-byte Poly1305 authenticator tag of msg using a 32-byte one-time key.
public func Sum(_ msg: [uint8], key: [uint8]) -> [uint8] {
    if key.count != KeySize {
        return []
    }
    var mac = MAC(key: key)
    mac.Write(msg)
    return mac.Sum()
}

/// Verify returns true if mac matches the Poly1305 tag of msg.
public func Verify(mac: [uint8], msg: [uint8], key: [uint8]) -> bool {
    let expected = Sum(msg, key: key)
    return subtle.ConstantTimeCompare(mac, expected) == 1
}
