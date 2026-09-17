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

/// Sum calculates the 16-byte Poly1305 authenticator tag of msg using a 32-byte one-time key.
public func Sum(_ msg: [uint8], key: [uint8]) -> [uint8] {
    if key.count != KeySize {
        return []
    }

    // Clamp r
    let r0 = uint64(readU32Le(key, 0) & 0x3ffffff)
    let r1 = uint64((readU32Le(key, 3) >> 2) & 0x3ffff03)
    let r2 = uint64((readU32Le(key, 6) >> 4) & 0x3ffc0ff)
    let r3 = uint64((readU32Le(key, 9) >> 6) & 0x3f03fff)
    let r4 = uint64((readU32Le(key, 12) >> 8) & 0x00fffff)

    let s1 = r1 &* 5
    let s2 = r2 &* 5
    let s3 = r3 &* 5
    let s4 = r4 &* 5

    var h0: uint64 = 0
    var h1: uint64 = 0
    var h2: uint64 = 0
    var h3: uint64 = 0
    var h4: uint64 = 0

    var offset = 0
    while offset < msg.count {
        let remain = msg.count - offset
        let chunkLen = remain < 16 ? remain : 16

        var block = [uint8](repeating: 0, count: 17)
        var j = 0
        while j < chunkLen {
            block[j] = msg[offset + j]
            j += 1
        }
        block[chunkLen] = 1 // append 0x01 byte

        let w0 = uint64(readU32Le(block, 0) & 0x3ffffff)
        let w1 = uint64((readU32Le(block, 3) >> 2) & 0x3ffffff)
        let w2 = uint64((readU32Le(block, 6) >> 4) & 0x3ffffff)
        let w3 = uint64((readU32Le(block, 9) >> 6) & 0x3ffffff)
        let w4 = uint64((readU32Le(block, 12) >> 8) | (uint32(block[16]) << 24))

        h0 &+= w0
        h1 &+= w1
        h2 &+= w2
        h3 &+= w3
        h4 &+= w4

        let d0 = h0 &* r0 &+ h1 &* s4 &+ h2 &* s3 &+ h3 &* s2 &+ h4 &* s1
        let d1 = h0 &* r1 &+ h1 &* r0 &+ h2 &* s4 &+ h3 &* s3 &+ h4 &* s2
        let d2 = h0 &* r2 &+ h1 &* r1 &+ h2 &* r0 &+ h3 &* s4 &+ h4 &* s3
        let d3 = h0 &* r3 &+ h1 &* r2 &+ h2 &* r1 &+ h3 &* r0 &+ h4 &* s4
        let d4 = h0 &* r4 &+ h1 &* r3 &+ h2 &* r2 &+ h3 &* r1 &+ h4 &* r0

        var c = d0 >> 26
        h0 = d0 & 0x3ffffff
        var carry_d1 = d1 &+ c
        c = carry_d1 >> 26
        h1 = carry_d1 & 0x3ffffff
        var carry_d2 = d2 &+ c
        c = carry_d2 >> 26
        h2 = carry_d2 & 0x3ffffff
        var carry_d3 = d3 &+ c
        c = carry_d3 >> 26
        h3 = carry_d3 & 0x3ffffff
        var carry_d4 = d4 &+ c
        c = carry_d4 >> 26
        h4 = carry_d4 & 0x3ffffff

        h0 &+= c &* 5
        c = h0 >> 26
        h0 &= 0x3ffffff
        h1 &+= c

        offset += chunkLen
    }

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

    // Read s (key[16..31])
    let sLo = uint64(readU32Le(key, 16)) | (uint64(readU32Le(key, 20)) << 32)
    let sHi = uint64(readU32Le(key, 24)) | (uint64(readU32Le(key, 28)) << 32)

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

/// Verify returns true if mac matches the Poly1305 tag of msg.
public func Verify(mac: [uint8], msg: [uint8], key: [uint8]) -> bool {
    let expected = Sum(msg, key: key)
    return subtle.ConstantTimeCompare(mac, expected) == 1
}
