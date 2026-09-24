// Package cipher provides AEAD cipher modes over a block cipher. GCM
// (Galois/Counter Mode, NIST SP 800-38D) is what the TLS 1.2 AES-GCM
// cipher suites Windows negotiates use to protect records.
package cipher

import "crypto/aes"

public let GCMNonceSize: int = 12
public let GCMTagSize: int = 16

public enum CipherError: Error {
    case authFailed
    case badParameter(string)

    public var Message: string {
        switch self {
        case .authFailed: return "cipher: message authentication failed"
        case .badParameter(let s): return "cipher: \(s)"
        }
    }
}

/// GCM wraps an AES block cipher in Galois/Counter Mode with a 96-bit
/// nonce and 128-bit tag, the profile TLS uses.
public struct GCM {
    var block: aes.Block
    // Sixteen multiples of the hash subkey H = E(0^128), indexed by a
    // nibble with its bits reversed, as high and low 64-bit halves: GHASH
    // then takes four bits of the input at a time (Shoup's method, as Go's
    // generic GCM does).
    var tableHi: [uint64]
    var tableLo: [uint64]

    public init(_ block: aes.Block) {
        self.block = block
        let (k0, k1, k2, k3) = block.EncryptWords(0, 0, 0, 0)
        let x0 = (uint64(k0) << 32) | uint64(k1)
        let x1 = (uint64(k2) << 32) | uint64(k3)
        var hi = [uint64](repeating: 0, count: 16)
        var lo = [uint64](repeating: 0, count: 16)
        hi[reverseNibble(1)] = x0
        lo[reverseNibble(1)] = x1
        var i = 2
        while i < 16 {
            // Doubling is a right shift in GCM's bit order, reduced by R.
            let h = hi[reverseNibble(i / 2)]
            let l = lo[reverseNibble(i / 2)]
            var dh = h >> 1
            let dl = (l >> 1) | (h << 63)
            if l & 1 == 1 { dh ^= 0xE100000000000000 }
            hi[reverseNibble(i)] = dh
            lo[reverseNibble(i)] = dl
            hi[reverseNibble(i + 1)] = dh ^ x0
            lo[reverseNibble(i + 1)] = dl ^ x1
            i += 2
        }
        self.tableHi = hi
        self.tableLo = lo
    }

    public static func New(key: [uint8]) throws -> GCM {
        let b = try aes.Block(key: key)
        return GCM(b)
    }

    /// Seal encrypts plaintext and appends the authentication tag. nonce
    /// must be 12 bytes.
    public func Seal(nonce: [uint8], plaintext: [uint8], additionalData: [uint8] = []) throws -> [uint8] {
        if nonce.count != GCMNonceSize {
            throw CipherError.badParameter("GCM nonce must be 12 bytes")
        }
        let n0 = be32(nonce, 0)
        let n1 = be32(nonce, 4)
        let n2 = be32(nonce, 8)
        // Counter mode from J0 + 1, where J0 = nonce || 1; room left for the tag.
        var out = gctr(n0, n1, n2, plaintext, 0, plaintext.count, plaintext.count + GCMTagSize)
        let (s0, s1) = ghash(additionalData, out, plaintext.count)
        let (e0, e1, e2, e3) = block.EncryptWords(n0, n1, n2, 1)
        putBeU64(&out, plaintext.count, s0 ^ ((uint64(e0) << 32) | uint64(e1)))
        putBeU64(&out, plaintext.count + 8, s1 ^ ((uint64(e2) << 32) | uint64(e3)))
        return out
    }

    /// Open verifies the tag and decrypts. ciphertextAndTag is the output
    /// of Seal (ciphertext with the 16-byte tag appended).
    public func Open(nonce: [uint8], ciphertextAndTag: [uint8], additionalData: [uint8] = []) throws -> [uint8] {
        if nonce.count != GCMNonceSize {
            throw CipherError.badParameter("GCM nonce must be 12 bytes")
        }
        if ciphertextAndTag.count < GCMTagSize {
            throw CipherError.authFailed
        }
        let clen = ciphertextAndTag.count - GCMTagSize
        let n0 = be32(nonce, 0)
        let n1 = be32(nonce, 4)
        let n2 = be32(nonce, 8)
        let (s0, s1) = ghash(additionalData, ciphertextAndTag, clen)
        let (e0, e1, e2, e3) = block.EncryptWords(n0, n1, n2, 1)
        let want0 = s0 ^ ((uint64(e0) << 32) | uint64(e1))
        let want1 = s1 ^ ((uint64(e2) << 32) | uint64(e3))
        let got0 = beU64(ciphertextAndTag, clen)
        let got1 = beU64(ciphertextAndTag, clen + 8)
        // Constant time: fold the difference before looking at it.
        if (want0 ^ got0) | (want1 ^ got1) != 0 {
            throw CipherError.authFailed
        }
        return gctr(n0, n1, n2, ciphertextAndTag, 0, clen, clen)
    }

    // gctr XORs input[start..<start+count] with the key stream from
    // counter nonce || 2 upward, into the front of a zeroed buffer of size
    // bytes.
    func gctr(_ n0: uint32, _ n1: uint32, _ n2: uint32, _ input: [uint8], _ start: int, _ count: int, _ size: int) -> [uint8] {
        var out = [uint8](repeating: 0, count: size)
        if count == 0 { return out }
        var ctr: uint32 = 2
        input.withUnsafeBufferPointer { ib in
            out.withUnsafeMutableBufferPointer { ob in
                let src = ib.baseAddress! + start
                let dst = ob.baseAddress!
                var off = 0
                while off < count {
                    let (k0, k1, k2, k3) = block.EncryptWords(n0, n1, n2, ctr)
                    ctr = ctr &+ 1
                    if off + 16 <= count {
                        xorWord(dst + off, src + off, k0)
                        xorWord(dst + off + 4, src + off + 4, k1)
                        xorWord(dst + off + 8, src + off + 8, k2)
                        xorWord(dst + off + 12, src + off + 12, k3)
                    } else {
                        let ks: [uint32] = [k0, k1, k2, k3]
                        var j = 0
                        while off + j < count {
                            let byte = uint8(truncatingIfNeeded: ks[j / 4] >> uint32(24 - 8 * (j % 4)))
                            (dst + off + j).pointee = (src + off + j).pointee ^ byte
                            j += 1
                        }
                    }
                    off += 16
                }
            }
        }
        return out
    }

    // ghash computes GHASH_H(AAD padded || C padded || len(AAD) || len(C))
    // where C is data[0..<clen].
    func ghash(_ aad: [uint8], _ data: [uint8], _ clen: int) -> (uint64, uint64) {
        var y0: uint64 = 0
        var y1: uint64 = 0
        tableHi.withUnsafeBufferPointer { hb in
            tableLo.withUnsafeBufferPointer { lb in
                let th = hb.baseAddress!
                let tl = lb.baseAddress!
                let (a0, a1) = absorb(0, 0, aad, aad.count, th, tl)
                let (c0, c1) = absorb(a0, a1, data, clen, th, tl)
                y0 = c0
                y1 = c1
                y0 ^= uint64(aad.count) &* 8
                y1 ^= uint64(clen) &* 8
                mulH(&y0, &y1, th, tl)
            }
        }
        return (y0, y1)
    }
}

// absorb folds data[0..<count] into the GHASH state, 16 bytes at a time,
// the last block zero-padded.
func absorb(_ in0: uint64, _ in1: uint64, _ data: [uint8], _ count: int,
            _ th: UnsafePointer<uint64>, _ tl: UnsafePointer<uint64>) -> (uint64, uint64) {
    if count == 0 { return (in0, in1) }
    var y0 = in0
    var y1 = in1
    data.withUnsafeBufferPointer { db in
        let p = db.baseAddress!
        var off = 0
        while off + 16 <= count {
            y0 ^= loadBe64(p + off)
            y1 ^= loadBe64(p + off + 8)
            mulH(&y0, &y1, th, tl)
            off += 16
        }
        if off < count {
            var a: uint64 = 0
            var b: uint64 = 0
            var j = 0
            while off + j < count {
                let v = uint64((p + off + j).pointee)
                if j < 8 { a |= v << uint64(56 - 8 * j) } else { b |= v << uint64(56 - 8 * (j - 8)) }
                j += 1
            }
            y0 ^= a
            y1 ^= b
            mulH(&y0, &y1, th, tl)
        }
    }
    return (y0, y1)
}

// mulH sets y to y * H, four bits at a time: multiply the running product
// by x^4 (reducing what falls off the end) and add the table's multiple
// of H for the next nibble of y.
func mulH(_ y0: inout uint64, _ y1: inout uint64, _ th: UnsafePointer<uint64>, _ tl: UnsafePointer<uint64>) {
    var zh: uint64 = 0
    var zl: uint64 = 0
    var half = 0
    while half < 2 {
        var w = half == 0 ? y1 : y0
        var j = 0
        while j < 16 {
            let msw = zl & 0xF
            zl = (zl >> 4) | (zh << 60)
            zh = (zh >> 4) ^ (reduction(msw) << 48)
            let n = int(w & 0xF)
            zh ^= (th + n).pointee
            zl ^= (tl + n).pointee
            w = w >> 4
            j += 1
        }
        half += 1
    }
    y0 = zh
    y1 = zl
}

// reduction is Go's gcmReductionTable: what x^4 times each nibble that
// shifts off the end contributes back, in the top 16 bits.
func reduction(_ n: uint64) -> uint64 {
    switch n {
    case 0: return 0x0000
    case 1: return 0x1c20
    case 2: return 0x3840
    case 3: return 0x2460
    case 4: return 0x7080
    case 5: return 0x6ca0
    case 6: return 0x48c0
    case 7: return 0x54e0
    case 8: return 0xe100
    case 9: return 0xfd20
    case 10: return 0xd940
    case 11: return 0xc560
    case 12: return 0x9180
    case 13: return 0x8da0
    case 14: return 0xa9c0
    default: return 0xb5e0
    }
}

func reverseNibble(_ i: int) -> int {
    var v = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
    v = ((v << 1) & 0xa) | ((v >> 1) & 0x5)
    return v
}

func xorWord(_ dst: UnsafeMutablePointer<uint8>, _ src: UnsafePointer<uint8>, _ k: uint32) {
    dst.pointee = src.pointee ^ uint8(truncatingIfNeeded: k >> 24)
    (dst + 1).pointee = (src + 1).pointee ^ uint8(truncatingIfNeeded: k >> 16)
    (dst + 2).pointee = (src + 2).pointee ^ uint8(truncatingIfNeeded: k >> 8)
    (dst + 3).pointee = (src + 3).pointee ^ uint8(truncatingIfNeeded: k)
}

func loadBe64(_ p: UnsafePointer<uint8>) -> uint64 {
    return (uint64(p.pointee) << 56) | (uint64((p + 1).pointee) << 48) | (uint64((p + 2).pointee) << 40) |
           (uint64((p + 3).pointee) << 32) | (uint64((p + 4).pointee) << 24) | (uint64((p + 5).pointee) << 16) |
           (uint64((p + 6).pointee) << 8) | uint64((p + 7).pointee)
}

func be32(_ b: [uint8], _ o: int) -> uint32 {
    return (uint32(b[o]) << 24) | (uint32(b[o+1]) << 16) | (uint32(b[o+2]) << 8) | uint32(b[o+3])
}

func beU64(_ b: [uint8], _ o: int) -> uint64 {
    return (uint64(b[o]) << 56) | (uint64(b[o+1]) << 48) | (uint64(b[o+2]) << 40) |
           (uint64(b[o+3]) << 32) | (uint64(b[o+4]) << 24) | (uint64(b[o+5]) << 16) |
           (uint64(b[o+6]) << 8) | uint64(b[o+7])
}

func putBeU64(_ b: inout [uint8], _ o: int, _ v: uint64) {
    b[o] = uint8(truncatingIfNeeded: v >> 56)
    b[o+1] = uint8(truncatingIfNeeded: v >> 48)
    b[o+2] = uint8(truncatingIfNeeded: v >> 40)
    b[o+3] = uint8(truncatingIfNeeded: v >> 32)
    b[o+4] = uint8(truncatingIfNeeded: v >> 24)
    b[o+5] = uint8(truncatingIfNeeded: v >> 16)
    b[o+6] = uint8(truncatingIfNeeded: v >> 8)
    b[o+7] = uint8(truncatingIfNeeded: v)
}
