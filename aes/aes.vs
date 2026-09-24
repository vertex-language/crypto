// Package aes implements the AES block cipher (FIPS 197) for 128- and
// 256-bit keys. It is the block primitive under crypto/cipher's GCM, which
// is what the TLS 1.2 AES-GCM cipher suites Windows negotiates use.
//
// This is a straightforward table-driven implementation. It is not
// constant-time (the S-box lookups are data-dependent); for the RDP client
// that is acceptable, and a hardened version can replace it later without
// changing the API.
package aes

public let BlockSize: int = 16

public enum AesError: Error {
    case invalidKeySize(int)

    public var Message: string {
        switch self {
        case .invalidKeySize(let n): return "aes: invalid key size \(n) (want 16 or 32)"
        }
    }
}

/// Block is an AES cipher set up with one key. It encrypts and decrypts
/// single 16-byte blocks; modes of operation live in crypto/cipher.
public struct Block {
    var enc: [uint32]   // encryption round keys
    var rounds: int

    public init(key: [uint8]) throws {
        if key.count != 16 && key.count != 32 {
            throw AesError.invalidKeySize(key.count)
        }
        self.rounds = key.count == 16 ? 10 : 14
        self.enc = []
        expandKey(key)
    }

    mutating func expandKey(_ key: [uint8]) {
        let nk = key.count / 4
        let total = (rounds + 1) * 4
        var w = [uint32](repeating: 0, count: total)
        var i = 0
        while i < nk {
            w[i] = (uint32(key[4*i]) << 24) | (uint32(key[4*i+1]) << 16) |
                   (uint32(key[4*i+2]) << 8) | uint32(key[4*i+3])
            i += 1
        }
        i = nk
        while i < total {
            var t = w[i-1]
            if i % nk == 0 {
                t = subWord(rotWord(t)) ^ (uint32(rcon[i/nk]) << 24)
            } else if nk > 6 && i % nk == 4 {
                t = subWord(t)
            }
            w[i] = w[i-nk] ^ t
            i += 1
        }
        enc = w
    }

    /// Encrypt transforms one 16-byte block, returning the ciphertext.
    /// (Decryption is not implemented: the TLS AES-GCM suites RDP uses run
    /// AES in counter mode, which needs only the forward direction.)
    public func Encrypt(_ input: [uint8]) -> [uint8] {
        let (o0, o1, o2, o3) = EncryptWords(word(input, 0), word(input, 4), word(input, 8), word(input, 12))
        var out = [uint8](repeating: 0, count: 16)
        putWord(&out, 0, o0)
        putWord(&out, 4, o1)
        putWord(&out, 8, o2)
        putWord(&out, 12, o3)
        return out
    }

    /// EncryptWords transforms one block given as four big-endian words:
    /// the form counter mode wants, with no arrays on the way.
    public func EncryptWords(_ w0: uint32, _ w1: uint32, _ w2: uint32, _ w3: uint32) -> (uint32, uint32, uint32, uint32) {
        let n = rounds
        return enc.withUnsafeBufferPointer { rkb in
            teTable.withUnsafeBufferPointer { tb in
                let rk = rkb.baseAddress!
                let t = tb.baseAddress!
                var s0 = w0 ^ rk.pointee
                var s1 = w1 ^ (rk + 1).pointee
                var s2 = w2 ^ (rk + 2).pointee
                var s3 = w3 ^ (rk + 3).pointee
                // T-tables: te0 at 0, te1 at 256, te2 at 512, te3 at 768;
                // each folds SubBytes and MixColumns for one byte position.
                var k = 4
                var round = 1
                while round < n {
                    let t0 = (t + int(s0 >> 24)).pointee ^ (t + 256 + int((s1 >> 16) & 0xff)).pointee ^
                             (t + 512 + int((s2 >> 8) & 0xff)).pointee ^ (t + 768 + int(s3 & 0xff)).pointee ^ (rk + k).pointee
                    let t1 = (t + int(s1 >> 24)).pointee ^ (t + 256 + int((s2 >> 16) & 0xff)).pointee ^
                             (t + 512 + int((s3 >> 8) & 0xff)).pointee ^ (t + 768 + int(s0 & 0xff)).pointee ^ (rk + k + 1).pointee
                    let t2 = (t + int(s2 >> 24)).pointee ^ (t + 256 + int((s3 >> 16) & 0xff)).pointee ^
                             (t + 512 + int((s0 >> 8) & 0xff)).pointee ^ (t + 768 + int(s1 & 0xff)).pointee ^ (rk + k + 2).pointee
                    let t3 = (t + int(s3 >> 24)).pointee ^ (t + 256 + int((s0 >> 16) & 0xff)).pointee ^
                             (t + 512 + int((s1 >> 8) & 0xff)).pointee ^ (t + 768 + int(s2 & 0xff)).pointee ^ (rk + k + 3).pointee
                    s0 = t0; s1 = t1; s2 = t2; s3 = t3
                    k += 4
                    round += 1
                }
                // Last round: SubBytes and ShiftRows only (the S-box sits at 1024).
                let sb = t + 1024
                let o0 = ((sb + int(s0 >> 24)).pointee << 24) | ((sb + int((s1 >> 16) & 0xff)).pointee << 16) |
                         ((sb + int((s2 >> 8) & 0xff)).pointee << 8) | (sb + int(s3 & 0xff)).pointee
                let o1 = ((sb + int(s1 >> 24)).pointee << 24) | ((sb + int((s2 >> 16) & 0xff)).pointee << 16) |
                         ((sb + int((s3 >> 8) & 0xff)).pointee << 8) | (sb + int(s0 & 0xff)).pointee
                let o2 = ((sb + int(s2 >> 24)).pointee << 24) | ((sb + int((s3 >> 16) & 0xff)).pointee << 16) |
                         ((sb + int((s0 >> 8) & 0xff)).pointee << 8) | (sb + int(s1 & 0xff)).pointee
                let o3 = ((sb + int(s3 >> 24)).pointee << 24) | ((sb + int((s0 >> 16) & 0xff)).pointee << 16) |
                         ((sb + int((s1 >> 8) & 0xff)).pointee << 8) | (sb + int(s2 & 0xff)).pointee
                return (o0 ^ (rk + k).pointee, o1 ^ (rk + k + 1).pointee, o2 ^ (rk + k + 2).pointee, o3 ^ (rk + k + 3).pointee)
            }
        }
    }
}

func word(_ b: [uint8], _ o: int) -> uint32 {
    return (uint32(b[o]) << 24) | (uint32(b[o+1]) << 16) | (uint32(b[o+2]) << 8) | uint32(b[o+3])
}

func putWord(_ b: inout [uint8], _ o: int, _ v: uint32) {
    b[o] = uint8(truncatingIfNeeded: v >> 24)
    b[o+1] = uint8(truncatingIfNeeded: v >> 16)
    b[o+2] = uint8(truncatingIfNeeded: v >> 8)
    b[o+3] = uint8(truncatingIfNeeded: v)
}

// teTable is te0..te3 (256 words each) then the S-box widened to words.
// te0[x] is the MixColumns column (2s, s, s, 3s) of s = S(x); te1..te3
// are it rotated a byte at a time.
let teTable: [uint32] = buildTeTable()

func buildTeTable() -> [uint32] {
    var t = [uint32](repeating: 0, count: 1280)
    var x = 0
    while x < 256 {
        let s = sbox[x]
        let e = (uint32(xtime(s)) << 24) | (uint32(s) << 16) | (uint32(s) << 8) | uint32(xtime(s) ^ s)
        t[x] = e
        t[256 + x] = (e >> 8) | (e << 24)
        t[512 + x] = (e >> 16) | (e << 16)
        t[768 + x] = (e >> 24) | (e << 8)
        t[1024 + x] = uint32(s)
        x += 1
    }
    return t
}

// GF(2^8) multiply.
func xtime(_ a: uint8) -> uint8 {
    let hi = (a & 0x80) != 0
    var r = a << 1
    if hi { r ^= 0x1b }
    return r
}

func subWord(_ w: uint32) -> uint32 {
    return (uint32(sbox[int(w >> 24)]) << 24) |
           (uint32(sbox[int((w >> 16) & 0xff)]) << 16) |
           (uint32(sbox[int((w >> 8) & 0xff)]) << 8) |
           uint32(sbox[int(w & 0xff)])
}
func rotWord(_ w: uint32) -> uint32 {
    return (w << 8) | (w >> 24)
}
