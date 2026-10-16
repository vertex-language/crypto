package cipher

import "crypto/aes"

// AES-GCM by the processor's AES and carry-less multiply instructions,
// where it has them: the IR's v128.aes_enc and v128.i64x2_clmul (§V5),
// which are AESE/AESMC and PMULL on AArch64 and AES-NI and PCLMULQDQ on
// x86-64. GCM.init chooses this with CPU.hasAES and CPU.hasCLMUL, and the
// functions here require both, so a binary built for a processor without
// them carries this path and the table one, and takes this one only where
// it runs.
//
// GHASH is computed on blocks with their bytes reversed, where GCM's
// reflected bit order becomes a plain polynomial one but for a shift by
// one: Gueron and Kounavis's algorithm (Intel, "Carry-Less Multiplication
// and Its Usage for Computing the GCM Mode", algorithm 5), which the IR's
// verbs -- SSE2's shapes -- write line for line.

// hwKeys is the round keys as vectors, in FIPS-197's byte order.
func hwKeys(_ b: aes.Block) -> [v128] {
    let w = b.RoundKeys
    var out: [v128] = []
    var i = 0
    while i + 3 < w.count {
        out.append(v128(w[i].byteSwapped, w[i + 1].byteSwapped, w[i + 2].byteSwapped, w[i + 3].byteSwapped))
        i += 4
    }
    return out
}

// reversal is the byte order flipped end for end: GCM's big-endian blocks
// as the little-endian polynomials the multiply works in.
let reversal = v128(0x08090a0b0c0d0e0f, 0x0001020304050607)

func reversed(_ x: v128) -> v128 { return v128I8x16Swizzle(x, reversal) }

// encryptBlock is one block through AES under rk, which has nr + 1 keys.
@requires(aes)
func encryptBlock(_ rk: UnsafePointer<v128>, _ nr: int, _ block: v128) -> v128 {
    var s = block ^ rk.pointee
    var i = 1
    while i < nr {
        s = v128AesEnc(s, (rk + i).pointee)
        i += 1
    }
    return v128AesEncLast(s, (rk + nr).pointee)
}

// gfmul is a times b in GF(2^128), both byte-reversed.
@requires(clmul)
func gfmul(_ a: v128, _ b: v128) -> v128 {
    let mid = v128I64x2Clmul(a, b, 2) ^ v128I64x2Clmul(a, b, 1)
    return reduce(v128I64x2Clmul(a, b, 0) ^ v128ShlBytes(mid, 8),
                  v128I64x2Clmul(a, b, 3) ^ v128ShrBytes(mid, 8))
}

// reduce is the 256-bit carry-less product hi:lo as a field element. Both
// of its steps are linear, so the XOR of several products reduced once is
// the XOR of each reduced: what lets ghashHW reduce once per four blocks.
@requires(clmul)
func reduce(_ lo0: v128, _ hi0: v128) -> v128 {
    var lo = lo0
    var hi = hi0

    // The 256-bit product hi:lo shifted left by one: the reflection's.
    let loCarry = v128I32x4ShrU(lo, 31)
    let hiCarry = v128I32x4ShrU(hi, 31)
    lo = v128I32x4Shl(lo, 1)
    hi = v128I32x4Shl(hi, 1)
    let across = v128ShrBytes(loCarry, 12)
    lo = lo | v128ShlBytes(loCarry, 4)
    hi = hi | v128ShlBytes(hiCarry, 4) | across

    // Reduced by x^128 + x^7 + x^2 + x + 1.
    let mid = v128I32x4Shl(lo, 31) ^ v128I32x4Shl(lo, 30) ^ v128I32x4Shl(lo, 25)
    let fold = v128ShrBytes(mid, 4)
    lo = lo ^ v128ShlBytes(mid, 12)
    let back = v128I32x4ShrU(lo, 1) ^ v128I32x4ShrU(lo, 2) ^ v128I32x4ShrU(lo, 7) ^ fold
    return hi ^ lo ^ back
}

// gcmHW is GCM's state on the instructions: the round keys, and H and
// its square, cube and fourth power, byte-reversed. It is made once per
// key and shared by every record.
final class gcmHW {
    let keys: [v128]
    let rounds: int
    let h: v128
    let h2: v128
    let h3: v128
    let h4: v128

    init(keys: [v128], rounds: int, h: v128, h2: v128, h3: v128, h4: v128) {
        self.keys = keys
        self.rounds = rounds
        self.h = h
        self.h2 = h2
        self.h3 = h3
        self.h4 = h4
    }
}

@requires(aes)
func newGCMHW(_ b: aes.Block) -> gcmHW {
    let keys = hwKeys(b)
    var h = v128.zero
    keys.withUnsafeBufferPointer { kb in
        h = reversed(encryptBlock(kb.baseAddress!, b.Rounds, v128.zero))
    }
    return powersHW(keys, b.Rounds, h)
}

@requires(clmul)
func powersHW(_ keys: [v128], _ rounds: int, _ h: v128) -> gcmHW {
    let h2 = gfmul(h, h)
    let h3 = gfmul(h2, h)
    return gcmHW(keys: keys, rounds: rounds, h: h, h2: h2, h3: h3, h4: gfmul(h3, h))
}

// loadPartial is up to sixteen bytes at p as a block, zero past count.
func loadPartial(_ p: UnsafePointer<uint8>, _ count: int) -> v128 {
    var tmp = [uint8](repeating: 0, count: 16)
    var i = 0
    while i < count {
        tmp[i] = (p + i).pointee
        i += 1
    }
    var out = v128.zero
    tmp.withUnsafeBufferPointer { tb in out = v128(loading: UnsafeRawPointer(tb.baseAddress!)) }
    return out
}

// ghashHW folds count bytes at p into x, the last block zero-padded. Four
// blocks at a time it is ((((x ^ c0)H ^ c1)H ^ c2)H ^ c3)H written as
// (x ^ c0)H^4 ^ c1 H^3 ^ c2 H^2 ^ c3 H: four products with nothing between
// them to wait on, and one reduction.
@requires(clmul)
func ghashHW(_ x: v128, _ g: gcmHW, _ p: UnsafePointer<uint8>, _ count: int) -> v128 {
    let h = g.h
    let h2 = g.h2
    let h3 = g.h3
    let h4 = g.h4
    var y = x
    var off = 0
    while off + 64 <= count {
        let a0 = y ^ reversed(v128(loading: UnsafeRawPointer(p + off)))
        let a1 = reversed(v128(loading: UnsafeRawPointer(p + off + 16)))
        let a2 = reversed(v128(loading: UnsafeRawPointer(p + off + 32)))
        let a3 = reversed(v128(loading: UnsafeRawPointer(p + off + 48)))
        let lo = v128I64x2Clmul(a0, h4, 0) ^ v128I64x2Clmul(a1, h3, 0) ^
                 v128I64x2Clmul(a2, h2, 0) ^ v128I64x2Clmul(a3, h, 0)
        let hi = v128I64x2Clmul(a0, h4, 3) ^ v128I64x2Clmul(a1, h3, 3) ^
                 v128I64x2Clmul(a2, h2, 3) ^ v128I64x2Clmul(a3, h, 3)
        let mid = v128I64x2Clmul(a0, h4, 1) ^ v128I64x2Clmul(a0, h4, 2) ^
                  v128I64x2Clmul(a1, h3, 1) ^ v128I64x2Clmul(a1, h3, 2) ^
                  v128I64x2Clmul(a2, h2, 1) ^ v128I64x2Clmul(a2, h2, 2) ^
                  v128I64x2Clmul(a3, h, 1) ^ v128I64x2Clmul(a3, h, 2)
        y = reduce(lo ^ v128ShlBytes(mid, 8), hi ^ v128ShrBytes(mid, 8))
        off += 64
    }
    while off + 16 <= count {
        y = gfmul(y ^ reversed(v128(loading: UnsafeRawPointer(p + off))), h)
        off += 16
    }
    if off < count {
        y = gfmul(y ^ reversed(loadPartial(p + off, count - off)), h)
    }
    return y
}

// ctrHW XORs count bytes at src with the key stream from the counter after
// j0 upward, into dst. The counter is kept with each word's bytes swapped,
// so that adding one to its last lane is the big-endian increment.
@requires(aes)
func ctrHW(_ rk: UnsafePointer<v128>, _ nr: int, _ j0: v128, _ src: UnsafePointer<uint8>,
           _ dst: UnsafeMutablePointer<uint8>, _ count: int) {
    let one = v128(0, 0, 0, 1)
    let two = v128(0, 0, 0, 2)
    let three = v128(0, 0, 0, 3)
    let four = v128(0, 0, 0, 4)
    var ctr = v128I32x4Bswap(j0)
    var off = 0
    // Four blocks a round at a time: each round's four AESEs depend on
    // nothing but their own block, so they overlap in the pipeline.
    while off + 64 <= count {
        let k0 = rk.pointee
        var s0 = v128I32x4Bswap(v128I32x4Add(ctr, one)) ^ k0
        var s1 = v128I32x4Bswap(v128I32x4Add(ctr, two)) ^ k0
        var s2 = v128I32x4Bswap(v128I32x4Add(ctr, three)) ^ k0
        var s3 = v128I32x4Bswap(v128I32x4Add(ctr, four)) ^ k0
        ctr = v128I32x4Add(ctr, four)
        var i = 1
        while i < nr {
            let k = (rk + i).pointee
            s0 = v128AesEnc(s0, k)
            s1 = v128AesEnc(s1, k)
            s2 = v128AesEnc(s2, k)
            s3 = v128AesEnc(s3, k)
            i += 1
        }
        let kl = (rk + nr).pointee
        (v128AesEncLast(s0, kl) ^ v128(loading: UnsafeRawPointer(src + off))).store(to: UnsafeMutableRawPointer(dst + off))
        (v128AesEncLast(s1, kl) ^ v128(loading: UnsafeRawPointer(src + off + 16))).store(to: UnsafeMutableRawPointer(dst + off + 16))
        (v128AesEncLast(s2, kl) ^ v128(loading: UnsafeRawPointer(src + off + 32))).store(to: UnsafeMutableRawPointer(dst + off + 32))
        (v128AesEncLast(s3, kl) ^ v128(loading: UnsafeRawPointer(src + off + 48))).store(to: UnsafeMutableRawPointer(dst + off + 48))
        off += 64
    }
    while off + 16 <= count {
        ctr = v128I32x4Add(ctr, one)
        let ks = encryptBlock(rk, nr, v128I32x4Bswap(ctr))
        (ks ^ v128(loading: UnsafeRawPointer(src + off))).store(to: UnsafeMutableRawPointer(dst + off))
        off += 16
    }
    if off < count {
        ctr = v128I32x4Add(ctr, one)
        let ks = encryptBlock(rk, nr, v128I32x4Bswap(ctr))
        var tmp = [uint8](repeating: 0, count: 16)
        tmp.withUnsafeMutableBufferPointer { tb in ks.store(to: UnsafeMutableRawPointer(tb.baseAddress!)) }
        var i = 0
        while off + i < count {
            (dst + off + i).pointee = (src + off + i).pointee ^ tmp[i]
            i += 1
        }
    }
}

// j0 is nonce || 1, the counter block the tag is masked with.
func j0Of(_ nonce: [uint8]) -> v128 {
    var block = [uint8](repeating: 0, count: 16)
    var i = 0
    while i < 12 {
        block[i] = nonce[i]
        i += 1
    }
    block[15] = 1
    var out = v128.zero
    block.withUnsafeBufferPointer { b in out = v128(loading: UnsafeRawPointer(b.baseAddress!)) }
    return out
}

// tagHW is GCM's tag: GHASH of the additional data and ciphertext with
// their lengths, masked by E(J0).
@requires(aes, clmul)
func tagHW(_ g: gcmHW, _ j0: v128, _ aad: [uint8], _ ct: UnsafePointer<uint8>, _ clen: int) -> v128 {
    var x = v128.zero
    if aad.count > 0 {
        aad.withUnsafeBufferPointer { ab in x = ghashHW(x, g, ab.baseAddress!, aad.count) }
    }
    if clen > 0 {
        x = ghashHW(x, g, ct, clen)
    }
    // len(A) || len(C) in bits, big-endian, reversed: C's in the low lane.
    x = gfmul(x ^ v128(uint64(clen) &* 8, uint64(aad.count) &* 8), g.h)
    var mask = v128.zero
    g.keys.withUnsafeBufferPointer { kb in mask = encryptBlock(kb.baseAddress!, g.rounds, j0) }
    return reversed(x) ^ mask
}

@requires(aes, clmul)
func sealHW(_ g: gcmHW, _ nonce: [uint8], _ plaintext: [uint8], _ aad: [uint8]) -> [uint8] {
    let j0 = j0Of(nonce)
    var out = [uint8](repeating: 0, count: plaintext.count + GCMTagSize)
    let n = plaintext.count
    out.withUnsafeMutableBufferPointer { ob in
        let dst = ob.baseAddress!
        if n > 0 {
            plaintext.withUnsafeBufferPointer { pb in
                g.keys.withUnsafeBufferPointer { kb in ctrHW(kb.baseAddress!, g.rounds, j0, pb.baseAddress!, dst, n) }
            }
        }
        tagHW(g, j0, aad, UnsafePointer<uint8>(dst), n).store(to: UnsafeMutableRawPointer(dst + n))
    }
    return out
}

// openHW is nil where the tag does not verify.
@requires(aes, clmul)
func openHW(_ g: gcmHW, _ nonce: [uint8], _ sealed: [uint8], _ aad: [uint8]) -> [uint8]? {
    let j0 = j0Of(nonce)
    let clen = sealed.count - GCMTagSize
    var out = [uint8](repeating: 0, count: clen)
    var ok = false
    sealed.withUnsafeBufferPointer { sb in
        let src = sb.baseAddress!
        let want = tagHW(g, j0, aad, src, clen)
        let got = v128(loading: UnsafeRawPointer(src + clen))
        // Constant time: every byte of the difference, gathered, then tested.
        ok = v128I8x16Bitmask(v128I8x16Eq(want, got)) == 0xffff
        if ok && clen > 0 {
            out.withUnsafeMutableBufferPointer { ob in
                g.keys.withUnsafeBufferPointer { kb in ctrHW(kb.baseAddress!, g.rounds, j0, src, ob.baseAddress!, clen) }
            }
        }
    }
    if !ok {
        return nil
    }
    return out
}
