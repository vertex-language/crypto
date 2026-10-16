package sha256

// SHA-256 by the processor's instructions, where it has them: the IR's
// sha256_rounds_abcd, sha256_rounds_efgh, sha256_msg1 and sha256_msg2
// (§V5), which are SHA256H, SHA256H2, SHA256SU0 and SHA256SU1 on AArch64
// and SHA-NI on x86-64. Four rounds a step, the state in two vectors in
// the algorithm's own order -- a, b, c, d and e, f, g, h -- and the
// schedule in four, W[t..t+3] each.

// kv is K four rounds at a time.
let kv: [v128] = {
    var out: [v128] = []
    var i = 0
    while i < 64 {
        out.append(v128(K[i], K[i + 1], K[i + 2], K[i + 3]))
        i += 4
    }
    return out
}()

// blocksHW compresses count blocks at p into the state at st: abcd, then
// efgh.
@requires(sha256)
func blocksHW(_ st: UnsafeMutablePointer<v128>, _ p: UnsafePointer<uint8>, _ count: int, _ k: UnsafePointer<v128>) {
    var abcd = st.pointee
    var efgh = (st + 1).pointee
    var blk = 0
    while blk < count {
        let q = UnsafeRawPointer(p + blk * BlockSize)
        // A block's words are big-endian.
        var w0 = v128I32x4Bswap(v128(loading: q))
        var w1 = v128I32x4Bswap(v128(loading: q + 16))
        var w2 = v128I32x4Bswap(v128(loading: q + 32))
        var w3 = v128I32x4Bswap(v128(loading: q + 48))
        let abcd0 = abcd
        let efgh0 = efgh
        var t = 0
        while t < 16 {
            let wk = v128I32x4Add(w0, (k + t).pointee)
            let next = v128Sha256RoundsAbcd(abcd, efgh, wk)
            efgh = v128Sha256RoundsEfgh(efgh, abcd, wk)
            abcd = next
            if t < 12 {
                // W[t+16..t+19], in the place W[t..t+3] leaves.
                w0 = v128Sha256Msg2(v128Sha256Msg1(w0, w1), w2, w3)
            }
            let first = w0
            w0 = w1
            w1 = w2
            w2 = w3
            w3 = first
            t += 1
        }
        abcd = v128I32x4Add(abcd, abcd0)
        efgh = v128I32x4Add(efgh, efgh0)
        blk += 1
    }
    st.pointee = abcd
    (st + 1).pointee = efgh
}
