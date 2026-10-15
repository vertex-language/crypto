// Package ecdsa verifies ECDSA signatures (FIPS 186-5, SEC 1 §4.1.4) on
// the NIST curves P-256, P-384 and P-521, which web certificates and TLS
// handshakes are signed with. Only verification is here -- public keys
// and public signatures -- so nothing secret passes through it and the
// arithmetic need not be constant-time.
//
// Points are kept in Jacobian coordinates (x = X/Z², y = Y/Z³), so the
// one inversion a verification needs is at the end.
package ecdsa

import "math/big"

/// Curve is a NIST prime curve, y² = x³ - 3x + b over GF(p).
public enum Curve {
    case p256
    case p384
    case p521
}

/// PublicKey is a point on Curve, checked to be on it.
public struct PublicKey {
    public var Curve: Curve
    public var X: big.Nat
    public var Y: big.Nat

    init(curve: Curve, x: big.Nat, y: big.Nat) {
        self.Curve = curve
        self.X = x
        self.Y = y
    }
}

public enum EcdsaError: Error {
    case invalidKey(string)
    case verificationFailed(string)

    public var Message: string {
        switch self {
        case .invalidKey(let s): return "ecdsa: invalid public key: \(s)"
        case .verificationFailed(let s): return "ecdsa: verification failed: \(s)"
        }
    }
}

/// Size is the byte length of a field element (and of a scalar) on c.
public func Size(_ c: Curve) -> int {
    switch c {
    case .p256: return 32
    case .p384: return 48
    case .p521: return 66
    }
}

// params are a curve's constants: the field prime p, the group order n,
// the coefficient b, and the base point G.
struct params {
    var p: big.Nat
    var n: big.Nat
    var b: big.Nat
    var gx: big.Nat
    var gy: big.Nat
}

func hex(_ s: string) -> big.Nat {
    if let v = big.Nat.Parse(s, radix: 16) {
        return v
    }
    return big.Nat()
}

func paramsOf(_ c: Curve) -> params {
    switch c {
    case .p256:
        return params(
            p: hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            n: hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            b: hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
            gx: hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            gy: hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
    case .p384:
        return params(
            p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
            n: hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
            b: hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
            gx: hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
            gy: hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"))
    case .p521:
        return params(
            p: hex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            n: hex("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"),
            b: hex("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
            gx: hex("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
            gy: hex("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"))
    }
}

// --- the field, GF(p) ---

func fadd(_ a: big.Nat, _ b: big.Nat, _ p: big.Nat) -> big.Nat {
    let s = big.Add(a, b)
    if big.Cmp(s, p) >= 0 {
        return big.Sub(s, p)
    }
    return s
}

func fsub(_ a: big.Nat, _ b: big.Nat, _ p: big.Nat) -> big.Nat {
    if big.Cmp(a, b) >= 0 {
        return big.Sub(a, b)
    }
    return big.Sub(big.Add(a, p), b)
}

func fmul(_ a: big.Nat, _ b: big.Nat, _ p: big.Nat) -> big.Nat {
    return big.MulMod(a, b, p)
}

// inverse is a⁻¹ mod a prime m, by Fermat: a^(m-2).
func inverse(_ a: big.Nat, _ m: big.Nat) -> big.Nat {
    return big.ExpMod(a, big.Sub(m, big.Nat.FromU32(2)), m)
}

// --- points, in Jacobian coordinates; Z = 0 is the point at infinity ---

struct point {
    var x: big.Nat
    var y: big.Nat
    var z: big.Nat
}

func infinity() -> point {
    return point(x: big.Nat.FromU32(1), y: big.Nat.FromU32(1), z: big.Nat())
}

// double is 2P, for a = -3 (dbl-2001-b).
func double(_ q: point, _ p: big.Nat) -> point {
    if q.z.IsZero || q.y.IsZero {
        return infinity()
    }
    let delta = fmul(q.z, q.z, p)
    let gamma = fmul(q.y, q.y, p)
    let beta = fmul(q.x, gamma, p)
    let t = fmul(fsub(q.x, delta, p), fadd(q.x, delta, p), p)
    let alpha = fadd(fadd(t, t, p), t, p)
    let beta2 = fadd(beta, beta, p)
    let beta4 = fadd(beta2, beta2, p)
    let beta8 = fadd(beta4, beta4, p)
    let x3 = fsub(fmul(alpha, alpha, p), beta8, p)
    let yz = fadd(q.y, q.z, p)
    let z3 = fsub(fsub(fmul(yz, yz, p), gamma, p), delta, p)
    let gamma2 = fmul(gamma, gamma, p)
    let g2 = fadd(gamma2, gamma2, p)
    let g4 = fadd(g2, g2, p)
    let g8 = fadd(g4, g4, p)
    let y3 = fsub(fmul(alpha, fsub(beta4, x3, p), p), g8, p)
    return point(x: x3, y: y3, z: z3)
}

// add is P + Q (add-2007-bl), doubling when they are the same point.
func add(_ a: point, _ b: point, _ p: big.Nat) -> point {
    if a.z.IsZero {
        return b
    }
    if b.z.IsZero {
        return a
    }
    let z1z1 = fmul(a.z, a.z, p)
    let z2z2 = fmul(b.z, b.z, p)
    let u1 = fmul(a.x, z2z2, p)
    let u2 = fmul(b.x, z1z1, p)
    let s1 = fmul(fmul(a.y, b.z, p), z2z2, p)
    let s2 = fmul(fmul(b.y, a.z, p), z1z1, p)
    if big.Cmp(u1, u2) == 0 {
        if big.Cmp(s1, s2) == 0 {
            return double(a, p)
        }
        return infinity()
    }
    let h = fsub(u2, u1, p)
    let h2 = fadd(h, h, p)
    let i = fmul(h2, h2, p)
    let j = fmul(h, i, p)
    let sd = fsub(s2, s1, p)
    let r = fadd(sd, sd, p)
    let v = fmul(u1, i, p)
    let x3 = fsub(fsub(fmul(r, r, p), j, p), fadd(v, v, p), p)
    let s1j = fmul(s1, j, p)
    let y3 = fsub(fmul(r, fsub(v, x3, p), p), fadd(s1j, s1j, p), p)
    let zs = fadd(a.z, b.z, p)
    let z3 = fmul(fsub(fsub(fmul(zs, zs, p), z1z1, p), z2z2, p), h, p)
    return point(x: x3, y: y3, z: z3)
}

func bitOf(_ k: [uint8], _ i: int) -> bool {
    // k is big-endian; bit 0 is the least significant.
    let byte = k.count - 1 - i / 8
    if byte < 0 {
        return false
    }
    return (k[byte] >> uint8(i % 8)) & 1 == 1
}

// combined is u1·G + u2·Q, by Shamir's trick: one pass of doublings over
// both scalars' bits.
func combined(_ u1: big.Nat, _ g: point, _ u2: big.Nat, _ q: point, _ p: big.Nat) -> point {
    let gq = add(g, q, p)
    let k1 = u1.ToBytes()
    let k2 = u2.ToBytes()
    var bits = u1.BitLen
    if u2.BitLen > bits {
        bits = u2.BitLen
    }
    var r = infinity()
    var i = bits - 1
    while i >= 0 {
        r = double(r, p)
        let b1 = bitOf(k1, i)
        let b2 = bitOf(k2, i)
        if b1 && b2 {
            r = add(r, gq, p)
        } else if b1 {
            r = add(r, g, p)
        } else if b2 {
            r = add(r, q, p)
        }
        i -= 1
    }
    return r
}

func onCurve(_ x: big.Nat, _ y: big.Nat, _ c: params) -> bool {
    if big.Cmp(x, c.p) >= 0 || big.Cmp(y, c.p) >= 0 {
        return false
    }
    let y2 = fmul(y, y, c.p)
    let x3 = fmul(fmul(x, x, c.p), x, c.p)
    let threeX = fadd(fadd(x, x, c.p), x, c.p)
    let rhs = fadd(fsub(x3, threeX, c.p), c.b, c.p)
    return big.Cmp(y2, rhs) == 0
}

/// ParsePublicKey reads an uncompressed SEC 1 point, 0x04 || X || Y, as a
/// certificate's subjectPublicKey holds it, and checks that it is on the
/// curve and not the point at infinity.
public func ParsePublicKey(curve: Curve, point: [uint8]) throws -> PublicKey {
    let size = Size(curve)
    if point.count != 1 + 2 * size || point[0] != 0x04 {
        throw EcdsaError.invalidKey("not an uncompressed point of the curve's size")
    }
    let x = big.Nat.FromBytes(Array(point[1..<(1 + size)]))
    let y = big.Nat.FromBytes(Array(point[(1 + size)..<(1 + 2 * size)]))
    if !onCurve(x, y, paramsOf(curve)) {
        throw EcdsaError.invalidKey("the point is not on the curve")
    }
    return PublicKey(curve: curve, x: x, y: y)
}

/// BasePointOnCurve reports whether the curve's base point satisfies its equation:
/// a check of the constants, for tests.
public func BasePointOnCurve(_ curve: Curve) -> bool {
    let c = paramsOf(curve)
    return onCurve(c.gx, c.gy, c)
}

/// OrderTimesBase reports whether n·G is the point at infinity: a check of
/// the group order, for tests.
public func OrderTimesBaseIsInfinity(_ curve: Curve) -> bool {
    let c = paramsOf(curve)
    let g = point(x: c.gx, y: c.gy, z: big.Nat.FromU32(1))
    let r = combined(c.n, g, big.Nat(), g, c.p)
    return r.z.IsZero
}

// derLength reads a DER length at b[at], moving at past it; -1 is a
// length that is not DER.
func derLength(_ b: [uint8], _ at: inout int) -> int {
    if at >= b.count {
        return -1
    }
    let first = int(b[at])
    at += 1
    if first < 0x80 {
        return first
    }
    let n = first & 0x7f
    if n == 0 || n > 2 || at + n > b.count {
        return -1
    }
    var v = 0
    var i = 0
    while i < n {
        v = (v << 8) | int(b[at])
        at += 1
        i += 1
    }
    if v < 0x80 || (n == 2 && v < 0x100) {
        return -1 // not the shortest form, which DER requires
    }
    return v
}

// derInteger reads a positive DER INTEGER at b[at] as its magnitude.
func derInteger(_ b: [uint8], _ at: inout int) -> [uint8]? {
    if at >= b.count || b[at] != 0x02 {
        return nil
    }
    at += 1
    let n = derLength(b, &at)
    if n <= 0 || at + n > b.count {
        return nil
    }
    let v = Array(b[at..<(at + n)])
    at += n
    if (v[0] & 0x80) != 0 {
        return nil // negative
    }
    if v.count > 1 && v[0] == 0 && (v[1] & 0x80) == 0 {
        return nil // a leading zero that is not needed
    }
    return v
}

/// ParseSignature reads an X9.62 signature, SEQUENCE { r INTEGER, s INTEGER },
/// strictly as DER.
public func ParseSignature(_ sig: [uint8]) -> (r: big.Nat, s: big.Nat)? {
    if sig.count < 2 || sig[0] != 0x30 {
        return nil
    }
    var at = 1
    let n = derLength(sig, &at)
    if n < 0 || at + n != sig.count {
        return nil
    }
    guard let r = derInteger(sig, &at) else {
        return nil
    }
    guard let s = derInteger(sig, &at) else {
        return nil
    }
    if at != sig.count {
        return nil
    }
    return (big.Nat.FromBytes(r), big.Nat.FromBytes(s))
}

/// Verify checks an X9.62 DER signature over digest, the hash of the
/// message, with key. A digest longer than the group order is cut to its
/// leftmost bits, as the standard says.
public func Verify(key: PublicKey, digest: [uint8], signature: [uint8]) throws {
    let c = paramsOf(key.Curve)
    guard let rs = ParseSignature(signature) else {
        throw EcdsaError.verificationFailed("the signature does not parse")
    }
    let r = rs.r
    let s = rs.s
    if r.IsZero || s.IsZero || big.Cmp(r, c.n) >= 0 || big.Cmp(s, c.n) >= 0 {
        throw EcdsaError.verificationFailed("r or s out of range")
    }
    if !onCurve(key.X, key.Y, c) {
        throw EcdsaError.invalidKey("the point is not on the curve")
    }
    var e = big.Nat.FromBytes(digest)
    let nBits = c.n.BitLen
    if digest.count * 8 > nBits {
        e = big.ShiftRight(e, digest.count * 8 - nBits)
    }
    e = big.Mod(e, c.n)
    let w = inverse(s, c.n)
    let u1 = big.MulMod(e, w, c.n)
    let u2 = big.MulMod(r, w, c.n)
    let one = big.Nat.FromU32(1)
    let g = point(x: c.gx, y: c.gy, z: one)
    let q = point(x: key.X, y: key.Y, z: one)
    let sum = combined(u1, g, u2, q, c.p)
    if sum.z.IsZero {
        throw EcdsaError.verificationFailed("u1·G + u2·Q is the point at infinity")
    }
    let zinv = inverse(sum.z, c.p)
    let zinv2 = fmul(zinv, zinv, c.p)
    let x = big.Mod(fmul(sum.x, zinv2, c.p), c.n)
    if big.Cmp(x, r) != 0 {
        throw EcdsaError.verificationFailed("the signature does not match")
    }
}
