package curve25519

public let ScalarSize: int = 32
public let PointSize: int = 32

public enum Curve25519Error: Error {
    case invalidScalarSize
    case invalidPointSize
}

func car25519(_ o: inout [int64]) {
    var i = 0
    while i < 16 {
        o[i] &+= (1 << 16)
        let c = o[i] >> 16
        if i < 15 {
            o[i + 1] &+= (c &- 1)
        } else {
            o[0] &+= 38 &* (c &- 1)
        }
        o[i] &-= (c << 16)
        i += 1
    }
}

func sel25519(_ p: inout [int64], _ q: inout [int64], _ b: int64) {
    let mask = ~(b &- 1)
    var i = 0
    while i < 16 {
        let t = mask & (p[i] ^ q[i])
        p[i] ^= t
        q[i] ^= t
        i += 1
    }
}

func pack25519(_ n: [int64]) -> [uint8] {
    var t = n
    car25519(&t)
    car25519(&t)
    car25519(&t)
    var j = 0
    while j < 2 {
        var m = [int64](repeating: 0, count: 16)
        m[0] = t[0] &- 0xffed
        var i = 1
        while i < 15 {
            m[i] = t[i] &- 0xffff &- ((m[i - 1] >> 16) & 1)
            m[i - 1] &= 0xffff
            i += 1
        }
        m[15] = t[15] &- 0x7fff &- ((m[14] >> 16) & 1)
        let b = (m[15] >> 16) & 1
        m[14] &= 0xffff
        sel25519(&t, &m, 1 &- b)
        j += 1
    }
    var out = [uint8](repeating: 0, count: 32)
    var i = 0
    while i < 16 {
        out[2 * i] = uint8(truncatingIfNeeded: t[i] & 0xff)
        out[2 * i + 1] = uint8(truncatingIfNeeded: (t[i] >> 8) & 0xff)
        i += 1
    }
    return out
}

func unpack25519(_ n: [uint8]) -> [int64] {
    var o = [int64](repeating: 0, count: 16)
    var i = 0
    while i < 16 {
        o[i] = int64(n[2 * i]) | (int64(n[2 * i + 1]) << 8)
        i += 1
    }
    o[15] &= 0x7fff
    return o
}

func addField(_ o: inout [int64], _ a: [int64], _ b: [int64]) {
    var i = 0
    while i < 16 {
        o[i] = a[i] &+ b[i]
        i += 1
    }
}

func subField(_ o: inout [int64], _ a: [int64], _ b: [int64]) {
    var i = 0
    while i < 16 {
        o[i] = a[i] &- b[i]
        i += 1
    }
}

func mulField(_ o: inout [int64], _ a: [int64], _ b: [int64]) {
    var t = [int64](repeating: 0, count: 31)
    var i = 0
    while i < 16 {
        var j = 0
        while j < 16 {
            t[i + j] &+= a[i] &* b[j]
            j += 1
        }
        i += 1
    }
    i = 0
    while i < 15 {
        t[i] &+= 38 &* t[i + 16]
        i += 1
    }
    i = 0
    while i < 16 {
        o[i] = t[i]
        i += 1
    }
    car25519(&o)
    car25519(&o)
}

func sqField(_ o: inout [int64], _ a: [int64]) {
    mulField(&o, a, a)
}

func inv25519(_ o: inout [int64], _ input: [int64]) {
    var c = input
    var a = 253
    while a >= 0 {
        sqField(&c, c)
        if a != 2 && a != 4 {
            mulField(&c, c, input)
        }
        a -= 1
    }
    var k = 0
    while k < 16 {
        o[k] = c[k]
        k += 1
    }
}

/// ScalarMult calculates the scalar product of scalar and point on Curve25519 (RFC 7748).
public func ScalarMult(scalar: [uint8], point: [uint8]) throws -> [uint8] {
    if scalar.count != ScalarSize {
        throw Curve25519Error.invalidScalarSize
    }
    if point.count != PointSize {
        throw Curve25519Error.invalidPointSize
    }

    var z = scalar
    z[31] = (z[31] & 127) | 64
    z[0] &= 248

    let x = unpack25519(point)
    var a = [int64](repeating: 0, count: 16)
    var b = x
    var c = [int64](repeating: 0, count: 16)
    var d = [int64](repeating: 0, count: 16)
    a[0] = 1
    d[0] = 1

    var const121665 = [int64](repeating: 0, count: 16)
    const121665[0] = 0xdb41
    const121665[1] = 1

    var e = [int64](repeating: 0, count: 16)
    var f = [int64](repeating: 0, count: 16)

    var i = 254
    while i >= 0 {
        let byteVal = z[i >> 3]
        let shiftCount = uint8(truncatingIfNeeded: i & 7)
        let bit = (byteVal >> shiftCount) & 1
        let r = int64(bit)
        sel25519(&a, &b, r)
        sel25519(&c, &d, r)

        addField(&e, a, c)
        subField(&a, a, c)
        addField(&c, b, d)
        subField(&b, b, d)

        sqField(&d, e)
        sqField(&f, a)
        mulField(&a, c, a)
        mulField(&c, b, e)

        addField(&e, a, c)
        subField(&a, a, c)
        sqField(&b, a)
        subField(&c, d, f)

        mulField(&a, c, const121665)
        addField(&a, a, d)
        mulField(&c, c, a)
        mulField(&a, d, f)
        mulField(&d, b, x)
        sqField(&b, e)

        sel25519(&a, &b, r)
        sel25519(&c, &d, r)

        i -= 1
    }

    var cInv = [int64](repeating: 0, count: 16)
    inv25519(&cInv, c)
    var res = [int64](repeating: 0, count: 16)
    mulField(&res, a, cInv)
    return pack25519(res)
}

/// BasePoint is the Curve25519 base point (9 followed by 31 zero bytes).
public let BasePoint: [uint8] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]

/// ScalarBaseMult calculates the public key corresponding to a private scalar.
public func ScalarBaseMult(scalar: [uint8]) throws -> [uint8] {
    return try ScalarMult(scalar: scalar, point: BasePoint)
}
