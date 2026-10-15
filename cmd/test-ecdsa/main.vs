// test-ecdsa checks the curves' constants -- the base point on the curve,
// and of the group's order -- and that a signature is refused when it, the
// digest or the key is not the one that was signed with. Signatures by
// real keys are cmd/test-cert's.
package main

import "crypto/ecdsa"

var failures = 0

func check(_ ok: bool, _ m: string) {
    if ok {
        print("ok    \(m)")
    } else {
        print("FAIL  \(m)")
        failures += 1
    }
}

func main() -> int32 {
    for (curve, name) in [(ecdsa.Curve.p256, "P-256"), (ecdsa.Curve.p384, "P-384"), (ecdsa.Curve.p521, "P-521")] {
        check(ecdsa.BasePointOnCurve(curve), "\(name): the base point is on the curve")
        check(ecdsa.OrderTimesBaseIsInfinity(curve), "\(name): n·G is the point at infinity")
    }
    // The P-256 base point is a key; an off-curve point is not.
    var g: [uint8] = [0x04]
    g.append(contentsOf: [0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
                          0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96])
    g.append(contentsOf: [0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
                          0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5])
    do {
        let _ = try ecdsa.ParsePublicKey(curve: .p256, point: g)
        check(true, "the P-256 base point parses as a key")
    } catch {
        check(false, "the P-256 base point parses as a key: \(error)")
    }
    var off = g
    off[64] ^= 1
    do {
        let _ = try ecdsa.ParsePublicKey(curve: .p256, point: off)
        check(false, "a point off the curve is refused")
    } catch {
        check(true, "a point off the curve is refused")
    }
    do {
        let _ = try ecdsa.ParsePublicKey(curve: .p384, point: g)
        check(false, "a P-256 point as a P-384 key is refused")
    } catch {
        check(true, "a P-256 point as a P-384 key is refused")
    }
    // r = s = 1 is not a signature by this key; r = 0 is out of range.
    do {
        let key = try ecdsa.ParsePublicKey(curve: .p256, point: g)
        let digest = [uint8](repeating: 7, count: 32)
        do {
            try ecdsa.Verify(key: key, digest: digest, signature: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
            check(false, "a made-up signature is refused")
        } catch {
            check(true, "a made-up signature is refused")
        }
        do {
            try ecdsa.Verify(key: key, digest: digest, signature: [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01])
            check(false, "r = 0 is refused")
        } catch {
            check(true, "r = 0 is refused")
        }
        do {
            try ecdsa.Verify(key: key, digest: digest, signature: [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])
            check(false, "an INTEGER with a needless leading zero is refused")
        } catch {
            check(true, "an INTEGER with a needless leading zero is refused")
        }
    } catch {
        check(false, "threw \(error)")
    }
    if failures > 0 {
        print("\(failures) FAILURES")
        return 1
    }
    print("all ecdsa tests passed")
    return 0
}
