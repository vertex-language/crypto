package main

import "crypto/hkdf"
import "crypto/sha256"

var failures = 0

func check(_ ok: bool, _ msg: string) {
    if ok {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func main() -> int32 {
    // RFC 5869 Test Case 1: SHA-256 with salt, info, L=42
    let ikm = [uint8](repeating: 0x0b, count: 22)
    var salt: [uint8] = []
    var s = 0
    while s <= 0x0c {
        salt.append(uint8(s))
        s += 1
    }

    var info: [uint8] = []
    var inf = 0xf0
    while inf <= 0xf9 {
        info.append(uint8(inf))
        inf += 1
    }

    let prk = hkdf.Extract(hash: .sha256, secret: ikm, salt: salt)
    check(sha256.ToHex(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "hkdf: rfc5869 case 1 prk")

    let okm = hkdf.Expand(hash: .sha256, prk: prk, info: info, length: 42)
    check(sha256.ToHex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "hkdf: rfc5869 case 1 okm")

    let derived = hkdf.DeriveKey(hash: .sha256, secret: ikm, salt: salt, info: info, length: 42)
    check(sha256.ToHex(derived) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "hkdf: DeriveKey matches separate extract + expand")

    if failures == 0 {
        print("all hkdf tests passed")
        return 0
    }
    return int32(failures)
}
