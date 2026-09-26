package main

import (
    "crypto/hmac"
    "crypto/sha256"
)

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
    // RFC 4231 Case 1
    let k1 = [uint8](repeating: 0x0b, count: 20)
    let mac1 = hmac.Compute(key: k1, message: "Hi There", hash: .sha256)
    check(sha256.ToHex(mac1) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "hmac: rfc4231 case 1")

    // RFC 4231 Case 2
    var k2: [uint8] = []
    for b in "Jefe".utf8 { k2.append(b) }
    let mac2 = hmac.Compute(key: k2, message: "what do ya want for nothing?", hash: .sha256)
    check(sha256.ToHex(mac2) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hmac: rfc4231 case 2")

    // RFC 4231 Case 3
    let k3 = [uint8](repeating: 0xaa, count: 32)
    let data3 = [uint8](repeating: 0xdd, count: 50)
    let mac3 = hmac.Compute(key: k3, message: data3, hash: .sha256)
    check(sha256.ToHex(mac3) == "cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0", "hmac: rfc4231 case 3")

    // Equal helper check
    check(hmac.Equal(mac1, mac1), "hmac: Equal with identical macs")
    check(!hmac.Equal(mac1, mac2), "hmac: Equal with different macs")

    if failures == 0 {
        print("all hmac tests passed")
        return 0
    }
    return int32(failures)
}
