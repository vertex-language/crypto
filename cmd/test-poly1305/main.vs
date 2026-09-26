package main

import (
    "crypto/poly1305"
    "encoding/hex"
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
    do {
        let keyHex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
        let key = try hex.DecodeString(keyHex)

        let text = "Cryptographic Forum Research Group"
        var msg: [uint8] = []
        for b in text.utf8 { msg.append(b) }

        let tag = poly1305.Sum(msg, key: key)
        let tagHex = hex.EncodeToString(tag)
        print("Poly1305 Tag: \(tagHex)")

        check(tagHex == "a8061dc1305136c6c22b8baf0c0127a9", "poly1305: matches RFC 8439 Section 2.5.2 vector")
        check(poly1305.Verify(mac: tag, msg: msg, key: key), "poly1305: Verify succeeds for valid tag")

        var badTag = tag
        badTag[0] ^= 1
        check(!poly1305.Verify(mac: badTag, msg: msg, key: key), "poly1305: Verify rejects modified tag")
    } catch {
        check(false, "poly1305: exception during test")
    }

    if failures == 0 {
        print("all poly1305 tests passed")
        return 0
    }
    return int32(failures)
}
