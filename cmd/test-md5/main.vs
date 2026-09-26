package main

import (
    "crypto/hmac"
    "crypto/md5"
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
    // RFC 1321 Vector 1: ""
    let h1 = md5.ToHex(md5.SumString(""))
    check(h1 == "d41d8cd98f00b204e9800998ecf8427e", "md5: empty string")

    // RFC 1321 Vector 2: "a"
    let h2 = md5.ToHex(md5.SumString("a"))
    check(h2 == "0cc175b9c0f1b6a831c399e269772661", "md5: 'a'")

    // RFC 1321 Vector 3: "abc"
    let h3 = md5.ToHex(md5.SumString("abc"))
    check(h3 == "900150983cd24fb0d6963f7d28e17f72", "md5: 'abc'")

    // RFC 1321 Vector 4: "message digest"
    let h4 = md5.ToHex(md5.SumString("message digest"))
    check(h4 == "f96b697d7cb7938d525a2f31aaf161d0", "md5: 'message digest'")

    // RFC 1321 Vector 5: "abcdefghijklmnopqrstuvwxyz"
    let h5 = md5.ToHex(md5.SumString("abcdefghijklmnopqrstuvwxyz"))
    check(h5 == "c3fcd3d76192e4007dfb496cca67e13b", "md5: alphabet")

    // RFC 1321 Vector 6: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    let h6 = md5.ToHex(md5.SumString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
    check(h6 == "d174ab98d277d9f5a5611c2c9f419d9f", "md5: alphanumeric")

    // Streaming API check
    var d = md5.New()
    d.WriteString("message ")
    d.WriteString("digest")
    check(md5.ToHex(d.Checksum()) == h4, "md5: streaming matches one-shot")

    // RFC 2202 HMAC-MD5 Test 1
    // Key: 16 bytes of 0x0b
    let k1 = [uint8](repeating: 0x0b, count: 16)
    let mac1 = hmac.Compute(key: k1, message: "Hi There", hash: .md5)
    check(md5.ToHex(mac1) == "9294727a3638bb1c13f48ef8158bfc9d", "hmac-md5: RFC 2202 test 1")

    // RFC 2202 HMAC-MD5 Test 2
    // Key: "Jefe", Data: "what do ya want for nothing?"
    var k2: [uint8] = []
    for b in "Jefe".utf8 { k2.append(b) }
    let mac2 = hmac.Compute(key: k2, message: "what do ya want for nothing?", hash: .md5)
    check(md5.ToHex(mac2) == "750c783e6ab0b503eaa86e310a5db738", "hmac-md5: RFC 2202 test 2")

    // TURN Long-Term Credential Key derivation test (RFC 5389 / RFC 8656)
    // key = MD5(username ":" realm ":" password)
    // e.g. "user" : "realm" : "pass" -> "user:realm:pass"
    let turnKey = md5.ToHex(md5.SumString("user:realm:pass"))
    check(turnKey == "8493fbc53ba582fb4c044c456bdc40eb", "turn: md5 key derivation")

    if failures == 0 {
        print("all md5 / hmac-md5 tests passed")
    } else {
        print("\(failures) tests failed")
    }
    return int32(failures)
}
