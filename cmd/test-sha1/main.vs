package main

import (
    "crypto/hmac"
    "crypto/sha1"
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
    // NIST SHA-1 Vector 1: Empty string
    let h1 = sha1.ToHex(sha1.Sum1String(""))
    check(h1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1: empty string")

    // NIST SHA-1 Vector 2: "abc"
    let h2 = sha1.ToHex(sha1.Sum1String("abc"))
    check(h2 == "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1: abc")

    // NIST SHA-1 Vector 3: 56-byte message
    let h3 = sha1.ToHex(sha1.Sum1String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    check(h3 == "84983e441c3bd26ebaae4aa1f95129e5e54670f1", "sha1: 56-byte message")

    // Streaming API check
    var d = sha1.New()
    d.WriteString("abcdbcde")
    d.WriteString("cdefdefg")
    d.WriteString("efghfghi")
    d.WriteString("ghijhijk")
    d.WriteString("ijkljklm")
    d.WriteString("klmnlmno")
    d.WriteString("mnopnopq")
    check(sha1.ToHex(d.Checksum()) == h3, "sha1: streaming matches one-shot")

    // RFC 2202 HMAC-SHA1 Test 1
    let k1 = [uint8](repeating: 0x0b, count: 20)
    let mac1 = hmac.Compute(key: k1, message: "Hi There", hash: .sha1)
    check(sha1.ToHex(mac1) == "b617318655057264e28bc0b6fb378c8ef146be00", "hmac-sha1: RFC 2202 test 1")

    // RFC 2202 HMAC-SHA1 Test 2
    var k2: [uint8] = []
    for b in "Jefe".utf8 { k2.append(b) }
    let mac2 = hmac.Compute(key: k2, message: "what do ya want for nothing?", hash: .sha1)
    check(sha1.ToHex(mac2) == "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", "hmac-sha1: RFC 2202 test 2")

    if failures == 0 {
        print("all sha1 / hmac-sha1 tests passed")
    } else {
        print("\(failures) tests failed")
    }
    return int32(failures)
}
