package main
import (
    "crypto/md4"
    "crypto/rc4"
)
var failures = 0
func check(_ ok: bool, _ m: string) { if ok { print("ok    \(m)") } else { print("FAIL  \(m)"); failures += 1 } }
func hex(_ b: [uint8]) -> string {
    let h: [uint8] = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]
    var o: [uint8] = []
    for x in b { o.append(h[int(x>>4)]); o.append(h[int(x&15)]) }
    return string(decoding: o, as: UTF8.self)
}
func bytesOf(_ s: string) -> [uint8] { var b: [uint8] = []; for c in s.utf8 { b.append(c) }; return b }
func main() -> int32 {
    print("=== md4 / rc4 ===")
    // RFC 1320 MD4 test vectors
    check(hex(md4.Sum([])) == "31d6cfe0d16ae931b73c59d7e0c089c0", "md4 empty")
    check(hex(md4.Sum(bytesOf("abc"))) == "a448017aaf21d8525fc10ae87aa6729d", "md4 abc")
    check(hex(md4.Sum(bytesOf("message digest"))) == "d9130a8164549fe818874806e1c7014b", "md4 message digest")
    check(hex(md4.Sum(bytesOf("abcdefghijklmnopqrstuvwxyz"))) == "d79e1c308aa5bbcdeea8ed63df412da9", "md4 a-z")
    // NT hash of "password": MD4(UTF16LE("password"))
    let pw: [uint8] = [0x70,0,0x61,0,0x73,0,0x73,0,0x77,0,0x6f,0,0x72,0,0x64,0]
    check(hex(md4.Sum(pw)) == "8846f7eaee8fb117ad06bdd830b7586c", "NT hash of 'password'")

    // RC4 RFC 6229 test vectors: key "Key", plaintext "Plaintext"
    let ct = rc4.Apply(key: bytesOf("Key"), data: bytesOf("Plaintext"))
    check(hex(ct) == "bbf316e8d940af0ad3", "rc4 Key/Plaintext")
    // round-trip
    var c = rc4.Cipher(key: bytesOf("Key"))
    let back = c.XORStream(ct)
    check(hex(back) == hex(bytesOf("Plaintext")), "rc4 round-trip")
    if failures > 0 { print("\(failures) FAILURES"); return 1 }
    print("all md4/rc4 tests passed")
    return 0
}
