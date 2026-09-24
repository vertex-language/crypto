package main
import "crypto/sha512"
var failures = 0
func check(_ ok: bool, _ msg: string) {
    if ok { print("ok    \(msg)") } else { print("FAIL  \(msg)"); failures += 1 }
}
func main() -> int32 {
    print("=== sha512 ===")
    // FIPS test vectors
    check(sha512.ToHex(sha512.Sum512([])) ==
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "sha512 empty")
    let abc: [uint8] = [0x61,0x62,0x63]
    check(sha512.ToHex(sha512.Sum512(abc)) ==
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "sha512 abc")
    check(sha512.ToHex(sha512.Sum384(abc)) ==
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "sha384 abc")
    check(sha512.ToHex(sha512.Sum384([])) ==
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "sha384 empty")
    // Long message crossing block boundary (112..128 padding edge)
    var m111 = [uint8](repeating: 0x61, count: 111)
    var m112 = [uint8](repeating: 0x61, count: 112)
    let _ = sha512.Sum512(m111)
    let _ = sha512.Sum512(m112)
    check(sha512.Sum512(m112).count == 64, "112-byte input hashes")
    if failures > 0 { print("\(failures) FAILURES"); return 1 }
    print("all sha512 tests passed")
    return 0
}
