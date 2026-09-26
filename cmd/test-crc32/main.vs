package main

import "crypto/crc32"

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
    // Vector 1: Empty string -> 0
    let c1 = crc32.ChecksumString("")
    check(c1 == 0, "crc32: empty string")

    // Vector 2: "123456789" -> 0xcbf43926
    let c2 = crc32.ChecksumString("123456789")
    check(c2 == 0xcbf43926, "crc32: 123456789")

    // Vector 3: "The quick brown fox jumps over the lazy dog" -> 0x414fa339
    let c3 = crc32.ChecksumString("The quick brown fox jumps over the lazy dog")
    check(c3 == 0x414fa339, "crc32: standard pangram")

    // Incremental update check
    var part1: [uint8] = []
    for b in "1234".utf8 { part1.append(b) }
    var part2: [uint8] = []
    for b in "56789".utf8 { part2.append(b) }

    let cPart1 = crc32.Update(0, part1)
    let cTotal = crc32.Update(cPart1, part2)
    check(cTotal == 0xcbf43926, "crc32: incremental update")

    if failures == 0 {
        print("all crc32 tests passed")
    } else {
        print("\(failures) tests failed")
    }
    return int32(failures)
}
