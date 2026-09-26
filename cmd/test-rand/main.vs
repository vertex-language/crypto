package main

import "crypto/rand"

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
        let b1 = try rand.Bytes(32)
        check(b1.count == 32, "rand: generated 32 random bytes")

        let b2 = try rand.Bytes(32)
        check(b2.count == 32, "rand: generated another 32 random bytes")

        var identical = true
        var i = 0
        while i < 32 {
            if b1[i] != b2[i] {
                identical = false
                break
            }
            i += 1
        }
        check(!identical, "rand: consecutive random sequences are distinct")

        var buf = [uint8](repeating: 0, count: 64)
        let n = try rand.Read(into: &buf)
        check(n == 64, "rand: Read filled entire buffer")

        var nonZero = false
        for b in buf {
            if b != 0 {
                nonZero = true
                break
            }
        }
        check(nonZero, "rand: Read generated non-zero entropy")
    } catch {
        check(false, "rand: exception thrown during random generation")
    }

    if failures == 0 {
        print("all rand tests passed")
        return 0
    }
    return int32(failures)
}
