package main

import "crypto/subtle"

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
    let a: [uint8] = [1, 2, 3, 4]
    let b: [uint8] = [1, 2, 3, 4]
    let c: [uint8] = [1, 2, 3, 5]
    let d: [uint8] = [1, 2, 3]

    check(subtle.ConstantTimeCompare(a, b) == 1, "subtle: compare equal slices")
    check(subtle.ConstantTimeCompare(a, c) == 0, "subtle: compare different slices")
    check(subtle.ConstantTimeCompare(a, d) == 0, "subtle: compare different lengths")

    check(subtle.ConstantTimeByteEq(42, 42) == 1, "subtle: byte eq equal")
    check(subtle.ConstantTimeByteEq(42, 43) == 0, "subtle: byte eq different")

    check(subtle.ConstantTimeEq(100, 100) == 1, "subtle: int32 eq equal")
    check(subtle.ConstantTimeEq(100, 200) == 0, "subtle: int32 eq different")

    check(subtle.ConstantTimeSelect(1, 10, 20) == 10, "subtle: select 1 returns x")
    check(subtle.ConstantTimeSelect(0, 10, 20) == 20, "subtle: select 0 returns y")

    check(subtle.ConstantTimeLessOrEq(5, 10) == 1, "subtle: 5 <= 10")
    check(subtle.ConstantTimeLessOrEq(10, 10) == 1, "subtle: 10 <= 10")
    check(subtle.ConstantTimeLessOrEq(11, 10) == 0, "subtle: 11 <= 10 is false")

    var dst: [uint8] = [0, 0, 0, 0]
    let src: [uint8] = [9, 8, 7, 6]
    subtle.ConstantTimeCopy(0, &dst, src)
    check(dst[0] == 0 && dst[1] == 0, "subtle: copy v=0 leaves unchanged")

    subtle.ConstantTimeCopy(1, &dst, src)
    check(dst[0] == 9 && dst[3] == 6, "subtle: copy v=1 copies contents")

    if failures == 0 {
        print("all subtle tests passed")
        return 0
    }
    return int32(failures)
}
