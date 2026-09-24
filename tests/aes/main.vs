package main
import "crypto/aes"
var failures = 0
func check(_ ok: bool, _ msg: string) {
    if ok { print("ok    \(msg)") } else { print("FAIL  \(msg)"); failures += 1 }
}
func hex(_ b: [uint8]) -> string {
    let h: [uint8] = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]
    var o: [uint8] = []
    for x in b { o.append(h[int(x >> 4)]); o.append(h[int(x & 15)]) }
    return string(decoding: o, as: UTF8.self)
}
func main() -> int32 {
    print("=== aes ===")
    // FIPS 197 Appendix B / C.1: AES-128
    let k128: [uint8] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]
    let pt: [uint8] = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]
    do {
        let b = try aes.Block(key: k128)
        let ct = b.Encrypt(pt)
        check(hex(ct) == "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128 encrypt (FIPS C.1)")
        // AES-256 C.3
        let k256: [uint8] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                             0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f]
        let b256 = try aes.Block(key: k256)
        let ct256 = b256.Encrypt(pt)
        check(hex(ct256) == "8ea2b7ca516745bfeafc49904b496089", "AES-256 encrypt (FIPS C.3)")
    } catch { check(false, "threw \(error)") }
    if failures > 0 { print("\(failures) FAILURES"); return 1 }
    print("all aes tests passed")
    return 0
}
