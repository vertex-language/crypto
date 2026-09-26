package main
import "crypto/ntlm"
import "crypto/hmac"
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
    print("=== ntlm MS-NLMP 4.2.4 vector ===")
    let ntowf = ntlm.NTOWFv2(user: "User", domain: "Domain", password: bytesOf("Password"))
    check(hex(ntowf) == "0c868a403bfd7a93a3001ef22ef02e3f", "NTOWFv2 got=\(hex(ntowf))")
    let ti: [uint8] = [0x02,0x00,0x0c,0x00,0x44,0x00,0x6f,0x00,0x6d,0x00,0x61,0x00,0x69,0x00,0x6e,0x00,
                       0x01,0x00,0x0c,0x00,0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,
                       0x00,0x00,0x00,0x00]
    var temp: [uint8] = [0x01,0x01,0,0,0,0,0,0]
    var k = 0
    while k < 8 { temp.append(0); k += 1 }
    let cc: [uint8] = [0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa]
    temp.append(contentsOf: cc)
    temp.append(0); temp.append(0); temp.append(0); temp.append(0)
    temp.append(contentsOf: ti)
    temp.append(0); temp.append(0); temp.append(0); temp.append(0)
    let serverChallenge: [uint8] = [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]
    var pin = serverChallenge
    pin.append(contentsOf: temp)
    let ntProof = hmac.Compute(key: ntowf, message: pin, hash: .md5)
    check(hex(ntProof) == "68cd0ab851e51c96aabc927bebef6a1c", "NTProofStr got=\(hex(ntProof))")
    let sbk = hmac.Compute(key: ntowf, message: ntProof, hash: .md5)
    check(hex(sbk) == "8de40ccadbc14a82f15cb0ad0de95ca3", "SessionBaseKey got=\(hex(sbk))")
    if failures > 0 { print("\(failures) FAILURES"); return 1 }
    print("all ntlm vector tests passed")
    return 0
}
