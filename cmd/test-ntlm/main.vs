package main
import "crypto/ntlm"
import "crypto/md4"
import "encoding/binary"
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
    print("=== ntlm (MS-NLMP 4.2 vectors) ===")
    // 4.2.1: User "User", Domain "Domain", Password "Password"
    // NT hash = MD4(UTF16LE("Password")) = a4f49c406510bdcab6824ee7c30fd852
    let ntHash = md4.Sum(binary.EncodeUTF16LE("Password"))
    check(hex(ntHash) == "a4f49c406510bdcab6824ee7c30fd852", "NT hash of 'Password'")
    // Negotiate/Authenticate smoke: build a synthetic challenge and ensure
    // Authenticate produces a well-formed type-3 with a MIC and a context.
    var cli = ntlm.Client(domain: "Domain", user: "User", password: bytesOf("Password"),
                          workstation: "COMPUTER", targetSPN: "TERMSRV/host")
    let neg = cli.Negotiate()
    check(neg.count >= 32 && neg[8] == 1, "negotiate type 1")
    // Minimal CHALLENGE: signature, type2, targetname(empty), flags,
    // serverChallenge=0102030405060708, reserved, targetinfo with a
    // timestamp AV then EOL.
    var ti: [uint8] = []
    // MsvAvTimestamp (id 7, len 8)
    ti.append(7); ti.append(0); ti.append(8); ti.append(0)
    var t = 0
    while t < 8 { ti.append(0); t += 1 }
    // EOL
    ti.append(0); ti.append(0); ti.append(0); ti.append(0)
    var chal = binary.Writer()
    for b in [0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00] { chal.U8(uint8(b)) }
    chal.U32LE(2)
    chal.U16LE(0); chal.U16LE(0); chal.U32LE(0)   // target name fields
    chal.U32LE(0x80000000 | 0x00080000 | 0x00800000 | 0x00000001)  // some flags
    for b in [1,2,3,4,5,6,7,8] { chal.U8(uint8(b)) }  // server challenge
    for _ in 0..<8 { chal.U8(0) }                     // reserved
    let tiOffset = chal.Count + 8   // fields (8) then payload
    chal.U16LE(uint16(ti.count)); chal.U16LE(uint16(ti.count)); chal.U32LE(uint32(tiOffset))
    chal.Append(ti)
    do {
        let auth = try cli.Authenticate(chal.Bytes)
        check(auth.count > 88 && auth[8] == 3, "authenticate type 3")
        check(cli.Ctx.Established, "context established")
        // Wrap/Unwrap self-consistency is checked with real server later.
        let wrapped = cli.Wrap([0xDE, 0xAD, 0xBE, 0xEF])
        check(wrapped.count == 16 + 4, "wrap = 16-byte sig + sealed")
        check(wrapped[0] == 0x01 && wrapped[1] == 0 && wrapped[2] == 0 && wrapped[3] == 0, "wrap version")
    } catch { check(false, "authenticate threw \(error)") }
    if failures > 0 { print("\(failures) FAILURES"); return 1 }
    print("all ntlm tests passed")
    return 0
}
