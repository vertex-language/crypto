package main
import "crypto/cipher"
var failures = 0
func check(_ ok: bool, _ msg: string) {
    if ok { print("ok    \(msg)") } else { print("FAIL  \(msg)"); failures += 1 }
}
func fromHex(_ s: string) -> [uint8] {
    let cs = [uint8](s.utf8)
    func nib(_ c: uint8) -> uint8 {
        if c >= 48 && c <= 57 { return c - 48 }
        if c >= 97 && c <= 102 { return c - 87 }
        return c - 55
    }
    var out: [uint8] = []
    var i = 0
    while i + 1 < cs.count { out.append((nib(cs[i]) << 4) | nib(cs[i+1])); i += 2 }
    return out
}
func hex(_ b: [uint8]) -> string {
    let h: [uint8] = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]
    var o: [uint8] = []
    for x in b { o.append(h[int(x>>4)]); o.append(h[int(x&15)]) }
    return string(decoding: o, as: UTF8.self)
}
func main() -> int32 {
    print("=== cipher/gcm ===")
    do {
        // NIST GCM test case 3 (AES-128): known answer.
        let key = fromHex("feffe9928665731c6d6a8f9467308308")
        let iv = fromHex("cafebabefacedbaddecaf888")
        let pt = fromHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
        let g = try cipher.GCM.New(key: key)
        let sealed = try g.Seal(nonce: iv, plaintext: pt)
        let ctExpected = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
        let tagExpected = "4d5c2af327cd64a62cf35abd2ba6fab4"
        let clen = pt.count
        var ct: [uint8] = []; var i = 0
        while i < clen { ct.append(sealed[i]); i += 1 }
        var tag: [uint8] = []
        while i < sealed.count { tag.append(sealed[i]); i += 1 }
        check(hex(ct) == ctExpected, "GCM-128 ciphertext (NIST case 3)")
        check(hex(tag) == tagExpected, "GCM-128 tag (NIST case 3)")
        // Round-trip open
        let back = try g.Open(nonce: iv, ciphertextAndTag: sealed)
        check(hex(back) == hex(pt), "GCM open round-trip")
        // Tamper detection
        var bad = sealed; bad[0] = bad[0] ^ 0xFF
        var caught = false
        do { let _ = try g.Open(nonce: iv, ciphertextAndTag: bad) } catch { caught = true }
        check(caught, "GCM open rejects tampered ciphertext")

        // Case 4: with AAD.
        let key4 = fromHex("feffe9928665731c6d6a8f9467308308")
        let iv4 = fromHex("cafebabefacedbaddecaf888")
        let pt4 = fromHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        let aad4 = fromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let g4 = try cipher.GCM.New(key: key4)
        let sealed4 = try g4.Seal(nonce: iv4, plaintext: pt4, additionalData: aad4)
        let tag4start = sealed4.count - 16
        var tag4: [uint8] = []; var k = tag4start
        while k < sealed4.count { tag4.append(sealed4[k]); k += 1 }
        check(hex(tag4) == "5bc94fbc3221a5db94fae95ae7121a47", "GCM-128 tag with AAD (NIST case 4)")

        // AES-256 (NIST case 15)
        let key256 = fromHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        let g256 = try cipher.GCM.New(key: key256)
        let sealed256 = try g256.Seal(nonce: iv, plaintext: pt)
        var ct256: [uint8] = []; i = 0
        while i < clen { ct256.append(sealed256[i]); i += 1 }
        check(hex(ct256) == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad", "GCM-256 ciphertext (NIST case 15)")
    } catch { check(false, "threw \(error)") }
    if failures > 0 { print("\(failures) FAILURES"); return 1 }
    print("all cipher tests passed")
    return 0
}
