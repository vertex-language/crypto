package main

import "crypto/subtle"
import "crypto/rand"
import "crypto/sha256"
import "crypto/hmac"
import "crypto/hkdf"
import "crypto/chacha20"
import "crypto/poly1305"
import "crypto/chacha20poly1305"
import "crypto/curve25519"
import "crypto/tls"
import "crypto/sha1"
import "crypto/crc32"
import "crypto/md5"
import "encoding/hex"

var failures = 0

func check(_ ok: bool, _ msg: string) {
    if ok {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func testSubtle() {
    print("=== crypto/subtle ===")
    let a: [uint8] = [1, 2, 3, 4]
    let b: [uint8] = [1, 2, 3, 4]
    let c: [uint8] = [1, 2, 3, 5]

    check(subtle.ConstantTimeCompare(a, b) == 1, "subtle: compare equal slices")
    check(subtle.ConstantTimeCompare(a, c) == 0, "subtle: compare different slices")
    check(subtle.ConstantTimeByteEq(42, 42) == 1, "subtle: byte eq equal")
    check(subtle.ConstantTimeByteEq(42, 43) == 0, "subtle: byte eq different")
    check(subtle.ConstantTimeSelect(1, 10, 20) == 10, "subtle: select 1 returns x")
    check(subtle.ConstantTimeSelect(0, 10, 20) == 20, "subtle: select 0 returns y")

    var dst: [uint8] = [0, 0, 0, 0]
    let src: [uint8] = [9, 8, 7, 6]
    subtle.ConstantTimeCopy(1, &dst, src)
    check(dst[0] == 9 && dst[3] == 6, "subtle: constant-time copy")
}

func testRand() {
    print("=== crypto/rand ===")
    do {
        let b1 = try rand.Bytes(32)
        let b2 = try rand.Bytes(32)
        check(b1.count == 32 && b2.count == 32, "rand: generated 32 random bytes")
        check(subtle.ConstantTimeCompare(b1, b2) == 0, "rand: consecutive sequences are distinct")
    } catch {
        check(false, "rand: exception thrown")
    }
}

func testSha256() {
    print("=== crypto/sha256 ===")
    let h1 = sha256.ToHex(sha256.Sum256(""))
    check(h1 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256: empty string")

    let h2 = sha256.ToHex(sha256.Sum256("abc"))
    check(h2 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256: abc")

    let h3 = sha256.ToHex(sha256.Sum256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    check(h3 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "sha256: 56-byte message")

    let h224 = sha256.ToHex(sha256.Sum224("abc"))
    check(h224 == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "sha224: abc")
}

func testHmac() {
    print("=== crypto/hmac ===")
    let k1 = [uint8](repeating: 0x0b, count: 20)
    let mac1 = hmac.Compute(key: k1, message: "Hi There", hash: .sha256)
    check(sha256.ToHex(mac1) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "hmac: rfc4231 case 1")
    check(hmac.Equal(mac1, mac1), "hmac: Equal with identical macs")
}

func testHkdf() {
    print("=== crypto/hkdf ===")
    let ikm = [uint8](repeating: 0x0b, count: 22)
    var salt: [uint8] = []
    var s = 0
    while s <= 0x0c {
        salt.append(uint8(s))
        s += 1
    }
    var info: [uint8] = []
    var inf = 0xf0
    while inf <= 0xf9 {
        info.append(uint8(inf))
        inf += 1
    }

    let prk = hkdf.Extract(hash: .sha256, secret: ikm, salt: salt)
    check(sha256.ToHex(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "hkdf: extract")

    let okm = hkdf.Expand(hash: .sha256, prk: prk, info: info, length: 42)
    check(sha256.ToHex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "hkdf: expand")
}

func testChaCha20() {
    print("=== crypto/chacha20 ===")
    var key = [uint8](repeating: 0, count: 32)
    var i = 0
    while i < 32 { key[i] = uint8(i); i += 1 }

    let nonce: [uint8] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]
    let msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var pt: [uint8] = []
    for b in msg.utf8 { pt.append(b) }

    do {
        let ct = try chacha20.Encrypt(key: key, nonce: nonce, plaintext: pt, counter: 1)
        let ctHex = hex.EncodeToString(ct)
        check(ctHex == "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d", "chacha20: matches RFC 8439 vector")
        let decrypted = try chacha20.Decrypt(key: key, nonce: nonce, ciphertext: ct, counter: 1)
        check(decrypted.count == pt.count, "chacha20: round trip")
    } catch {
        check(false, "chacha20: exception")
    }
}

func testPoly1305() {
    print("=== crypto/poly1305 ===")
    do {
        let key = try hex.DecodeString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        let text = "Cryptographic Forum Research Group"
        var msg: [uint8] = []
        for b in text.utf8 { msg.append(b) }

        let tag = poly1305.Sum(msg, key: key)
        let tagHex = hex.EncodeToString(tag)
        check(tagHex == "a8061dc1305136c6c22b8baf0c0127a9", "poly1305: matches RFC 8439 Section 2.5.2 vector")
        check(poly1305.Verify(mac: tag, msg: msg, key: key), "poly1305: verify valid tag")
    } catch {
        check(false, "poly1305: exception")
    }
}

func testChaCha20Poly1305() {
    print("=== crypto/chacha20poly1305 ===")
    var key = [uint8](repeating: 0, count: 32)
    var i = 0
    while i < 32 { key[i] = uint8(0x80 + i); i += 1 }

    let nonce: [uint8] = [7, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
    let aad: [uint8] = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]
    let msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var pt: [uint8] = []
    for b in msg.utf8 { pt.append(b) }

    do {
        let sealed = try chacha20poly1305.Seal(key: key, nonce: nonce, plaintext: pt, additionalData: aad)
        let ctLen = sealed.count - 16
        var tag = [uint8](repeating: 0, count: 16)
        var t = 0
        while t < 16 { tag[t] = sealed[ctLen + t]; t += 1 }
        check(hex.EncodeToString(tag) == "1ae10b594f09e26a7e902ecbd0600691", "chacha20poly1305: matches RFC 8439 Section 2.8.2 tag")

        let opened = try chacha20poly1305.Open(key: key, nonce: nonce, ciphertextAndTag: sealed, additionalData: aad)
        check(opened.count == pt.count, "chacha20poly1305: round trip")
    } catch {
        check(false, "chacha20poly1305: exception")
    }
}

func testCurve25519() {
    print("=== crypto/curve25519 ===")
    do {
        let alicePriv = try hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let alicePub = try curve25519.ScalarBaseMult(scalar: alicePriv)
        check(hex.EncodeToString(alicePub) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "curve25519: Alice public key RFC 7748")

        let bobPriv = try hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let bobPub = try curve25519.ScalarBaseMult(scalar: bobPriv)
        check(hex.EncodeToString(bobPub) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "curve25519: Bob public key RFC 7748")

        let sharedA = try curve25519.ScalarMult(scalar: alicePriv, point: bobPub)
        let sharedB = try curve25519.ScalarMult(scalar: bobPriv, point: alicePub)
        check(hex.EncodeToString(sharedA) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "curve25519: shared secret RFC 7748")
        check(hex.EncodeToString(sharedA) == hex.EncodeToString(sharedB), "curve25519: shared secret symmetric")
    } catch {
        check(false, "curve25519: exception")
    }
}

func testTls() {
    print("=== crypto/tls ===")
    let secret = [uint8](repeating: 0x55, count: 32)
    let context = [uint8](repeating: 0xaa, count: 32)
    let derived = tls.HkdfExpandLabel(secret: secret, label: "c hs traffic", context: context, length: 32)
    check(derived.count == 32, "tls: HkdfExpandLabel length 32")

    var ks = tls.KeySchedule()
    check(ks.EarlySecret.count == 32, "tls: EarlySecret initialized")
    let dummyShared = [uint8](repeating: 0x42, count: 32)
    ks.DeriveHandshakeSecret(sharedSecret: dummyShared)
    check(ks.HandshakeSecret.count == 32, "tls: HandshakeSecret derived")

    do {
        let key = [uint8](repeating: 0x11, count: 32)
        let iv = [uint8](repeating: 0x22, count: 12)
        var encCipher = tls.RecordCipher(key: key, iv: iv)
        var decCipher = tls.RecordCipher(key: key, iv: iv)

        let plaintext: [uint8] = [0x01, 0x02, 0x03, 0x04]
        let record = try encCipher.Encrypt(contentType: tls.RecordType.ApplicationData, plaintext: plaintext)
        check(record.count == 5 + plaintext.count + 1 + 16, "tls: record length matches")

        var header = [uint8](repeating: 0, count: 5)
        var payload = [uint8](repeating: 0, count: record.count - 5)
        var i = 0
        while i < 5 { header[i] = record[i]; i += 1 }
        i = 0
        while i < payload.count { payload[i] = record[5 + i]; i += 1 }

        let dec = try decCipher.Decrypt(header: header, payload: payload)
        check(dec.ContentType == tls.RecordType.ApplicationData, "tls: decrypted content type")
        check(dec.Data.count == plaintext.count && dec.Data[0] == 0x01 && dec.Data[3] == 0x04, "tls: decrypted plaintext matches")
    } catch {
        check(false, "tls: exception during record test")
    }
}

func testSha1() {
    print("=== crypto/sha1 ===")
    let h1 = sha1.ToHex(sha1.Sum1String(""))
    check(h1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1: empty string")

    let h2 = sha1.ToHex(sha1.Sum1String("abc"))
    check(h2 == "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1: abc")

    let k1 = [uint8](repeating: 0x0b, count: 20)
    let mac1 = hmac.Compute(key: k1, message: "Hi There", hash: .sha1)
    check(sha1.ToHex(mac1) == "b617318655057264e28bc0b6fb378c8ef146be00", "hmac-sha1: RFC 2202 test 1")
}

func testCrc32() {
    print("=== crypto/crc32 ===")
    check(crc32.ChecksumString("") == 0, "crc32: empty string")
    check(crc32.ChecksumString("123456789") == 0xcbf43926, "crc32: 123456789")
    check(crc32.ChecksumString("The quick brown fox jumps over the lazy dog") == 0x414fa339, "crc32: standard pangram")
}

func testMd5() {
    print("=== crypto/md5 ===")
    check(md5.ToHex(md5.SumString("")) == "d41d8cd98f00b204e9800998ecf8427e", "md5: empty string")
    check(md5.ToHex(md5.SumString("abc")) == "900150983cd24fb0d6963f7d28e17f72", "md5: abc")
    check(md5.ToHex(md5.SumString("user:realm:pass")) == "8493fbc53ba582fb4c044c456bdc40eb", "md5: turn key derivation")
    let k = [uint8](repeating: 0x0b, count: 16)
    let mac = hmac.Compute(key: k, message: "Hi There", hash: .md5)
    check(md5.ToHex(mac) == "9294727a3638bb1c13f48ef8158bfc9d", "hmac-md5: RFC 2202 test 1")
}

func main() -> int32 {
    testSubtle()
    testRand()
    testSha256()
    testSha1()
    testCrc32()
    testMd5()
    testHmac()
    testHkdf()
    testChaCha20()
    testPoly1305()
    testChaCha20Poly1305()
    testCurve25519()
    testTls()

    if failures == 0 {
        print("\n=== all crypto checks passed ===")
        return 0
    }
    print("\n\(failures) checks failed")
    return int32(failures)
}
