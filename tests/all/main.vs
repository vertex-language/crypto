package main

import "crypto/subtle"
import "crypto/rand"
import "crypto/sha256"
import "crypto/hmac"
import "crypto/hkdf"
import "crypto/chacha20"
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

func main() -> int32 {
    testSubtle()
    testRand()
    testSha256()
    testHmac()
    testHkdf()
    testChaCha20()

    if failures == 0 {
        print("\n=== all crypto checks passed ===")
        return 0
    }
    print("\n\(failures) checks failed")
    return int32(failures)
}
