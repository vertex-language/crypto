package main

import (
    "crypto/chacha20"
    "encoding/hex"
)

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
    var key = [uint8](repeating: 0, count: 32)
    var i = 0
    while i < 32 {
        key[i] = uint8(i)
        i += 1
    }

    let nonce: [uint8] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]
    let msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var pt: [uint8] = []
    for b in msg.utf8 {
        pt.append(b)
    }

    do {
        let ct = try chacha20.Encrypt(key: key, nonce: nonce, plaintext: pt, counter: 1)
        let ctHex = hex.EncodeToString(ct)

        let expectedHex = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        check(ctHex == expectedHex, "chacha20: matches RFC 8439 Section 2.4.2 Sunscreen test vector")

        let decrypted = try chacha20.Decrypt(key: key, nonce: nonce, ciphertext: ct, counter: 1)
        check(decrypted.count == pt.count, "chacha20: decrypted length matches")

        var roundTrip = true
        var j = 0
        while j < pt.count {
            if decrypted[j] != pt[j] {
                roundTrip = false
                break
            }
            j += 1
        }
        check(roundTrip, "chacha20: round-trip encrypt / decrypt matches original plaintext")
    } catch {
        check(false, "chacha20: exception during encrypt / decrypt")
    }

    if failures == 0 {
        print("all chacha20 tests passed")
        return 0
    }
    return int32(failures)
}
