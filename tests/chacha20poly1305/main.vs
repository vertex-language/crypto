package main

import "crypto/chacha20poly1305"
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

func main() -> int32 {
    var key = [uint8](repeating: 0, count: 32)
    var i = 0
    while i < 32 {
        key[i] = uint8(0x80 + i)
        i += 1
    }

    let nonce: [uint8] = [7, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
    let aad: [uint8] = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]

    let msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var pt: [uint8] = []
    for b in msg.utf8 { pt.append(b) }

    do {
        let sealed = try chacha20poly1305.Seal(key: key, nonce: nonce, plaintext: pt, additionalData: aad)
        let sealedHex = hex.EncodeToString(sealed)
        print("Sealed hex prefix: \(sealedHex)")

        // Tag is the last 16 bytes (32 hex characters)
        let ctLen = sealed.count - 16
        var tag = [uint8](repeating: 0, count: 16)
        var t = 0
        while t < 16 {
            tag[t] = sealed[ctLen + t]
            t += 1
        }
        let tagHex = hex.EncodeToString(tag)
        print("Tag hex: \(tagHex)")

        check(tagHex == "1ae10b594f09e26a7e902ecbd0600691", "chacha20poly1305: matches RFC 8439 Section 2.8.2 Tag")

        // Decrypt and authenticate
        let opened = try chacha20poly1305.Open(key: key, nonce: nonce, ciphertextAndTag: sealed, additionalData: aad)
        check(opened.count == pt.count, "chacha20poly1305: decrypted length matches")

        var match = true
        var j = 0
        while j < pt.count {
            if opened[j] != pt[j] {
                match = false
                break
            }
            j += 1
        }
        check(match, "chacha20poly1305: round-trip seal / open matches plaintext")

        // Tamper with ciphertext -> must fail authentication
        var tampered = sealed
        tampered[0] ^= 0x55
        var caughtAuthError = false
        do {
            _ = try chacha20poly1305.Open(key: key, nonce: nonce, ciphertextAndTag: tampered, additionalData: aad)
        } catch chacha20poly1305.AeadError.authenticationFailed {
            caughtAuthError = true
        } catch {
            caughtAuthError = false
        }
        check(caughtAuthError, "chacha20poly1305: rejects tampered ciphertext")

        // Tamper with AAD -> must fail authentication
        var badAad = aad
        badAad[0] ^= 0x01
        var caughtAadError = false
        do {
            _ = try chacha20poly1305.Open(key: key, nonce: nonce, ciphertextAndTag: sealed, additionalData: badAad)
        } catch chacha20poly1305.AeadError.authenticationFailed {
            caughtAadError = true
        } catch {
            caughtAadError = false
        }
        check(caughtAadError, "chacha20poly1305: rejects tampered AAD")
    } catch {
        check(false, "chacha20poly1305: exception during test")
    }

    if failures == 0 {
        print("all chacha20poly1305 tests passed")
        return 0
    }
    return int32(failures)
}
