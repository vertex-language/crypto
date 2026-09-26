package main

import "crypto/curve25519"
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
    do {
        let alicePrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        let alicePriv = try hex.DecodeString(alicePrivHex)
        let alicePub = try curve25519.ScalarBaseMult(scalar: alicePriv)
        let alicePubHex = hex.EncodeToString(alicePub)
        print("Alice pub: \(alicePubHex)")
        check(alicePubHex == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "curve25519: Alice public key matches RFC 7748 Section 6.1")

        let bobPrivHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        let bobPriv = try hex.DecodeString(bobPrivHex)
        let bobPub = try curve25519.ScalarBaseMult(scalar: bobPriv)
        let bobPubHex = hex.EncodeToString(bobPub)
        print("Bob pub: \(bobPubHex)")
        check(bobPubHex == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "curve25519: Bob public key matches RFC 7748 Section 6.1")

        let sharedA = try curve25519.ScalarMult(scalar: alicePriv, point: bobPub)
        let sharedB = try curve25519.ScalarMult(scalar: bobPriv, point: alicePub)

        let sharedAHex = hex.EncodeToString(sharedA)
        let sharedBHex = hex.EncodeToString(sharedB)
        print("Shared secret A: \(sharedAHex)")
        print("Shared secret B: \(sharedBHex)")

        check(sharedAHex == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "curve25519: Shared secret matches RFC 7748 Section 6.1")
        check(sharedAHex == sharedBHex, "curve25519: Shared secret is symmetric between Alice and Bob")
    } catch {
        check(false, "curve25519: exception during test")
    }

    if failures == 0 {
        print("all curve25519 tests passed")
        return 0
    }
    return int32(failures)
}
