// test-cert checks crypto/cert offline: signatures by scheme against
// certificates from testdata/cert, and a self-signed chain refused. Run
// from the repository root.
package main

import (
    "crypto/cert"
    "fs"
)

var failures = 0

func check(_ ok: bool, _ m: string) {
    if ok {
        print("ok    \(m)")
    } else {
        print("FAIL  \(m)")
        failures += 1
    }
}

func read(_ name: string) -> [uint8] {
    do {
        return try fs.ReadFile(fs.Path("testdata/cert/" + name))
    } catch {
        print("FAIL  cannot read testdata/cert/\(name): \(error)")
        failures += 1
        return []
    }
}

// verifies reports whether a signature verified, and fails the check with
// the error when it should have.
func verifies(_ certificate: [uint8], _ scheme: uint16, _ data: [uint8], _ sig: [uint8]) -> bool {
    do {
        try cert.VerifySignature(certificate: certificate, scheme: scheme, data: data, signature: sig)
        return true
    } catch {
        return false
    }
}

// refused checks that a broken chain is refused as expired, or with
// expiredOnly false, as untrusted or expired.
func refused(_ chain: [[uint8]], _ host: string, _ what: string, expiredOnly: bool) {
    do {
        try cert.VerifyChain(chain, host: host)
        check(false, "\(what) is refused")
    } catch let e as cert.CertError {
        switch e {
        case .expired: check(true, "\(what) is refused (\(e.Message))")
        case .untrusted: check(!expiredOnly, expiredOnly ? "\(what) is refused as expired, not: \(e.Message)" : "\(what) is refused (\(e.Message))")
        default: check(false, "\(what) is refused as expired or untrusted, not: \(e.Message)")
        }
    } catch {
        check(false, "\(what) threw \(error)")
    }
}

func main() -> int32 {
    let ec = read("ec.der")
    let rsa = read("rsa.der")
    let message = read("message")
    var tampered = message
    tampered[0] ^= 1

    check(verifies(ec, cert.Scheme.ecdsaP256SHA256, message, read("ec.sig")), "ECDSA P-256 SHA-256 verifies")
    check(!verifies(ec, cert.Scheme.ecdsaP256SHA256, tampered, read("ec.sig")), "ECDSA over other data is refused")
    check(!verifies(ec, cert.Scheme.rsaPSSSHA256, message, read("ec.sig")), "an RSA scheme with an EC key is refused")
    check(verifies(rsa, cert.Scheme.rsaPSSSHA256, message, read("pss.sig")), "RSA-PSS SHA-256 verifies")
    check(verifies(rsa, cert.Scheme.rsaPKCS1SHA256, message, read("pkcs1.sig")), "RSA PKCS#1 v1.5 SHA-256 verifies")
    check(!verifies(rsa, cert.Scheme.rsaPKCS1SHA256, message, read("pss.sig")), "a PSS signature as PKCS#1 is refused")
    check(!verifies(rsa, cert.Scheme.rsaPSSSHA256, tampered, read("pss.sig")), "RSA-PSS over other data is refused")

    do {
        try cert.VerifyChain([ec], host: "test.vertex.invalid")
        check(false, "a self-signed chain is refused")
    } catch let e as cert.CertError {
        switch e {
        case .untrusted: check(true, "a self-signed chain is refused (\(e.Message))")
        default: check(false, "a self-signed chain is refused as untrusted, not: \(e.Message)")
        }
    } catch {
        check(false, "a self-signed chain threw \(error)")
    }
    // badssl.com's broken chains, captured once: expired for good, and
    // leading to no root the system has (an expired verdict is right too,
    // once they run out in 2028).
    refused([read("expired-1.der"), read("expired-2.der"), read("expired-3.der")],
            "expired.badssl.com", "an expired chain", expiredOnly: true)
    refused([read("self-signed-1.der")], "self-signed.badssl.com", "a self-signed server certificate", expiredOnly: false)
    refused([read("untrusted-root-1.der"), read("untrusted-root-2.der")], "untrusted-root.badssl.com",
            "a chain to an untrusted root", expiredOnly: false)

    do {
        try cert.VerifyChain([], host: "")
        check(false, "an empty chain is refused")
    } catch {
        check(true, "an empty chain is refused")
    }
    do {
        try cert.VerifyChain([[1, 2, 3]], host: "")
        check(false, "a chain that does not parse is refused")
    } catch let e as cert.CertError {
        switch e {
        case .invalid: check(true, "a chain that does not parse is refused as invalid")
        default: check(false, "a chain that does not parse is refused as invalid, not: \(e.Message)")
        }
    } catch {
        check(false, "a chain that does not parse threw \(error)")
    }

    if failures > 0 {
        print("\(failures) FAILURES")
        return 1
    }
    print("all cert tests passed")
    return 0
}
