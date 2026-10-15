package cert

// The system's certificate trust on Linux. There is no one system
// verifier to ask -- distributions differ, and libcrypto is not always
// there -- so this is Go's way: the trusted roots are the distribution's
// own bundle, which its ca-certificates package keeps (or $SSL_CERT_FILE,
// when set), and crypto/x509 builds and checks the path.

import (
    "crypto/ecdsa"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/x509"
    "encoding/base64"
    "fs"
    "os/env"
    "time"
)

// rootFiles are where distributions keep their bundle of trusted roots,
// as PEM; the first that holds any is used.
let rootFiles: [string] = [
    "/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Gentoo, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL 6
    "/etc/ssl/ca-bundle.pem",                            // openSUSE
    "/etc/pki/tls/cacert.pem",                           // OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS, RHEL 7
    "/etc/ssl/cert.pem",                                 // Alpine
]

func find(_ data: [uint8], _ marker: [uint8], from: int) -> int {
    var i = from
    while i + marker.count <= data.count {
        var j = 0
        while j < marker.count && data[i + j] == marker[j] {
            j += 1
        }
        if j == marker.count {
            return i
        }
        i += 1
    }
    return -1
}

// poolOf reads every CERTIFICATE block of a PEM bundle into a pool,
// leaving out any that does not parse.
func poolOf(_ data: [uint8]) -> x509.CertPool {
    let begin = Array("-----BEGIN CERTIFICATE-----".utf8)
    let end = Array("-----END CERTIFICATE-----".utf8)
    var pool = x509.CertPool()
    var at = 0
    while true {
        let b = find(data, begin, from: at)
        if b < 0 {
            break
        }
        let e = find(data, end, from: b + begin.count)
        if e < 0 {
            break
        }
        at = e + end.count
        do {
            let der = try base64.DecodeString(string(decoding: data[(b + begin.count)..<e], as: UTF8.self))
            pool.Add(try x509.Parse(der))
        } catch {
            continue
        }
    }
    return pool
}

// systemRoots reads the distribution's trusted roots.
func systemRoots() throws -> x509.CertPool {
    var files = rootFiles
    if let f = env.Get("SSL_CERT_FILE"), !f.isEmpty {
        files = [f]
    }
    for f in files {
        var data: [uint8] = []
        do {
            data = try fs.ReadFile(fs.Path(f))
        } catch {
            continue
        }
        let pool = poolOf(data)
        if pool.Count > 0 {
            return pool
        }
    }
    throw CertError.untrusted("no trusted roots: none of \(files) holds a certificate (install ca-certificates, or set SSL_CERT_FILE)")
}

func parse(_ der: [uint8]) throws -> x509.Certificate {
    do {
        return try x509.Parse(der)
    } catch let e as x509.X509Error {
        throw CertError.invalid(e.Message)
    } catch {
        throw CertError.invalid("\(error)")
    }
}

func systemVerifyChain(_ chain: [[uint8]], host: string) throws {
    var certs: [x509.Certificate] = []
    for der in chain {
        certs.append(try parse(der))
    }
    var opts = x509.VerifyOptions(roots: try systemRoots(), currentTime: time.Timestamp.Now().UnixSeconds)
    opts.DNSName = host
    opts.Intermediates = Array(certs[1..<certs.count])
    do {
        let _ = try x509.Verify(certs[0], opts)
    } catch let e as x509.VerifyError {
        switch e {
        case .hostname: throw CertError.nameMismatch(e.Message)
        case .expired: throw CertError.expired(e.Message)
        default: throw CertError.untrusted(e.Message)
        }
    } catch {
        throw CertError.untrusted("\(error)")
    }
}

// The kinds of signature a TLS SignatureScheme names.
let pkcs1 = 1
let pss = 2
let ecdsaKind = 3

func systemVerifySignature(certificate: [uint8], scheme: uint16, data: [uint8], signature: [uint8]) throws {
    var hash: rsa.Hash = .sha256
    var kind = 0
    var curve: ecdsa.Curve = .p256
    switch scheme {
    case 0x0401: kind = pkcs1; hash = .sha256
    case 0x0501: kind = pkcs1; hash = .sha384
    case 0x0601: kind = pkcs1; hash = .sha512
    case 0x0804: kind = pss; hash = .sha256
    case 0x0805: kind = pss; hash = .sha384
    case 0x0806: kind = pss; hash = .sha512
    case 0x0403: kind = ecdsaKind; hash = .sha256; curve = .p256
    case 0x0503: kind = ecdsaKind; hash = .sha384; curve = .p384
    case 0x0603: kind = ecdsaKind; hash = .sha512; curve = .p521
    default: throw CertError.unsupported("the signature scheme is not supported")
    }
    let c = try parse(certificate)
    if kind == ecdsaKind {
        guard let key = c.ECPublicKey else {
            throw CertError.badSignature("the signature scheme does not fit the certificate's key")
        }
        if key.Curve != curve {
            throw CertError.badSignature("the signature scheme does not fit the certificate's curve")
        }
        let digest = hash == .sha256 ? sha256.Sum256(data) : hash == .sha384 ? sha512.Sum384(data) : sha512.Sum512(data)
        do {
            try ecdsa.Verify(key: key, digest: digest, signature: signature)
        } catch let e as ecdsa.EcdsaError {
            throw CertError.badSignature(e.Message)
        }
        return
    }
    if !c.IsRSA {
        throw CertError.badSignature("the signature scheme does not fit the certificate's key")
    }
    if let why = x509.WeakRSAKey(c.RSAPublicKey) {
        throw CertError.unsupported("the certificate's \(why)")
    }
    do {
        if kind == pss {
            try rsa.VerifyPSS(key: c.RSAPublicKey, hash: hash, data: data, signature: signature)
        } else {
            try rsa.VerifyPKCS1v15(key: c.RSAPublicKey, hash: hash, data: data, signature: signature)
        }
    } catch let e as rsa.RsaError {
        throw CertError.badSignature(e.Message)
    }
}
