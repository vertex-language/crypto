// TLS 1.2 client (RFC 5246) with ECDHE key exchange, AES-GCM record
// protection (RFC 5288) and RSA server authentication. This is the profile
// Microsoft Windows negotiates for RDP: the built-in TLS 1.3 client here
// cannot talk to a Windows RDP listener, which offers only up to TLS 1.2
// (measured: ECDHE-RSA-AES256-GCM-SHA384 with a self-signed RSA-2048
// certificate).
//
// The whole handshake is driven by Conn12 over a tcp.TcpStream. The server
// certificate is parsed and exposed so a CredSSP layer above can bind to
// its public key, and the ServerKeyExchange signature is verified.
package tls

import "net/tcp"
import "crypto/rand"
import "crypto/curve25519"
import "crypto/cipher"
import "crypto/hmac"
import "crypto/sha256"
import "crypto/sha512"
import "crypto/x509"
import "crypto/rsa"

// Cipher suites we offer (ECDHE_RSA + AES-GCM).
let suiteECDHE_RSA_AES256_GCM_SHA384: uint16 = 0xC030
let suiteECDHE_RSA_AES128_GCM_SHA256: uint16 = 0xC02F

let groupX25519: uint16 = 0x001D

// Handshake message types.
let hsClientHello: uint8 = 1
let hsServerHello: uint8 = 2
let hsCertificate: uint8 = 11
let hsServerKeyExchange: uint8 = 12
let hsServerHelloDone: uint8 = 14
let hsClientKeyExchange: uint8 = 16
let hsFinished: uint8 = 20

public enum Tls12Error: Error {
    case handshake(string)
    case alert(uint8)
    case verify(string)
    case closed

    public var Message: string {
        switch self {
        case .handshake(let s): return "tls12: handshake: \(s)"
        case .alert(let d): return "tls12: fatal alert \(d)"
        case .verify(let s): return "tls12: verification: \(s)"
        case .closed: return "tls12: connection closed"
        }
    }
}

// prf12 is the TLS 1.2 PRF: P_hash(secret, label || seed) expanded to
// `length` bytes (RFC 5246 5.5). `useSHA384` selects the hash for the
// negotiated suite.
func prf12(secret: [uint8], label: string, seed: [uint8], length: int, useSHA384: bool) -> [uint8] {
    var labelSeed: [uint8] = []
    for b in label.utf8 { labelSeed.append(b) }
    labelSeed.append(contentsOf: seed)
    let alg: hmac.HashAlgorithm = useSHA384 ? .sha384 : .sha256
    // P_hash: A(0)=seed; A(i)=HMAC(secret, A(i-1)); out += HMAC(secret, A(i)||labelSeed)
    var out: [uint8] = []
    var a = labelSeed
    while out.count < length {
        a = hmac.Compute(key: secret, message: a, hash: alg)
        var input = a
        input.append(contentsOf: labelSeed)
        let block = hmac.Compute(key: secret, message: input, hash: alg)
        var i = 0
        while i < block.count && out.count < length { out.append(block[i]); i += 1 }
    }
    return out
}

// gcmRecord protects records in one direction with AES-GCM.
struct gcmRecord {
    var gcm: cipher.GCM
    var fixedIV: [uint8]   // 4-byte salt (implicit nonce)
    var seq: uint64

    // seal encrypts a handshake/application record. `explicit` is the
    // 8-byte per-record nonce placed on the wire before the ciphertext.
    mutating func seal(contentType: uint8, version: uint16, plaintext: [uint8]) throws -> [uint8] {
        var explicit = [uint8](repeating: 0, count: 8)
        var s = seq
        var i = 7
        while i >= 0 { explicit[i] = uint8(truncatingIfNeeded: s); s >>= 8; i -= 1 }
        var nonce = fixedIV
        nonce.append(contentsOf: explicit)
        // AAD = seq(8) || type || version(2) || plaintext length(2)
        var aad = seqBytes(seq)
        aad.append(contentType)
        aad.append(uint8(truncatingIfNeeded: version >> 8))
        aad.append(uint8(truncatingIfNeeded: version))
        aad.append(uint8(truncatingIfNeeded: plaintext.count >> 8))
        aad.append(uint8(truncatingIfNeeded: plaintext.count))
        let sealed = try gcm.Seal(nonce: nonce, plaintext: plaintext, additionalData: aad)
        seq &+= 1
        var out = explicit
        out.append(contentsOf: sealed)
        return out
    }

    mutating func open(contentType: uint8, version: uint16, fragment: [uint8]) throws -> [uint8] {
        if fragment.count < 8 { throw Tls12Error.handshake("short GCM record") }
        var nonce = fixedIV
        var i = 0
        while i < 8 { nonce.append(fragment[i]); i += 1 }
        var body: [uint8] = []
        i = 8
        while i < fragment.count { body.append(fragment[i]); i += 1 }
        let plaintextLen = body.count - 16
        if plaintextLen < 0 { throw Tls12Error.handshake("short GCM body") }
        var aad = seqBytes(seq)
        aad.append(contentType)
        aad.append(uint8(truncatingIfNeeded: version >> 8))
        aad.append(uint8(truncatingIfNeeded: version))
        aad.append(uint8(truncatingIfNeeded: plaintextLen >> 8))
        aad.append(uint8(truncatingIfNeeded: plaintextLen))
        do {
            let pt = try gcm.Open(nonce: nonce, ciphertextAndTag: body, additionalData: aad)
            seq &+= 1
            return pt
        } catch {
            throw Tls12Error.verify("GCM auth failed")
        }
    }
}

func seqBytes(_ seq: uint64) -> [uint8] {
    var out = [uint8](repeating: 0, count: 8)
    var s = seq
    var i = 7
    while i >= 0 { out[i] = uint8(truncatingIfNeeded: s); s >>= 8; i -= 1 }
    return out
}
