// Package cert answers two questions with the operating system's own
// certificate trust: does a server's chain lead to a root this machine
// trusts, for the host the client asked for; and does a signature verify
// under a certificate's public key. The system builds the path, applies
// the user's and the administrator's trust settings, and checks validity
// and names, so a Vertex program trusts exactly what the rest of the
// machine does -- a corporate root included -- and ships no root list.
//
//     try cert.VerifyChain(chain, host: "huggingface.co")
//     try cert.VerifySignature(certificate: chain[0], scheme: cert.Scheme.ecdsaP256SHA256,
//                              data: signed, signature: sig)
package cert

/// CertError is why a chain or a signature was refused, with the system's
/// own words for it.
public enum CertError: Error {
    /// No path from the chain to a root this machine trusts.
    case untrusted(string)
    /// The server's certificate is not for the host that was asked for.
    case nameMismatch(string)
    /// A certificate in the chain is expired, or not valid yet.
    case expired(string)
    /// The signature does not verify under the certificate's key.
    case badSignature(string)
    /// This platform has no system trust here yet, or the scheme is one
    /// the system does not verify.
    case unsupported(string)
    /// A certificate that does not parse.
    case invalid(string)

    public var Message: string {
        switch self {
        case .untrusted(let s): return "certificate not trusted: \(s)"
        case .nameMismatch(let s): return "certificate name mismatch: \(s)"
        case .expired(let s): return "certificate expired or not yet valid: \(s)"
        case .badSignature(let s): return "bad signature: \(s)"
        case .unsupported(let s): return "unsupported: \(s)"
        case .invalid(let s): return "invalid certificate: \(s)"
        }
    }
}

/// Scheme is a TLS SignatureScheme (RFC 8446 §4.2.3): what a signature is
/// and the hash it is over.
public enum Scheme {
    public static let rsaPKCS1SHA256: uint16 = 0x0401
    public static let rsaPKCS1SHA384: uint16 = 0x0501
    public static let rsaPKCS1SHA512: uint16 = 0x0601
    public static let rsaPSSSHA256: uint16 = 0x0804
    public static let rsaPSSSHA384: uint16 = 0x0805
    public static let rsaPSSSHA512: uint16 = 0x0806
    public static let ecdsaP256SHA256: uint16 = 0x0403
    public static let ecdsaP384SHA384: uint16 = 0x0503
    public static let ecdsaP521SHA512: uint16 = 0x0603
}

/// VerifyChain checks a certificate chain, DER-encoded and the server's own
/// certificate first, against the system's trusted roots and today's date,
/// and that the first is for host. An empty host checks the chain alone.
public func VerifyChain(_ chain: [[uint8]], host: string) throws {
    if chain.isEmpty {
        throw CertError.invalid("no certificates")
    }
    var ders: [uint8] = []
    var lengths: [int64] = []
    for der in chain {
        ders.append(contentsOf: der)
        lengths.append(int64(der.count))
    }
    let code = ders.withUnsafeBufferPointer { d in
        lengths.withUnsafeBufferPointer { l in
            certVerifyChain(d.baseAddress, l.baseAddress, int32(chain.count), host)
        }
    }
    try check(code)
}

/// VerifySignature checks signature over data with the public key of
/// certificate, a DER certificate, by TLS signature scheme (see Scheme).
public func VerifySignature(certificate: [uint8], scheme: uint16, data: [uint8], signature: [uint8]) throws {
    let code = certificate.withUnsafeBufferPointer { c in
        data.withUnsafeBufferPointer { d in
            signature.withUnsafeBufferPointer { s in
                certVerifySignature(c.baseAddress, int64(c.count), int32(scheme),
                                    d.baseAddress, int64(d.count), s.baseAddress, int64(s.count))
            }
        }
    }
    try check(code)
}

// check turns a result into its error, with the system's message.
func check(_ code: int32) throws {
    if code == Code.ok {
        return
    }
    var buf = [uint8](repeating: 0, count: 512)
    let n = buf.withUnsafeMutableBufferPointer { b in certLastError(b.baseAddress, int64(b.count)) }
    let why = string(decoding: buf[0..<int(n)], as: UTF8.self)
    switch code {
    case Code.nameMismatch: throw CertError.nameMismatch(why)
    case Code.expired: throw CertError.expired(why)
    case Code.badSignature: throw CertError.badSignature(why)
    case Code.unsupported: throw CertError.unsupported(why)
    case Code.invalid: throw CertError.invalid(why)
    default: throw CertError.untrusted(why)
    }
}
