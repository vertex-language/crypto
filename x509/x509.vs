// Package x509 parses X.509 certificates (RFC 5280) far enough for a TLS
// client and RDP: the RSA public key, the validity window, the subject
// common name and DNS SANs, and the pieces needed to verify the
// certificate's signature. It is not a full path validator yet.
package x509

import (
    "crypto/rsa"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/asn1"
)

public enum X509Error: Error {
    case parse(string)
    case unsupported(string)

    public var Message: string {
        switch self {
        case .parse(let s): return "x509: parse error: \(s)"
        case .unsupported(let s): return "x509: unsupported: \(s)"
        }
    }
}

// OIDs we recognize.
let oidRSAEncryption: [uint64] = [1,2,840,113549,1,1,1]
let oidSHA256RSA: [uint64] = [1,2,840,113549,1,1,11]
let oidSHA384RSA: [uint64] = [1,2,840,113549,1,1,12]
let oidSHA512RSA: [uint64] = [1,2,840,113549,1,1,13]
let oidSHA1RSA: [uint64] = [1,2,840,113549,1,1,5]
let oidRSAPSS: [uint64] = [1,2,840,113549,1,1,10]
let oidCommonName: [uint64] = [2,5,4,3]
let oidSubjectAltName: [uint64] = [2,5,29,17]

/// SignatureAlgorithm identifies how a certificate was signed.
public enum SignatureAlgorithm {
    case sha1RSA
    case sha256RSA
    case sha384RSA
    case sha512RSA
    case rsaPSS
    case unknown
}

func hashFor(_ a: SignatureAlgorithm) -> rsa.Hash {
    switch a {
    case .sha1RSA: return .sha1
    case .sha256RSA: return .sha256
    case .sha384RSA: return .sha384
    case .sha512RSA: return .sha512
    case .rsaPSS: return .sha256
    case .unknown: return .sha256
    }
}

/// Certificate holds the parsed fields a TLS/RDP client uses.
public struct Certificate {
    /// The exact DER bytes of tbsCertificate, over which the signature is
    /// computed.
    public var RawTBS: [uint8] = []
    public var SignatureAlgorithm: SignatureAlgorithm = .unknown
    public var Signature: [uint8] = []

    public var RSAPublicKey: rsa.PublicKey = rsa.PublicKey(nBytes: [0], eBytes: [1])
    /// The DER contents of the subjectPublicKey BIT STRING (the encoded
    /// RSAPublicKey). CredSSP's public-key binding hashes exactly these
    /// bytes ([MS-CSSP] 3.1.5).
    public var RawSubjectPublicKey: [uint8] = []
    /// The whole subjectPublicKeyInfo TLV.
    public var RawSubjectPublicKeyInfo: [uint8] = []

    public var Subject: string = ""
    public var Issuer: string = ""
    public var DNSNames: [string] = []
    public var NotBefore: string = ""
    public var NotAfter: string = ""
    public var IsRSA: bool = false

    public init() {}
}

/// Parse reads one DER-encoded certificate.
public func Parse(_ der: [uint8]) throws -> Certificate {
    var cert = Certificate()
    do {
        var top = asn1.Reader(der)
        var certSeq = try top.Sequence()

        // tbsCertificate: capture its raw bytes, then parse a copy.
        cert.RawTBS = try certSeq.Raw()
        var tbs = asn1.Reader(cert.RawTBS)
        var tbsSeq = try tbs.Sequence()

        // [0] version (optional, EXPLICIT). Skip if present.
        if let _ = try tbsSeq.OptionalContext(0) {
            // consumed
        }
        // serialNumber INTEGER
        let _ = try tbsSeq.BigInteger()
        // signature AlgorithmIdentifier (inner) -- skip
        var innerAlg = try tbsSeq.Sequence()
        let _ = try innerAlg.ObjectIdentifier()
        // issuer Name
        cert.Issuer = try parseName(&tbsSeq)
        // validity SEQUENCE { notBefore, notAfter }
        var validity = try tbsSeq.Sequence()
        cert.NotBefore = try parseTime(&validity)
        cert.NotAfter = try parseTime(&validity)
        // subject Name
        cert.Subject = try parseName(&tbsSeq)
        // subjectPublicKeyInfo: capture its raw TLV, then parse a copy.
        cert.RawSubjectPublicKeyInfo = try tbsSeq.Raw()
        var spkiTop = asn1.Reader(cert.RawSubjectPublicKeyInfo)
        var spki = try spkiTop.Sequence()
        var pkAlg = try spki.Sequence()
        let pkOID = try pkAlg.ObjectIdentifier()
        let spk = try spki.BitString()
        cert.RawSubjectPublicKey = spk
        if asn1.OIDEqual(pkOID, oidRSAEncryption) {
            cert.IsRSA = true
            var rk = asn1.Reader(spk)
            var rsaSeq = try rk.Sequence()
            let modulus = try rsaSeq.BigInteger()
            let exponent = try rsaSeq.BigInteger()
            cert.RSAPublicKey = rsa.PublicKey(nBytes: modulus, eBytes: exponent)
        }
        // Optional [3] extensions -- look for subjectAltName.
        while !tbsSeq.AtEnd {
            let tag = try tbsSeq.PeekTag()
            if tag == (asn1.Class.ContextSpecific | 0x20 | 3) {
                var extsWrap = try tbsSeq.TaggedContext(3)
                var exts = try extsWrap.Sequence()
                while !exts.AtEnd {
                    var ext = try exts.Sequence()
                    let extOID = try ext.ObjectIdentifier()
                    // optional critical BOOLEAN
                    if (try ext.PeekTag()) == asn1.Tag.Boolean {
                        let _ = try ext.Boolean()
                    }
                    let extValue = try ext.OctetString()
                    if asn1.OIDEqual(extOID, oidSubjectAltName) {
                        cert.DNSNames = try parseSAN(extValue)
                    }
                }
            } else {
                try tbsSeq.Skip()
            }
        }

        // signatureAlgorithm
        var sigAlg = try certSeq.Sequence()
        let sigOID = try sigAlg.ObjectIdentifier()
        cert.SignatureAlgorithm = sigAlgFromOID(sigOID)
        // signatureValue BIT STRING
        cert.Signature = try certSeq.BitString()
    } catch let e as X509Error {
        throw e
    } catch let e as asn1.Asn1Error {
        throw X509Error.parse(e.Message)
    }
    return cert
}

/// VerifySignedBy checks this certificate's signature against an issuer's
/// RSA public key. For a self-signed certificate the issuer is itself.
public func VerifySignedBy(_ cert: Certificate, _ issuerKey: rsa.PublicKey) throws {
    do {
        switch cert.SignatureAlgorithm {
        case .rsaPSS:
            try rsa.VerifyPSS(key: issuerKey, hash: .sha256, data: cert.RawTBS, signature: cert.Signature)
        case .unknown:
            throw X509Error.unsupported("signature algorithm")
        default:
            try rsa.VerifyPKCS1v15(key: issuerKey, hash: hashFor(cert.SignatureAlgorithm),
                                   data: cert.RawTBS, signature: cert.Signature)
        }
    } catch let e as rsa.RsaError {
        throw X509Error.parse(e.Message)
    }
}

/// FingerprintSHA256 is the SHA-256 of the whole certificate DER, for
/// pinning and trust-on-first-use display.
public func FingerprintSHA256(_ der: [uint8]) -> [uint8] {
    return sha256.Sum256(der)
}

// --- helpers ---

func sigAlgFromOID(_ oid: [uint64]) -> SignatureAlgorithm {
    if asn1.OIDEqual(oid, oidSHA256RSA) { return .sha256RSA }
    if asn1.OIDEqual(oid, oidSHA384RSA) { return .sha384RSA }
    if asn1.OIDEqual(oid, oidSHA512RSA) { return .sha512RSA }
    if asn1.OIDEqual(oid, oidSHA1RSA) { return .sha1RSA }
    if asn1.OIDEqual(oid, oidRSAPSS) { return .rsaPSS }
    return .unknown
}

// parseName walks a Name (RDNSequence) and returns the common name.
func parseName(_ r: inout asn1.Reader) throws -> string {
    var name = try r.Sequence()
    var cn = ""
    while !name.AtEnd {
        var rdn = try name.Set()
        while !rdn.AtEnd {
            var atv = try rdn.Sequence()
            let oid = try atv.ObjectIdentifier()
            let value = try readDirectoryString(&atv)
            if asn1.OIDEqual(oid, oidCommonName) {
                cn = value
            }
        }
    }
    return cn
}

func readDirectoryString(_ r: inout asn1.Reader) throws -> string {
    let tag = try r.PeekTag()
    var body = try r.Expect(tag)
    let bytes = body.RawContents()
    return string(decoding: bytes, as: UTF8.self)
}

func parseTime(_ r: inout asn1.Reader) throws -> string {
    let tag = try r.PeekTag()
    var body = try r.Expect(tag)
    let bytes = body.RawContents()
    return string(decoding: bytes, as: UTF8.self)
}

func parseSAN(_ der: [uint8]) throws -> [string] {
    var names: [string] = []
    var r = asn1.Reader(der)
    var seq = try r.Sequence()
    while !seq.AtEnd {
        let tag = try seq.PeekTag()
        // dNSName is [2] IMPLICIT IA5String (context tag 0x82).
        var val = try seq.Expect(tag)
        if tag == (asn1.Class.ContextSpecific | 2) {
            names.append(string(decoding: val.RawContents(), as: UTF8.self))
        }
    }
    return names
}
