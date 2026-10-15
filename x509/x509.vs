// Package x509 parses X.509 certificates (RFC 5280) and verifies chains
// of them to a pool of trusted roots, for a TLS client and RDP: RSA and
// ECDSA (P-256, P-384, P-521) keys and signatures, the validity window,
// the names, and the extensions a path validator needs -- basic
// constraints, key usage, extended key usage and name constraints.
//
// Parse records what a certificate says and refuses only what does not
// parse; Verify (verify.vs) is where a certificate is judged.
package x509

import (
    "crypto/ecdsa"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
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
let oidMGF1: [uint64] = [1,2,840,113549,1,1,8]
let oidSHA256: [uint64] = [2,16,840,1,101,3,4,2,1]
let oidSHA384: [uint64] = [2,16,840,1,101,3,4,2,2]
let oidSHA512: [uint64] = [2,16,840,1,101,3,4,2,3]
let oidECPublicKey: [uint64] = [1,2,840,10045,2,1]
let oidECDSASHA256: [uint64] = [1,2,840,10045,4,3,2]
let oidECDSASHA384: [uint64] = [1,2,840,10045,4,3,3]
let oidECDSASHA512: [uint64] = [1,2,840,10045,4,3,4]
let oidP256: [uint64] = [1,2,840,10045,3,1,7]
let oidP384: [uint64] = [1,3,132,0,34]
let oidP521: [uint64] = [1,3,132,0,35]
let oidCommonName: [uint64] = [2,5,4,3]
let oidSubjectKeyId: [uint64] = [2,5,29,14]
let oidKeyUsage: [uint64] = [2,5,29,15]
let oidSubjectAltName: [uint64] = [2,5,29,17]
let oidBasicConstraints: [uint64] = [2,5,29,19]
let oidNameConstraints: [uint64] = [2,5,29,30]
let oidCRLDistributionPoints: [uint64] = [2,5,29,31]
let oidCertificatePolicies: [uint64] = [2,5,29,32]
let oidAuthorityKeyId: [uint64] = [2,5,29,35]
let oidExtKeyUsage: [uint64] = [2,5,29,37]
let oidAuthorityInfoAccess: [uint64] = [1,3,6,1,5,5,7,1,1]

/// The extended key usages Verify looks for.
public let OIDServerAuth: [uint64] = [1,3,6,1,5,5,7,3,1]
public let OIDAnyExtendedKeyUsage: [uint64] = [2,5,29,37,0]

/// The key usage bits (RFC 5280 §4.2.1.3), as Certificate.KeyUsage holds
/// them.
public let KeyUsageDigitalSignature: int = 1 << 0
public let KeyUsageKeyEncipherment: int = 1 << 2
public let KeyUsageCertSign: int = 1 << 5

/// SignatureAlgorithm identifies how a certificate was signed.
public enum SignatureAlgorithm {
    case sha1RSA
    case sha256RSA
    case sha384RSA
    case sha512RSA
    case rsaPSS
    case ecdsaSHA256
    case ecdsaSHA384
    case ecdsaSHA512
    case unknown
}

func hashFor(_ a: SignatureAlgorithm) -> rsa.Hash {
    switch a {
    case .sha1RSA: return .sha1
    case .sha256RSA: return .sha256
    case .sha384RSA: return .sha384
    case .sha512RSA: return .sha512
    case .rsaPSS: return .sha256
    case .ecdsaSHA256: return .sha256
    case .ecdsaSHA384: return .sha384
    case .ecdsaSHA512: return .sha512
    case .unknown: return .sha256
    }
}

/// Certificate holds the parsed fields a TLS/RDP client uses.
public struct Certificate {
    /// The whole certificate, DER.
    public var Raw: [uint8] = []
    /// The exact DER bytes of tbsCertificate, over which the signature is
    /// computed.
    public var RawTBS: [uint8] = []
    public var Version: int = 1
    public var SignatureAlgorithm: SignatureAlgorithm = .unknown
    public var Signature: [uint8] = []
    /// For rsaPSS: the hash its parameters name, and whether they are the
    /// profile Verify accepts (MGF1 with the same hash, a salt as long as
    /// the hash).
    public var PSSHash: rsa.Hash = .sha256
    public var PSSSupported: bool = false
    /// Whether the signature algorithm inside tbsCertificate is the one
    /// outside it, as RFC 5280 §4.1.1.2 requires.
    public var SignatureAlgorithmsMatch: bool = false

    public var RSAPublicKey: rsa.PublicKey = rsa.PublicKey(nBytes: [0], eBytes: [1])
    /// The DER contents of the subjectPublicKey BIT STRING (the encoded
    /// RSAPublicKey). CredSSP's public-key binding hashes exactly these
    /// bytes ([MS-CSSP] 3.1.5).
    public var RawSubjectPublicKey: [uint8] = []
    /// The whole subjectPublicKeyInfo TLV.
    public var RawSubjectPublicKeyInfo: [uint8] = []
    public var IsRSA: bool = false
    /// An ECDSA key on a curve this package knows, checked to be on it.
    public var ECPublicKey: ecdsa.PublicKey? = nil

    /// The common names of the subject and the issuer, for messages.
    public var Subject: string = ""
    public var Issuer: string = ""
    /// The subject and issuer Names, DER, as a chain is linked by.
    public var RawSubject: [uint8] = []
    public var RawIssuer: [uint8] = []
    public var DNSNames: [string] = []
    /// IP address subject alternative names, 4 or 16 bytes each.
    public var IPAddresses: [[uint8]] = []
    public var NotBefore: string = ""
    public var NotAfter: string = ""
    /// The validity window in seconds since 1970, UTC.
    public var NotBeforeUnix: int64 = 0
    public var NotAfterUnix: int64 = 0

    public var BasicConstraintsValid: bool = false
    public var IsCA: bool = false
    /// The basic constraints' pathLenConstraint; -1 when there is none.
    public var MaxPathLen: int = -1
    public var HasKeyUsage: bool = false
    /// keyUsage's bits, bit i for the standard's bit i (KeyUsageCertSign
    /// and the rest).
    public var KeyUsage: int = 0
    public var ExtKeyUsage: [[uint64]] = []
    public var HasExtKeyUsage: bool = false

    public var PermittedDNSDomains: [string] = []
    public var ExcludedDNSDomains: [string] = []
    /// IP name constraints: an address and its mask, 8 or 32 bytes.
    public var PermittedIPRanges: [[uint8]] = []
    public var ExcludedIPRanges: [[uint8]] = []
    /// Name constraints of a kind Verify does not evaluate (e-mail, URI,
    /// directory name), which make it refuse the certificate as a CA.
    public var HasUnsupportedNameConstraints: bool = false
    /// A critical extension this package does not understand, or one that
    /// appears twice: Verify refuses such a certificate.
    public var UnhandledCriticalExtension: bool = false

    public init() {}
}

/// Parse reads one DER-encoded certificate.
public func Parse(_ der: [uint8]) throws -> Certificate {
    var cert = Certificate()
    cert.Raw = der
    do {
        var top = asn1.Reader(der)
        var certSeq = try top.Sequence()
        if !top.AtEnd {
            throw X509Error.parse("trailing data after the certificate")
        }

        // tbsCertificate: capture its raw bytes, then parse a copy.
        cert.RawTBS = try certSeq.Raw()
        var tbs = asn1.Reader(cert.RawTBS)
        var tbsSeq = try tbs.Sequence()

        // [0] version (optional, EXPLICIT).
        if var v = try tbsSeq.OptionalContext(0) {
            let n = try v.Integer()
            if n < 0 || n > 2 {
                throw X509Error.parse("version \(n + 1)")
            }
            cert.Version = int(n) + 1
        }
        // serialNumber INTEGER
        let _ = try tbsSeq.BigInteger()
        // signature AlgorithmIdentifier, which must be the outer one.
        let innerAlg = try tbsSeq.Raw()
        // issuer Name
        cert.RawIssuer = try tbsSeq.Raw()
        cert.Issuer = try commonNameOf(cert.RawIssuer)
        // validity SEQUENCE { notBefore, notAfter }
        var validity = try tbsSeq.Sequence()
        let before = try parseTime(&validity)
        let after = try parseTime(&validity)
        cert.NotBefore = before.text
        cert.NotBeforeUnix = before.unix
        cert.NotAfter = after.text
        cert.NotAfterUnix = after.unix
        // subject Name
        cert.RawSubject = try tbsSeq.Raw()
        cert.Subject = try commonNameOf(cert.RawSubject)
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
        } else if asn1.OIDEqual(pkOID, oidECPublicKey) && !pkAlg.AtEnd
                  && (try pkAlg.PeekTag()) == asn1.Tag.ObjectIdentifier {
            let curveOID = try pkAlg.ObjectIdentifier()
            if let curve = curveOf(curveOID) {
                do {
                    cert.ECPublicKey = try ecdsa.ParsePublicKey(curve: curve, point: spk)
                } catch {
                    cert.ECPublicKey = nil
                }
            }
        }
        // [1] issuerUniqueID and [2] subjectUniqueID, then [3] extensions.
        while !tbsSeq.AtEnd {
            let tag = try tbsSeq.PeekTag()
            if tag == (asn1.Class.ContextSpecific | 0x20 | 3) {
                var extsWrap = try tbsSeq.TaggedContext(3)
                var exts = try extsWrap.Sequence()
                try parseExtensions(&exts, &cert)
            } else {
                try tbsSeq.Skip()
            }
        }

        // signatureAlgorithm
        let outerAlg = try certSeq.Raw()
        cert.SignatureAlgorithmsMatch = bytesEqual(innerAlg, outerAlg)
        var sigAlgTop = asn1.Reader(outerAlg)
        var sigAlg = try sigAlgTop.Sequence()
        let sigOID = try sigAlg.ObjectIdentifier()
        cert.SignatureAlgorithm = sigAlgFromOID(sigOID)
        if cert.SignatureAlgorithm == .rsaPSS {
            parsePSSParams(&sigAlg, &cert)
        }
        // signatureValue BIT STRING
        cert.Signature = try certSeq.BitString()
        if !certSeq.AtEnd {
            throw X509Error.parse("trailing data in the certificate")
        }
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
        case .sha1RSA, .sha256RSA, .sha384RSA, .sha512RSA:
            try rsa.VerifyPKCS1v15(key: issuerKey, hash: hashFor(cert.SignatureAlgorithm),
                                   data: cert.RawTBS, signature: cert.Signature)
        default:
            throw X509Error.unsupported("signature algorithm")
        }
    } catch let e as rsa.RsaError {
        throw X509Error.parse(e.Message)
    }
}

/// CheckSignatureFrom checks that parent's key signed cert, by an
/// algorithm fit for the web today: RSA (PKCS#1 v1.5 or PSS, a key of
/// 2048 bits at least) or ECDSA, with SHA-256, -384 or -512. SHA-1 and
/// anything else are refused.
public func CheckSignatureFrom(_ cert: Certificate, _ parent: Certificate) throws {
    if !cert.SignatureAlgorithmsMatch {
        throw X509Error.parse("the signature algorithms inside and outside the certificate differ")
    }
    switch cert.SignatureAlgorithm {
    case .sha256RSA, .sha384RSA, .sha512RSA, .rsaPSS:
        if !parent.IsRSA {
            throw X509Error.unsupported("an RSA signature from an issuer whose key is not RSA")
        }
        if let why = WeakRSAKey(parent.RSAPublicKey) {
            throw X509Error.unsupported("the issuer's \(why)")
        }
        do {
            if cert.SignatureAlgorithm == .rsaPSS {
                if !cert.PSSSupported {
                    throw X509Error.unsupported("RSA-PSS parameters")
                }
                try rsa.VerifyPSS(key: parent.RSAPublicKey, hash: cert.PSSHash, data: cert.RawTBS,
                                  signature: cert.Signature)
            } else {
                try rsa.VerifyPKCS1v15(key: parent.RSAPublicKey, hash: hashFor(cert.SignatureAlgorithm),
                                       data: cert.RawTBS, signature: cert.Signature)
            }
        } catch let e as rsa.RsaError {
            throw X509Error.parse(e.Message)
        }
    case .ecdsaSHA256, .ecdsaSHA384, .ecdsaSHA512:
        guard let key = parent.ECPublicKey else {
            throw X509Error.unsupported("an ECDSA signature from an issuer without an ECDSA key this package reads")
        }
        do {
            try ecdsa.Verify(key: key, digest: digest(hashFor(cert.SignatureAlgorithm), cert.RawTBS),
                             signature: cert.Signature)
        } catch let e as ecdsa.EcdsaError {
            throw X509Error.parse(e.Message)
        }
    case .sha1RSA:
        throw X509Error.unsupported("a SHA-1 signature")
    default:
        throw X509Error.unsupported("the signature algorithm")
    }
}

/// FingerprintSHA256 is the SHA-256 of the whole certificate DER, for
/// pinning and trust-on-first-use display.
public func FingerprintSHA256(_ der: [uint8]) -> [uint8] {
    return sha256.Sum256(der)
}

/// WeakRSAKey says what is wrong with an RSA key no signature should be
/// accepted under -- a modulus under 2048 bits, or an exponent that is
/// even or 1 -- or nil for a sound one.
public func WeakRSAKey(_ key: rsa.PublicKey) -> string? {
    if key.N.BitLen < 2048 {
        return "RSA key of \(key.N.BitLen) bits"
    }
    let e = key.E.ToBytes()
    if key.E.BitLen < 2 || (e[e.count - 1] & 1) == 0 {
        return "RSA key's public exponent"
    }
    return nil
}

// --- helpers ---

func digest(_ h: rsa.Hash, _ data: [uint8]) -> [uint8] {
    switch h {
    case .sha1: return sha1.Sum1(data)
    case .sha256: return sha256.Sum256(data)
    case .sha384: return sha512.Sum384(data)
    case .sha512: return sha512.Sum512(data)
    }
}

func bytesEqual(_ a: [uint8], _ b: [uint8]) -> bool {
    if a.count != b.count {
        return false
    }
    var i = 0
    while i < a.count {
        if a[i] != b[i] {
            return false
        }
        i += 1
    }
    return true
}

func curveOf(_ oid: [uint64]) -> ecdsa.Curve? {
    if asn1.OIDEqual(oid, oidP256) { return .p256 }
    if asn1.OIDEqual(oid, oidP384) { return .p384 }
    if asn1.OIDEqual(oid, oidP521) { return .p521 }
    return nil
}

func sigAlgFromOID(_ oid: [uint64]) -> SignatureAlgorithm {
    if asn1.OIDEqual(oid, oidSHA256RSA) { return .sha256RSA }
    if asn1.OIDEqual(oid, oidSHA384RSA) { return .sha384RSA }
    if asn1.OIDEqual(oid, oidSHA512RSA) { return .sha512RSA }
    if asn1.OIDEqual(oid, oidSHA1RSA) { return .sha1RSA }
    if asn1.OIDEqual(oid, oidRSAPSS) { return .rsaPSS }
    if asn1.OIDEqual(oid, oidECDSASHA256) { return .ecdsaSHA256 }
    if asn1.OIDEqual(oid, oidECDSASHA384) { return .ecdsaSHA384 }
    if asn1.OIDEqual(oid, oidECDSASHA512) { return .ecdsaSHA512 }
    return .unknown
}

func hashOfOID(_ oid: [uint64]) -> rsa.Hash? {
    if asn1.OIDEqual(oid, oidSHA256) { return .sha256 }
    if asn1.OIDEqual(oid, oidSHA384) { return .sha384 }
    if asn1.OIDEqual(oid, oidSHA512) { return .sha512 }
    return nil
}

func hashLength(_ h: rsa.Hash) -> int64 {
    switch h {
    case .sha1: return 20
    case .sha256: return 32
    case .sha384: return 48
    case .sha512: return 64
    }
}

// parsePSSParams reads RSASSA-PSS-params (RFC 4055 §3.1) after the OID.
// Only SHA-256/384/512, MGF1 with the same hash and a salt of the hash's
// length are marked supported; the defaults (SHA-1) are not.
func parsePSSParams(_ alg: inout asn1.Reader, _ cert: inout Certificate) {
    cert.PSSSupported = false
    do {
        var params = try alg.Sequence()
        guard var hashWrap = try params.OptionalContext(0) else {
            return
        }
        var hashAlg = try hashWrap.Sequence()
        guard let h = hashOfOID(try hashAlg.ObjectIdentifier()) else {
            return
        }
        guard var mgfWrap = try params.OptionalContext(1) else {
            return
        }
        var mgf = try mgfWrap.Sequence()
        if !asn1.OIDEqual(try mgf.ObjectIdentifier(), oidMGF1) {
            return
        }
        var mgfHash = try mgf.Sequence()
        guard let mh = hashOfOID(try mgfHash.ObjectIdentifier()) else {
            return
        }
        if mh != h {
            return
        }
        guard var saltWrap = try params.OptionalContext(2) else {
            return
        }
        if try saltWrap.Integer() != hashLength(h) {
            return
        }
        if var trailer = try params.OptionalContext(3) {
            if try trailer.Integer() != 1 {
                return
            }
        }
        if !params.AtEnd {
            return
        }
        cert.PSSHash = h
        cert.PSSSupported = true
    } catch {
        cert.PSSSupported = false
    }
}

// parseExtensions reads the extensions SEQUENCE into cert, marking a
// critical one it does not know, or any that appears twice.
func parseExtensions(_ exts: inout asn1.Reader, _ cert: inout Certificate) throws {
    var seen: [[uint64]] = []
    while !exts.AtEnd {
        var ext = try exts.Sequence()
        let extOID = try ext.ObjectIdentifier()
        var critical = false
        if (try ext.PeekTag()) == asn1.Tag.Boolean {
            critical = try ext.Boolean()
        }
        let value = try ext.OctetString()
        for s in seen {
            if asn1.OIDEqual(s, extOID) {
                cert.UnhandledCriticalExtension = true
            }
        }
        seen.append(extOID)
        if asn1.OIDEqual(extOID, oidSubjectAltName) {
            try parseSAN(value, &cert)
        } else if asn1.OIDEqual(extOID, oidBasicConstraints) {
            var r = asn1.Reader(value)
            var bc = try r.Sequence()
            cert.BasicConstraintsValid = true
            if !bc.AtEnd && (try bc.PeekTag()) == asn1.Tag.Boolean {
                cert.IsCA = try bc.Boolean()
            }
            if !bc.AtEnd && (try bc.PeekTag()) == asn1.Tag.Integer {
                let n = try bc.Integer()
                if n < 0 || n > 1 << 20 {
                    throw X509Error.parse("pathLenConstraint \(n)")
                }
                cert.MaxPathLen = int(n)
            }
        } else if asn1.OIDEqual(extOID, oidKeyUsage) {
            var r = asn1.Reader(value)
            var bits = try r.Expect(asn1.Tag.BitString)
            let b = bits.RawContents()
            if b.count < 1 || b[0] > 7 {
                throw X509Error.parse("keyUsage")
            }
            var usage = 0
            var i = 1
            while i < b.count && i <= 2 {
                var bit = 0
                while bit < 8 {
                    if (b[i] >> uint8(7 - bit)) & 1 == 1 {
                        usage |= 1 << ((i - 1) * 8 + bit)
                    }
                    bit += 1
                }
                i += 1
            }
            cert.HasKeyUsage = true
            cert.KeyUsage = usage
        } else if asn1.OIDEqual(extOID, oidExtKeyUsage) {
            var r = asn1.Reader(value)
            var list = try r.Sequence()
            cert.HasExtKeyUsage = true
            while !list.AtEnd {
                cert.ExtKeyUsage.append(try list.ObjectIdentifier())
            }
        } else if asn1.OIDEqual(extOID, oidNameConstraints) {
            try parseNameConstraints(value, &cert)
        } else if asn1.OIDEqual(extOID, oidSubjectKeyId) || asn1.OIDEqual(extOID, oidAuthorityKeyId)
                  || asn1.OIDEqual(extOID, oidCRLDistributionPoints) || asn1.OIDEqual(extOID, oidCertificatePolicies)
                  || asn1.OIDEqual(extOID, oidAuthorityInfoAccess) {
            // Known, and nothing Verify needs.
        } else if critical {
            cert.UnhandledCriticalExtension = true
        }
    }
}

// commonNameOf walks a Name (RDNSequence), DER, and returns the common name.
func commonNameOf(_ raw: [uint8]) throws -> string {
    var r = asn1.Reader(raw)
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

func digits(_ b: [uint8], _ at: int, _ n: int) throws -> int64 {
    var v: int64 = 0
    var i = 0
    while i < n {
        let c = b[at + i]
        if c < 0x30 || c > 0x39 {
            throw X509Error.parse("a time with a non-digit")
        }
        v = v * 10 + int64(c - 0x30)
        i += 1
    }
    return v
}

// daysFromCivil is the number of days from 1970-01-01 to y-m-d in the
// proleptic Gregorian calendar.
func daysFromCivil(_ year: int64, _ month: int64, _ day: int64) -> int64 {
    let y = month <= 2 ? year - 1 : year
    let era = (y >= 0 ? y : y - 399) / 400
    let yoe = y - era * 400
    let mp = month > 2 ? month - 3 : month + 9
    let doy = (153 * mp + 2) / 5 + day - 1
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    return era * 146097 + doe - 719468
}

// parseTime reads a UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime
// (YYYYMMDDHHMMSSZ), the only forms RFC 5280 §4.1.2.5 allows.
func parseTime(_ r: inout asn1.Reader) throws -> (text: string, unix: int64) {
    let tag = try r.PeekTag()
    var body = try r.Expect(tag)
    let b = body.RawContents()
    let text = string(decoding: b, as: UTF8.self)
    var year: int64 = 0
    var at = 0
    if tag == asn1.Tag.UTCTime && b.count == 13 {
        year = try digits(b, 0, 2)
        year += year < 50 ? 2000 : 1900
        at = 2
    } else if tag == asn1.Tag.GeneralizedTime && b.count == 15 {
        year = try digits(b, 0, 4)
        at = 4
    } else {
        throw X509Error.parse("a validity time that is not UTCTime or GeneralizedTime in Z form: \(text)")
    }
    if b[b.count - 1] != 0x5a {
        throw X509Error.parse("a validity time not in UTC: \(text)")
    }
    let month = try digits(b, at, 2)
    let day = try digits(b, at + 2, 2)
    let hour = try digits(b, at + 4, 2)
    let minute = try digits(b, at + 6, 2)
    let second = try digits(b, at + 8, 2)
    if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        throw X509Error.parse("a validity time out of range: \(text)")
    }
    let unix = daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
    return (text, unix)
}

// parseSAN reads subjectAltName's GeneralNames: dNSName ([2] IA5String)
// and iPAddress ([7] OCTET STRING); the other kinds are skipped.
func parseSAN(_ der: [uint8], _ cert: inout Certificate) throws {
    var r = asn1.Reader(der)
    var seq = try r.Sequence()
    while !seq.AtEnd {
        let tag = try seq.PeekTag()
        var val = try seq.Expect(tag)
        if tag == (asn1.Class.ContextSpecific | 2) {
            cert.DNSNames.append(string(decoding: val.RawContents(), as: UTF8.self))
        } else if tag == (asn1.Class.ContextSpecific | 7) {
            let ip = val.RawContents()
            if ip.count != 4 && ip.count != 16 {
                throw X509Error.parse("an IP address name of \(ip.count) bytes")
            }
            cert.IPAddresses.append(ip)
        }
    }
}

// parseNameConstraints reads NameConstraints (RFC 5280 §4.2.1.10): the
// dNSName and iPAddress subtrees, and a mark for any other kind.
func parseNameConstraints(_ der: [uint8], _ cert: inout Certificate) throws {
    var r = asn1.Reader(der)
    var nc = try r.Sequence()
    while !nc.AtEnd {
        let tag = try nc.PeekTag()
        var subtrees = try nc.Expect(tag)
        let permitted = tag == (asn1.Class.ContextSpecific | 0x20 | 0)
        if !permitted && tag != (asn1.Class.ContextSpecific | 0x20 | 1) {
            throw X509Error.parse("name constraints")
        }
        while !subtrees.AtEnd {
            var subtree = try subtrees.Sequence()
            let baseTag = try subtree.PeekTag()
            var base = try subtree.Expect(baseTag)
            if !subtree.AtEnd {
                // minimum and maximum, which RFC 5280 says are 0 and absent.
                cert.HasUnsupportedNameConstraints = true
            }
            if baseTag == (asn1.Class.ContextSpecific | 2) {
                let name = string(decoding: base.RawContents(), as: UTF8.self)
                if permitted {
                    cert.PermittedDNSDomains.append(name)
                } else {
                    cert.ExcludedDNSDomains.append(name)
                }
            } else if baseTag == (asn1.Class.ContextSpecific | 7) {
                let range = base.RawContents()
                if range.count != 8 && range.count != 32 {
                    throw X509Error.parse("an IP name constraint of \(range.count) bytes")
                }
                if permitted {
                    cert.PermittedIPRanges.append(range)
                } else {
                    cert.ExcludedIPRanges.append(range)
                }
            } else {
                cert.HasUnsupportedNameConstraints = true
            }
        }
    }
}
