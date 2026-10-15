package x509

import "encoding/asn1"

// Chain verification, as RFC 5280 §6 and the CA/Browser Forum's baseline
// describe it for a TLS server, and as Go's crypto/x509 does it: build
// paths from the server's certificate through the intermediates it sent
// to a root in the pool, each link's signature checked; then judge a path
// by its certificates' constraints and dates, and the server's
// certificate by the host name. Anything not understood is refused.

/// CertPool is a set of trusted root certificates.
public struct CertPool {
    var certs: [Certificate] = []

    public init() {}

    public mutating func Add(_ c: Certificate) {
        certs.append(c)
    }

    public var Count: int { return certs.count }

    func contains(_ c: Certificate) -> bool {
        for r in certs {
            if bytesEqual(r.Raw, c.Raw) {
                return true
            }
        }
        return false
    }
}

/// VerifyOptions is what Verify checks a certificate against.
public struct VerifyOptions {
    /// The host name the certificate must be for; empty checks none. An
    /// IP address is matched against the certificate's IP address names.
    public var DNSName: string = ""
    public var Roots: CertPool
    /// Certificates that may link the leaf to a root: the rest of what
    /// the server sent.
    public var Intermediates: [Certificate] = []
    /// The time to check validity at, in seconds since 1970, UTC.
    public var CurrentTime: int64

    public init(roots: CertPool, currentTime: int64) {
        self.Roots = roots
        self.CurrentTime = currentTime
    }
}

public enum VerifyError: Error {
    /// No path leads from the certificate to a root in the pool.
    case unknownAuthority(string)
    /// The certificate is not for the host name asked for.
    case hostname(string)
    /// A certificate on the path is expired, or not valid yet.
    case expired(string)
    /// A path exists, but a certificate on it may not be used this way.
    case notAuthorized(string)

    public var Message: string {
        switch self {
        case .unknownAuthority(let s): return "x509: certificate signed by unknown authority: \(s)"
        case .hostname(let s): return "x509: \(s)"
        case .expired(let s): return "x509: certificate has expired or is not yet valid: \(s)"
        case .notAuthorized(let s): return "x509: \(s)"
        }
    }
}

// Bounds on the search, so a hostile chain cannot make it run long.
let maxChainLength = 10
let maxSignatureChecks = 100
let maxPaths = 16

/// Verify checks leaf against opts and returns the path it verified, leaf
/// first and the root last.
public func Verify(_ leaf: Certificate, _ opts: VerifyOptions) throws -> [Certificate] {
    var paths: [[Certificate]] = []
    var budget = maxSignatureChecks
    if opts.Roots.contains(leaf) {
        paths.append([leaf])
    } else {
        build([leaf], opts, &budget, &paths)
    }
    if paths.isEmpty {
        let issuer = leaf.Issuer.isEmpty ? "an issuer with no common name" : "\"\(leaf.Issuer)\""
        throw VerifyError.unknownAuthority("no path from \"\(leaf.Subject)\" to a trusted root (issued by \(issuer))")
    }
    var first: VerifyError? = nil
    for path in paths {
        do {
            try checkPath(path, opts)
            if !opts.DNSName.isEmpty {
                try VerifyHostname(leaf, opts.DNSName)
            }
            return path
        } catch let e as VerifyError {
            if first == nil {
                first = e
            }
        }
    }
    if let e = first {
        throw e
    }
    throw VerifyError.unknownAuthority("no path verified")
}

func inPath(_ path: [Certificate], _ c: Certificate) -> bool {
    for p in path {
        if bytesEqual(p.Raw, c.Raw) {
            return true
        }
    }
    return false
}

// build extends path, whose last certificate is not yet trusted, by every
// root and intermediate that signed it, appending each path that reaches
// a root to paths.
func build(_ path: [Certificate], _ opts: VerifyOptions, _ budget: inout int, _ paths: inout [[Certificate]]) {
    let cur = path[path.count - 1]
    if path.count >= maxChainLength {
        return
    }
    for root in opts.Roots.certs {
        if paths.count >= maxPaths || budget <= 0 {
            return
        }
        if !bytesEqual(root.RawSubject, cur.RawIssuer) || inPath(path, root) {
            continue
        }
        budget -= 1
        do {
            try CheckSignatureFrom(cur, root)
            var p = path
            p.append(root)
            paths.append(p)
        } catch {
            continue
        }
    }
    for inter in opts.Intermediates {
        if paths.count >= maxPaths || budget <= 0 {
            return
        }
        if !bytesEqual(inter.RawSubject, cur.RawIssuer) || inPath(path, inter) || opts.Roots.contains(inter) {
            continue
        }
        budget -= 1
        do {
            try CheckSignatureFrom(cur, inter)
        } catch {
            continue
        }
        var p = path
        p.append(inter)
        build(p, opts, &budget, &paths)
    }
}

func hasEKU(_ c: Certificate, _ oid: [uint64]) -> bool {
    for u in c.ExtKeyUsage {
        if asn1.OIDEqual(u, oid) {
            return true
        }
    }
    return false
}

func describe(_ c: Certificate) -> string {
    return c.Subject.isEmpty ? "a certificate with no common name" : "\"\(c.Subject)\""
}

// checkPath judges a path that links by signatures: each certificate's
// use, its constraints, and last its dates, so that a path refused only
// for its dates says so.
func checkPath(_ path: [Certificate], _ opts: VerifyOptions) throws {
    let leaf = path[0]
    var i = 0
    while i < path.count {
        let c = path[i]
        let isRoot = i == path.count - 1
        if c.UnhandledCriticalExtension {
            throw VerifyError.notAuthorized("\(describe(c)) has a critical extension that is not understood")
        }
        if c.HasExtKeyUsage && !hasEKU(c, OIDServerAuth) && !hasEKU(c, OIDAnyExtendedKeyUsage) {
            throw VerifyError.notAuthorized("\(describe(c)) is not for TLS server authentication")
        }
        if i == 0 {
            if c.HasKeyUsage && (c.KeyUsage & (KeyUsageDigitalSignature | KeyUsageKeyEncipherment)) == 0 {
                throw VerifyError.notAuthorized("\(describe(c))'s key usage does not allow a TLS server")
            }
        } else {
            // An issuer. A root from the pool may be a version 1
            // certificate with no basic constraints; anything else must
            // say it is a CA.
            if isRoot {
                if c.BasicConstraintsValid && !c.IsCA {
                    throw VerifyError.notAuthorized("\(describe(c)) is not a CA")
                }
            } else {
                if !c.BasicConstraintsValid || !c.IsCA {
                    throw VerifyError.notAuthorized("\(describe(c)) is not a CA")
                }
                if c.HasKeyUsage && (c.KeyUsage & KeyUsageCertSign) == 0 {
                    throw VerifyError.notAuthorized("\(describe(c))'s key usage does not allow signing certificates")
                }
            }
            if c.BasicConstraintsValid && c.MaxPathLen >= 0 && i - 1 > c.MaxPathLen {
                throw VerifyError.notAuthorized("\(describe(c)) allows \(c.MaxPathLen) intermediates below it, not \(i - 1)")
            }
            try checkNameConstraints(c, leaf, opts.DNSName)
        }
        i += 1
    }
    for c in path {
        if opts.CurrentTime < c.NotBeforeUnix {
            throw VerifyError.expired("\(describe(c)) is not valid before \(c.NotBefore)")
        }
        if opts.CurrentTime > c.NotAfterUnix {
            throw VerifyError.expired("\(describe(c)) expired at \(c.NotAfter)")
        }
    }
}

// --- names ---

func lower(_ s: string) -> [uint8] {
    var out: [uint8] = []
    for b in s.utf8 {
        if b >= 0x41 && b <= 0x5a {
            out.append(b + 0x20)
        } else {
            out.append(b)
        }
    }
    return out
}

// labels splits a lower-cased host name at its dots, a trailing dot
// dropped.
func labels(_ name: [uint8]) -> [[uint8]] {
    var n = name
    if n.count > 0 && n[n.count - 1] == 0x2e {
        n = Array(n[0..<(n.count - 1)])
    }
    var out: [[uint8]] = []
    var cur: [uint8] = []
    for b in n {
        if b == 0x2e {
            out.append(cur)
            cur = []
        } else {
            cur.append(b)
        }
    }
    out.append(cur)
    return out
}

// validLabel is a host name label: letters, digits, '-' and '_' (which
// real names carry), not empty.
func validLabel(_ l: [uint8]) -> bool {
    if l.isEmpty || l.count > 63 {
        return false
    }
    for b in l {
        let ok = (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b == 0x2d || b == 0x5f
        if !ok {
            return false
        }
    }
    return true
}

// matchHostname reports whether a certificate's DNS name matches host,
// both lower-cased: label by label, a "*" allowed only as the whole
// leftmost label of the pattern, matching exactly one label.
func matchHostname(_ pattern: [uint8], _ host: [uint8]) -> bool {
    let p = labels(pattern)
    let h = labels(host)
    if p.count != h.count || p.count < 2 {
        return false
    }
    var i = 0
    while i < p.count {
        if !validLabel(h[i]) {
            return false
        }
        if i == 0 && p[i].count == 1 && p[i][0] == 0x2a {
            i += 1
            continue
        }
        if !validLabel(p[i]) || !bytesEqual(p[i], h[i]) {
            return false
        }
        i += 1
    }
    return true
}

// parseIPv4 reads a dotted quad, strictly: four decimal parts of at most
// three digits, each no more than 255, no leading zeros.
func parseIPv4(_ s: [uint8]) -> [uint8]? {
    var out: [uint8] = []
    var v = 0
    var digits = 0
    var i = 0
    while i <= s.count {
        if i == s.count || s[i] == 0x2e {
            if digits == 0 || out.count == 4 {
                return nil
            }
            out.append(uint8(v))
            v = 0
            digits = 0
        } else if s[i] >= 0x30 && s[i] <= 0x39 {
            if digits > 0 && v == 0 {
                return nil
            }
            v = v * 10 + int(s[i] - 0x30)
            digits += 1
            if v > 255 {
                return nil
            }
        } else {
            return nil
        }
        i += 1
    }
    if out.count != 4 {
        return nil
    }
    return out
}

func hexValue(_ b: uint8) -> int {
    if b >= 0x30 && b <= 0x39 { return int(b - 0x30) }
    if b >= 0x61 && b <= 0x66 { return int(b - 0x61) + 10 }
    if b >= 0x41 && b <= 0x46 { return int(b - 0x41) + 10 }
    return -1
}

// parseIPv6 reads an IPv6 address in hex groups, with at most one "::"
// and an optional dotted-quad tail; brackets are taken off first.
func parseIPv6(_ text: [uint8]) -> [uint8]? {
    var s = text
    if s.count >= 2 && s[0] == 0x5b && s[s.count - 1] == 0x5d {
        s = Array(s[1..<(s.count - 1)])
    }
    var head: [uint8] = []
    var tail: [uint8] = []
    var gap = false
    var i = 0
    if s.count >= 2 && s[0] == 0x3a && s[1] == 0x3a {
        gap = true
        i = 2
    } else if s.count >= 1 && s[0] == 0x3a {
        return nil
    }
    while i < s.count {
        // A dotted quad ends the address.
        var j = i
        var dotted = false
        while j < s.count && s[j] != 0x3a {
            if s[j] == 0x2e {
                dotted = true
            }
            j += 1
        }
        if dotted {
            if j != s.count {
                return nil
            }
            guard let v4 = parseIPv4(Array(s[i..<j])) else {
                return nil
            }
            if gap { tail.append(contentsOf: v4) } else { head.append(contentsOf: v4) }
            i = j
            break
        }
        if j - i < 1 || j - i > 4 {
            return nil
        }
        var v = 0
        var k = i
        while k < j {
            let h = hexValue(s[k])
            if h < 0 {
                return nil
            }
            v = v * 16 + h
            k += 1
        }
        let group: [uint8] = [uint8(v >> 8), uint8(v & 0xff)]
        if gap { tail.append(contentsOf: group) } else { head.append(contentsOf: group) }
        i = j
        if i < s.count {
            // s[i] is ':'.
            if i + 1 < s.count && s[i + 1] == 0x3a {
                if gap {
                    return nil
                }
                gap = true
                i += 2
            } else {
                i += 1
                if i == s.count {
                    return nil
                }
            }
        }
    }
    let n = head.count + tail.count
    if gap {
        if n > 14 {
            return nil
        }
        var out = head
        out.append(contentsOf: [uint8](repeating: 0, count: 16 - n))
        out.append(contentsOf: tail)
        return out
    }
    if n != 16 {
        return nil
    }
    return head
}

// parseIP reads host as an IP address literal, or nil when it is a name.
func parseIP(_ host: [uint8]) -> [uint8]? {
    for b in host {
        if b == 0x3a {
            return parseIPv6(host)
        }
    }
    return parseIPv4(host)
}

/// VerifyHostname checks that c is for host: one of its DNS names matches
/// it, or for an IP address, one of its IP address names is it. The
/// common name is not looked at, as browsers have long stopped doing.
public func VerifyHostname(_ c: Certificate, _ host: string) throws {
    let h = lower(host)
    if let ip = parseIP(h) {
        for a in c.IPAddresses {
            if bytesEqual(a, ip) {
                return
            }
        }
        throw VerifyError.hostname("certificate is not valid for IP address \(host)")
    }
    for name in c.DNSNames {
        if matchHostname(lower(name), h) {
            return
        }
    }
    if c.DNSNames.isEmpty {
        throw VerifyError.hostname("certificate names no hosts (a common name alone is not used), not \(host)")
    }
    var names = ""
    for name in c.DNSNames {
        names += names.isEmpty ? name : ", " + name
    }
    throw VerifyError.hostname("certificate is valid for \(names), not \(host)")
}

// dnsWithin reports whether name is within a dNSName constraint: equal to
// it or below it ("example.com" covers "a.example.com"), or with a
// leading dot, strictly below it. An empty constraint covers every name.
func dnsWithin(_ name: [uint8], _ constraint: [uint8]) -> bool {
    var n = name
    if n.count > 0 && n[n.count - 1] == 0x2e {
        n = Array(n[0..<(n.count - 1)])
    }
    if constraint.isEmpty {
        return true
    }
    if constraint[0] == 0x2e {
        return n.count > constraint.count && bytesEqual(Array(n[(n.count - constraint.count)..<n.count]), constraint)
    }
    if bytesEqual(n, constraint) {
        return true
    }
    if n.count <= constraint.count {
        return false
    }
    return n[n.count - constraint.count - 1] == 0x2e
        && bytesEqual(Array(n[(n.count - constraint.count)..<n.count]), constraint)
}

func ipWithin(_ ip: [uint8], _ range: [uint8]) -> bool {
    if range.count != 2 * ip.count {
        return false
    }
    var i = 0
    while i < ip.count {
        let mask = range[ip.count + i]
        if (ip[i] & mask) != (range[i] & mask) {
            return false
        }
        i += 1
    }
    return true
}

// checkNameConstraints applies issuer's name constraints to the leaf's
// names and the host asked for. Each kind of constraint bounds names of
// its kind only.
func checkNameConstraints(_ issuer: Certificate, _ leaf: Certificate, _ host: string) throws {
    if issuer.PermittedDNSDomains.isEmpty && issuer.ExcludedDNSDomains.isEmpty
        && issuer.PermittedIPRanges.isEmpty && issuer.ExcludedIPRanges.isEmpty
        && !issuer.HasUnsupportedNameConstraints {
        return
    }
    if issuer.HasUnsupportedNameConstraints {
        throw VerifyError.notAuthorized("\(describe(issuer)) has name constraints of a kind that is not evaluated")
    }
    var dns: [[uint8]] = []
    var ips: [[uint8]] = leaf.IPAddresses
    for n in leaf.DNSNames {
        dns.append(lower(n))
    }
    if !host.isEmpty {
        let h = lower(host)
        if let ip = parseIP(h) {
            ips.append(ip)
        } else {
            dns.append(h)
        }
    }
    for n in dns {
        if !issuer.PermittedDNSDomains.isEmpty {
            var ok = false
            for c in issuer.PermittedDNSDomains {
                if dnsWithin(n, lower(c)) {
                    ok = true
                }
            }
            if !ok {
                throw VerifyError.notAuthorized("\"\(string(decoding: n, as: UTF8.self))\" is outside \(describe(issuer))'s permitted names")
            }
        }
        for c in issuer.ExcludedDNSDomains {
            if dnsWithin(n, lower(c)) {
                throw VerifyError.notAuthorized("\"\(string(decoding: n, as: UTF8.self))\" is excluded by \(describe(issuer))")
            }
        }
    }
    for ip in ips {
        if !issuer.PermittedIPRanges.isEmpty {
            var ok = false
            for r in issuer.PermittedIPRanges {
                if ipWithin(ip, r) {
                    ok = true
                }
            }
            if !ok {
                throw VerifyError.notAuthorized("an IP address is outside \(describe(issuer))'s permitted ranges")
            }
        }
        for r in issuer.ExcludedIPRanges {
            if ipWithin(ip, r) {
                throw VerifyError.notAuthorized("an IP address is excluded by \(describe(issuer))")
            }
        }
    }
}
