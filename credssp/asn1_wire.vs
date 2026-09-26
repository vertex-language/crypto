package credssp

import (
    "crypto/tls"
    "encoding/asn1"
    "encoding/binary"
)

struct tsResponse {
    var negoToken: [uint8]
    var pubKeyAuth: [uint8]
    var authInfo: [uint8]
    var errorCode: uint32
}

// encodeTSRequest builds a TSRequest DER structure. Any of the optional
// members may be empty to omit them.
func encodeTSRequest(negoToken: [uint8] = [], authInfo: [uint8] = [],
                     pubKeyAuth: [uint8] = [], clientNonce: [uint8] = []) -> [uint8] {
    var body = asn1.Writer()

    // [0] version INTEGER
    var ver = asn1.Writer()
    ver.Integer(credSSPVersion)
    body.ExplicitContext(0, ver.Bytes)

    // [1] negoTokens NegoData ::= SEQUENCE OF SEQUENCE { [0] OCTET STRING }
    if negoToken.count > 0 {
        var inner = asn1.Writer()
        inner.OctetString(negoToken)
        var oneEntry = asn1.Writer()
        oneEntry.ExplicitContext(0, inner.Bytes)     // negoToken [0]
        var seqOfEntry = asn1.Writer()
        seqOfEntry.Sequence(oneEntry.Bytes)          // the inner SEQUENCE
        var negoData = asn1.Writer()
        negoData.Sequence(seqOfEntry.Bytes)          // SEQUENCE OF
        body.ExplicitContext(1, negoData.Bytes)
    }

    // [2] authInfo OCTET STRING
    if authInfo.count > 0 {
        var ai = asn1.Writer()
        ai.OctetString(authInfo)
        body.ExplicitContext(2, ai.Bytes)
    }

    // [3] pubKeyAuth OCTET STRING
    if pubKeyAuth.count > 0 {
        var pk = asn1.Writer()
        pk.OctetString(pubKeyAuth)
        body.ExplicitContext(3, pk.Bytes)
    }

    // [5] clientNonce OCTET STRING
    if clientNonce.count > 0 {
        var cn = asn1.Writer()
        cn.OctetString(clientNonce)
        body.ExplicitContext(5, cn.Bytes)
    }

    var top = asn1.Writer()
    top.Sequence(body.Bytes)
    return top.Bytes
}

// parseTSRequest reads a TSRequest, pulling out the first negoToken and any
// pubKeyAuth / authInfo / errorCode.
func parseTSRequest(_ der: [uint8]) throws -> tsResponse {
    var out = tsResponse(negoToken: [], pubKeyAuth: [], authInfo: [], errorCode: 0)
    var top = asn1.Reader(der)
    var seq = try top.Sequence()
    // [0] version
    if let vr0 = try seq.OptionalContext(0) {
        var vr = vr0
        let _ = try vr.Integer()
    }
    // [1] negoTokens
    if let nd0 = try seq.OptionalContext(1) {
        var nd = nd0
        var seqOf = try nd.Sequence()
        if !seqOf.AtEnd {
            var entry = try seqOf.Sequence()
            var tok = try entry.TaggedContext(0)
            out.negoToken = try tok.OctetString()
        }
    }
    // [2] authInfo
    if let ai0 = try seq.OptionalContext(2) {
        var ai = ai0
        out.authInfo = try ai.OctetString()
    }
    // [3] pubKeyAuth
    if let pk0 = try seq.OptionalContext(3) {
        var pk = pk0
        out.pubKeyAuth = try pk.OctetString()
    }
    // [4] errorCode
    if let ec0 = try seq.OptionalContext(4) {
        var ec = ec0
        let code = try ec.Integer()
        out.errorCode = uint32(truncatingIfNeeded: code)
    }
    return out
}

// encodeTSCredentials wraps a password credential (credType 1).
func encodeTSCredentials(domain: string, user: string, password: [uint8]) -> [uint8] {
    // TSPasswordCreds ::= SEQUENCE { [0] domain, [1] user, [2] password }, UTF16LE
    var pw = asn1.Writer()
    var d = asn1.Writer(); d.OctetString(binary.EncodeUTF16LE(domain)); pw.ExplicitContext(0, d.Bytes)
    var u = asn1.Writer(); u.OctetString(binary.EncodeUTF16LE(user)); pw.ExplicitContext(1, u.Bytes)
    var p = asn1.Writer(); p.OctetString(binary.EncodeUTF16LE(passwordString(password))); pw.ExplicitContext(2, p.Bytes)
    var pwSeq = asn1.Writer(); pwSeq.Sequence(pw.Bytes)

    // TSCredentials ::= SEQUENCE { [0] credType INTEGER, [1] credentials OCTET STRING }
    var body = asn1.Writer()
    var ct = asn1.Writer(); ct.Integer(1); body.ExplicitContext(0, ct.Bytes)
    var cr = asn1.Writer(); cr.OctetString(pwSeq.Bytes); body.ExplicitContext(1, cr.Bytes)
    var top = asn1.Writer()
    top.Sequence(body.Bytes)
    return top.Bytes
}

func passwordString(_ p: [uint8]) -> string {
    return string(decoding: p, as: UTF8.self)
}

// --- TLS framing of TSRequests ---

// writeTSRequest sends one DER TSRequest as TLS application data.
func writeTSRequest(_ conn: inout tls.Conn12, _ der: [uint8]) async throws {
    try await conn.Write(der)
}

// readTSRequest reads TLS application data until a full DER SEQUENCE is
// available, then parses it.
func readTSRequest(_ conn: inout tls.Conn12) async throws -> tsResponse {
    var buf: [uint8] = []
    while true {
        // Do we have a complete outer TLV yet?
        if let total = derTotalLength(buf) {
            if buf.count >= total {
                return try parseTSRequest(buf)
            }
        }
        var chunk = [uint8](repeating: 0, count: 8192)
        let n = try await conn.Read(into: &chunk)
        if n <= 0 { throw CredSSPError.protocolError("connection closed during CredSSP") }
        var i = 0
        while i < n { buf.append(chunk[i]); i += 1 }
    }
}

// derTotalLength returns the full length (header + contents) of the DER
// value at the start of b, or nil if the length header isn't complete.
func derTotalLength(_ b: [uint8]) -> int? {
    if b.count < 2 { return nil }
    let first = b[1]
    if (first & 0x80) == 0 {
        return 2 + int(first)
    }
    let n = int(first & 0x7f)
    if n == 0 || n > 4 { return nil }
    if b.count < 2 + n { return nil }
    var len = 0
    var i = 0
    while i < n { len = (len << 8) | int(b[2 + i]); i += 1 }
    return 2 + n + len
}
