package tls

import (
    "crypto/rsa"
    "crypto/x509"
)

// buildClientHello constructs a TLS 1.2 ClientHello offering ECDHE_RSA
// AES-GCM suites and X25519, with SNI, signature_algorithms, extended
// master secret and (empty) renegotiation_info.
func buildClientHello(serverName: string, clientRandom: [uint8], keyShare: [uint8]) -> [uint8] {
    var b: [uint8] = []
    // client_version = TLS 1.2
    b.append(0x03); b.append(0x03)
    // random
    b.append(contentsOf: clientRandom)
    // session_id (empty)
    b.append(0x00)
    // cipher_suites
    b.append(0x00); b.append(0x04)
    b.append(0xC0); b.append(0x30)   // ECDHE_RSA_AES256_GCM_SHA384
    b.append(0xC0); b.append(0x2F)   // ECDHE_RSA_AES128_GCM_SHA256
    // compression: null only
    b.append(0x01); b.append(0x00)

    // extensions
    var ext: [uint8] = []

    // server_name (0x0000)
    if serverName.count > 0 {
        var sn: [uint8] = []
        for c in serverName.utf8 { sn.append(c) }
        var snList: [uint8] = []
        snList.append(0x00)                                   // name_type host_name
        snList.append(uint8(truncatingIfNeeded: sn.count >> 8))
        snList.append(uint8(truncatingIfNeeded: sn.count))
        snList.append(contentsOf: sn)
        var snExt: [uint8] = []
        snExt.append(uint8(truncatingIfNeeded: snList.count >> 8))
        snExt.append(uint8(truncatingIfNeeded: snList.count))
        snExt.append(contentsOf: snList)
        appendExtension(&ext, 0x0000, snExt)
    }

    // supported_groups (0x000a): x25519
    appendExtension(&ext, 0x000a, [0x00, 0x02, 0x00, 0x1D])
    // ec_point_formats (0x000b): uncompressed
    appendExtension(&ext, 0x000b, [0x01, 0x00])
    // signature_algorithms (0x000d)
    var sigs: [uint8] = []
    let schemes: [uint16] = [0x0804, 0x0805, 0x0501, 0x0401, 0x0403, 0x0201]
    sigs.append(uint8(truncatingIfNeeded: (schemes.count * 2) >> 8))
    sigs.append(uint8(truncatingIfNeeded: schemes.count * 2))
    for s in schemes {
        sigs.append(uint8(truncatingIfNeeded: s >> 8))
        sigs.append(uint8(truncatingIfNeeded: s))
    }
    appendExtension(&ext, 0x000d, sigs)
    // extended_master_secret (0x0017): empty
    appendExtension(&ext, 0x0017, [])
    // renegotiation_info (0xff01): empty
    appendExtension(&ext, 0xff01, [0x00])

    b.append(uint8(truncatingIfNeeded: ext.count >> 8))
    b.append(uint8(truncatingIfNeeded: ext.count))
    b.append(contentsOf: ext)

    return handshakeMessage(hsClientHello, b)
}

func appendExtension(_ out: inout [uint8], _ extType: uint16, _ data: [uint8]) {
    out.append(uint8(truncatingIfNeeded: extType >> 8))
    out.append(uint8(truncatingIfNeeded: extType))
    out.append(uint8(truncatingIfNeeded: data.count >> 8))
    out.append(uint8(truncatingIfNeeded: data.count))
    out.append(contentsOf: data)
}

// parseServerHello reads the negotiated suite and server random.
func (c: inout Conn12) parseServerHello(_ body: [uint8]) throws -> [uint8] {
    if body.count < 38 { throw Tls12Error.handshake("short ServerHello") }
    var off = 2   // server_version
    var serverRandom: [uint8] = []
    var i = 0
    while i < 32 { serverRandom.append(body[off + i]); i += 1 }
    off += 32
    let sidLen = int(body[off]); off += 1 + sidLen
    if off + 3 > body.count { throw Tls12Error.handshake("ServerHello truncated at suite") }
    let suite = (uint16(body[off]) << 8) | uint16(body[off + 1])
    off += 2
    // compression method (1) then optional extensions -- not needed.
    c.suite = suite
    if suite == suiteECDHE_RSA_AES256_GCM_SHA384 {
        c.useSHA384 = true; c.keyLen = 32
    } else if suite == suiteECDHE_RSA_AES128_GCM_SHA256 {
        c.useSHA384 = false; c.keyLen = 16
    } else {
        throw Tls12Error.handshake("server chose unsupported suite \(suite)")
    }
    return serverRandom
}

// parseCertificate reads the Certificate message's chain, checks it
// against the system's roots unless the configuration leaves that to the
// caller, and parses the server's own certificate, whose key signs the
// ServerKeyExchange.
func (c: inout Conn12) parseCertificate(_ body: [uint8]) throws {
    if body.count < 6 { throw Tls12Error.handshake("short Certificate") }
    // total list length (3), then entries of length (3) + der
    let listEnd = 3 + ((int(body[0]) << 16) | (int(body[1]) << 8) | int(body[2]))
    if listEnd > body.count { throw Tls12Error.handshake("Certificate truncated") }
    var chain: [[uint8]] = []
    var off = 3
    while off + 3 <= listEnd {
        let n = (int(body[off]) << 16) | (int(body[off + 1]) << 8) | int(body[off + 2])
        off += 3
        if off + n > listEnd { throw Tls12Error.handshake("Certificate truncated") }
        chain.append(Array(body[off..<(off + n)]))
        off += n
    }
    if chain.isEmpty { throw Tls12Error.handshake("the server sent no certificate") }
    do {
        try verifyChain(chain, c.config)
    } catch let e as TlsError {
        throw Tls12Error.verify(e.Message)
    }
    c.PeerCertificates = chain
    c.PeerCertificateDER = chain[0]
    do {
        c.PeerCertificate = try x509.Parse(chain[0])
    } catch {
        throw Tls12Error.handshake("certificate parse failed")
    }
}

// parseServerKeyExchange validates the ECDHE parameters' signature against
// the server certificate and returns the server's ephemeral public key.
func (c: inout Conn12) parseServerKeyExchange(_ body: [uint8], clientRandom: [uint8], serverRandom: [uint8]) throws -> [uint8] {
    if body.count < 4 { throw Tls12Error.handshake("short ServerKeyExchange") }
    var off = 0
    let curveType = body[off]; off += 1
    if curveType != 0x03 { throw Tls12Error.handshake("SKE curve_type not named_curve") }
    let namedCurve = (uint16(body[off]) << 8) | uint16(body[off + 1]); off += 2
    if namedCurve != groupX25519 { throw Tls12Error.handshake("SKE curve not X25519") }
    let pubLen = int(body[off]); off += 1
    if off + pubLen > body.count { throw Tls12Error.handshake("SKE pubkey truncated") }
    var serverPub: [uint8] = []
    var i = 0
    while i < pubLen { serverPub.append(body[off + i]); i += 1 }
    let paramsEnd = off + pubLen
    off = paramsEnd

    // ECParameters bytes that were signed: curve_type .. pubkey.
    var params: [uint8] = []
    i = 0
    while i < paramsEnd { params.append(body[i]); i += 1 }

    // SignatureAndHashAlgorithm (2) + signature (2-byte length prefixed).
    if off + 4 > body.count { throw Tls12Error.handshake("SKE signature header truncated") }
    let hashByte = body[off]
    let sigByte = body[off + 1]
    off += 2
    let sigLen = (int(body[off]) << 8) | int(body[off + 1]); off += 2
    if off + sigLen > body.count { throw Tls12Error.handshake("SKE signature truncated") }
    var signature: [uint8] = []
    i = 0
    while i < sigLen { signature.append(body[off + i]); i += 1 }

    // Signed data = client_random || server_random || ECParameters.
    var signed: [uint8] = []
    signed.append(contentsOf: clientRandom)
    signed.append(contentsOf: serverRandom)
    signed.append(contentsOf: params)

    if c.config.InsecureSkipVerify {
        // Still parse; skip the cryptographic check.
        return serverPub
    }

    do {
        if hashByte == 0x08 {
            // New-style SignatureScheme in the two bytes (PSS/EdDSA family).
            let scheme = (uint16(hashByte) << 8) | uint16(sigByte)
            let h: rsa.Hash = scheme == 0x0805 ? .sha384 : .sha256
            try rsa.VerifyPSS(key: c.PeerCertificate.RSAPublicKey, hash: h, data: signed, signature: signature)
        } else if sigByte == 0x01 {
            let h = rsaHashFromByte(hashByte)
            try rsa.VerifyPKCS1v15(key: c.PeerCertificate.RSAPublicKey, hash: h, data: signed, signature: signature)
        } else {
            throw Tls12Error.verify("unsupported SKE signature algorithm (\(hashByte),\(sigByte))")
        }
    } catch let e as rsa.RsaError {
        throw Tls12Error.verify("ServerKeyExchange signature: \(e.Message)")
    }
    return serverPub
}

func rsaHashFromByte(_ b: uint8) -> rsa.Hash {
    switch b {
    case 2: return .sha1
    case 4: return .sha256
    case 5: return .sha384
    case 6: return .sha512
    default: return .sha256
    }
}
