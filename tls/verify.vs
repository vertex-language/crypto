package tls

import "crypto/cert"

// The server's certificate, in TLS 1.3 (RFC 8446 §4.4.2-4.4.3) and the
// checks both versions share.

// parseCertificateList13 reads a TLS 1.3 Certificate message, header
// included: a request context, then entries of a DER certificate and its
// extensions. The server's own certificate is first.
func parseCertificateList13(_ msg: [uint8]) throws -> [[uint8]] {
    var off = 4
    if off >= msg.count {
        throw TlsError.certificate("short Certificate message")
    }
    off += 1 + int(msg[off]) // certificate_request_context
    if off + 3 > msg.count {
        throw TlsError.certificate("Certificate list truncated")
    }
    let listEnd = off + 3 + ((int(msg[off]) << 16) | (int(msg[off + 1]) << 8) | int(msg[off + 2]))
    off += 3
    if listEnd > msg.count {
        throw TlsError.certificate("Certificate list truncated")
    }
    var chain: [[uint8]] = []
    while off < listEnd {
        if off + 3 > listEnd {
            throw TlsError.certificate("certificate entry truncated")
        }
        let n = (int(msg[off]) << 16) | (int(msg[off + 1]) << 8) | int(msg[off + 2])
        off += 3
        if off + n + 2 > listEnd {
            throw TlsError.certificate("certificate entry truncated")
        }
        chain.append(Array(msg[off..<(off + n)]))
        off += n
        off += 2 + ((int(msg[off]) << 8) | int(msg[off + 1])) // extensions
    }
    if chain.isEmpty {
        throw TlsError.certificate("the server sent no certificate")
    }
    return chain
}

// parseCertificateVerify reads a CertificateVerify message, header
// included: the signature scheme and the signature.
func parseCertificateVerify(_ msg: [uint8]) throws -> (scheme: uint16, signature: [uint8]) {
    if msg.count < 8 {
        throw TlsError.certificate("short CertificateVerify message")
    }
    let scheme = (uint16(msg[4]) << 8) | uint16(msg[5])
    let n = (int(msg[6]) << 8) | int(msg[7])
    if 8 + n > msg.count {
        throw TlsError.certificate("CertificateVerify signature truncated")
    }
    return (scheme, Array(msg[8..<(8 + n)]))
}

// serverSignedContent is what a TLS 1.3 server signs in CertificateVerify:
// 64 spaces, the context string, a zero byte, and the transcript hash
// through Certificate.
func serverSignedContent(_ transcriptHash: [uint8]) -> [uint8] {
    var out = [uint8](repeating: 0x20, count: 64)
    out.append(contentsOf: Array("TLS 1.3, server CertificateVerify".utf8))
    out.append(0)
    out.append(contentsOf: transcriptHash)
    return out
}

// verifyChain checks the server's chain against the system's roots and
// the name the client asked for, unless the configuration leaves that to
// the caller.
func verifyChain(_ chain: [[uint8]], _ config: Config) throws {
    if config.InsecureSkipVerify || !config.VerifyChain {
        return
    }
    do {
        try cert.VerifyChain(chain, host: config.ServerName)
    } catch let e as cert.CertError {
        throw TlsError.certificate(e.Message)
    }
}

// verifyHandshakeSignature checks that the server signed data with its
// certificate's key: proof it holds the key the certificate names.
func verifyHandshakeSignature(_ leaf: [uint8], scheme: uint16, data: [uint8], signature: [uint8]) throws {
    do {
        try cert.VerifySignature(certificate: leaf, scheme: scheme, data: data, signature: signature)
    } catch let e as cert.CertError {
        throw TlsError.certificate("the server's handshake signature: \(e.Message)")
    }
}
