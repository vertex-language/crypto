// Package credssp implements the client side of CredSSP / NLA (MS-CSSP)
// over an established TLS 1.2 channel. It carries an NTLM exchange inside
// TSRequest structures, binds to the server's TLS public key with the
// version-6 SHA-256 hashes, and finally delegates the user's password as
// TSCredentials. This is how Windows RDP authenticates before the RDP
// connection proper begins.
//
// NTLM tokens are placed directly in negoTokens (Windows accepts raw
// NTLM there, as its own clients and FreeRDP do); a SPNEGO wrapper and
// Kerberos can be added later without changing this flow.
package credssp

import (
    "crypto/ntlm"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "encoding/asn1"
    "net/tcp"
)

public enum CredSSPError: Error {
    case protocolError(string)
    case serverError(uint32)
    case bindingMismatch

    public var Message: string {
        switch self {
        case .protocolError(let s): return "credssp: \(s)"
        case .serverError(let code): return "credssp: server returned NTSTATUS 0x\(hexU32(code))"
        case .bindingMismatch: return "credssp: server public-key binding mismatch (possible man-in-the-middle)"
        }
    }
}

func hexU32(_ v: uint32) -> string {
    let h: [uint8] = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]
    var o: [uint8] = []
    var i = 7
    while i >= 0 { o.append(h[int((v >> uint32(i*4)) & 0xf)]); i -= 1 }
    return string(decoding: o, as: UTF8.self)
}

let clientToServerMagic = "CredSSP Client-To-Server Binding Hash"
let serverToClientMagic = "CredSSP Server-To-Client Binding Hash"
let credSSPVersion: int64 = 6

/// Credentials to delegate over CredSSP.
public struct Credentials {
    public var Domain: string
    public var User: string
    public var Password: [uint8]
    public var Host: string
    /// The server certificate's subjectPublicKey
    /// (tls.Conn12.PeerCertificate.RawSubjectPublicKey).
    public var SubjectPublicKey: [uint8]

    public init(domain: string, user: string, password: [uint8], host: string, subjectPublicKey: [uint8]) {
        self.Domain = domain; self.User = user; self.Password = password
        self.Host = host; self.SubjectPublicKey = subjectPublicKey
    }
}

/// Authenticate runs the full CredSSP client exchange over an established
/// TLS connection.
public func Authenticate(conn: inout tls.Conn12, creds: Credentials) async throws {
    let domain = creds.Domain
    let user = creds.User
    let password = creds.Password
    let host = creds.Host
    let subjectPublicKey = creds.SubjectPublicKey
    var ntlmClient = ntlm.Client(domain: domain, user: user, password: password,
                                 workstation: "VERTEX", targetSPN: "TERMSRV/\(host)")

    // 1. Send TSRequest{version, negoTokens: NTLM NEGOTIATE}.
    let negotiate = ntlmClient.Negotiate()
    try await writeTSRequest(&conn, encodeTSRequest(negoToken: negotiate))

    // 2. Read TSRequest{negoTokens: NTLM CHALLENGE}.
    var resp = try await readTSRequest(&conn)
    if resp.errorCode != 0 { throw CredSSPError.serverError(resp.errorCode) }
    if resp.negoToken.count == 0 { throw CredSSPError.protocolError("no CHALLENGE token") }
    let challenge = resp.negoToken

    // 3. AUTHENTICATE + pubKeyAuth binding (version 5/6: SHA-256 hash).
    let authToken: [uint8]
    do {
        authToken = try ntlmClient.Authenticate(challenge)
    } catch {
        throw CredSSPError.protocolError("NTLM authenticate failed")
    }
    let nonce = try rand.Bytes(32)
    let clientHash = bindingHash(magic: clientToServerMagic, nonce: nonce, publicKey: subjectPublicKey)
    let pubKeyAuth = ntlmClient.Wrap(clientHash)
    try await writeTSRequest(&conn, encodeTSRequest(negoToken: authToken, pubKeyAuth: pubKeyAuth, clientNonce: nonce))

    // 4. Read server's pubKeyAuth and verify the server-to-client binding.
    resp = try await readTSRequest(&conn)
    if resp.errorCode != 0 { throw CredSSPError.serverError(resp.errorCode) }
    if resp.pubKeyAuth.count == 0 { throw CredSSPError.protocolError("no server pubKeyAuth") }
    let serverHash: [uint8]
    do {
        serverHash = try ntlmClient.Unwrap(resp.pubKeyAuth)
    } catch {
        throw CredSSPError.protocolError("server pubKeyAuth unwrap failed")
    }
    let expected = bindingHash(magic: serverToClientMagic, nonce: nonce, publicKey: subjectPublicKey)
    if !constEqual(serverHash, expected) {
        throw CredSSPError.bindingMismatch
    }

    // 5. Delegate credentials as TSCredentials in authInfo.
    let creds = encodeTSCredentials(domain: domain, user: user, password: password)
    let authInfo = ntlmClient.Wrap(creds)
    try await writeTSRequest(&conn, encodeTSRequest(authInfo: authInfo))
}

// bindingHash = SHA256(magic ++ '\0' ++ nonce ++ subjectPublicKey).
func bindingHash(magic: string, nonce: [uint8], publicKey: [uint8]) -> [uint8] {
    var input: [uint8] = []
    for b in magic.utf8 { input.append(b) }
    input.append(0)   // the magic string's NUL terminator is included
    input.append(contentsOf: nonce)
    input.append(contentsOf: publicKey)
    return sha256.Sum256(input)
}

func constEqual(_ a: [uint8], _ b: [uint8]) -> bool {
    if a.count != b.count { return false }
    var d: uint8 = 0
    var i = 0
    while i < a.count { d |= a[i] ^ b[i]; i += 1 }
    return d == 0
}
