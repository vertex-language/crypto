// Package ntlm implements the client side of NTLMv2 (MS-NLMP), enough for
// CredSSP/NLA: the NEGOTIATE and AUTHENTICATE messages, the NTLMv2 response
// and session-key hierarchy, the message integrity code (MIC), and the
// GSS-style Wrap/Unwrap (sign+seal) used to protect CredSSP's public-key
// and credential tokens.
//
// NTLM is legacy and weak; it is used because Windows requires it for NLA
// when Kerberos is unavailable. Microsoft is phasing it out, so a Kerberos
// mechanism can slot in beside this later behind the same interface.
package ntlm

import "crypto/md4"
import "crypto/md5"
import "crypto/hmac"
import "crypto/rc4"
import "crypto/rand"
import "encoding/binary"

// Negotiate flags (MS-NLMP 2.2.2.5).
let NEGOTIATE_UNICODE: uint32 = 0x00000001
let NEGOTIATE_OEM: uint32 = 0x00000002
let REQUEST_TARGET: uint32 = 0x00000004
let NEGOTIATE_SIGN: uint32 = 0x00000010
let NEGOTIATE_SEAL: uint32 = 0x00000020
let NEGOTIATE_NTLM: uint32 = 0x00000200
let NEGOTIATE_ALWAYS_SIGN: uint32 = 0x00008000
let NEGOTIATE_EXTENDED_SESSIONSECURITY: uint32 = 0x00080000
let NEGOTIATE_TARGET_INFO: uint32 = 0x00800000
let NEGOTIATE_VERSION: uint32 = 0x02000000
let NEGOTIATE_128: uint32 = 0x20000000
let NEGOTIATE_KEY_EXCH: uint32 = 0x40000000
let NEGOTIATE_56: uint32 = 0x80000000

func clientFlags() -> uint32 {
    return NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_SIGN | NEGOTIATE_SEAL |
        NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY |
        NEGOTIATE_TARGET_INFO | NEGOTIATE_VERSION | NEGOTIATE_128 | NEGOTIATE_KEY_EXCH | NEGOTIATE_56
}

public enum NtlmError: Error {
    case malformed(string)
    case verify(string)

    public var Message: string {
        switch self {
        case .malformed(let s): return "ntlm: \(s)"
        case .verify(let s): return "ntlm: \(s)"
        }
    }
}

let signature: [uint8] = [0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00]   // "NTLMSSP\0"

/// Context carries the negotiated session keys and running cipher state for
/// signing and sealing after authentication (GSS Wrap/Unwrap).
public struct Context {
    var clientSigningKey: [uint8]
    var serverSigningKey: [uint8]
    var clientSeal: rc4.Cipher
    var serverSeal: rc4.Cipher
    var clientSeq: uint32
    var serverSeq: uint32
    public var Established: bool

    public init() {
        clientSigningKey = []; serverSigningKey = []
        clientSeal = rc4.Cipher(key: [0]); serverSeal = rc4.Cipher(key: [0])
        clientSeq = 0; serverSeq = 0; Established = false
    }
}

/// Client drives an NTLMv2 exchange and then protects tokens.
public struct Client {
    public var Domain: string
    public var User: string
    public var Password: [uint8]     // UTF-8 password bytes
    public var Workstation: string
    public var TargetSPN: string     // "TERMSRV/<host>"

    var negotiateMessage: [uint8] = []
    public var Ctx: Context = Context()

    public init(domain: string, user: string, password: [uint8], workstation: string = "VERTEX", targetSPN: string = "") {
        self.Domain = domain
        self.User = user
        self.Password = password
        self.Workstation = workstation
        self.TargetSPN = targetSPN
    }

    /// Negotiate returns the NEGOTIATE_MESSAGE (type 1).
    public mutating func Negotiate() -> [uint8] {
        var w = binary.Writer()
        w.Append(signature)
        w.U32LE(1)                       // MessageType
        w.U32LE(clientFlags())
        // DomainName fields (len, maxlen, offset) -- empty
        w.U16LE(0); w.U16LE(0); w.U32LE(0)
        // Workstation fields -- empty
        w.U16LE(0); w.U16LE(0); w.U32LE(0)
        // Version (8): Windows 10 build 19041, NTLM revision 15
        w.U8(10); w.U8(0); w.U16LE(19041); w.U8(0); w.U8(0); w.U8(0); w.U8(15)
        negotiateMessage = w.Bytes
        return negotiateMessage
    }

    /// Authenticate consumes the CHALLENGE_MESSAGE (type 2) and returns the
    /// AUTHENTICATE_MESSAGE (type 3), setting up the signing/sealing context.
    public mutating func Authenticate(_ challenge: [uint8]) throws -> [uint8] {
        let ch = try parseChallenge(challenge)

        // NTOWFv2 = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user)+domain))
        let ntowf = NTOWFv2(user: User, domain: Domain, password: Password)

        // Build the NTLMv2 client challenge blob (temp). The prefix is
        // RespType(1) HiRespType(1) Reserved1(2) Reserved2(4) = 8 bytes,
        // then Timestamp(8), ClientChallenge(8), Reserved3(4), TargetInfo.
        let clientChallenge = try rand.Bytes(8)
        let timestamp = ch.timestamp   // use the server's timestamp

        // Target info for the response: the server's AV pairs with the
        // MsvAvFlags MIC bit set, terminated, then 8 bytes of padding.
        let responseTargetInfo = augmentTargetInfo(ch.targetInfo)

        var temp: [uint8] = []
        temp.append(0x01); temp.append(0x01)             // RespType, HiRespType
        temp.append(0); temp.append(0)                   // Reserved1 (2)
        temp.append(0); temp.append(0); temp.append(0); temp.append(0)   // Reserved2 (4)
        temp.append(contentsOf: timestamp)               // Timestamp (8)
        temp.append(contentsOf: clientChallenge)         // ClientChallenge (8)
        temp.append(0); temp.append(0); temp.append(0); temp.append(0)   // Reserved3 (4)
        temp.append(contentsOf: responseTargetInfo)      // AV pairs + padding

        // NTProofStr = HMAC_MD5(ntowf, serverChallenge || temp)
        var proofInput = ch.serverChallenge
        proofInput.append(contentsOf: temp)
        let ntProof = hmac.Compute(key: ntowf, message: proofInput, hash: .md5)

        var ntResponse = ntProof
        ntResponse.append(contentsOf: temp)

        // SessionBaseKey = HMAC_MD5(ntowf, NTProofStr); with NTLMv2 +
        // extended session security this is also the KeyExchangeKey.
        let sessionBaseKey = hmac.Compute(key: ntowf, message: ntProof, hash: .md5)
        let keyExchangeKey = sessionBaseKey

        // LMv2 response = HMAC_MD5(ntowf, serverChallenge || clientChallenge)
        // || clientChallenge (24 bytes), as a Windows client sends.
        var lmInput = ch.serverChallenge
        lmInput.append(contentsOf: clientChallenge)
        var lmResponse = hmac.Compute(key: ntowf, message: lmInput, hash: .md5)
        lmResponse.append(contentsOf: clientChallenge)

        // Exported session key + key exchange.
        let exportedSessionKey = try rand.Bytes(16)
        let encryptedSessionKey = rc4.Apply(key: keyExchangeKey, data: exportedSessionKey)

        // Assemble AUTHENTICATE with a zeroed MIC, then fill the MIC in.
        let flags = clientFlags()
        var auth = buildAuthenticate(
            lmResponse: lmResponse, ntResponse: ntResponse,
            domain: Domain, user: User, workstation: Workstation,
            encryptedSessionKey: encryptedSessionKey, flags: flags,
            mic: [uint8](repeating: 0, count: 16))

        // MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)
        var micInput = negotiateMessage
        micInput.append(contentsOf: challenge)
        micInput.append(contentsOf: auth)
        let mic = hmac.Compute(key: exportedSessionKey, message: micInput, hash: .md5)
        // Patch the MIC into the AUTHENTICATE message at its fixed offset.
        patchMIC(&auth, mic)

        // Derive signing/sealing keys and RC4 handles.
        Ctx = makeContext(exportedSessionKey)
        return auth
    }
}

// makeContext derives the four NTLM keys and RC4 sealing handles.
func makeContext(_ exportedSessionKey: [uint8]) -> Context {
    var ctx = Context()
    ctx.clientSigningKey = signKey(exportedSessionKey, "session key to client-to-server signing key magic constant")
    ctx.serverSigningKey = signKey(exportedSessionKey, "session key to server-to-client signing key magic constant")
    let clientSealKey = signKey(exportedSessionKey, "session key to client-to-server sealing key magic constant")
    let serverSealKey = signKey(exportedSessionKey, "session key to server-to-client sealing key magic constant")
    ctx.clientSeal = rc4.Cipher(key: clientSealKey)
    ctx.serverSeal = rc4.Cipher(key: serverSealKey)
    ctx.clientSeq = 0
    ctx.serverSeq = 0
    ctx.Established = true
    return ctx
}

func signKey(_ sessionKey: [uint8], _ magic: string) -> [uint8] {
    var input = sessionKey
    for b in magic.utf8 { input.append(b) }
    input.append(0)   // magic constant includes the terminating NUL
    return md5.Sum(input)
}

// ntowfv2 computes the NTLMv2 one-way function.
public func NTOWFv2(user: string, domain: string, password: [uint8]) -> [uint8] {
    let ntHash = md4.Sum(binary.EncodeUTF16LE(passwordString(password)))
    let identity = binary.EncodeUTF16LE(upperASCII(user) + domain)
    return hmac.Compute(key: ntHash, message: identity, hash: .md5)
}

func passwordString(_ p: [uint8]) -> string {
    return string(decoding: p, as: UTF8.self)
}

func upperASCII(_ s: string) -> string {
    var out: [uint8] = []
    for b in s.utf8 {
        if b >= 97 && b <= 122 { out.append(b - 32) } else { out.append(b) }
    }
    return string(decoding: out, as: UTF8.self)
}
