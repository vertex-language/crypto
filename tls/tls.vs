package tls

// TLS Protocol Versions
public struct ProtocolVersion {
    public static let TLS13: uint16 = 0x0304
    public static let TLS12: uint16 = 0x0303
}
public let VersionTLS13: uint16 = 0x0304
public let VersionTLS12: uint16 = 0x0303

// TLS 1.3 Cipher Suites (RFC 8446 Section B.4)
public struct CipherSuite {
    public static let TLS_AES_128_GCM_SHA256: uint16 = 0x1301
    public static let TLS_AES_256_GCM_SHA384: uint16 = 0x1302
    public static let TLS_CHACHA20_POLY1305_SHA256: uint16 = 0x1303
}
public let TLS_AES_128_GCM_SHA256: uint16 = 0x1301
public let TLS_AES_256_GCM_SHA384: uint16 = 0x1302
public let TLS_CHACHA20_POLY1305_SHA256: uint16 = 0x1303

// Supported Groups / Curves (RFC 8446 Section 4.2.7)
public struct NamedGroup {
    public static let X25519: uint16 = 0x001d
}
public let GroupX25519: uint16 = 0x001d

// Signature Algorithms (RFC 8446 Section 4.2.3)
public struct SignatureScheme {
    public static let Ed25519: uint16 = 0x0807
    public static let EcdsaSecp256r1Sha256: uint16 = 0x0403
    public static let RsaPssRsaeSha256: uint16 = 0x0804
    public static let RsaPkcs1Sha256: uint16 = 0x0401
}
public let SigEd25519: uint16 = 0x0807
public let SigEcdsaSecp256r1Sha256: uint16 = 0x0403
public let SigRsaPssRsaeSha256: uint16 = 0x0804
public let SigRsaPkcs1Sha256: uint16 = 0x0401

// Extension Types (RFC 8446 Section 4.2)
public struct ExtensionType {
    public static let ServerName: uint16 = 0x0000
    public static let SupportedGroups: uint16 = 0x000a
    public static let SignatureAlgorithms: uint16 = 0x000d
    public static let ALPN: uint16 = 0x0010
    public static let SupportedVersions: uint16 = 0x002b
    public static let KeyShare: uint16 = 0x0033
}
public let ExtServerName: uint16 = 0x0000
public let ExtSupportedGroups: uint16 = 0x000a
public let ExtSignatureAlgorithms: uint16 = 0x000d
public let ExtALPN: uint16 = 0x0010
public let ExtSupportedVersions: uint16 = 0x002b
public let ExtKeyShare: uint16 = 0x0033

// Handshake Types (RFC 8446 Section 4)
public struct HandshakeType {
    public static let ClientHello: uint8 = 1
    public static let ServerHello: uint8 = 2
    public static let NewSessionTicket: uint8 = 4
    public static let EncryptedExtensions: uint8 = 8
    public static let Certificate: uint8 = 11
    public static let CertificateVerify: uint8 = 15
    public static let Finished: uint8 = 20
    public static let KeyUpdate: uint8 = 24
}
public let HandshakeClientHello: uint8 = 1
public let HandshakeServerHello: uint8 = 2
public let HandshakeNewSessionTicket: uint8 = 4
public let HandshakeEncryptedExtensions: uint8 = 8
public let HandshakeCertificate: uint8 = 11
public let HandshakeCertificateVerify: uint8 = 15
public let HandshakeFinished: uint8 = 20
public let HandshakeKeyUpdate: uint8 = 24

// Record Content Types (RFC 8446 Section 5.1)
public struct RecordType {
    public static let Invalid: uint8 = 0
    public static let ChangeCipherSpec: uint8 = 20
    public static let Alert: uint8 = 21
    public static let Handshake: uint8 = 22
    public static let ApplicationData: uint8 = 23
}
public let RecordInvalid: uint8 = 0
public let RecordChangeCipherSpec: uint8 = 20
public let RecordAlert: uint8 = 21
public let RecordHandshake: uint8 = 22
public let RecordApplicationData: uint8 = 23

// Alert Levels & Descriptions
public struct Alert {
    public static let LevelWarning: uint8 = 1
    public static let LevelFatal: uint8 = 2
    public static let CloseNotify: uint8 = 0
    public static let UnexpectedMessage: uint8 = 10
    public static let BadRecordMac: uint8 = 20
    public static let HandshakeFailure: uint8 = 40
    public static let IllegalParameter: uint8 = 47
    public static let InternalError: uint8 = 80
}
public let AlertLevelWarning: uint8 = 1
public let AlertLevelFatal: uint8 = 2
public let AlertCloseNotify: uint8 = 0
public let AlertUnexpectedMessage: uint8 = 10
public let AlertBadRecordMac: uint8 = 20
public let AlertHandshakeFailure: uint8 = 40
public let AlertIllegalParameter: uint8 = 47
public let AlertInternalError: uint8 = 80

/// TlsError represents transport security failures.
public enum TlsError: Error {
    case handshakeFailed(string)
    case unexpectedMessage(string)
    case badRecordMac(string)
    case unsupportedCipherSuite(string)
    case unsupportedVersion(string)
    case recordOverflow(string)
    case closed(string)
    case alertReceived(string)

    public var Message: string {
        switch self {
        case .handshakeFailed(let s):
            return "tls: handshake failed: \(s)"
        case .unexpectedMessage(let s):
            return "tls: unexpected message: \(s)"
        case .badRecordMac(let s):
            return "tls: bad record mac: \(s)"
        case .unsupportedCipherSuite(let s):
            return "tls: unsupported cipher suite: \(s)"
        case .unsupportedVersion(let s):
            return "tls: unsupported version: \(s)"
        case .recordOverflow(let s):
            return "tls: record overflow: \(s)"
        case .closed(let s):
            return "tls: connection closed: \(s)"
        case .alertReceived(let s):
            return "tls: alert received: \(s)"
        }
    }
}

/// Config configures a TLS client connection.
public struct Config {
    public var ServerName: string
    public var InsecureSkipVerify: bool
    public var NextProtos: [string]
    public var MinVersion: uint16
    public var MaxVersion: uint16

    public init(serverName: string = "",
                insecureSkipVerify: bool = true,
                nextProtos: [string] = [],
                minVersion: uint16 = 0x0304,
                maxVersion: uint16 = 0x0304) {
        self.ServerName = serverName
        self.InsecureSkipVerify = insecureSkipVerify
        self.NextProtos = nextProtos
        self.MinVersion = minVersion
        self.MaxVersion = maxVersion
    }
}

/// ConnectionState records the negotiated parameters of an established TLS session.
public struct ConnectionState {
    public var HandshakeComplete: bool = false
    public var ServerName: string = ""
    public var NegotiatedProtocol: string = ""
    public var CipherSuite: uint16 = 0
    public var Version: uint16 = 0

    public init() {}
}
