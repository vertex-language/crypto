package dtls

// DTLS Protocol Versions (RFC 6347 / RFC 9147)
public struct ProtocolVersion {
    public static let DTLS12: uint16 = 0xFEFD // 1's complement of 1.2
    public static let DTLS13: uint16 = 0xFEFC // 1's complement of 1.3
}

public let VersionDTLS12: uint16 = 0xFEFD
public let VersionDTLS13: uint16 = 0xFEFC

// DTLS Content Types (RFC 9147 Section 4)
public struct ContentType {
    public static let ChangeCipherSpec: uint8 = 20
    public static let Alert: uint8            = 21
    public static let Handshake: uint8        = 22
    public static let ApplicationData: uint8  = 23
    public static let Ack: uint8              = 26
}

public let RecordChangeCipherSpec: uint8 = 20
public let RecordAlert: uint8            = 21
public let RecordHandshake: uint8        = 22
public let RecordApplicationData: uint8  = 23
public let RecordAck: uint8              = 26

// DTLS Handshake Types (RFC 9147 Section 5)
public struct HandshakeType {
    public static let HelloRequest: uint8        = 0
    public static let ClientHello: uint8         = 1
    public static let ServerHello: uint8         = 2
    public static let HelloVerifyRequest: uint8  = 3
    public static let Certificate: uint8         = 11
    public static let ServerKeyExchange: uint8   = 12
    public static let CertificateRequest: uint8  = 13
    public static let ServerHelloDone: uint8     = 14
    public static let CertificateVerify: uint8   = 15
    public static let ClientKeyExchange: uint8   = 16
    public static let Finished: uint8            = 20
}

public let HandshakeClientHello: uint8        = 1
public let HandshakeServerHello: uint8        = 2
public let HandshakeHelloVerifyRequest: uint8 = 3
public let HandshakeCertificate: uint8        = 11
public let HandshakeCertificateVerify: uint8  = 15
public let HandshakeFinished: uint8           = 20

// RFC 5764 DTLS-SRTP Protection Profiles
public struct SrtpProfile {
    public static let SRTP_AES128_CM_HMAC_SHA1_80: uint16 = 0x0001
    public static let SRTP_AES128_CM_HMAC_SHA1_32: uint16 = 0x0002
    public static let SRTP_AEAD_AES_128_GCM: uint16        = 0x0007
    public static let SRTP_AEAD_AES_256_GCM: uint16        = 0x0008
}

public enum DtlsError: Error {
    case recordOverflow(string)
    case recordTooSmall
    case replayDetected(uint64)
    case invalidMac
    case badHandshake(string)
    case timedOut(string)
    case unexpectedMessage(string)
    case closed

    public var Message: string {
        switch self {
        case .recordOverflow(let s):
            return "DTLS record overflow: \(s)"
        case .recordTooSmall:
            return "DTLS record too small"
        case .replayDetected(let seq):
            return "DTLS replay detected for sequence number \(seq)"
        case .invalidMac:
            return "DTLS record authentication / MAC verification failed"
        case .badHandshake(let s):
            return "DTLS handshake error: \(s)"
        case .timedOut(let s):
            return "DTLS operation timed out: \(s)"
        case .unexpectedMessage(let s):
            return "DTLS unexpected message: \(s)"
        case .closed:
            return "DTLS connection closed"
        }
    }
}
