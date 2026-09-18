package dtls

import "crypto/tls"

/// SrtpKeys holds the derived SRTP master keys and salts for both peers (RFC 5764 Section 4.2).
public struct SrtpKeys {
    public var ClientWriteKey: [uint8]
    public var ServerWriteKey: [uint8]
    public var ClientWriteSalt: [uint8]
    public var ServerWriteSalt: [uint8]
}

/// Derives SRTP encryption keys and salts from DTLS keying material according to RFC 5764 Section 4.2.
/// E.g. for SRTP_AES128_CM_HMAC_SHA1_80: keyLength = 16, saltLength = 14 (total 60 bytes).
public func DeriveSrtpKeys(exporterSecret: [uint8],
                           keyLength: int = 16,
                           saltLength: int = 14) -> SrtpKeys {
    let totalLen = (keyLength + saltLength) * 2
    // RFC 5764 Section 4.2: Exporter label is "EXTRACTOR-dtls_srtp"
    let raw = tls.HkdfExpandLabel(secret: exporterSecret, label: "EXTRACTOR-dtls_srtp", context: [], length: totalLen)

    var clientKey: [uint8] = []
    var serverKey: [uint8] = []
    var clientSalt: [uint8] = []
    var serverSalt: [uint8] = []

    var i = 0
    while i < keyLength && i < raw.count {
        clientKey.append(raw[i])
        if (keyLength + i) < raw.count {
            serverKey.append(raw[keyLength + i])
        }
        i += 1
    }

    let saltOffset = keyLength * 2
    var s = 0
    while s < saltLength && (saltOffset + s) < raw.count {
        clientSalt.append(raw[saltOffset + s])
        if (saltOffset + saltLength + s) < raw.count {
            serverSalt.append(raw[saltOffset + saltLength + s])
        }
        s += 1
    }

    return SrtpKeys(
        ClientWriteKey: clientKey,
        ServerWriteKey: serverKey,
        ClientWriteSalt: clientSalt,
        ServerWriteSalt: serverSalt
    )
}
