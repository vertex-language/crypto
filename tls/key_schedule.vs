package tls

import (
    "crypto/hkdf"
    "crypto/hmac"
    "crypto/sha256"
)

public struct TrafficSecrets {
    public var ClientSecret: [uint8]
    public var ServerSecret: [uint8]

    public init(clientSecret: [uint8], serverSecret: [uint8]) {
        self.ClientSecret = clientSecret
        self.ServerSecret = serverSecret
    }
}

public struct TrafficKeys {
    public var Key: [uint8]
    public var IV: [uint8]

    public init(key: [uint8], iv: [uint8]) {
        self.Key = key
        self.IV = iv
    }
}

/// HkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1).
public func HkdfExpandLabel(secret: [uint8], label: string, context: [uint8], length: int) -> [uint8] {
    let fullLabel = "tls13 " + label
    var hkdfLabel: [uint8] = []

    // 2-byte length in network byte order
    hkdfLabel.append(uint8(truncatingIfNeeded: (length >> 8) & 0xff))
    hkdfLabel.append(uint8(truncatingIfNeeded: length & 0xff))

    // 1-byte label length + label bytes
    hkdfLabel.append(uint8(truncatingIfNeeded: fullLabel.utf8.count))
    for b in fullLabel.utf8 {
        hkdfLabel.append(b)
    }

    // 1-byte context length + context bytes
    hkdfLabel.append(uint8(truncatingIfNeeded: context.count))
    var i = 0
    while i < context.count {
        hkdfLabel.append(context[i])
        i += 1
    }

    return hkdf.Expand(hash: .sha256, prk: secret, info: hkdfLabel, length: length)
}

/// DeriveSecret implements TLS 1.3 Derive-Secret(Secret, Label, Messages) (RFC 8446 Section 7.1).
public func DeriveSecret(secret: [uint8], label: string, transcriptHash: [uint8]) -> [uint8] {
    return HkdfExpandLabel(secret: secret, label: label, context: transcriptHash, length: 32)
}

/// Transcript tracks the running handshake hash using SHA-256.
public struct Transcript {
    var digest: sha256.Digest = sha256.Digest()

    public init() {}

    public mutating func Update(_ data: [uint8]) {
        digest.Write(data)
    }

    public func CurrentHash() -> [uint8] {
        return digest.Checksum()
    }
}

/// KeySchedule manages the derivation of TLS 1.3 secrets across handshake phases.
public struct KeySchedule {
    public var EarlySecret: [uint8]
    public var HandshakeSecret: [uint8]
    public var MasterSecret: [uint8]

    public init() {
        let zero32 = [uint8](repeating: 0, count: 32)
        self.EarlySecret = hkdf.Extract(hash: .sha256, secret: zero32, salt: zero32)
        self.HandshakeSecret = []
        self.MasterSecret = []
    }

    /// DeriveHandshakeSecret combines early secret and the shared X25519 secret.
    public mutating func DeriveHandshakeSecret(sharedSecret: [uint8]) {
        let emptyHash = sha256.Sum256("")
        let derived = DeriveSecret(secret: self.EarlySecret, label: "derived", transcriptHash: emptyHash)
        self.HandshakeSecret = hkdf.Extract(hash: .sha256, secret: sharedSecret, salt: derived)
    }

    /// DeriveHandshakeTrafficSecrets calculates client and server handshake traffic secrets.
    public func DeriveHandshakeTrafficSecrets(transcriptHash: [uint8]) -> TrafficSecrets {
        let client = DeriveSecret(secret: self.HandshakeSecret, label: "c hs traffic", transcriptHash: transcriptHash)
        let server = DeriveSecret(secret: self.HandshakeSecret, label: "s hs traffic", transcriptHash: transcriptHash)
        return TrafficSecrets(clientSecret: client, serverSecret: server)
    }

    /// DeriveTrafficKeys derives the key and 12-byte IV from a traffic
    /// secret: a 32-byte key for ChaCha20-Poly1305, 16 for AES-128-GCM.
    public func DeriveTrafficKeys(trafficSecret: [uint8], cipherSuite: uint16 = 0x1303) -> TrafficKeys {
        let key = HkdfExpandLabel(secret: trafficSecret, label: "key", context: [], length: KeyLength(cipherSuite))
        let iv = HkdfExpandLabel(secret: trafficSecret, label: "iv", context: [], length: 12)
        return TrafficKeys(key: key, iv: iv)
    }

    /// DeriveFinishedKey derives the 32-byte HMAC key for Finished verify_data.
    public func DeriveFinishedKey(trafficSecret: [uint8]) -> [uint8] {
        return HkdfExpandLabel(secret: trafficSecret, label: "finished", context: [], length: 32)
    }

    /// ComputeFinished calculates HMAC-SHA256(finishedKey, transcriptHash).
    public func ComputeFinished(finishedKey: [uint8], transcriptHash: [uint8]) -> [uint8] {
        return hmac.Compute(key: finishedKey, message: transcriptHash, hash: .sha256)
    }

    /// DeriveMasterSecret moves from handshake secret to master secret.
    public mutating func DeriveMasterSecret() {
        let zero32 = [uint8](repeating: 0, count: 32)
        let emptyHash = sha256.Sum256("")
        let derived = DeriveSecret(secret: self.HandshakeSecret, label: "derived", transcriptHash: emptyHash)
        self.MasterSecret = hkdf.Extract(hash: .sha256, secret: zero32, salt: derived)
    }

    /// DeriveApplicationTrafficSecrets derives client and server application traffic secrets.
    public func DeriveApplicationTrafficSecrets(transcriptHash: [uint8]) -> TrafficSecrets {
        let client = DeriveSecret(secret: self.MasterSecret, label: "c ap traffic", transcriptHash: transcriptHash)
        let server = DeriveSecret(secret: self.MasterSecret, label: "s ap traffic", transcriptHash: transcriptHash)
        return TrafficSecrets(clientSecret: client, serverSecret: server)
    }
}
