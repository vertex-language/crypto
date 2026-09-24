package tls

import "net/tcp"
import "crypto/rand"
import "crypto/curve25519"
import "crypto/cipher"
import "crypto/sha256"
import "crypto/sha512"
import "crypto/x509"
import "crypto/rsa"

let recTypeChangeCipherSpec: uint8 = 20
let recTypeAlert: uint8 = 21
let recTypeHandshake: uint8 = 22
let recTypeAppData: uint8 = 23
let ver12: uint16 = 0x0303

/// Conn12 is a TLS 1.2 client connection over a TCP stream.
public struct Conn12 {
    public var stream: tcp.TcpStream
    public var config: Config

    // Negotiated parameters.
    public var suite: uint16 = 0
    var useSHA384: bool = false
    var keyLen: int = 32

    var clientCipher: gcmRecord
    var serverCipher: gcmRecord
    var encryptedOut: bool = false
    var encryptedIn: bool = false

    // Plaintext buffer of received record payloads not yet consumed, and
    // the current record type being drained.
    var inBuf: [uint8] = []

    // Accumulated handshake messages (for the transcript / Finished hash).
    var transcript: [uint8] = []

    /// The server's leaf certificate, parsed. The caller applies its own
    /// trust policy (CredSSP also binds to its public key).
    public var PeerCertificate: x509.Certificate = x509.Certificate()
    public var PeerCertificateDER: [uint8] = []
    public var Handshaked: bool = false

    public init(stream: tcp.TcpStream, config: Config) {
        self.stream = stream
        self.config = config
        self.clientCipher = gcmRecord(gcm: try! cipher.GCM.New(key: [uint8](repeating: 0, count: 16)), fixedIV: [], seq: 0)
        self.serverCipher = gcmRecord(gcm: try! cipher.GCM.New(key: [uint8](repeating: 0, count: 16)), fixedIV: [], seq: 0)
    }

    func transcriptHash() -> [uint8] {
        return useSHA384 ? sha512.Sum384(transcript) : sha256.Sum256(transcript)
    }

    /// Handshake runs the full TLS 1.2 client handshake.
    public mutating func Handshake() async throws {
        // 1. Client ephemeral X25519 keys and random.
        let clientPriv = try rand.Bytes(32)
        let clientPub = try curve25519.ScalarBaseMult(scalar: clientPriv)
        let clientRandom = try rand.Bytes(32)

        // 2. ClientHello.
        let ch = buildClientHello(serverName: config.ServerName, clientRandom: clientRandom, keyShare: clientPub)
        addHandshake(ch)
        try await writePlaintextRecord(recTypeHandshake, ch)

        // 3. Read server flight up to ServerHelloDone.
        var serverRandom: [uint8] = []
        var serverPub: [uint8] = []
        var gotHello = false
        var gotCert = false
        var gotSKE = false
        var done = false
        while !done {
            let msg = try await readHandshakeMessage()
            addHandshake(msg.raw)
            switch msg.msgType {
            case hsServerHello:
                serverRandom = try parseServerHello(msg.body)
                gotHello = true
            case hsCertificate:
                try parseCertificate(msg.body)
                gotCert = true
            case hsServerKeyExchange:
                serverPub = try parseServerKeyExchange(msg.body, clientRandom: clientRandom, serverRandom: serverRandom)
                gotSKE = true
            case hsServerHelloDone:
                done = true
            default:
                throw Tls12Error.handshake("unexpected handshake message \(msg.msgType)")
            }
        }
        if !gotHello || !gotCert || !gotSKE {
            throw Tls12Error.handshake("server flight incomplete")
        }

        // 4. Shared secret and ClientKeyExchange.
        let shared = try curve25519.ScalarMult(scalar: clientPriv, point: serverPub)
        var cke: [uint8] = []
        cke.append(uint8(clientPub.count))
        cke.append(contentsOf: clientPub)
        let ckeMsg = handshakeMessage(hsClientKeyExchange, cke)
        addHandshake(ckeMsg)

        // 5. Master secret via extended master secret (RFC 7627).
        let sessionHash = transcriptHash()
        let master = prf12(secret: shared, label: "extended master secret",
                           seed: sessionHash, length: 48, useSHA384: useSHA384)

        // 6. Key block.
        var seed = serverRandom
        seed.append(contentsOf: clientRandom)
        let need = keyLen * 2 + 8
        let kb = prf12(secret: master, label: "key expansion", seed: seed, length: need, useSHA384: useSHA384)
        var off = 0
        let cKey = slice(kb, off, keyLen); off += keyLen
        let sKey = slice(kb, off, keyLen); off += keyLen
        let cIV = slice(kb, off, 4); off += 4
        let sIV = slice(kb, off, 4); off += 4
        self.clientCipher = gcmRecord(gcm: try cipher.GCM.New(key: cKey), fixedIV: cIV, seq: 0)
        self.serverCipher = gcmRecord(gcm: try cipher.GCM.New(key: sKey), fixedIV: sIV, seq: 0)

        // 7. Send ClientKeyExchange, ChangeCipherSpec, and encrypted Finished.
        try await writePlaintextRecord(recTypeHandshake, ckeMsg)
        try await writePlaintextRecord(recTypeChangeCipherSpec, [0x01])
        encryptedOut = true

        let clientVerify = prf12(secret: master, label: "client finished",
                                 seed: transcriptHash(), length: 12, useSHA384: useSHA384)
        let finishedMsg = handshakeMessage(hsFinished, clientVerify)
        addHandshake(finishedMsg)
        try await writeRecord(recTypeHandshake, finishedMsg)

        // 8. Read server ChangeCipherSpec then encrypted Finished.
        let expectedServerVerify = prf12(secret: master, label: "server finished",
                                         seed: transcriptHash(), length: 12, useSHA384: useSHA384)
        try await readServerChangeCipherSpec()
        encryptedIn = true
        let sfin = try await readHandshakeMessage()
        if sfin.msgType != hsFinished {
            throw Tls12Error.handshake("expected server Finished, got \(sfin.msgType)")
        }
        if !constEq(sfin.body, expectedServerVerify) {
            throw Tls12Error.verify("server Finished mismatch")
        }
        Handshaked = true
    }

    mutating func addHandshake(_ msg: [uint8]) {
        transcript.append(contentsOf: msg)
    }

    // --- record I/O ---

    mutating func writePlaintextRecord(_ contentType: uint8, _ payload: [uint8]) async throws {
        var rec: [uint8] = []
        rec.append(contentType)
        rec.append(uint8(truncatingIfNeeded: ver12 >> 8))
        rec.append(uint8(truncatingIfNeeded: ver12))
        rec.append(uint8(truncatingIfNeeded: payload.count >> 8))
        rec.append(uint8(truncatingIfNeeded: payload.count))
        rec.append(contentsOf: payload)
        try await stream.Write(rec)
    }

    mutating func writeRecord(_ contentType: uint8, _ payload: [uint8]) async throws {
        if !encryptedOut {
            try await writePlaintextRecord(contentType, payload)
            return
        }
        let sealed = try clientCipher.seal(contentType: contentType, version: ver12, plaintext: payload)
        try await writePlaintextRecord(contentType, sealed)
    }

    // readRawRecord reads one TLS record, returning (type, fragment). The
    // fragment is decrypted if we are in the encrypted phase.
    mutating func readRawRecord() async throws -> (uint8, [uint8]) {
        var header = [uint8](repeating: 0, count: 5)
        try await stream.ReadFull(into: &header)
        let contentType = header[0]
        let length = (int(header[3]) << 8) | int(header[4])
        var fragment = [uint8](repeating: 0, count: length)
        if length > 0 { try await stream.ReadFull(into: &fragment) }
        if contentType == recTypeAlert && !encryptedIn {
            if fragment.count >= 2 { throw Tls12Error.alert(fragment[1]) }
            throw Tls12Error.alert(0)
        }
        if encryptedIn && contentType != recTypeChangeCipherSpec {
            let pt = try serverCipher.open(contentType: contentType, version: ver12, fragment: fragment)
            if contentType == recTypeAlert {
                if pt.count >= 2 { throw Tls12Error.alert(pt[1]) }
                throw Tls12Error.alert(0)
            }
            return (contentType, pt)
        }
        return (contentType, fragment)
    }

    // readHandshakeMessage returns the next whole handshake message,
    // buffering record fragments and splitting on the 4-byte header.
    mutating func readHandshakeMessage() async throws -> (msgType: uint8, body: [uint8], raw: [uint8]) {
        while true {
            if inBuf.count >= 4 {
                let msgLen = (int(inBuf[1]) << 16) | (int(inBuf[2]) << 8) | int(inBuf[3])
                if inBuf.count >= 4 + msgLen {
                    let msgType = inBuf[0]
                    var raw: [uint8] = []
                    var i = 0
                    while i < 4 + msgLen { raw.append(inBuf[i]); i += 1 }
                    var body: [uint8] = []
                    i = 4
                    while i < 4 + msgLen { body.append(inBuf[i]); i += 1 }
                    var rest: [uint8] = []
                    i = 4 + msgLen
                    while i < inBuf.count { rest.append(inBuf[i]); i += 1 }
                    inBuf = rest
                    return (msgType: msgType, body: body, raw: raw)
                }
            }
            let (ct, frag) = try await readRawRecord()
            if ct != recTypeHandshake {
                throw Tls12Error.handshake("expected handshake record, got type \(ct)")
            }
            inBuf.append(contentsOf: frag)
        }
    }

    mutating func readServerChangeCipherSpec() async throws {
        // Any buffered handshake bytes should be empty here.
        let (ct, _) = try await readRawRecord()
        if ct != recTypeChangeCipherSpec {
            throw Tls12Error.handshake("expected ChangeCipherSpec, got type \(ct)")
        }
    }

    // --- application data ---

    /// Write sends application data as one or more encrypted records.
    public mutating func Write(_ data: [uint8]) async throws {
        var off = 0
        let maxChunk = 16384
        while off < data.count {
            var chunk: [uint8] = []
            var i = off
            while i < data.count && i < off + maxChunk { chunk.append(data[i]); i += 1 }
            try await writeRecord(recTypeAppData, chunk)
            off += maxChunk
        }
    }

    /// Read fills buffer with decrypted application data, returning the
    /// count. Returns 0 on clean close.
    public mutating func Read(into buffer: inout [uint8]) async throws -> int {
        if inBuf.count == 0 {
            do {
                let (ct, pt) = try await readRawRecord()
                if ct == recTypeAppData || ct == recTypeHandshake {
                    inBuf.append(contentsOf: pt)
                }
            } catch let e as Tls12Error {
                if case .alert(let d) = e {
                    if d == 0 { return 0 }   // close_notify
                }
                throw e
            }
        }
        var n = 0
        while n < buffer.count && n < inBuf.count {
            buffer[n] = inBuf[n]
            n += 1
        }
        var rest: [uint8] = []
        var i = n
        while i < inBuf.count { rest.append(inBuf[i]); i += 1 }
        inBuf = rest
        return n
    }

    public mutating func Close() {
        stream.Close()
    }
}

// --- parsing helpers ---

func slice(_ b: [uint8], _ off: int, _ n: int) -> [uint8] {
    var out: [uint8] = []
    var i = 0
    while i < n { out.append(b[off + i]); i += 1 }
    return out
}

func constEq(_ a: [uint8], _ b: [uint8]) -> bool {
    if a.count != b.count { return false }
    var d: uint8 = 0
    var i = 0
    while i < a.count { d |= a[i] ^ b[i]; i += 1 }
    return d == 0
}

func handshakeMessage(_ msgType: uint8, _ body: [uint8]) -> [uint8] {
    var out: [uint8] = []
    out.append(msgType)
    out.append(uint8(truncatingIfNeeded: body.count >> 16))
    out.append(uint8(truncatingIfNeeded: body.count >> 8))
    out.append(uint8(truncatingIfNeeded: body.count))
    out.append(contentsOf: body)
    return out
}
