package tls

import "net/tcp"
import "crypto/curve25519"
import "crypto/rand"
import "crypto/subtle"

/// Conn represents an established or in-progress TLS 1.3 encrypted connection over TCP.
public struct Conn {
    public var stream: tcp.TcpStream
    public var config: Config
    public var state: ConnectionState = ConnectionState()

    var clientCipher: RecordCipher = RecordCipher(key: [], iv: [])
    var serverCipher: RecordCipher = RecordCipher(key: [], iv: [])
    var readBuffer: [uint8] = []
    var readPos: int = 0

    public init(stream: tcp.TcpStream) {
        self.stream = stream
        self.config = Config()
        self.state = ConnectionState()
        self.clientCipher = RecordCipher(key: [], iv: [])
        self.serverCipher = RecordCipher(key: [], iv: [])
        self.readBuffer = []
    }

    public init(stream: tcp.TcpStream, config: Config) {
        self.stream = stream
        self.config = config
        self.state = ConnectionState()
        self.clientCipher = RecordCipher(key: [], iv: [])
        self.serverCipher = RecordCipher(key: [], iv: [])
        self.readBuffer = []
    }

    /// Handshake performs the full TLS 1.3 handshake with the remote peer.
    public mutating func Handshake() async throws {
        if self.state.HandshakeComplete {
            return
        }

        // 1. Generate client ephemeral private and public keys using Curve25519
        let clientPrivateKey = try rand.Bytes(32)
        let clientPublicKey = try curve25519.ScalarBaseMult(scalar: clientPrivateKey)

        // 2. Generate cryptographically secure client random and session ID
        let clientRandom = try rand.Bytes(32)
        let sessionId = try rand.Bytes(32)

        // 3. Build ClientHello message
        let clientHelloMsg = BuildClientHello(
            serverName: self.config.ServerName,
            clientRandom: clientRandom,
            sessionId: sessionId,
            clientPublicKey: clientPublicKey,
            alpnProtos: self.config.NextProtos
        )

        // 4. Initialize Handshake Transcript
        var transcript = Transcript()
        transcript.Update(clientHelloMsg)

        // 5. Wrap ClientHello into record and send to server
        let clientHelloRecord = WrapInRecord(contentType: RecordHandshake, payload: clientHelloMsg, legacyVersion: 0x0301)
        try await self.stream.Write(clientHelloRecord)

        // 6. Read ServerHello record
        var header = [uint8](repeating: 0, count: 5)
        try await self.stream.ReadFull(into: &header)

        // Handle optional middlebox compatibility ChangeCipherSpec record (RFC 8446 Section 5)
        if header[0] == RecordChangeCipherSpec {
            let ccsLen = (int(header[3]) << 8) | int(header[4])
            var ccsPayload = [uint8](repeating: 0, count: ccsLen)
            try await self.stream.ReadFull(into: &ccsPayload)
            try await self.stream.ReadFull(into: &header)
        }

        if header[0] != RecordHandshake {
            throw TlsError.unexpectedMessage("expected handshake record (22) for server hello, got \(header[0])")
        }

        let shLen = (int(header[3]) << 8) | int(header[4])
        var shPayload = [uint8](repeating: 0, count: shLen)
        try await self.stream.ReadFull(into: &shPayload)

        let shInfo = try ParseServerHello(shPayload)
        transcript.Update(shPayload)

        // 7. Derive Handshake Secrets & Traffic Keys
        let sharedSecret = try curve25519.ScalarMult(scalar: clientPrivateKey, point: shInfo.ServerPublicKey)
        var keySchedule = KeySchedule()
        keySchedule.DeriveHandshakeSecret(sharedSecret: sharedSecret)

        let hsTraffic = keySchedule.DeriveHandshakeTrafficSecrets(transcriptHash: transcript.CurrentHash())
        let clientHsKeys = keySchedule.DeriveTrafficKeys(trafficSecret: hsTraffic.ClientSecret, cipherSuite: shInfo.CipherSuite)
        let serverHsKeys = keySchedule.DeriveTrafficKeys(trafficSecret: hsTraffic.ServerSecret, cipherSuite: shInfo.CipherSuite)

        let serverFinishedKey = keySchedule.DeriveFinishedKey(trafficSecret: hsTraffic.ServerSecret)
        let clientFinishedKey = keySchedule.DeriveFinishedKey(trafficSecret: hsTraffic.ClientSecret)

        var clientHsCipher = RecordCipher(key: clientHsKeys.Key, iv: clientHsKeys.IV, cipherSuite: shInfo.CipherSuite)
        var serverHsCipher = RecordCipher(key: serverHsKeys.Key, iv: serverHsKeys.IV, cipherSuite: shInfo.CipherSuite)

        // 8. Read encrypted handshake records until Finished (type 20)
        var serverFinishedReceived = false
        var hsBuf: [uint8] = []

        while !serverFinishedReceived {
            try await self.stream.ReadFull(into: &header)

            if header[0] == RecordChangeCipherSpec {
                let ccsLen = (int(header[3]) << 8) | int(header[4])
                var ccsPayload = [uint8](repeating: 0, count: ccsLen)
                try await self.stream.ReadFull(into: &ccsPayload)
                continue
            }

            let recLen = (int(header[3]) << 8) | int(header[4])
            var encPayload = [uint8](repeating: 0, count: recLen)
            try await self.stream.ReadFull(into: &encPayload)

            let dec = try serverHsCipher.Decrypt(header: header, payload: encPayload)
            if dec.ContentType == RecordAlert {
                let code = dec.Data.count > 1 ? dec.Data[1] : 0
                throw TlsError.alertReceived("code \(code): alert received from server during handshake")
            }
            if dec.ContentType != RecordHandshake {
                throw TlsError.unexpectedMessage("expected handshake record in protected phase, got \(dec.ContentType)")
            }

            var d = 0
            while d < dec.Data.count {
                hsBuf.append(dec.Data[d])
                d += 1
            }

            while hsBuf.count >= 4 {
                let msgType = hsBuf[0]
                let msgLen = (int(hsBuf[1]) << 16) | (int(hsBuf[2]) << 8) | int(hsBuf[3])
                let totalLen = 4 + msgLen
                if hsBuf.count < totalLen {
                    break
                }

                var fullMsg = [uint8](repeating: 0, count: totalLen)
                var m = 0
                while m < totalLen {
                    fullMsg[m] = hsBuf[m]
                    m += 1
                }

                var remain: [uint8] = []
                var remIdx = totalLen
                while remIdx < hsBuf.count {
                    remain.append(hsBuf[remIdx])
                    remIdx += 1
                }
                hsBuf = remain

                if msgType == HandshakeEncryptedExtensions {
                    let alpn = ParseEncryptedExtensions(fullMsg)
                    if !alpn.isEmpty {
                        self.state.NegotiatedProtocol = alpn
                    }
                    transcript.Update(fullMsg)
                } else if msgType == HandshakeCertificate {
                    transcript.Update(fullMsg)
                } else if msgType == HandshakeCertificateVerify {
                    transcript.Update(fullMsg)
                } else if msgType == HandshakeFinished {
                    var serverVerifyData = [uint8](repeating: 0, count: msgLen)
                    var v = 0
                    while v < msgLen {
                        serverVerifyData[v] = fullMsg[4 + v]
                        v += 1
                    }
                    let expectedVerifyData = keySchedule.ComputeFinished(finishedKey: serverFinishedKey, transcriptHash: transcript.CurrentHash())
                    if subtle.ConstantTimeCompare(serverVerifyData, expectedVerifyData) != 1 {
                        throw TlsError.handshakeFailed("server finished verify_data mismatch")
                    }
                    transcript.Update(fullMsg)
                    serverFinishedReceived = true
                    break
                } else {
                    transcript.Update(fullMsg)
                }
            }
        }

        // 9. Send Client Finished message
        let clientVerifyData = keySchedule.ComputeFinished(finishedKey: clientFinishedKey, transcriptHash: transcript.CurrentHash())
        var clientFinishedMsg: [uint8] = []
        clientFinishedMsg.append(HandshakeFinished)
        clientFinishedMsg.append(0x00)
        clientFinishedMsg.append(0x00)
        clientFinishedMsg.append(uint8(truncatingIfNeeded: clientVerifyData.count))
        var cv = 0
        while cv < clientVerifyData.count {
            clientFinishedMsg.append(clientVerifyData[cv])
            cv += 1
        }

        let clientFinishedRecord = try clientHsCipher.Encrypt(contentType: RecordHandshake, plaintext: clientFinishedMsg)
        try await self.stream.Write(clientFinishedRecord)

        // 10. Transition to Application Traffic Secrets & Ciphers
        keySchedule.DeriveMasterSecret()
        let appTraffic = keySchedule.DeriveApplicationTrafficSecrets(transcriptHash: transcript.CurrentHash())
        let clientAppKeys = keySchedule.DeriveTrafficKeys(trafficSecret: appTraffic.ClientSecret, cipherSuite: shInfo.CipherSuite)
        let serverAppKeys = keySchedule.DeriveTrafficKeys(trafficSecret: appTraffic.ServerSecret, cipherSuite: shInfo.CipherSuite)

        self.clientCipher = RecordCipher(key: clientAppKeys.Key, iv: clientAppKeys.IV, cipherSuite: shInfo.CipherSuite)
        self.serverCipher = RecordCipher(key: serverAppKeys.Key, iv: serverAppKeys.IV, cipherSuite: shInfo.CipherSuite)

        self.state.HandshakeComplete = true
        self.state.ServerName = self.config.ServerName
        self.state.CipherSuite = shInfo.CipherSuite
        self.state.Version = VersionTLS13
    }

    /// Read reads decrypted application data into buffer.
    public mutating func Read(into buffer: inout [uint8]) async throws -> int {
        if !self.state.HandshakeComplete {
            try await self.Handshake()
        }
        if buffer.isEmpty {
            return 0
        }

        // A record's plaintext is kept whole and read from readPos on:
        // nothing is moved until the next record replaces it.
        while self.readPos >= self.readBuffer.count {
            var header = [uint8](repeating: 0, count: 5)
            let n = try await self.stream.Read(into: &header)
            if n == 0 {
                return 0
            }
            if n < 5 {
                var hRem = [uint8](repeating: 0, count: 5 - n)
                try await self.stream.ReadFull(into: &hRem)
                var idx = 0
                while idx < hRem.count {
                    header[n + idx] = hRem[idx]
                    idx += 1
                }
            }

            let recLen = (int(header[3]) << 8) | int(header[4])
            var encPayload = [uint8](repeating: 0, count: recLen)
            try await self.stream.ReadFull(into: &encPayload)

            let dec = try self.serverCipher.Decrypt(header: header, payload: encPayload)
            if dec.ContentType == RecordAlert {
                let code = dec.Data.count > 1 ? dec.Data[1] : 0
                if code == AlertCloseNotify {
                    return 0
                }
                throw TlsError.alertReceived("code \(code): alert received from server during read")
            }
            if dec.ContentType == RecordApplicationData {
                self.readBuffer = dec.Data
                self.readPos = 0
            }
            // Post-handshake messages (NewSessionTicket) are dropped.
        }

        let avail = self.readBuffer.count - self.readPos
        let count = buffer.count < avail ? buffer.count : avail
        let from = self.readPos
        buffer.withUnsafeMutableBufferPointer { dst in
            self.readBuffer.withUnsafeBufferPointer { src in
                var i = 0
                while i < count {
                    dst[i] = src[from + i]
                    i += 1
                }
            }
        }
        self.readPos += count
        return count
    }

    /// ReadFull reads until buffer is filled.
    public mutating func ReadFull(into buffer: inout [uint8]) async throws {
        let wanted = buffer.count
        var filled = 0
        var chunk = [uint8](repeating: 0, count: wanted)
        while filled < wanted {
            if chunk.count != wanted - filled {
                chunk = [uint8](repeating: 0, count: wanted - filled)
            }
            let n = try await self.Read(into: &chunk)
            if n == 0 {
                throw TlsError.closed("stream closed before buffer was filled")
            }
            let at = filled
            buffer.withUnsafeMutableBufferPointer { dst in
                chunk.withUnsafeBufferPointer { src in
                    var i = 0
                    while i < n {
                        dst[at + i] = src[i]
                        i += 1
                    }
                }
            }
            filled += n
        }
    }

    /// ReadToEnd reads until the remote peer closes the stream.
    public mutating func ReadToEnd(limit: int = 8 * 1024 * 1024) async throws -> [uint8] {
        var out: [uint8] = []
        var chunk = [uint8](repeating: 0, count: 4096)
        while true {
            let n = try await self.Read(into: &chunk)
            if n == 0 {
                return out
            }
            if out.count + n > limit {
                throw TlsError.recordOverflow("reading from TLS stream exceeded limit")
            }
            var i = 0
            while i < n {
                out.append(chunk[i])
                i += 1
            }
        }
    }

    /// Write encrypts and writes application data to the server.
    public mutating func Write(_ data: [uint8]) async throws {
        if !self.state.HandshakeComplete {
            try await self.Handshake()
        }

        let maxChunk = 16384
        var offset = 0
        while offset < data.count {
            let end = (offset + maxChunk < data.count) ? (offset + maxChunk) : data.count
            var chunk: [uint8] = []
            var i = offset
            while i < end {
                chunk.append(data[i])
                i += 1
            }

            let record = try self.clientCipher.Encrypt(contentType: RecordApplicationData, plaintext: chunk)
            try await self.stream.Write(record)
            offset = end
        }
    }

    /// WriteText encrypts and writes a string to the server.
    public mutating func WriteText(_ text: string) async throws {
        var bytes: [uint8] = []
        for b in text.utf8 {
            bytes.append(b)
        }
        try await self.Write(bytes)
    }

    /// Close closes the underlying TCP connection.
    public mutating func Close() {
        self.stream.Close()
    }

    /// GetConnectionState returns the negotiated session state.
    public func GetConnectionState() -> ConnectionState {
        return self.state
    }
}

/// Client wraps a connected TCP stream into a TLS client.
public func Client(_ stream: tcp.TcpStream, config: Config = Config()) -> Conn {
    return Conn(stream: stream, config: config)
}

/// Connect connects to host and port over TCP, then performs the TLS 1.3 handshake.
public func Connect(host: string, port: uint16, config: Config = Config()) async throws -> Conn {
    return try await Dial(host: host, port: port, config: config)
}

/// Dial connects to host and port over TCP, then performs the TLS 1.3 handshake.
public func Dial(host: string, port: uint16, config: Config = Config()) async throws -> Conn {
    var cfg = config
    if cfg.ServerName.isEmpty {
        cfg.ServerName = host
    }
    let stream = try await tcp.Connect(host: host, port: port)
    var conn = Conn(stream: stream, config: cfg)
    try await conn.Handshake()
    return conn
}

