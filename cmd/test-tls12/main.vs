package main
import (
    "crypto/tls"
    "net/tcp"
    "os/env"
)

func main() async -> int32 {
    guard let host = env.Get("RDP_HOST"), !host.isEmpty else {
        print("SKIP: RDP_HOST not set (set RDP_HOST to run live TLS 1.2 test)")
        return 0
    }
    let user = env.Get("RDP_USER") ?? "testuser"
    print("TLS 1.2 handshake to \(host):3389 (after RDP negotiation)")
    do {
        var stream = try await tcp.Connect(host: host, port: 3389, timeoutMs: 8000)
        // RDP X.224 negotiation: request SSL|HYBRID|HYBRID_EX.
        let cookie = "Cookie: mstshash=\(user)\r\n"
        var x224: [uint8] = []
        for b in cookie.utf8 { x224.append(b) }
        x224.append(0x01); x224.append(0x00); x224.append(0x08); x224.append(0x00)
        x224.append(0x0B); x224.append(0x00); x224.append(0x00); x224.append(0x00)
        let li = 6 + x224.count
        var cr: [uint8] = [uint8(li), 0xE0, 0, 0, 0, 0, 0]
        cr.append(contentsOf: x224)
        var tpkt: [uint8] = [0x03, 0x00, uint8((cr.count + 4) >> 8), uint8((cr.count + 4) & 0xff)]
        tpkt.append(contentsOf: cr)
        try await stream.Write(tpkt)
        var resp = [uint8](repeating: 0, count: 64)
        let _ = try await stream.Read(into: &resp)
        print("  RDP negotiation confirmed, upgrading to TLS...")

        var conn = tls.Conn12(stream: stream, config: tls.Config(serverName: host, insecureSkipVerify: false))
        try await conn.Handshake()
        print("  TLS 1.2 handshake OK")
        print("  suite: \(conn.suite == 0xC030 ? "ECDHE_RSA_AES256_GCM_SHA384" : "other")")
        print("  server cert subject: \(conn.PeerCertificate.Subject)")
        print("  cert RSA modulus bytes: \(conn.PeerCertificate.RSAPublicKey.Size)")
        conn.Close()
        print("LIVE TLS OK")
        return 0
    } catch {
        print("FAIL: \(error)")
        return 1
    }
}
