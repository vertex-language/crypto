package main
import (
    "crypto/credssp"
    "crypto/tls"
    "net/tcp"
    "os/env"
)

func main() async -> int32 {
    guard let host = env.Get("RDP_HOST"), !host.isEmpty else {
        print("SKIP: RDP_HOST not set (set RDP_HOST, RDP_USER, RDP_PASSWORD to run live NLA test)")
        return 0
    }
    let user = env.Get("RDP_USER") ?? "testuser"
    guard let password = env.GetBytes("RDP_PASSWORD"), !password.isEmpty else {
        print("SKIP: RDP_PASSWORD not set (set RDP_PASSWORD to run live NLA test)")
        return 0
    }
    let domain = env.Get("RDP_DOMAIN") ?? ""
    print("Full NLA login to \(host):3389")
    do {
        var stream = try await tcp.Connect(host: host, port: 3389, timeoutMs: 8000)
        // X.224: request SSL|HYBRID|HYBRID_EX
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

        var conn = tls.Conn12(stream: stream, config: tls.Config(serverName: host, insecureSkipVerify: false))
        try await conn.Handshake()
        print("  TLS up (\(conn.PeerCertificate.Subject)), running CredSSP...")

        let creds = credssp.Credentials(domain: domain, user: user, password: password, host: host,
                                        subjectPublicKey: conn.PeerCertificate.RawSubjectPublicKey)
        try await credssp.Authenticate(conn: &conn, creds: creds)
        print("LOGIN OK: NLA authentication succeeded")
        conn.Close()
        return 0
    } catch {
        print("FAIL: \(error)")
        return 1
    }
}
