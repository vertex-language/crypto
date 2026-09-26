// test-cert-live checks certificate verification against real servers:
// well-known sites connect with verification on, over TLS 1.3 and 1.2, and
// a real chain is refused for a host it is not for. Needs the network.
// (The broken chains are cmd/test-cert's, offline.)
package main

import (
    "crypto/cert"
    "crypto/tls"
    "net/tcp"
)

var failures = 0

func check(_ ok: bool, _ m: string) {
    if ok {
        print("ok    \(m)")
    } else {
        print("FAIL  \(m)")
        failures += 1
    }
}

// handshake connects to host:443 with verification on, over TLS 1.3 or,
// with tls12, TLS 1.2, and returns the error, or "" when it succeeded.
func handshake(_ host: string, tls12: bool) async -> string {
    do {
        if tls12 {
            let stream = try await tcp.Connect(host: host, port: 443)
            var conn = tls.Conn12(stream: stream, config: tls.Config(serverName: host))
            try await conn.Handshake()
            conn.Close()
        } else {
            var conn = try await tls.Dial(host: host, port: 443)
            conn.Close()
        }
        return ""
    } catch let e as tls.TlsError {
        return e.Message
    } catch let e as tls.Tls12Error {
        return e.Message
    } catch {
        return "\(error)"
    }
}

func main() async -> int32 {
    for host in ["huggingface.co", "www.google.com", "github.com"] {
        let err = await handshake(host, tls12: false)
        check(err.isEmpty, "TLS 1.3 to \(host) verifies" + (err.isEmpty ? "" : ": \(err)"))
    }
    let err12 = await handshake("huggingface.co", tls12: true)
    check(err12.isEmpty, "TLS 1.2 to huggingface.co verifies" + (err12.isEmpty ? "" : ": \(err12)"))

    // A real chain, checked for a name it is not for.
    do {
        var conn = try await tls.Dial(host: "huggingface.co", port: 443)
        let chain = conn.state.PeerCertificates
        conn.Close()
        check(chain.count >= 2, "huggingface.co sent its chain (\(chain.count) certificates)")
        do {
            try cert.VerifyChain(chain, host: "example.org")
            check(false, "huggingface.co's chain is refused for example.org")
        } catch let e as cert.CertError {
            switch e {
            case .nameMismatch: check(true, "huggingface.co's chain is refused for example.org (\(e.Message))")
            default: check(false, "huggingface.co's chain is refused for example.org as a name mismatch, not: \(e.Message)")
            }
        }
    } catch {
        check(false, "huggingface.co: \(error)")
    }

    if failures > 0 {
        print("\(failures) FAILURES")
        return 1
    }
    print("all live certificate tests passed")
    return 0
}
