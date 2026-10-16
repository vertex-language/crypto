package main

import (
    "crypto/sha256"
    "crypto/tls"
    "time"
)

func rate(_ what: string, _ bytes: int, _ a: time.Instant) {
    let s = (time.Instant.Now() - a).AsSeconds()
    print("\(what)  \(int(float64(bytes) / s / 1_000_000)) MB/s  (\(int(s * 1000)) ms)")
}

func main() -> int32 {
    let mb = 16
    let chunk = [uint8](repeating: 0x5a, count: 16000)
    do {
        let big = [uint8](repeating: 7, count: 1 << 18)
        var h = sha256.Digest()
        var t = time.Instant.Now()
        for _ in 0..<(mb * 4) { h.Write(big) }
        _ = h.Checksum()
        rate("sha256          ", mb << 20, t)

        for suite in [uint16(0x1301), uint16(0x1303)] {
            let key = [uint8](repeating: 1, count: tls.KeyLength(suite))
            let iv = [uint8](repeating: 2, count: 12)
            var enc = tls.RecordCipher(key: key, iv: iv, cipherSuite: suite)
            var dec = tls.RecordCipher(key: key, iv: iv, cipherSuite: suite)
            var records: [[uint8]] = []
            let n = mb * 1048576 / 16000
            t = time.Instant.Now()
            for _ in 0..<n { records.append(try enc.Encrypt(contentType: 23, plaintext: chunk)) }
            rate(suite == 0x1301 ? "aes-gcm  seal   " : "chacha   seal   ", n * 16000, t)
            t = time.Instant.Now()
            for r in records {
                _ = try dec.Decrypt(header: Array(r[0..<5]), payload: Array(r[5..<r.count]))
            }
            rate(suite == 0x1301 ? "aes-gcm  open   " : "chacha   open   ", n * 16000, t)
        }
    } catch {
        print("\(error)")
        return 1
    }
    return 0
}
