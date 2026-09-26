package main

import "crypto/tls"
import "crypto/subtle"
import "crypto/sha256"

var failures = 0

func check(_ ok: bool, _ msg: string) {
    if ok {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func bytesEqual(_ a: [uint8], _ b: [uint8]) -> bool {
    if a.count != b.count {
        return false
    }
    var i = 0
    while i < a.count {
        if a[i] != b[i] {
            return false
        }
        i += 1
    }
    return true
}

func testHkdfExpandLabel() {
    print("=== tls: key schedule & HKDF-Expand-Label ===")
    let secret = [uint8](repeating: 0x55, count: 32)
    let context = [uint8](repeating: 0xaa, count: 32)
    let derived = tls.HkdfExpandLabel(secret: secret, label: "c hs traffic", context: context, length: 32)
    check(derived.count == 32, "HkdfExpandLabel length 32")

    let derived2 = tls.HkdfExpandLabel(secret: secret, label: "c hs traffic", context: context, length: 32)
    check(bytesEqual(derived, derived2), "HkdfExpandLabel is deterministic")

    let derivedIv = tls.HkdfExpandLabel(secret: secret, label: "iv", context: [], length: 12)
    check(derivedIv.count == 12, "HkdfExpandLabel length 12 for IV")
}

func testKeySchedule() {
    var ks = tls.KeySchedule()
    check(ks.EarlySecret.count == 32, "EarlySecret initialized (32 bytes)")

    let dummyShared = [uint8](repeating: 0x42, count: 32)
    ks.DeriveHandshakeSecret(sharedSecret: dummyShared)
    check(ks.HandshakeSecret.count == 32, "HandshakeSecret derived (32 bytes)")

    let transcriptHash = sha256.Sum256("hello transcript")
    let hsTraffic = ks.DeriveHandshakeTrafficSecrets(transcriptHash: transcriptHash)
    check(hsTraffic.ClientSecret.count == 32, "client handshake traffic secret (32 bytes)")
    check(hsTraffic.ServerSecret.count == 32, "server handshake traffic secret (32 bytes)")
    check(!bytesEqual(hsTraffic.ClientSecret, hsTraffic.ServerSecret), "client and server secrets are distinct")

    let clientKeys = ks.DeriveTrafficKeys(trafficSecret: hsTraffic.ClientSecret)
    check(clientKeys.Key.count == 32, "client traffic key length 32")
    check(clientKeys.IV.count == 12, "client traffic IV length 12")

    let finishedKey = ks.DeriveFinishedKey(trafficSecret: hsTraffic.ClientSecret)
    check(finishedKey.count == 32, "client finished key length 32")

    let finishedData = ks.ComputeFinished(finishedKey: finishedKey, transcriptHash: transcriptHash)
    check(finishedData.count == 32, "finished verify_data length 32")

    ks.DeriveMasterSecret()
    check(ks.MasterSecret.count == 32, "MasterSecret derived (32 bytes)")

    let appTraffic = ks.DeriveApplicationTrafficSecrets(transcriptHash: transcriptHash)
    check(appTraffic.ClientSecret.count == 32, "client app traffic secret (32 bytes)")
    check(appTraffic.ServerSecret.count == 32, "server app traffic secret (32 bytes)")
}

func testRecordLayer() {
    print("=== tls: record layer protected AEAD ===")
    let key = [uint8](repeating: 0x33, count: 32)
    let iv = [uint8](repeating: 0x77, count: 12)

    var encCipher = tls.RecordCipher(key: key, iv: iv)
    var decCipher = tls.RecordCipher(key: key, iv: iv)

    var plaintext: [uint8] = []
    for b in "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8 {
        plaintext.append(b)
    }

    do {
        // Record 1: Application Data
        let record = try encCipher.Encrypt(contentType: tls.RecordType.ApplicationData, plaintext: plaintext)
        check(record.count == 5 + plaintext.count + 1 + 16, "record length = 5 (hdr) + plaintext + 1 (type) + 16 (tag)")
        check(record[0] == tls.RecordType.ApplicationData, "record outer type is 23")
        check(record[1] == 0x03 && record[2] == 0x03, "record legacy version is 0x0303")

        var hdr: [uint8] = []
        var i = 0
        while i < 5 { hdr.append(record[i]); i += 1 }
        var payload: [uint8] = []
        while i < record.count { payload.append(record[i]); i += 1 }

        let dec = try decCipher.Decrypt(header: hdr, payload: payload)
        check(dec.ContentType == tls.RecordType.ApplicationData, "decrypted content type is 23")
        check(bytesEqual(dec.Data, plaintext), "decrypted plaintext matches original")

        // Record 2: Next record with incremented sequence number
        var plaintext2: [uint8] = []
        for b in "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".utf8 { plaintext2.append(b) }

        let record2 = try encCipher.Encrypt(contentType: tls.RecordType.ApplicationData, plaintext: plaintext2)
        var hdr2: [uint8] = []
        i = 0
        while i < 5 { hdr2.append(record2[i]); i += 1 }
        var payload2: [uint8] = []
        while i < record2.count { payload2.append(record2[i]); i += 1 }

        let dec2 = try decCipher.Decrypt(header: hdr2, payload: payload2)
        check(bytesEqual(dec2.Data, plaintext2), "second record with seq=1 decrypted successfully")

        // Record 3: Tampered record should fail authentication
        var tamperedPayload = payload2
        tamperedPayload[0] ^= 0xff
        var tamperedFailed = false
        do {
            _ = try decCipher.Decrypt(header: hdr2, payload: tamperedPayload)
        } catch {
            tamperedFailed = true
        }
        check(tamperedFailed, "tampered record fails AEAD tag verification")
    } catch {
        check(false, "record layer exception thrown")
    }
}

func testClientHello() {
    print("=== tls: client hello construction ===")
    let clientRandom = [uint8](repeating: 0x01, count: 32)
    let sessionId = [uint8](repeating: 0x02, count: 32)
    let clientPubKey = [uint8](repeating: 0x03, count: 32)

    let ch = tls.BuildClientHello(
        serverName: "example.com",
        clientRandom: clientRandom,
        sessionId: sessionId,
        clientPublicKey: clientPubKey,
        alpnProtos: ["http/1.1"]
    )

    check(ch.count > 100, "ClientHello message size > 100 bytes")
    check(ch[0] == tls.HandshakeType.ClientHello, "Handshake type is ClientHello (1)")

    let wrapped = tls.WrapInRecord(contentType: tls.RecordType.Handshake, payload: ch, legacyVersion: 0x0301)
    check(wrapped.count == 5 + ch.count, "wrapped record has 5-byte header")
    check(wrapped[0] == tls.RecordType.Handshake, "wrapped record content type is 22")
    check(wrapped[1] == 0x03 && wrapped[2] == 0x01, "wrapped legacy version is 0x0301")
}

func testServerHello() {
    print("=== tls: server hello parsing ===")
    var shMsg: [uint8] = []
    shMsg.append(tls.HandshakeType.ServerHello)
    // 3-byte length placeholder
    shMsg.append(0x00)
    shMsg.append(0x00)
    shMsg.append(0x00)

    // Legacy version 0x0303
    shMsg.append(0x03)
    shMsg.append(0x03)

    // Server random (32 bytes)
    var r = 0
    while r < 32 {
        shMsg.append(uint8(truncatingIfNeeded: r + 1))
        r += 1
    }

    // Session ID length 0
    shMsg.append(0x00)

    // CipherSuite: 0x1303
    shMsg.append(0x13)
    shMsg.append(0x03)

    // Legacy compression
    shMsg.append(0x00)

    // Extensions
    var exts: [uint8] = []
    // supported_versions (0x002b) -> 0x0304
    exts.append(0x00); exts.append(0x2b)
    exts.append(0x00); exts.append(0x02)
    exts.append(0x03); exts.append(0x04)

    // key_share (0x0033) -> group 0x001d + 32-byte key
    exts.append(0x00); exts.append(0x33)
    exts.append(0x00); exts.append(0x24) // 36 bytes
    exts.append(0x00); exts.append(0x1d) // X25519
    exts.append(0x00); exts.append(0x20) // 32 bytes
    var k = 0
    while k < 32 {
        exts.append(uint8(truncatingIfNeeded: 0x50 + k))
        k += 1
    }

    shMsg.append(uint8(truncatingIfNeeded: (exts.count >> 8) & 0xff))
    shMsg.append(uint8(truncatingIfNeeded: exts.count & 0xff))
    var e = 0
    while e < exts.count {
        shMsg.append(exts[e])
        e += 1
    }

    // Fix length
    let bodyLen = shMsg.count - 4
    shMsg[1] = uint8(truncatingIfNeeded: (bodyLen >> 16) & 0xff)
    shMsg[2] = uint8(truncatingIfNeeded: (bodyLen >> 8) & 0xff)
    shMsg[3] = uint8(truncatingIfNeeded: bodyLen & 0xff)

    do {
        let info = try tls.ParseServerHello(shMsg)
        check(info.CipherSuite == tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "ServerHello cipher suite is 0x1303")
        check(info.ServerRandom.count == 32, "ServerHello random has 32 bytes")
        check(info.ServerPublicKey.count == 32, "ServerHello public key has 32 bytes")
        check(info.ServerPublicKey[0] == 0x50, "ServerHello public key matches payload")
    } catch {
        check(false, "ParseServerHello threw error")
    }
}

func main() -> int32 {
    print("Running crypto/tls unit test suite...")
    testHkdfExpandLabel()
    testKeySchedule()
    testRecordLayer()
    testClientHello()
    testServerHello()

    if failures == 0 {
        print("\n=== all crypto/tls checks passed ===")
        return 0
    } else {
        print("\n=== \(failures) crypto/tls checks failed ===")
        return 1
    }
}
