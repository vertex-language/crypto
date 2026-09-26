package main

import (
    "crypto/dtls"
    "crypto/sha256"
)

var failures = 0

func check(_ ok: bool, _ msg: string) {
    if ok {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func testReplayWindow() {
    print("=== dtls: anti-replay window ===")
    var win = dtls.AntiReplayWindow()

    check(win.Update(0), "replay: first packet 0 accepted")
    check(!win.Update(0), "replay: duplicate packet 0 rejected")
    check(win.Update(1), "replay: packet 1 accepted")
    check(win.Update(2), "replay: packet 2 accepted")
    check(win.Update(3), "replay: packet 3 accepted")
    check(!win.Update(2), "replay: duplicate packet 2 rejected")

    // Advance window to sequence 20
    check(win.Update(20), "replay: packet 20 accepted (advances window)")
    check(!win.Update(20), "replay: duplicate packet 20 rejected")
    check(win.Update(15), "replay: packet 15 accepted (within window 20-64)")
    check(!win.Update(15), "replay: duplicate packet 15 rejected")

    // Large jump: advance to sequence 100
    check(win.Update(100), "replay: packet 100 accepted (large advance)")
    // Packet 20 is now (100 - 20 = 80 >= 64), so it must be rejected as too old
    check(!win.Update(20), "replay: packet 20 rejected as outside left edge of window")
    check(win.Update(95), "replay: packet 95 accepted (within window 100-64)")

    // Reset window
    win.Reset()
    check(win.Update(5), "replay: packet 5 accepted after reset")
}

func testRecordProtection() {
    print("=== dtls: datagram record protection ===")
    let key: [uint8] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    ]
    let iv: [uint8] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab
    ]

    var enc = dtls.RecordCipher(key: key, iv: iv, epoch: 1)
    var dec = dtls.RecordCipher(key: key, iv: iv, epoch: 1)

    let msg = "WebRTC DataChannel over DTLS 1.3"
    var plaintext: [uint8] = []
    for b in msg.utf8 { plaintext.append(b) }

    do {
        let record = try enc.Encrypt(contentType: dtls.ContentType.ApplicationData, plaintext: plaintext)

        // Verify header size and structure
        check(record.count == 13 + plaintext.count + 1 + 16, "dtls record: total length matches header + inner + tag")
        check(record[0] == dtls.ContentType.ApplicationData, "dtls record: outer content type is 23")
        check(record[1] == 0xFE && record[2] == 0xFD, "dtls record: version is DTLS 1.2 legacy wire format")
        check(record[3] == 0x00 && record[4] == 0x01, "dtls record: epoch is 1")
        check(record[10] == 0x00, "dtls record: first sequence number is 0")

        // Decrypt
        let opened = try dec.Decrypt(record: record)
        check(opened.ContentType == dtls.ContentType.ApplicationData, "dtls record: decrypted inner content type matches")
        check(opened.Epoch == 1, "dtls record: decrypted epoch matches")
        check(opened.SequenceNumber == 0, "dtls record: decrypted sequence number matches")
        check(opened.Data.count == plaintext.count, "dtls record: decrypted plaintext count matches")
        check(string(decoding: opened.Data, as: UTF8.self) == msg, "dtls record: decrypted text matches original")

        // Enforce anti-replay on records
        var replayCaught = false
        do {
            _ = try dec.Decrypt(record: record)
        } catch {
            replayCaught = true
        }
        check(replayCaught, "dtls record: replay of identical record caught and rejected")

        // Second record
        let record2 = try enc.Encrypt(contentType: dtls.ContentType.Handshake, plaintext: [10, 20, 30])
        let opened2 = try dec.Decrypt(record: record2)
        check(opened2.ContentType == dtls.ContentType.Handshake, "dtls record: second record content type is Handshake")
        check(opened2.SequenceNumber == 1, "dtls record: second record sequence number is 1")
        check(opened2.Data.count == 3 && opened2.Data[1] == 20, "dtls record: second record payload matches")

        // Tamper detection: flip a byte in ciphertext
        var tampered = record2
        tampered[15] ^= 0xFF
        var tamperCaught = false
        do {
            _ = try dec.Decrypt(record: tampered)
        } catch {
            tamperCaught = true
        }
        check(tamperCaught, "dtls record: tampered record rejected by AEAD authentication")

    } catch {
        check(false, "dtls record: exception during record test")
    }
}

func testSrtpKeyDerivation() {
    print("=== dtls: RFC 5764 DTLS-SRTP key derivation ===")
    let exporterSecret = [uint8](repeating: 0x42, count: 32)
    let keys = dtls.DeriveSrtpKeys(exporterSecret: exporterSecret, keyLength: 16, saltLength: 14)

    check(keys.ClientWriteKey.count == 16, "srtp: client write key length is 16 bytes")
    check(keys.ServerWriteKey.count == 16, "srtp: server write key length is 16 bytes")
    check(keys.ClientWriteSalt.count == 14, "srtp: client write salt length is 14 bytes")
    check(keys.ServerWriteSalt.count == 14, "srtp: server write salt length is 14 bytes")

    // Ensure client and server keys are distinct
    var different = false
    var i = 0
    while i < 16 {
        if keys.ClientWriteKey[i] != keys.ServerWriteKey[i] {
            different = true
            break
        }
        i += 1
    }
    check(different, "srtp: client and server keys are distinct")
}

func testFingerprint() {
    print("=== dtls: certificate fingerprint (RFC 8122) ===")
    let sampleCert: [uint8] = [
        0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xb4, 0x31, 0x15, 0x03, 0x02, 0x01, 0x02
    ]
    let fp = dtls.CalculateFingerprint(sampleCert)
    check(!fp.isEmpty, "fingerprint: non-empty fingerprint generated")

    // Verify format: XX:XX:...
    var colons = 0
    for b in fp.utf8 {
        if b == 58 { colons += 1 }
    }
    check(colons == 31, "fingerprint: SHA-256 fingerprint contains exactly 31 colons (32 hex octets)")

    check(dtls.VerifyFingerprint(sampleCert, expectedFingerprint: fp), "fingerprint: VerifyFingerprint exact match")

    var lowerBytes: [uint8] = []
    for b in fp.utf8 {
        if b >= 65 && b <= 70 {
            lowerBytes.append(b + 32)
        } else {
            lowerBytes.append(b)
        }
    }
    let lowerFp = string(decoding: lowerBytes, as: UTF8.self)
    check(dtls.VerifyFingerprint(sampleCert, expectedFingerprint: lowerFp), "fingerprint: VerifyFingerprint case-insensitive match")
}

func testHandshake() {
    print("\n=== Testing Handshake Framing and Hello Negotiation ===")

    let dummyPayload: [uint8] = [1, 2, 3, 4, 5]
    let wrapped = dtls.WrapDtlsHandshake(type: dtls.HandshakeType.ClientHello, body: dummyPayload, messageSeq: 7)
    check(wrapped.count == 12 + dummyPayload.count, "handshake: wrapped size is 12-byte header + body")
    check(wrapped[0] == dtls.HandshakeType.ClientHello, "handshake: header msg_type correct")
    check(wrapped[4] == 0 && wrapped[5] == 7, "handshake: message_seq 7 encoded correctly")

    let parsed = dtls.ParseDtlsHandshake(data: wrapped)
    check(parsed.Ok, "handshake: parsed successfully")
    check(parsed.Message.Type == dtls.HandshakeType.ClientHello, "handshake: parsed type matches")
    check(parsed.Message.MessageSeq == 7, "handshake: parsed message_seq matches")
    check(parsed.Message.Body.count == dummyPayload.count, "handshake: parsed body count matches")

    // Client Hello & Server Hello
    do {
        let clientPriv = [uint8](repeating: 0x01, count: 32)
        let clientPub = try curve25519.ScalarBaseMult(clientPriv)
        let serverPriv = [uint8](repeating: 0x02, count: 32)
        let serverPub = try curve25519.ScalarBaseMult(serverPriv)

        let chRand = [uint8](repeating: 0xaa, count: 32)
        let chBody = dtls.BuildDtlsClientHello(random: chRand, sessionId: [1, 2, 3], cookie: [], publicKey: clientPub, srtpProfiles: [0x0001])
        let chParsed = dtls.ParseDtlsClientHello(body: chBody)
        check(chParsed.PublicKey.count == 32, "client hello: parsed 32-byte public key")
        check(chParsed.SrtpProfile == 0x0001, "client hello: parsed SRTP profile 0x0001")

        let shRand = [uint8](repeating: 0xbb, count: 32)
        let shBody = dtls.BuildDtlsServerHello(random: shRand, sessionId: [1, 2, 3], cipherSuite: 0x1303, publicKey: serverPub, srtpProfile: 0x0001)
        let shParsed = dtls.ParseDtlsServerHello(body: shBody)
        check(shParsed.CipherSuite == 0x1303, "server hello: parsed cipher suite 0x1303")
        check(shParsed.PublicKey.count == 32, "server hello: parsed 32-byte public key")
        check(shParsed.SrtpProfile == 0x0001, "server hello: parsed SRTP profile 0x0001")

        // Curve25519 DH key exchange
        let clientShared = try curve25519.ScalarMult(scalar: clientPriv, point: shParsed.PublicKey)
        let serverShared = try curve25519.ScalarMult(scalar: serverPriv, point: chParsed.PublicKey)
        check(clientShared == serverShared, "handshake: client and server derive identical shared secret")
    } catch {
        check(false, "handshake: curve25519 error")
    }
}

func main() -> int32 {
    testReplayWindow()
    testRecordProtection()
    testSrtpKeyDerivation()
    testFingerprint()
    testHandshake()

    if failures == 0 {
        print("\nAll crypto/dtls tests passed!")
        return 0
    } else {
        print("\n\(failures) tests failed in crypto/dtls")
        return int32(failures)
    }
}

