package ntlm

import "crypto/hmac"

// Wrap signs and seals a message the way GSS_WrapEx does for NTLM: it
// returns the 16-byte signature followed by the sealed data. CredSSP uses
// this for the pubKeyAuth and authInfo tokens.
public func (c: inout Client) Wrap(_ message: [uint8]) -> [uint8] {
    let seq = c.Ctx.clientSeq
    // Checksum over the plaintext with the client signing key.
    var input = seqLE(seq)
    input.append(contentsOf: message)
    let mac = hmac.Compute(key: c.Ctx.clientSigningKey, message: input, hash: .md5)
    var checksum: [uint8] = []
    var i = 0
    while i < 8 { checksum.append(mac[i]); i += 1 }
    // Seal the message, then encrypt the checksum on the same RC4 stream.
    let sealed = c.Ctx.clientSeal.XORStream(message)
    let encChecksum = c.Ctx.clientSeal.XORStream(checksum)
    c.Ctx.clientSeq = seq &+ 1

    var sig: [uint8] = [0x01, 0x00, 0x00, 0x00]   // version 1, LE
    sig.append(contentsOf: encChecksum)
    sig.append(contentsOf: seqLE(seq))

    var out = sig
    out.append(contentsOf: sealed)
    return out
}

// Unwrap verifies and decrypts a token the server produced (signature ||
// sealed data), returning the plaintext.
public func (c: inout Client) Unwrap(_ token: [uint8]) throws -> [uint8] {
    if token.count < 16 { throw NtlmError.verify("short wrapped token") }
    var sealed: [uint8] = []
    var i = 16
    while i < token.count { sealed.append(token[i]); i += 1 }
    // Decrypt the message, then the signature's checksum, on the server
    // sealing stream (same order the server used to produce them).
    let message = c.Ctx.serverSeal.XORStream(sealed)
    let seq = c.Ctx.serverSeq
    var input = seqLE(seq)
    input.append(contentsOf: message)
    let mac = hmac.Compute(key: c.Ctx.serverSigningKey, message: input, hash: .md5)
    var checksum: [uint8] = []
    i = 0
    while i < 8 { checksum.append(mac[i]); i += 1 }
    let encChecksum = c.Ctx.serverSeal.XORStream(checksum)
    c.Ctx.serverSeq = seq &+ 1

    // Compare against the signature's checksum bytes (offset 4..12).
    var ok = token[0] == 0x01
    i = 0
    while i < 8 {
        if token[4 + i] != encChecksum[i] { ok = false }
        i += 1
    }
    if !ok { throw NtlmError.verify("wrapped token signature mismatch") }
    return message
}

func seqLE(_ v: uint32) -> [uint8] {
    return [uint8(truncatingIfNeeded: v), uint8(truncatingIfNeeded: v >> 8),
            uint8(truncatingIfNeeded: v >> 16), uint8(truncatingIfNeeded: v >> 24)]
}
