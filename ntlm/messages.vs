package ntlm

import "encoding/binary"

struct challengeInfo {
    var serverChallenge: [uint8]
    var targetInfo: [uint8]
    var timestamp: [uint8]
    var flags: uint32
}

// parseChallenge reads a CHALLENGE_MESSAGE (type 2).
func parseChallenge(_ msg: [uint8]) throws -> challengeInfo {
    if msg.count < 48 { throw NtlmError.malformed("short CHALLENGE") }
    var r = binary.Reader(msg)
    do {
        let sig = try r.Bytes(8)
        var i = 0
        while i < 8 { if sig[i] != signature[i] { throw NtlmError.malformed("bad signature") }; i += 1 }
        let mtype = try r.U32LE()
        if mtype != 2 { throw NtlmError.malformed("not a CHALLENGE message") }
        // TargetName fields (len, maxlen, offset)
        let _ = try r.U16LE(); let _ = try r.U16LE(); let _ = try r.U32LE()
        let flags = try r.U32LE()
        let serverChallenge = try r.Bytes(8)
        let _ = try r.Bytes(8)   // reserved
        let tiLen = int(try r.U16LE())
        let _ = try r.U16LE()
        let tiOffset = int(try r.U32LE())

        var targetInfo: [uint8] = []
        if tiLen > 0 && tiOffset + tiLen <= msg.count {
            var j = 0
            while j < tiLen { targetInfo.append(msg[tiOffset + j]); j += 1 }
        }
        let timestamp = extractTimestamp(targetInfo)
        return challengeInfo(serverChallenge: serverChallenge, targetInfo: targetInfo,
                             timestamp: timestamp, flags: flags)
    } catch let e as NtlmError {
        throw e
    } catch {
        throw NtlmError.malformed("truncated CHALLENGE")
    }
}

// extractTimestamp finds the MsvAvTimestamp (AvId 7) in an AV pair list, or
// returns 8 zero bytes if absent.
func extractTimestamp(_ ti: [uint8]) -> [uint8] {
    var off = 0
    while off + 4 <= ti.count {
        let id = uint16(ti[off]) | (uint16(ti[off+1]) << 8)
        let len = int(ti[off+2]) | (int(ti[off+3]) << 8)
        off += 4
        if id == 0 { break }   // MsvAvEOL
        if id == 7 && off + 8 <= ti.count {
            var ts: [uint8] = []
            var i = 0
            while i < 8 { ts.append(ti[off + i]); i += 1 }
            return ts
        }
        off += len
    }
    return [0,0,0,0,0,0,0,0]
}

// augmentTargetInfo copies the server's AV pairs (dropping the EOL),
// appends an MsvAvFlags pair with the MIC bit (0x2) set, re-terminates
// with EOL, and adds 8 bytes of padding -- the layout a Windows client
// sends and the sspi reference implementation produces.
func augmentTargetInfo(_ ti: [uint8]) -> [uint8] {
    var out: [uint8] = []
    var off = 0
    while off + 4 <= ti.count {
        let id = uint16(ti[off]) | (uint16(ti[off+1]) << 8)
        let len = int(ti[off+2]) | (int(ti[off+3]) << 8)
        if id == 0 { break }   // drop the server's EOL; we re-add it
        var val: [uint8] = []
        var i = 0
        while i < len && off + 4 + i < ti.count { val.append(ti[off + 4 + i]); i += 1 }
        appendAV(&out, id, val)
        off += 4 + len
    }
    // MsvAvFlags with MESSAGE_INTEGRITY_CHECK (0x2), then EOL.
    appendAV(&out, 6, [0x02, 0x00, 0x00, 0x00])
    appendAV(&out, 0, [])
    // Trailing 8-byte padding (AvEOL + reserved), as sspi appends.
    var p = 0
    while p < 8 { out.append(0); p += 1 }
    return out
}

func appendAV(_ out: inout [uint8], _ id: uint16, _ value: [uint8]) {
    out.append(uint8(truncatingIfNeeded: id))
    out.append(uint8(truncatingIfNeeded: id >> 8))
    out.append(uint8(truncatingIfNeeded: value.count))
    out.append(uint8(truncatingIfNeeded: value.count >> 8))
    out.append(contentsOf: value)
}

// The AUTHENTICATE fixed header is 88 bytes (through the 16-byte MIC), so
// the variable payload begins there.
let authHeaderLen: int = 88
let micOffset: int = 72

// buildAuthenticate assembles an AUTHENTICATE_MESSAGE (type 3).
func buildAuthenticate(lmResponse: [uint8], ntResponse: [uint8],
                       domain: string, user: string, workstation: string,
                       encryptedSessionKey: [uint8], flags: uint32, mic: [uint8]) -> [uint8] {
    let domainU = binary.EncodeUTF16LE(domain)
    let userU = binary.EncodeUTF16LE(user)
    let wsU = binary.EncodeUTF16LE(workstation)

    // Payload layout after the header, in this order.
    var payload: [uint8] = []
    let base = authHeaderLen
    let domainOff = base + payload.count; payload.append(contentsOf: domainU)
    let userOff = base + payload.count; payload.append(contentsOf: userU)
    let wsOff = base + payload.count; payload.append(contentsOf: wsU)
    let lmOff = base + payload.count; payload.append(contentsOf: lmResponse)
    let ntOff = base + payload.count; payload.append(contentsOf: ntResponse)
    let skOff = base + payload.count; payload.append(contentsOf: encryptedSessionKey)

    var w = binary.Writer()
    w.Append(signature)
    w.U32LE(3)
    field(&w, lmResponse.count, lmOff)
    field(&w, ntResponse.count, ntOff)
    field(&w, domainU.count, domainOff)
    field(&w, userU.count, userOff)
    field(&w, wsU.count, wsOff)
    field(&w, encryptedSessionKey.count, skOff)
    w.U32LE(flags)
    // Version (8)
    w.U8(10); w.U8(0); w.U16LE(19041); w.U8(0); w.U8(0); w.U8(0); w.U8(15)
    // MIC (16)
    w.Append(mic)
    w.Append(payload)
    return w.Bytes
}

func field(_ w: inout binary.Writer, _ len: int, _ offset: int) {
    w.U16LE(uint16(truncatingIfNeeded: len))
    w.U16LE(uint16(truncatingIfNeeded: len))
    w.U32LE(uint32(truncatingIfNeeded: offset))
}

func patchMIC(_ auth: inout [uint8], _ mic: [uint8]) {
    var i = 0
    while i < 16 && micOffset + i < auth.count {
        auth[micOffset + i] = mic[i]
        i += 1
    }
}

/// ChallengeNames returns the server's NetBIOS domain and computer names
/// from a CHALLENGE_MESSAGE's target info (for choosing a logon domain).
public func ChallengeNames(_ msg: [uint8]) -> (nbDomain: string, nbComputer: string) {
    var nbDomain = ""
    var nbComputer = ""
    do {
        let ch = try parseChallenge(msg)
        var off = 0
        let ti = ch.targetInfo
        while off + 4 <= ti.count {
            let id = uint16(ti[off]) | (uint16(ti[off+1]) << 8)
            let len = int(ti[off+2]) | (int(ti[off+3]) << 8)
            off += 4
            if id == 0 { break }
            if off + len <= ti.count {
                var val: [uint8] = []
                var i = 0
                while i < len { val.append(ti[off + i]); i += 1 }
                let s = binary.DecodeUTF16LE(val)
                if id == 2 { nbDomain = s }
                if id == 1 { nbComputer = s }
            }
            off += len
        }
    } catch {
    }
    return (nbDomain: nbDomain, nbComputer: nbComputer)
}
