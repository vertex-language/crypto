package dtls

import "crypto/sha256"

/// Computes the uppercase colon-delimited SHA-256 fingerprint of a DER certificate (RFC 8122).
/// E.g. "2B:04:D9:6A:..."
public func CalculateFingerprint(_ der: [uint8]) -> string {
    let hash = sha256.Sum256(der)
    let hexChars: [uint8] = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70] // 0-9, A-F
    var res: [uint8] = []
    var i = 0
    while i < hash.count {
        if i > 0 {
            res.append(58) // ':'
        }
        let b = hash[i]
        res.append(hexChars[int(b >> 4)])
        res.append(hexChars[int(b & 0x0F)])
        i += 1
    }
    return string(decoding: res, as: UTF8.self)
}

func normalizeFingerprint(_ s: string) -> string {
    var out: [uint8] = []
    for b in s.utf8 {
        if b >= 97 && b <= 102 { // 'a'...'f'
            out.append(b - 32)
        } else {
            out.append(b)
        }
    }
    return string(decoding: out, as: UTF8.self)
}

/// Verifies whether a certificate's SHA-256 fingerprint matches an SDP fingerprint attribute value.
public func VerifyFingerprint(_ der: [uint8], expectedFingerprint: string) -> bool {
    let computed = CalculateFingerprint(der)
    let normalizedExpected = normalizeFingerprint(expectedFingerprint)
    return computed == normalizedExpected
}
