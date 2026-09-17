package hkdf

import "crypto/hmac"

func hashLength(_ alg: hmac.HashAlgorithm) -> int {
    switch alg {
    case .sha256:
        return 32
    case .sha224:
        return 28
    }
}

/// Extract generates a pseudorandom key (PRK) from the input keying material (secret)
/// and an optional salt according to RFC 5869 Section 2.2.
public func Extract(hash: hmac.HashAlgorithm = .sha256,
                    secret: [uint8],
                    salt: [uint8] = []) -> [uint8] {
    let hLen = hashLength(hash)
    var s = salt
    if s.isEmpty {
        s = [uint8](repeating: 0, count: hLen)
    }
    return hmac.Compute(key: s, message: secret, hash: hash)
}

/// Expand expands the pseudorandom key (PRK) using info and requested output length
/// according to RFC 5869 Section 2.3.
public func Expand(hash: hmac.HashAlgorithm = .sha256,
                   prk: [uint8],
                   info: [uint8],
                   length: int) -> [uint8] {
    let hLen = hashLength(hash)
    if length > 255 * hLen {
        return []
    }

    var okm: [uint8] = []
    var t: [uint8] = []
    var counter: uint8 = 1

    while okm.count < length {
        var input: [uint8] = []
        var ti = 0
        while ti < t.count {
            input.append(t[ti])
            ti += 1
        }
        var inf = 0
        while inf < info.count {
            input.append(info[inf])
            inf += 1
        }
        input.append(counter)

        t = hmac.Compute(key: prk, message: input, hash: hash)

        var j = 0
        while j < t.count && okm.count < length {
            okm.append(t[j])
            j += 1
        }

        counter &+= 1
    }

    return okm
}

/// Expand expands the pseudorandom key (PRK) using a string info.
public func Expand(hash: hmac.HashAlgorithm = .sha256,
                   prk: [uint8],
                   info: string,
                   length: int) -> [uint8] {
    var bytes: [uint8] = []
    for b in info.utf8 {
        bytes.append(b)
    }
    return Expand(hash: hash, prk: prk, info: bytes, length: length)
}

/// DeriveKey combines Extract and Expand into a single step.
public func DeriveKey(hash: hmac.HashAlgorithm = .sha256,
                      secret: [uint8],
                      salt: [uint8] = [],
                      info: [uint8] = [],
                      length: int) -> [uint8] {
    let prk = Extract(hash: hash, secret: secret, salt: salt)
    return Expand(hash: hash, prk: prk, info: info, length: length)
}
