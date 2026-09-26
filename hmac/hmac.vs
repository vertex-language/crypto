package hmac

import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/subtle"
)

public enum HashAlgorithm {
    case sha256
    case sha224
    case sha1
    case md5
    case sha384
    case sha512
}

func hashBlockSize(_ alg: HashAlgorithm) -> int {
    switch alg {
    case .sha256, .sha224, .sha1, .md5:
        return 64
    case .sha384, .sha512:
        return 128
    }
}

func hashFunc(_ alg: HashAlgorithm, _ data: [uint8]) -> [uint8] {
    switch alg {
    case .sha256:
        return sha256.Sum256(data)
    case .sha224:
        return sha256.Sum224(data)
    case .sha1:
        return sha1.Sum1(data)
    case .md5:
        return md5.Sum(data)
    case .sha384:
        return sha512.Sum384(data)
    case .sha512:
        return sha512.Sum512(data)
    }
}

/// Compute calculates the HMAC of a message with the given key and hash algorithm.
public func Compute(key: [uint8], message: [uint8], hash: HashAlgorithm = .sha256) -> [uint8] {
    let blockSize = hashBlockSize(hash)
    var k: [uint8] = []

    if key.count > blockSize {
        k = hashFunc(hash, key)
    } else {
        k = key
    }

    // Pad key to blockSize with zeros.
    while k.count < blockSize {
        k.append(0)
    }

    var kIpad: [uint8] = []
    var kOpad: [uint8] = []
    var i = 0
    while i < blockSize {
        kIpad.append(k[i] ^ 0x36)
        kOpad.append(k[i] ^ 0x5c)
        i += 1
    }

    // Inner hash: H(K_ipad || message)
    var innerInput = kIpad
    var m = 0
    while m < message.count {
        innerInput.append(message[m])
        m += 1
    }
    let innerHash = hashFunc(hash, innerInput)

    // Outer hash: H(K_opad || innerHash)
    var outerInput = kOpad
    var h = 0
    while h < innerHash.count {
        outerInput.append(innerHash[h])
        h += 1
    }
    return hashFunc(hash, outerInput)
}

/// Compute calculates the HMAC of a string message with the given key.
public func Compute(key: [uint8], message: string, hash: HashAlgorithm = .sha256) -> [uint8] {
    var bytes: [uint8] = []
    for b in message.utf8 {
        bytes.append(b)
    }
    return Compute(key: key, message: bytes, hash: hash)
}

/// Equal compares two MACs for equality without leaking timing information.
public func Equal(_ mac1: [uint8], _ mac2: [uint8]) -> bool {
    return subtle.ConstantTimeCompare(mac1, mac2) == 1
}
