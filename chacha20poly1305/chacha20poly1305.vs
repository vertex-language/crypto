package chacha20poly1305

import (
    "crypto/chacha20"
    "crypto/poly1305"
    "crypto/subtle"
)

public let KeySize: int = 32
public let NonceSize: int = 12
public let TagSize: int = 16

public enum AeadError: Error {
    case invalidKey
    case invalidNonce
    case authenticationFailed
}

func pad16(_ b: inout [uint8]) {
    let remainder = b.count % 16
    if remainder != 0 {
        var p = 0
        let count = 16 - remainder
        while p < count {
            b.append(0)
            p += 1
        }
    }
}

func appendU64Le(_ b: inout [uint8], _ v: uint64) {
    var shift: uint64 = 0
    var i = 0
    while i < 8 {
        b.append(uint8(truncatingIfNeeded: v >> shift))
        shift &+= 8
        i += 1
    }
}

func generatePolyKey(key: [uint8], nonce: [uint8]) throws -> [uint8] {
    let zeroBlock = [uint8](repeating: 0, count: 64)
    let ks = try chacha20.Encrypt(key: key, nonce: nonce, plaintext: zeroBlock, counter: 0)
    var polyKey = [uint8](repeating: 0, count: 32)
    var i = 0
    while i < 32 {
        polyKey[i] = ks[i]
        i += 1
    }
    return polyKey
}

/// AEAD represents a ChaCha20-Poly1305 Authenticated Encryption with Associated Data instance (RFC 8439).
public struct AEAD {
    let key: [uint8]

    public init(key: [uint8]) {
        self.key = key
    }

    public static func New(key: [uint8]) throws -> AEAD {
        if key.count != KeySize {
            throw AeadError.invalidKey
        }
        return AEAD(key: key)
    }

    /// Seal encrypts and authenticates plaintext, appending the 16-byte Poly1305 tag.
    public func Seal(nonce: [uint8], plaintext: [uint8], additionalData: [uint8] = []) throws -> [uint8] {
        if nonce.count != NonceSize {
            throw AeadError.invalidNonce
        }

        // 1. Generate one-time Poly1305 key from ChaCha20 block 0
        let polyKey = try generatePolyKey(key: self.key, nonce: nonce)

        // 2. Encrypt plaintext with ChaCha20 starting at counter 1
        let ciphertext = try chacha20.Encrypt(key: self.key, nonce: nonce, plaintext: plaintext, counter: 1)

        // 3. Construct Poly1305 input: AAD || pad16 || Ciphertext || pad16 || len(AAD) || len(CT)
        var polyIn: [uint8] = []
        var a = 0
        while a < additionalData.count {
            polyIn.append(additionalData[a])
            a += 1
        }
        pad16(&polyIn)

        var c = 0
        while c < ciphertext.count {
            polyIn.append(ciphertext[c])
            c += 1
        }
        pad16(&polyIn)

        appendU64Le(&polyIn, uint64(additionalData.count))
        appendU64Le(&polyIn, uint64(ciphertext.count))

        // 4. Compute Poly1305 tag
        let tag = poly1305.Sum(polyIn, key: polyKey)

        // 5. Append tag to ciphertext
        var result = ciphertext
        var t = 0
        while t < tag.count {
            result.append(tag[t])
            t += 1
        }
        return result
    }

    /// Open authenticates and decrypts ciphertextAndTag, returning the plaintext.
    public func Open(nonce: [uint8], ciphertextAndTag: [uint8], additionalData: [uint8] = []) throws -> [uint8] {
        if nonce.count != NonceSize {
            throw AeadError.invalidNonce
        }
        if ciphertextAndTag.count < TagSize {
            throw AeadError.authenticationFailed
        }

        let ctLen = ciphertextAndTag.count - TagSize
        var ciphertext = [uint8](repeating: 0, count: ctLen)
        var tag = [uint8](repeating: 0, count: TagSize)

        var i = 0
        while i < ctLen {
            ciphertext[i] = ciphertextAndTag[i]
            i += 1
        }
        i = 0
        while i < TagSize {
            tag[i] = ciphertextAndTag[ctLen + i]
            i += 1
        }

        // 1. Generate one-time Poly1305 key
        let polyKey = try generatePolyKey(key: self.key, nonce: nonce)

        // 2. Construct Poly1305 input
        var polyIn: [uint8] = []
        var a = 0
        while a < additionalData.count {
            polyIn.append(additionalData[a])
            a += 1
        }
        pad16(&polyIn)

        var c = 0
        while c < ciphertext.count {
            polyIn.append(ciphertext[c])
            c += 1
        }
        pad16(&polyIn)

        appendU64Le(&polyIn, uint64(additionalData.count))
        appendU64Le(&polyIn, uint64(ciphertext.count))

        // 3. Verify tag in constant time
        if !poly1305.Verify(mac: tag, msg: polyIn, key: polyKey) {
            throw AeadError.authenticationFailed
        }

        // 4. Decrypt ciphertext
        return try chacha20.Decrypt(key: self.key, nonce: nonce, ciphertext: ciphertext, counter: 1)
    }
}

/// Seal encrypts and authenticates plaintext with key and nonce.
public func Seal(key: [uint8], nonce: [uint8], plaintext: [uint8], additionalData: [uint8] = []) throws -> [uint8] {
    let aead = try AEAD.New(key: key)
    return try aead.Seal(nonce: nonce, plaintext: plaintext, additionalData: additionalData)
}

/// Open authenticates and decrypts ciphertextAndTag with key and nonce.
public func Open(key: [uint8], nonce: [uint8], ciphertextAndTag: [uint8], additionalData: [uint8] = []) throws -> [uint8] {
    let aead = try AEAD.New(key: key)
    return try aead.Open(nonce: nonce, ciphertextAndTag: ciphertextAndTag, additionalData: additionalData)
}
