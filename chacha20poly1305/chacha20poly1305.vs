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

// tag is the Poly1305 tag RFC 8439 puts on a record: of aad, padded to
// 16 bytes, ciphertext, padded, and the two lengths, little-endian. The
// pieces are written to the MAC as they are, not gathered into one input.
func tag(_ polyKey: [uint8], _ aad: [uint8], _ ciphertext: [uint8]) -> [uint8] {
    var mac = poly1305.MAC(key: polyKey)
    mac.Write(aad)
    mac.Write(padding(aad.count))
    mac.Write(ciphertext)
    mac.Write(padding(ciphertext.count))
    var lengths = [uint8](repeating: 0, count: 16)
    var i = 0
    while i < 8 {
        lengths[i] = uint8(truncatingIfNeeded: uint64(aad.count) >> uint64(i * 8))
        lengths[8 + i] = uint8(truncatingIfNeeded: uint64(ciphertext.count) >> uint64(i * 8))
        i += 1
    }
    mac.Write(lengths)
    return mac.Sum()
}

// padding is the zeros that bring n bytes to a multiple of 16.
func padding(_ n: int) -> [uint8] {
    return [uint8](repeating: 0, count: (16 - n % 16) % 16)
}

func generatePolyKey(key: [uint8], nonce: [uint8]) throws -> [uint8] {
    let zeroBlock = [uint8](repeating: 0, count: 64)
    let ks = try chacha20.Encrypt(key: key, nonce: nonce, plaintext: zeroBlock, counter: 0)
    return Array(ks[0..<32])
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

        // 3. Tag AAD || pad16 || Ciphertext || pad16 || len(AAD) || len(CT)
        var result = ciphertext
        result.append(contentsOf: tag(polyKey, additionalData, ciphertext))
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
        let ciphertext = Array(ciphertextAndTag[0..<ctLen])
        let mac = Array(ciphertextAndTag[ctLen..<ciphertextAndTag.count])

        // 1. Generate one-time Poly1305 key
        let polyKey = try generatePolyKey(key: self.key, nonce: nonce)

        // 2. Verify tag in constant time
        if subtle.ConstantTimeCompare(mac, tag(polyKey, additionalData, ciphertext)) != 1 {
            throw AeadError.authenticationFailed
        }

        // 3. Decrypt ciphertext
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
