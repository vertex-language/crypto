// Package rsa implements RSA public-key operations needed by a TLS client
// and RDP: PKCS#1 v1.5 and PSS signature verification, and the raw public
// operation. Only public-key math is here -- no private keys -- so there
// is no secret to protect and the code need not be constant-time.
package rsa

import "math/big"
import "crypto/sha256"
import "crypto/sha512"
import "crypto/sha1"

/// PublicKey is an RSA public key: modulus N and exponent E.
public struct PublicKey {
    public var N: big.Nat
    public var E: big.Nat
    /// Modulus size in bytes (k), the length of a signature/ciphertext.
    public var Size: int

    public init(nBytes: [uint8], eBytes: [uint8]) {
        self.N = big.Nat.FromBytes(nBytes)
        self.E = big.Nat.FromBytes(eBytes)
        self.Size = self.N.ToBytes().count
    }
}

public enum RsaError: Error {
    case verificationFailed(string)
    case unsupported(string)

    public var Message: string {
        switch self {
        case .verificationFailed(let s): return "rsa: verification failed: \(s)"
        case .unsupported(let s): return "rsa: \(s)"
        }
    }
}

/// Hash names the digest a signature was made with.
public enum Hash {
    case sha1
    case sha256
    case sha384
    case sha512
}

func hashCompute(_ h: Hash, _ data: [uint8]) -> [uint8] {
    switch h {
    case .sha1: return sha1.Sum1(data)
    case .sha256: return sha256.Sum256(data)
    case .sha384: return sha512.Sum384(data)
    case .sha512: return sha512.Sum512(data)
    }
}

func hashSize(_ h: Hash) -> int {
    switch h {
    case .sha1: return 20
    case .sha256: return 32
    case .sha384: return 48
    case .sha512: return 64
    }
}

func digestInfoPrefix(_ h: Hash) -> [uint8] {
    switch h {
    case .sha1:
        return [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]
    case .sha256:
        return [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
    case .sha384:
        return [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30]
    case .sha512:
        return [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40]
    }
}

/// PublicOp is the raw RSA public operation: signature^E mod N, returned
/// left-padded to the modulus size. This is the encoded message a
/// signature reveals.
public func PublicOp(_ key: PublicKey, _ sig: [uint8]) -> [uint8] {
    let s = big.Nat.FromBytes(sig)
    let m = big.ExpMod(s, key.E, key.N)
    return m.ToBytesPadded(key.Size)
}

/// VerifyPKCS1v15 checks an RSASSA-PKCS1-v1_5 signature over data.
public func VerifyPKCS1v15(key: PublicKey, hash: Hash, data: [uint8], signature: [uint8]) throws {
    if signature.count != key.Size {
        throw RsaError.verificationFailed("signature length \(signature.count) != modulus size \(key.Size)")
    }
    let em = PublicOp(key, signature)
    // Expected: 0x00 0x01 PS(0xff...) 0x00 DigestInfo(hash) H(data)
    let digest = hashCompute(hash, data)
    let prefix = digestInfoPrefix(hash)
    let tLen = prefix.count + digest.count
    if key.Size < tLen + 11 {
        throw RsaError.verificationFailed("modulus too small")
    }
    var expected: [uint8] = []
    expected.append(0x00)
    expected.append(0x01)
    var i = 0
    let psLen = key.Size - tLen - 3
    while i < psLen { expected.append(0xff); i += 1 }
    expected.append(0x00)
    expected.append(contentsOf: prefix)
    expected.append(contentsOf: digest)

    if !constEqual(em, expected) {
        throw RsaError.verificationFailed("PKCS#1 v1.5 padding or digest mismatch")
    }
}

/// VerifyPSS checks an RSASSA-PSS signature over data (MGF1 with the same
/// hash, salt length equal to the hash length -- the TLS profile).
public func VerifyPSS(key: PublicKey, hash: Hash, data: [uint8], signature: [uint8]) throws {
    if signature.count != key.Size {
        throw RsaError.verificationFailed("signature length mismatch")
    }
    let em = PublicOp(key, signature)
    let emBits = key.N.BitLen - 1
    let emLen = (emBits + 7) / 8
    // em may be shorter than key.Size when the modulus's top bit is 0;
    // take the low emLen bytes.
    var m = em
    if em.count > emLen {
        var trimmed: [uint8] = []
        var i = em.count - emLen
        while i < em.count { trimmed.append(em[i]); i += 1 }
        m = trimmed
    }
    let hLen = hashSize(hash)
    let sLen = hLen
    if emLen < hLen + sLen + 2 {
        throw RsaError.verificationFailed("PSS inconsistent")
    }
    if m[emLen - 1] != 0xbc {
        throw RsaError.verificationFailed("PSS trailer")
    }
    let maskedDBLen = emLen - hLen - 1
    var maskedDB: [uint8] = []
    var i = 0
    while i < maskedDBLen { maskedDB.append(m[i]); i += 1 }
    var hVal: [uint8] = []
    while i < maskedDBLen + hLen { hVal.append(m[i]); i += 1 }

    // Top 8*emLen - emBits bits of the leftmost byte must be zero.
    let zeroBits = 8 * emLen - emBits
    if zeroBits > 0 && (maskedDB[0] & uint8(truncatingIfNeeded: 0xff << uint32(8 - zeroBits))) != 0 {
        throw RsaError.verificationFailed("PSS leftmost bits")
    }
    let dbMask = mgf1(hVal, maskedDBLen, hash)
    var db = [uint8](repeating: 0, count: maskedDBLen)
    i = 0
    while i < maskedDBLen { db[i] = maskedDB[i] ^ dbMask[i]; i += 1 }
    // Clear the leftmost zeroBits.
    if zeroBits > 0 {
        db[0] &= uint8(truncatingIfNeeded: 0xff >> uint32(zeroBits))
    }
    // db = PS(0x00..) 0x01 salt
    let psEnd = maskedDBLen - sLen - 1
    i = 0
    while i < psEnd {
        if db[i] != 0 { throw RsaError.verificationFailed("PSS PS not zero") }
        i += 1
    }
    if db[psEnd] != 0x01 { throw RsaError.verificationFailed("PSS 0x01 missing") }
    var salt: [uint8] = []
    i = psEnd + 1
    while i < maskedDBLen { salt.append(db[i]); i += 1 }

    // H' = Hash(0x00*8 || mHash || salt)
    let mHash = hashCompute(hash, data)
    var mPrime: [uint8] = [0,0,0,0,0,0,0,0]
    mPrime.append(contentsOf: mHash)
    mPrime.append(contentsOf: salt)
    let hPrime = hashCompute(hash, mPrime)
    if !constEqual(hVal, hPrime) {
        throw RsaError.verificationFailed("PSS hash mismatch")
    }
}

// mgf1 is the PKCS#1 mask generation function.
func mgf1(_ seed: [uint8], _ length: int, _ hash: Hash) -> [uint8] {
    var out: [uint8] = []
    var counter: uint32 = 0
    while out.count < length {
        var input = seed
        input.append(uint8(truncatingIfNeeded: counter >> 24))
        input.append(uint8(truncatingIfNeeded: counter >> 16))
        input.append(uint8(truncatingIfNeeded: counter >> 8))
        input.append(uint8(truncatingIfNeeded: counter))
        let block = hashCompute(hash, input)
        var i = 0
        while i < block.count && out.count < length { out.append(block[i]); i += 1 }
        counter += 1
    }
    return out
}

func constEqual(_ a: [uint8], _ b: [uint8]) -> bool {
    if a.count != b.count { return false }
    var diff: uint8 = 0
    var i = 0
    while i < a.count { diff |= a[i] ^ b[i]; i += 1 }
    return diff == 0
}
