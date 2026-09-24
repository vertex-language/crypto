// Package rc4 implements the RC4 stream cipher. RC4 is insecure and used
// only where a legacy protocol requires it: NTLM sealing/signing and RDP
// licensing encryption run RC4 keystreams.
package rc4

/// Cipher is an RC4 keystream generator. XORStream applies it; a fresh
/// Cipher is needed per independent stream.
public struct Cipher {
    var s: [uint8]
    var i: int = 0
    var j: int = 0

    public init(key: [uint8]) {
        s = [uint8](repeating: 0, count: 256)
        var k = 0
        while k < 256 { s[k] = uint8(k); k += 1 }
        var jj = 0
        k = 0
        while k < 256 {
            jj = (jj + int(s[k]) + int(key[k % key.count])) & 0xff
            let t = s[k]; s[k] = s[jj]; s[jj] = t
            k += 1
        }
        i = 0; j = 0
    }

    /// XORStream returns input XOR the next keystream bytes, advancing the
    /// cipher state. Encrypt and decrypt are the same operation.
    public mutating func XORStream(_ input: [uint8]) -> [uint8] {
        var out = [uint8](repeating: 0, count: input.count)
        var n = 0
        while n < input.count {
            i = (i + 1) & 0xff
            j = (j + int(s[i])) & 0xff
            let t = s[i]; s[i] = s[j]; s[j] = t
            let k = s[(int(s[i]) + int(s[j])) & 0xff]
            out[n] = input[n] ^ k
            n += 1
        }
        return out
    }
}

/// Apply is a one-shot RC4 of data under key (for callers that need a
/// single independent stream).
public func Apply(key: [uint8], data: [uint8]) -> [uint8] {
    var c = Cipher(key: key)
    return c.XORStream(data)
}
