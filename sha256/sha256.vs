package sha256

// The size of a SHA-256 checksum in bytes.
public let Size: int = 32

// The size of a SHA-224 checksum in bytes.
public let Size224: int = 28

// The blocksize of SHA-256 and SHA-224 in bytes.
public let BlockSize: int = 64

let K: [uint32] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

func rotr(_ x: uint32, _ n: uint32) -> uint32 {
    return (x >> n) | (x &<< (32 &- n))
}

func ch(_ x: uint32, _ y: uint32, _ z: uint32) -> uint32 {
    return (x & y) ^ (~x & z)
}

func maj(_ x: uint32, _ y: uint32, _ z: uint32) -> uint32 {
    return (x & y) ^ (x & z) ^ (y & z)
}

func sigma0(_ x: uint32) -> uint32 {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

func sigma1(_ x: uint32) -> uint32 {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

func s0(_ x: uint32) -> uint32 {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

func s1(_ x: uint32) -> uint32 {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// Digest represents the partial evaluation of a SHA-256 or SHA-224 checksum.
public struct Digest {
    var h0: uint32 = 0x6a09e667
    var h1: uint32 = 0xbb67ae85
    var h2: uint32 = 0x3c6ef372
    var h3: uint32 = 0xa54ff53a
    var h4: uint32 = 0x510e527f
    var h5: uint32 = 0x9b05688c
    var h6: uint32 = 0x1f83d9ab
    var h7: uint32 = 0x5be0cd19

    var buf: [uint8] = []
    var length: uint64 = 0
    public var is224: bool = false

    public init(is224: bool = false) {
        self.is224 = is224
        Reset()
    }

    public mutating func Reset() {
        if is224 {
            h0 = 0xc1059ed8
            h1 = 0x367cd507
            h2 = 0x3070dd17
            h3 = 0xf70e5939
            h4 = 0xffc00b31
            h5 = 0x68581511
            h6 = 0x64f98fa7
            h7 = 0xbefa4fa4
        } else {
            h0 = 0x6a09e667
            h1 = 0xbb67ae85
            h2 = 0x3c6ef372
            h3 = 0xa54ff53a
            h4 = 0x510e527f
            h5 = 0x9b05688c
            h6 = 0x1f83d9ab
            h7 = 0x5be0cd19
        }
        buf = []
        length = 0
    }

    public mutating func Write(_ p: [uint8]) {
        length &+= uint64(p.count)
        var i = 0
        while i < p.count {
            buf.append(p[i])
            if buf.count == BlockSize {
                processBlock(buf)
                buf.removeAll()
            }
            i += 1
        }
    }

    public mutating func WriteString(_ s: string) {
        var bytes: [uint8] = []
        for b in s.utf8 {
            bytes.append(b)
        }
        Write(bytes)
    }

    mutating func processBlock(_ block: [uint8]) {
        var w = [uint32](repeating: 0, count: 64)
        var i = 0
        while i < 16 {
            let offset = i * 4
            w[i] = (uint32(block[offset]) << 24) |
                   (uint32(block[offset + 1]) << 16) |
                   (uint32(block[offset + 2]) << 8) |
                   uint32(block[offset + 3])
            i += 1
        }
        while i < 64 {
            w[i] = s1(w[i - 2]) &+ w[i - 7] &+ s0(w[i - 15]) &+ w[i - 16]
            i += 1
        }

        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4
        var f = h5
        var g = h6
        var h = h7

        var t = 0
        while t < 64 {
            let t1 = h &+ sigma1(e) &+ ch(e, f, g) &+ K[t] &+ w[t]
            let t2 = sigma0(a) &+ maj(a, b, c)
            h = g
            g = f
            f = e
            e = d &+ t1
            d = c
            c = b
            b = a
            a = t1 &+ t2
            t += 1
        }

        h0 &+= a
        h1 &+= b
        h2 &+= c
        h3 &+= d
        h4 &+= e
        h5 &+= f
        h6 &+= g
        h7 &+= h
    }

    /// Finalize and return the digest.
    public func Checksum() -> [uint8] {
        var clone = self
        var pad: [uint8] = []
        pad.append(0x80)

        let totalBits = clone.length &* 8
        let currentLen = (clone.buf.count + 1) % BlockSize
        let padLen = (currentLen <= 56) ? (56 - currentLen) : (BlockSize + 56 - currentLen)

        var p = 0
        while p < padLen {
            pad.append(0)
            p += 1
        }

        var shift: uint64 = 56
        while true {
            pad.append(uint8(truncatingIfNeeded: totalBits >> shift))
            if shift == 0 {
                break
            }
            shift &-= 8
        }

        clone.Write(pad)

        var digest: [uint8] = []
        func appendWord(_ w: uint32) {
            digest.append(uint8(truncatingIfNeeded: w >> 24))
            digest.append(uint8(truncatingIfNeeded: w >> 16))
            digest.append(uint8(truncatingIfNeeded: w >> 8))
            digest.append(uint8(truncatingIfNeeded: w))
        }

        appendWord(clone.h0)
        appendWord(clone.h1)
        appendWord(clone.h2)
        appendWord(clone.h3)
        appendWord(clone.h4)
        appendWord(clone.h5)
        appendWord(clone.h6)
        if !is224 {
            appendWord(clone.h7)
        }
        return digest
    }
}

/// New returns a new Digest computing the SHA-256 checksum.
public func New() -> Digest {
    return Digest(is224: false)
}

/// New224 returns a new Digest computing the SHA-224 checksum.
public func New224() -> Digest {
    return Digest(is224: true)
}

/// Sum256 returns the SHA-256 checksum of the data.
public func Sum256(_ data: [uint8]) -> [uint8] {
    var d = New()
    d.Write(data)
    return d.Checksum()
}

/// Sum256 returns the SHA-256 checksum of the UTF-8 string.
public func Sum256(_ text: string) -> [uint8] {
    var d = New()
    d.WriteString(text)
    return d.Checksum()
}

/// Sum224 returns the SHA-224 checksum of the data.
public func Sum224(_ data: [uint8]) -> [uint8] {
    var d = New224()
    d.Write(data)
    return d.Checksum()
}

/// Sum224 returns the SHA-224 checksum of the UTF-8 string.
public func Sum224(_ text: string) -> [uint8] {
    var d = New224()
    d.WriteString(text)
    return d.Checksum()
}

/// ToHex converts a byte slice into a lowercase hexadecimal string.
public func ToHex(_ bytes: [uint8]) -> string {
    let hexChars: [CChar] = [
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, // 0-9
        97, 98, 99, 100, 101, 102               // a-f
    ]
    var out: [CChar] = []
    var i = 0
    while i < bytes.count {
        let b = bytes[i]
        out.append(hexChars[int(b >> 4)])
        out.append(hexChars[int(b & 0x0f)])
        i += 1
    }
    out.append(0)
    return string(cString: out)
}
