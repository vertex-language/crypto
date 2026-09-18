package crc32

// IEEE is by far and away the most common CRC-32 polynomial.
// Used by ethernet (IEEE 802.3), vzip, gzip, PNG, STUN (RFC 8489), etc.
public let IEEE: uint32 = 0xEDB88320

func makeTable(_ poly: uint32) -> [uint32] {
    var tab = [uint32](repeating: 0, count: 256)
    var i: uint32 = 0
    while i < 256 {
        var c = i
        var j = 0
        while j < 8 {
            if (c & 1) != 0 {
                c = poly ^ (c >> 1)
            } else {
                c = c >> 1
            }
            j += 1
        }
        tab[int(i)] = c
        i += 1
    }
    return tab
}

let tableIEEE: [uint32] = makeTable(IEEE)

/// Update returns the result of adding the bytes in data to the crc.
public func Update(_ crc: uint32, _ data: [uint8]) -> uint32 {
    var c = ~crc
    var i = 0
    while i < data.count {
        let idx = int((c ^ uint32(data[i])) & 0xFF)
        c = tableIEEE[idx] ^ (c >> 8)
        i += 1
    }
    return ~c
}

/// Checksum returns the CRC-32 checksum of data using the polynomial represented by the Table.
public func Checksum(_ data: [uint8]) -> uint32 {
    return Update(0, data)
}

/// ChecksumIEEE returns the CRC-32 checksum of data using the IEEE polynomial.
public func ChecksumIEEE(_ data: [uint8]) -> uint32 {
    return Checksum(data)
}

/// ChecksumString returns the CRC-32 checksum of a string.
public func ChecksumString(_ s: string) -> uint32 {
    var bytes: [uint8] = []
    for b in s.utf8 {
        bytes.append(b)
    }
    return Checksum(bytes)
}
