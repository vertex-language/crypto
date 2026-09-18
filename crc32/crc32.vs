package crc32

// IEEE is by far and away the most common CRC-32 polynomial.
// Used by ethernet (IEEE 802.3), vzip, gzip, PNG, STUN (RFC 8489), etc.
public let IEEE: uint32 = 0xEDB88320

// Castagnoli is used in SCTP (RFC 3309 / RFC 4960), iSCSI, Btrfs, ext4.
public let Castagnoli: uint32 = 0x82F63B78

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
let tableCastagnoli: [uint32] = makeTable(Castagnoli)

/// Update returns the result of adding the bytes in data to the crc using IEEE table.
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

/// UpdateCastagnoli returns the result of adding bytes using the Castagnoli table.
public func UpdateCastagnoli(_ crc: uint32, _ data: [uint8]) -> uint32 {
    var c = ~crc
    var i = 0
    while i < data.count {
        let idx = int((c ^ uint32(data[i])) & 0xFF)
        c = tableCastagnoli[idx] ^ (c >> 8)
        i += 1
    }
    return ~c
}

/// Checksum returns the CRC-32 checksum of data using the IEEE polynomial.
public func Checksum(_ data: [uint8]) -> uint32 {
    return Update(0, data)
}

/// ChecksumIEEE returns the CRC-32 checksum of data using the IEEE polynomial.
public func ChecksumIEEE(_ data: [uint8]) -> uint32 {
    return Checksum(data)
}

/// ChecksumCastagnoli returns the CRC-32C checksum of data using the Castagnoli polynomial (RFC 3309 / RFC 4960).
public func ChecksumCastagnoli(_ data: [uint8]) -> uint32 {
    return UpdateCastagnoli(0, data)
}

/// ChecksumString returns the CRC-32 checksum of a string using IEEE polynomial.
public func ChecksumString(_ s: string) -> uint32 {
    var bytes: [uint8] = []
    for b in s.utf8 {
        bytes.append(b)
    }
    return Checksum(bytes)
}

/// ChecksumCastagnoliString returns the CRC-32C checksum of a string using Castagnoli polynomial.
public func ChecksumCastagnoliString(_ s: string) -> uint32 {
    var bytes: [uint8] = []
    for b in s.utf8 {
        bytes.append(b)
    }
    return ChecksumCastagnoli(bytes)
}
