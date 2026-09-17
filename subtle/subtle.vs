package subtle

/// ConstantTimeCompare returns 1 if the two byte slices, x and y, have equal contents
/// and 0 otherwise. The time taken is proportional to the slice length and is
/// independent of the contents.
public func ConstantTimeCompare(_ x: [uint8], _ y: [uint8]) -> int32 {
    if x.count != y.count {
        return 0
    }
    var v: uint8 = 0
    var i = 0
    while i < x.count {
        v |= x[i] ^ y[i]
        i += 1
    }
    return ConstantTimeByteEq(v, 0)
}

/// ConstantTimeByteEq returns 1 if x == y and 0 otherwise.
public func ConstantTimeByteEq(_ x: uint8, _ y: uint8) -> int32 {
    let diff = uint32(x ^ y)
    return int32((diff &- 1) >> 31)
}

/// ConstantTimeEq returns 1 if x == y and 0 otherwise.
public func ConstantTimeEq(_ x: int32, _ y: int32) -> int32 {
    let diff = uint32(bitPattern: x ^ y)
    return int32((diff &- 1) >> 31)
}

/// ConstantTimeSelect returns x if v == 1 and y if v == 0.
/// Its behavior is undefined if v takes any other value.
public func ConstantTimeSelect(_ v: int32, _ x: int32, _ y: int32) -> int32 {
    return (~(v &- 1) & x) | ((v &- 1) & y)
}

/// ConstantTimeCopy copies the contents of src into dst if v == 1.
/// If v == 0, dst is left unchanged.
public func ConstantTimeCopy(_ v: int32, _ dst: inout [uint8], _ src: [uint8]) {
    let mask = uint8(truncatingIfNeeded: ~(v &- 1))
    var i = 0
    let n = dst.count < src.count ? dst.count : src.count
    while i < n {
        dst[i] = (dst[i] & ~mask) | (src[i] & mask)
        i += 1
    }
}

/// ConstantTimeLessOrEq returns 1 if x <= y and 0 otherwise.
/// Behavior is undefined if x or y are negative or >= 2^31.
public func ConstantTimeLessOrEq(_ x: int32, _ y: int32) -> int32 {
    let diff = uint32(bitPattern: x &- y &- 1)
    return int32((diff >> 31) & 1)
}
