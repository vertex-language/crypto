package rand

@_silgen_name("arc4random_buf")
func c_arc4random_buf(_ buf: UnsafeMutableRawPointer?, _ n: Int) -> Void

public enum RandError: Error {
    case readFailed(string)
}

/// Read fills buffer with cryptographically secure random bytes from the platform CSPRNG.
public func Read(into buffer: inout [uint8]) throws -> int {
    if buffer.isEmpty {
        return 0
    }
    buffer.withUnsafeMutableBytes { raw in
        c_arc4random_buf(raw.baseAddress, raw.count)
    }
    return buffer.count
}

/// Bytes allocates and returns a buffer of count cryptographically secure random bytes.
public func Bytes(_ count: int) throws -> [uint8] {
    if count <= 0 {
        return []
    }
    var buffer = [uint8](repeating: 0, count: count)
    _ = try Read(into: &buffer)
    return buffer
}
