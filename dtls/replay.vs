package dtls

/// AntiReplayWindow implements the 64-packet sliding window anti-replay protection
/// specified in RFC 6347 Section 4.1.2.6 and RFC 9147 Section 4.1.
public struct AntiReplayWindow {
    public var MaxSeq: uint64 = 0
    public var Bitmap: uint64 = 0
    public var HasReceived: bool = false

    public init() {}

    /// Checks if a sequence number is a duplicate or too old, without updating window state.
    public func Check(_ seq: uint64) -> bool {
        if !self.HasReceived {
            return true
        }

        if seq > self.MaxSeq {
            return true
        }

        let diff = self.MaxSeq - seq
        if diff >= 64 {
            return false // Too old, fell outside left edge of window
        }

        let bit: uint64 = 1 << diff
        return (self.Bitmap & bit) == 0
    }

    /// Records the reception of a sequence number and advances the sliding window.
    /// Returns true if accepted, false if rejected as duplicate/replayed.
    public mutating func Update(_ seq: uint64) -> bool {
        if !self.HasReceived {
            self.HasReceived = true
            self.MaxSeq = seq
            self.Bitmap = 1
            return true
        }

        if seq > self.MaxSeq {
            let diff = seq - self.MaxSeq
            if diff < 64 {
                self.Bitmap = (self.Bitmap << diff) | 1
            } else {
                self.Bitmap = 1
            }
            self.MaxSeq = seq
            return true
        }

        let diff = self.MaxSeq - seq
        if diff >= 64 {
            return false // Replay: packet is older than window depth
        }

        let bit: uint64 = 1 << diff
        if (self.Bitmap & bit) != 0 {
            return false // Replay: packet already received
        }

        self.Bitmap |= bit
        return true
    }

    /// Resets the sliding window for a new epoch.
    public mutating func Reset() {
        self.MaxSeq = 0
        self.Bitmap = 0
        self.HasReceived = false
    }
}
