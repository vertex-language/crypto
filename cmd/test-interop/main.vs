package main

import (
    "crypto/sha256"
    "encoding/hex"
)

func main() -> int32 {
    let digest = sha256.Sum256("hello vertex ecosystem")
    let h = hex.EncodeToString(digest)
    print("SHA-256 with encoding/hex: \(h)")
    if h == "b52579f909e7082c05a7373013e5a1c177a04dd3f23ac05bf61b041f0e5f1127" {
        print("ok cross-repo import")
        return 0
    }
    return 1
}
