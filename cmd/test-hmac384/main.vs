package main
import (
    "crypto/hmac"
    "crypto/sha512"
)
func main() -> int32 {
    let key = [uint8](repeating: 0x0b, count: 20)
    let data: [uint8] = [0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65]
    let m384 = hmac.Compute(key: key, message: data, hash: .sha384)
    let ok384 = sha512.ToHex(m384) == "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
    let m512 = hmac.Compute(key: key, message: data, hash: .sha512)
    let ok512 = sha512.ToHex(m512) == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    if ok384 && ok512 { print("hmac sha384/512 ok"); return 0 }
    print("FAIL 384=\(ok384) 512=\(ok512)"); return 1
}
