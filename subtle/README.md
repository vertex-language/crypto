# crypto/subtle

Constant-time comparison routines to prevent timing side-channel attacks (`subtle.ConstantTimeCompare`).

```vertex
import "crypto/subtle"
```

## Functions

- `func ConstantTimeCompare(_ x: [uint8], _ y: [uint8]) -> int32`: ConstantTimeCompare returns 1 if the two byte slices, x and y, have equal contents and 0 otherwise.
- `func ConstantTimeByteEq(_ x: uint8, _ y: uint8) -> int32`: ConstantTimeByteEq returns 1 if x == y and 0 otherwise.
- `func ConstantTimeEq(_ x: int32, _ y: int32) -> int32`: ConstantTimeEq returns 1 if x == y and 0 otherwise.
- `func ConstantTimeSelect(_ v: int32, _ x: int32, _ y: int32) -> int32`: ConstantTimeSelect returns x if v == 1 and y if v == 0. Its behavior is undefined if v takes any other value.
- `func ConstantTimeCopy(_ v: int32, _ dst: inout [uint8], _ src: [uint8])`: ConstantTimeCopy copies the contents of src into dst if v == 1. If v == 0, dst is left unchanged.
- `func ConstantTimeLessOrEq(_ x: int32, _ y: int32) -> int32`: ConstantTimeLessOrEq returns 1 if x <= y and 0 otherwise. Behavior is undefined if x or y are negative or >= 2^31.

Part of the [`crypto`](https://github.com/vertex-language/crypto) repository.
