package main

import "crypto/sha256"

var failures = 0

func check(_ ok: bool, _ msg: string) {
    if ok {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func main() -> int32 {
    // SHA-256 NIST Vector 1: Empty string
    let h1 = sha256.ToHex(sha256.Sum256(""))
    check(h1 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256: empty string")

    // SHA-256 NIST Vector 2: "abc"
    let h2 = sha256.ToHex(sha256.Sum256("abc"))
    check(h2 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256: abc")

    // SHA-256 NIST Vector 3: 56-byte message
    let h3 = sha256.ToHex(sha256.Sum256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    check(h3 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "sha256: 56-byte message")

    // SHA-224 NIST Vector 1: Empty string
    let h224_1 = sha256.ToHex(sha256.Sum224(""))
    check(h224_1 == "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "sha224: empty string")

    // SHA-224 NIST Vector 2: "abc"
    let h224_2 = sha256.ToHex(sha256.Sum224("abc"))
    check(h224_2 == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "sha224: abc")

    // SHA-224 NIST Vector 3: 56-byte message
    let h224_3 = sha256.ToHex(sha256.Sum224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    check(h224_3 == "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", "sha224: 56-byte message")

    // Streaming API check
    var d = sha256.New()
    d.WriteString("abcdbcde")
    d.WriteString("cdefdefg")
    d.WriteString("efghfghi")
    d.WriteString("ghijhijk")
    d.WriteString("ijkljklm")
    d.WriteString("klmnlmno")
    d.WriteString("mnopnopq")
    let streamHex = sha256.ToHex(d.Checksum())
    check(streamHex == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "sha256: streaming chunks match sum")

    if failures == 0 {
        print("all sha256/sha224 tests passed")
        return 0
    }
    return int32(failures)
}
