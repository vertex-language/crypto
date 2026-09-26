Vectors for `cmd/test-cert`, made with openssl:

- `ec.der`: a self-signed P-256 certificate (named curve) for `test.vertex.invalid`
- `rsa.der`: a self-signed RSA-2048 certificate
- `ec.sig`: ECDSA P-256 SHA-256 (X9.62 DER) over `message`, by `ec.der`'s key
- `pss.sig`, `pkcs1.sig`: RSA-PSS (32-byte salt) and PKCS#1 v1.5, SHA-256, over `message`, by `rsa.der`'s key
- `expired-*.der`, `self-signed-1.der`, `untrusted-root-*.der`: the chains
  `expired.badssl.com`, `self-signed.badssl.com` and
  `untrusted-root.badssl.com` served in September 2026, server first
