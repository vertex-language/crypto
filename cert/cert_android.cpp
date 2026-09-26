// The system's certificate trust on Android: not yet. Its store is the
// platform's, reached through Java (X509TrustManager), and a C++ path to it
// has not been written; see cert.cpp.
module;
#include <stdint.h>
#include <string.h>
#include <string_view>
module crypto.cert;

namespace {
const char message[] = "certificate verification is not available on Android yet";
}

int32_t certVerifyChain(const uint8_t*, const int64_t*, int32_t, std::string_view) noexcept {
    return Code::unsupported;
}

int32_t certVerifySignature(const uint8_t*, int64_t, int32_t, const uint8_t*, int64_t,
                            const uint8_t*, int64_t) noexcept {
    return Code::unsupported;
}

int64_t certLastError(uint8_t* out, int64_t capacity) noexcept {
    int64_t n = (int64_t)sizeof message - 1;
    if (n > capacity) {
        n = capacity;
    }
    memcpy(out, message, (size_t)n);
    return n;
}
