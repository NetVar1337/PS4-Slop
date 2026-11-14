// src/core/util/sha256.cpp
#include "core/util/sha256.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/sha.h>
#endif

namespace slop::core::util {

std::string sha256_hex(const uint8_t* data, size_t len) {
#ifndef _WIN32
    unsigned char digest[SHA256_DIGEST_LENGTH];
    ::SHA256(data, len, digest);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(sizeof(digest) * 2);
    for (unsigned char b : digest) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
#else
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return out;
    DWORD hl = 0, cb = 0;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hl),
                          sizeof(hl), &cb, 0) == 0) {
        std::vector<uint8_t> digest(hl);
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
            if (BCryptHashData(hash, const_cast<PUCHAR>(data),
                               static_cast<ULONG>(len), 0) == 0 &&
                BCryptFinishHash(hash, digest.data(), hl, 0) == 0) {
                static constexpr char kHex[] = "0123456789abcdef";
                out.reserve(digest.size() * 2);
                for (uint8_t b : digest) {
                    out.push_back(kHex[b >> 4]);
                    out.push_back(kHex[b & 0xF]);
                }
            }
            BCryptDestroyHash(hash);
        }
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
#endif
}

} // namespace slop::core::util
