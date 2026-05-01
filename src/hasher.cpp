#include "hasher.h"

#include <openssl/evp.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

// ─── Internal helpers ────────────────────────────────────────────────────────

// Maps our enum to the OpenSSL EVP message-digest descriptor.
// EVP_MD is an opaque struct managed entirely by OpenSSL — we never free it.
static const EVP_MD* getEvpMd(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::MD5:    return EVP_md5();
        case HashAlgorithm::SHA1:   return EVP_sha1();
        case HashAlgorithm::SHA256: return EVP_sha256();
    }
    return nullptr; // unreachable, but silences compiler warning
}

// Converts a raw byte array to a lowercase hex string.
// e.g. {0xde, 0xad} → "dead"
static std::string bytesToHex(const unsigned char* bytes, unsigned int length) {
    std::ostringstream oss;
    for (unsigned int i = 0; i < length; ++i) {
        // setw(2) + setfill('0') ensures single-digit bytes are zero-padded (e.g. 0x0a → "0a")
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

// ─── Public API ──────────────────────────────────────────────────────────────

bool parseAlgorithm(const std::string& flag, HashAlgorithm& out) {
    if (flag == "--md5")    { out = HashAlgorithm::MD5;    return true; }
    if (flag == "--sha1")   { out = HashAlgorithm::SHA1;   return true; }
    if (flag == "--sha256") { out = HashAlgorithm::SHA256; return true; }
    return false;
}

std::string algorithmName(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::MD5:    return "MD5";
        case HashAlgorithm::SHA1:   return "SHA-1";
        case HashAlgorithm::SHA256: return "SHA-256";
    }
    return "UNKNOWN";
}

std::string hashBytes(const unsigned char* data, size_t length, HashAlgorithm algo) {
    const EVP_MD* md = getEvpMd(algo);
    if (!md) return "";

    // EVP_MD_CTX is the stateful context that accumulates data across multiple
    // Update() calls. This matters for large files where we feed data in chunks.
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    unsigned char digest[EVP_MAX_MD_SIZE]; // EVP_MAX_MD_SIZE = 64 bytes, enough for any algo
    unsigned int digestLen = 0;

    // Init → Update → Final is the standard OpenSSL streaming hash pattern.
    // Even for a single buffer we follow this pattern for consistency with file_io.
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, length)  != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);
    return bytesToHex(digest, digestLen);
}

std::string hashText(const std::string& text, HashAlgorithm algo) {
    // Cast is safe: we're treating the string's character data as raw bytes.
    return hashBytes(
        reinterpret_cast<const unsigned char*>(text.data()),
        text.size(),
        algo
    );
}
