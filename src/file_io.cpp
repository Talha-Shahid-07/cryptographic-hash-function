#include "file_io.h"

#include <openssl/evp.h>
#include <fcntl.h>      // open()
#include <unistd.h>     // read(), close()
#include <cerrno>       // errno
#include <cstring>      // strerror()
#include <sstream>
#include <iomanip>

// ─── Internal helpers ────────────────────────────────────────────────────────

// Maps our enum to the OpenSSL EVP descriptor.
// Duplicated from hasher.cpp intentionally — file_io has its own EVP usage
// (streaming context) separate from the single-buffer path in hasher.
static const EVP_MD* getEvpMd(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::MD5:    return EVP_md5();
        case HashAlgorithm::SHA1:   return EVP_sha1();
        case HashAlgorithm::SHA256: return EVP_sha256();
    }
    return nullptr;
}

static std::string bytesToHex(const unsigned char* bytes, unsigned int length) {
    std::ostringstream oss;
    for (unsigned int i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

// ─── Public API ──────────────────────────────────────────────────────────────

std::string hashFile(const std::string& filepath, HashAlgorithm algo, std::string& errorMsg) {
    // O_RDONLY: open for reading only.
    // No O_CREAT: we never create files here — fail loudly if path is wrong.
    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd == -1) {
        errorMsg = "Cannot open '" + filepath + "': " + strerror(errno);
        return "";
    }

    const EVP_MD* md = getEvpMd(algo);
    if (!md) {
        close(fd);
        errorMsg = "Unknown algorithm";
        return "";
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        errorMsg = "Failed to allocate EVP context";
        return "";
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        errorMsg = "EVP_DigestInit failed";
        return "";
    }

    // Stack-allocated buffer — no heap allocation needed for the chunk itself.
    unsigned char buffer[CHUNK_SIZE];
    ssize_t bytesRead;

    // The core loop: read CHUNK_SIZE bytes at a time, feed each chunk to the
    // EVP context. EVP accumulates state internally across all Update() calls,
    // so the final digest reflects the entire file regardless of chunk count.
    while ((bytesRead = read(fd, buffer, CHUNK_SIZE)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(bytesRead)) != 1) {
            EVP_MD_CTX_free(ctx);
            close(fd);
            errorMsg = "EVP_DigestUpdate failed";
            return "";
        }
    }

    // read() returns 0 on EOF, -1 on error.
    if (bytesRead == -1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        errorMsg = "Read error on '" + filepath + "': " + strerror(errno);
        return "";
    }

    // close() as early as possible — don't hold the file descriptor open
    // while doing final digest computation.
    close(fd);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1) {
        EVP_MD_CTX_free(ctx);
        errorMsg = "EVP_DigestFinal failed";
        return "";
    }

    EVP_MD_CTX_free(ctx);
    return bytesToHex(digest, digestLen);
}
