#pragma once

#include <string>

// Supported hashing algorithms.
// Using an enum class to avoid namespace pollution and force explicit qualification.
enum class HashAlgorithm {
    MD5,
    SHA1,
    SHA256
};

// Converts a CLI flag string (e.g. "--sha256") to the corresponding enum.
// Returns false if the string doesn't match any supported algorithm.
bool parseAlgorithm(const std::string& flag, HashAlgorithm& out);

// Returns a human-readable name for the algorithm (e.g. "SHA-256").
std::string algorithmName(HashAlgorithm algo);

// Hashes raw bytes using the specified algorithm.
// Returns the result as a lowercase hex string.
// Returns an empty string on failure.
std::string hashBytes(const unsigned char* data, size_t length, HashAlgorithm algo);

// Hashes a string (text/password input).
// Convenience wrapper around hashBytes.
std::string hashText(const std::string& text, HashAlgorithm algo);
