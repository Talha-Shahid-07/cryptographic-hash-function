#pragma once

#include "hasher.h"
#include <string>

// Path to the flat-file database where hash records are stored.
// Format per line: filepath:algorithm:hexdigest
// e.g.  /home/user/report.pdf:SHA-256:abc123...
static const std::string HASH_DB_PATH = "hashes.db";

// Saves the hash of a file to the record store.
// If a record for this filepath+algorithm already exists, it is overwritten.
// Returns true on success.
bool storeFileHash(const std::string& filepath, HashAlgorithm algo, const std::string& hexDigest);

// Verifies a file's current hash against its stored record.
// Recomputes the hash from disk, then compares with the stored value.
// storedHash is populated with the value from the DB (useful for display).
// currentHash is populated with the freshly computed value.
// Returns true if they match (file is intact).
bool verifyFileHash(
    const std::string& filepath,
    HashAlgorithm algo,
    std::string& storedHash,
    std::string& currentHash,
    std::string& errorMsg
);

// Verifies a file's current hash against a manually provided hex string.
// Does not touch the DB — useful for one-off checks.
bool verifyAgainstProvided(
    const std::string& filepath,
    HashAlgorithm algo,
    const std::string& providedHash,
    std::string& currentHash,
    std::string& errorMsg
);
