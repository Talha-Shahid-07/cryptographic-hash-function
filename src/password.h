#pragma once

#include "hasher.h"
#include <string>

// Path to the flat-file password store.
// Format per line: username:salt:hexdigest
// The salt is a random hex string generated at store time.
static const std::string PASSWORD_DB_PATH = "passwords.db";

// Why salt?
//   Without salt, two users with the same password produce identical hashes.
//   An attacker with the DB can use precomputed "rainbow tables" to reverse them.
//   A random salt means each password hash is unique even if passwords match.
//   Salt is not secret — it's stored alongside the hash. Its purpose is
//   uniqueness, not secrecy.

// Generates a cryptographically random hex salt of the given byte length.
// Default 16 bytes = 32 hex characters = 128 bits of randomness.
std::string generateSalt(size_t byteLength = 16);

// Stores a salted hash of the password for the given username.
// If the username already exists, its record is overwritten.
// Returns true on success.
bool storePassword(const std::string& username, const std::string& password, HashAlgorithm algo);

// Verifies a plaintext password attempt against the stored salted hash.
// Retrieves the stored salt, recomputes hash(salt + password), compares.
// Returns true if the password is correct.
bool verifyPassword(const std::string& username, const std::string& attempt, HashAlgorithm algo, std::string& errorMsg);
