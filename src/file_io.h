#pragma once

#include "hasher.h"
#include <string>

// Size of each read() chunk — 4KB matches typical OS page size.
// Reading in chunks means we never load the entire file into memory at once,
// which is critical for large files (GBs) that would otherwise cause OOM.
static constexpr size_t CHUNK_SIZE = 4096;

// Reads a file using POSIX system calls (open/read/close) and computes its
// cryptographic hash by feeding chunks into the OpenSSL EVP context.
//
// Why POSIX over fopen()?
//   open() is a direct OS system call. fopen() is a C library wrapper that
//   adds buffering on top. Using open() directly demonstrates OS-level I/O
//   and gives us control over buffer sizes and error conditions.
//
// Returns the hex digest string on success, empty string on any failure.
// Sets errorMsg to a human-readable description if something goes wrong.
std::string hashFile(const std::string& filepath, HashAlgorithm algo, std::string& errorMsg);
