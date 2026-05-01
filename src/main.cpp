#include "hasher.h"
#include "file_io.h"
#include "integrity.h"
#include "password.h"
#include "batch.h"

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

// ─── Usage ────────────────────────────────────────────────────────────────────

static void printUsage(const std::string& prog) {
    std::cerr
        << "Usage:\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --file <path>\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --text <string>\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --store <filepath>\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --verify <filepath>\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --verify <filepath> --against <hash>\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --store-password <username> <password>\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --check-password <username> <password>\n"
        << "  " << prog << " <--md5|--sha1|--sha256> --batch <file1> [file2 ...] [--output <logfile>]\n";
}

// ─── Argument parsing helpers ─────────────────────────────────────────────────

// Finds a flag in argv and returns the value immediately after it.
// Returns "" if the flag isn't present or has no following argument.
static std::string getArgAfter(const std::vector<std::string>& args, const std::string& flag) {
    for (size_t i = 0; i + 1 < args.size(); ++i) {
        if (args[i] == flag) return args[i + 1];
    }
    return "";
}

static bool hasFlag(const std::vector<std::string>& args, const std::string& flag) {
    for (const auto& a : args) if (a == flag) return true;
    return false;
}

// Collects all arguments after a given flag up to the next flag (starts with '--')
// or end of args. Used for --batch which takes a variable number of file paths.
static std::vector<std::string> getArgsAfter(const std::vector<std::string>& args, const std::string& flag) {
    std::vector<std::string> result;
    bool collecting = false;
    for (const auto& a : args) {
        if (a == flag) { collecting = true; continue; }
        if (collecting) {
            if (a.substr(0, 2) == "--") break; // hit the next flag — stop
            result.push_back(a);
        }
    }
    return result;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    // Convert raw argv to a vector for easier manipulation.
    std::vector<std::string> args(argv + 1, argv + argc);

    // ── Step 1: parse the algorithm flag (must be first argument) ────────────
    HashAlgorithm algo;
    if (!parseAlgorithm(args[0], algo)) {
        std::cerr << "Error: first argument must be --md5, --sha1, or --sha256\n";
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    // ── Step 2: dispatch on the operation flag ────────────────────────────────

    // ── --file: hash a single file ────────────────────────────────────────────
    if (hasFlag(args, "--file")) {
        std::string filepath = getArgAfter(args, "--file");
        if (filepath.empty()) {
            std::cerr << "Error: --file requires a path argument\n";
            return EXIT_FAILURE;
        }
        std::string errorMsg;
        std::string digest = hashFile(filepath, algo, errorMsg);
        if (digest.empty()) {
            std::cerr << "Error: " << errorMsg << "\n";
            return EXIT_FAILURE;
        }
        std::cout << algorithmName(algo) << "  " << filepath << "\n" << digest << "\n";
        return EXIT_SUCCESS;
    }

    // ── --text: hash a string ─────────────────────────────────────────────────
    if (hasFlag(args, "--text")) {
        std::string text = getArgAfter(args, "--text");
        if (text.empty()) {
            std::cerr << "Error: --text requires a string argument\n";
            return EXIT_FAILURE;
        }
        std::string digest = hashText(text, algo);
        if (digest.empty()) {
            std::cerr << "Error: hashing failed\n";
            return EXIT_FAILURE;
        }
        std::cout << algorithmName(algo) << "  \"" << text << "\"\n" << digest << "\n";
        return EXIT_SUCCESS;
    }

    // ── --store: hash a file and save to DB ───────────────────────────────────
    if (hasFlag(args, "--store")) {
        std::string filepath = getArgAfter(args, "--store");
        if (filepath.empty()) {
            std::cerr << "Error: --store requires a filepath\n";
            return EXIT_FAILURE;
        }
        std::string errorMsg;
        std::string digest = hashFile(filepath, algo, errorMsg);
        if (digest.empty()) {
            std::cerr << "Error: " << errorMsg << "\n";
            return EXIT_FAILURE;
        }
        if (!storeFileHash(filepath, algo, digest)) {
            std::cerr << "Error: could not write to " << HASH_DB_PATH << "\n";
            return EXIT_FAILURE;
        }
        std::cout << "Stored " << algorithmName(algo) << " hash for " << filepath << "\n"
                  << digest << "\n";
        return EXIT_SUCCESS;
    }

    // ── --verify: check a file against stored or provided hash ───────────────
    if (hasFlag(args, "--verify")) {
        std::string filepath = getArgAfter(args, "--verify");
        if (filepath.empty()) {
            std::cerr << "Error: --verify requires a filepath\n";
            return EXIT_FAILURE;
        }

        std::string against = getArgAfter(args, "--against");
        std::string errorMsg, storedHash, currentHash;

        bool match;
        if (!against.empty()) {
            // Verify against manually provided hash — no DB involved.
            match = verifyAgainstProvided(filepath, algo, against, currentHash, errorMsg);
            if (!errorMsg.empty() && currentHash.empty()) {
                std::cerr << "Error: " << errorMsg << "\n";
                return EXIT_FAILURE;
            }
            std::cout << "Provided:  " << against    << "\n"
                      << "Computed:  " << currentHash << "\n";
        } else {
            // Verify against DB record.
            match = verifyFileHash(filepath, algo, storedHash, currentHash, errorMsg);
            if (!match && currentHash.empty()) {
                // Error before we could even compute — e.g. file not found or no DB record.
                std::cerr << "Error: " << errorMsg << "\n";
                return EXIT_FAILURE;
            }
            std::cout << "Stored:   " << storedHash  << "\n"
                      << "Computed: " << currentHash << "\n";
        }

        if (match) {
            std::cout << "MATCH — file is intact.\n";
            return EXIT_SUCCESS;
        } else {
            std::cout << "MISMATCH — file has been modified or corrupted.\n";
            return EXIT_FAILURE; // non-zero exit so scripts can detect tampering
        }
    }

    // ── --store-password ──────────────────────────────────────────────────────
    if (hasFlag(args, "--store-password")) {
        std::string username = getArgAfter(args, "--store-password");
        // Password is the argument after the username.
        std::string password;
        for (size_t i = 0; i + 1 < args.size(); ++i) {
            if (args[i] == "--store-password" && i + 2 < args.size()) {
                password = args[i + 2];
                break;
            }
        }
        if (username.empty() || password.empty()) {
            std::cerr << "Error: --store-password requires <username> <password>\n";
            return EXIT_FAILURE;
        }
        if (!storePassword(username, password, algo)) {
            std::cerr << "Error: could not store password\n";
            return EXIT_FAILURE;
        }
        std::cout << "Password stored for user '" << username << "'\n";
        return EXIT_SUCCESS;
    }

    // ── --check-password ──────────────────────────────────────────────────────
    if (hasFlag(args, "--check-password")) {
        std::string username = getArgAfter(args, "--check-password");
        std::string attempt;
        for (size_t i = 0; i + 1 < args.size(); ++i) {
            if (args[i] == "--check-password" && i + 2 < args.size()) {
                attempt = args[i + 2];
                break;
            }
        }
        if (username.empty() || attempt.empty()) {
            std::cerr << "Error: --check-password requires <username> <password>\n";
            return EXIT_FAILURE;
        }
        std::string errorMsg;
        bool valid = verifyPassword(username, attempt, algo, errorMsg);
        if (!errorMsg.empty() && !valid) {
            std::cerr << "Error: " << errorMsg << "\n";
            return EXIT_FAILURE;
        }
        if (valid) {
            std::cout << "Password CORRECT for user '" << username << "'\n";
            return EXIT_SUCCESS;
        } else {
            std::cout << "Password INCORRECT for user '" << username << "'\n";
            return EXIT_FAILURE;
        }
    }

    // ── --batch: parallel hash multiple files ─────────────────────────────────
    if (hasFlag(args, "--batch")) {
        std::vector<std::string> files = getArgsAfter(args, "--batch");
        if (files.empty()) {
            std::cerr << "Error: --batch requires at least one file path\n";
            return EXIT_FAILURE;
        }
        std::string outputPath = getArgAfter(args, "--output");

        auto results = batchHashFiles(files, algo, outputPath);

        for (const auto& r : results) {
            if (r.success) {
                std::cout << r.hexDigest << "  " << r.filepath << "\n";
            } else {
                std::cerr << "FAILED  " << r.filepath << ": " << r.error << "\n";
            }
        }

        if (!outputPath.empty()) {
            std::cout << "Results saved to " << outputPath << "\n";
        }
        return EXIT_SUCCESS;
    }

    // ── No recognized operation flag ──────────────────────────────────────────
    std::cerr << "Error: no recognized operation flag\n";
    printUsage(argv[0]);
    return EXIT_FAILURE;
}
