#include "integrity.h"
#include "file_io.h"

#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

// ─── Record format ────────────────────────────────────────────────────────────
// Each line in hashes.db: filepath:algorithm:hexdigest
// We use ':' as a delimiter. Filepaths containing ':' are a known limitation
// (uncommon on Linux, non-existent concern on Windows paths handled via MinGW).

struct HashRecord {
    std::string filepath;
    std::string algorithm;
    std::string hexDigest;
};

// ─── Internal helpers ─────────────────────────────────────────────────────────

// Parses a single DB line into a HashRecord.
// Returns false if the line is malformed.
static bool parseLine(const std::string& line, HashRecord& out) {
    // Find the two delimiter positions
    size_t first = line.find(':');
    if (first == std::string::npos) return false;

    size_t second = line.find(':', first + 1);
    if (second == std::string::npos) return false;

    out.filepath  = line.substr(0, first);
    out.algorithm = line.substr(first + 1, second - first - 1);
    out.hexDigest = line.substr(second + 1);
    return !out.filepath.empty() && !out.algorithm.empty() && !out.hexDigest.empty();
}

// Loads all records from the DB file.
// Returns an empty vector if the file doesn't exist yet (first use is valid).
static std::vector<HashRecord> loadRecords() {
    std::vector<HashRecord> records;
    std::ifstream file(HASH_DB_PATH);
    if (!file.is_open()) return records; // file doesn't exist yet — that's fine

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        HashRecord rec;
        if (parseLine(line, rec)) {
            records.push_back(rec);
        }
    }
    return records;
}

// Writes all records back to the DB file, overwriting it entirely.
static bool saveRecords(const std::vector<HashRecord>& records) {
    std::ofstream file(HASH_DB_PATH, std::ios::trunc);
    if (!file.is_open()) return false;

    for (const auto& rec : records) {
        file << rec.filepath << ':' << rec.algorithm << ':' << rec.hexDigest << '\n';
    }
    return file.good();
}

// ─── Public API ───────────────────────────────────────────────────────────────

bool storeFileHash(const std::string& filepath, HashAlgorithm algo, const std::string& hexDigest) {
    auto records = loadRecords();
    const std::string algoName = algorithmName(algo);

    // Check if a record for this filepath + algorithm already exists.
    // If so, update it in place rather than appending a duplicate.
    for (auto& rec : records) {
        if (rec.filepath == filepath && rec.algorithm == algoName) {
            rec.hexDigest = hexDigest;
            return saveRecords(records);
        }
    }

    // No existing record — append a new one.
    records.push_back({filepath, algoName, hexDigest});
    return saveRecords(records);
}

bool verifyFileHash(
    const std::string& filepath,
    HashAlgorithm algo,
    std::string& storedHash,
    std::string& currentHash,
    std::string& errorMsg)
{
    auto records = loadRecords();
    const std::string algoName = algorithmName(algo);

    // Find the stored record for this filepath + algorithm combination.
    auto it = std::find_if(records.begin(), records.end(),
        [&](const HashRecord& rec) {
            return rec.filepath == filepath && rec.algorithm == algoName;
        });

    if (it == records.end()) {
        errorMsg = "No stored hash found for '" + filepath + "' with " + algoName;
        return false;
    }

    storedHash = it->hexDigest;

    // Recompute the hash from disk right now.
    currentHash = hashFile(filepath, algo, errorMsg);
    if (currentHash.empty()) return false; // errorMsg set by hashFile

    return storedHash == currentHash;
}

bool verifyAgainstProvided(
    const std::string& filepath,
    HashAlgorithm algo,
    const std::string& providedHash,
    std::string& currentHash,
    std::string& errorMsg)
{
    currentHash = hashFile(filepath, algo, errorMsg);
    if (currentHash.empty()) return false;

    return currentHash == providedHash;
}
