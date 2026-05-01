#include "password.h"
#include "hasher.h"

#include <openssl/rand.h>   // RAND_bytes() — cryptographically secure RNG
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

// ─── Record format ────────────────────────────────────────────────────────────
// Each line in passwords.db: username:salt:hexdigest

struct PasswordRecord {
    std::string username;
    std::string salt;       // stored in hex
    std::string hexDigest;
};

// ─── Internal helpers ─────────────────────────────────────────────────────────

static bool parseLine(const std::string& line, PasswordRecord& out) {
    size_t first = line.find(':');
    if (first == std::string::npos) return false;

    size_t second = line.find(':', first + 1);
    if (second == std::string::npos) return false;

    out.username  = line.substr(0, first);
    out.salt      = line.substr(first + 1, second - first - 1);
    out.hexDigest = line.substr(second + 1);
    return !out.username.empty() && !out.salt.empty() && !out.hexDigest.empty();
}

static std::vector<PasswordRecord> loadRecords() {
    std::vector<PasswordRecord> records;
    std::ifstream file(PASSWORD_DB_PATH);
    if (!file.is_open()) return records;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        PasswordRecord rec;
        if (parseLine(line, rec)) records.push_back(rec);
    }
    return records;
}

static bool saveRecords(const std::vector<PasswordRecord>& records) {
    std::ofstream file(PASSWORD_DB_PATH, std::ios::trunc);
    if (!file.is_open()) return false;

    for (const auto& rec : records) {
        file << rec.username << ':' << rec.salt << ':' << rec.hexDigest << '\n';
    }
    return file.good();
}

// ─── Public API ───────────────────────────────────────────────────────────────

std::string generateSalt(size_t byteLength) {
    std::vector<unsigned char> buf(byteLength);

    // RAND_bytes() uses the OS entropy source (/dev/urandom on Linux).
    // This is cryptographically secure — not std::rand() which is predictable.
    if (RAND_bytes(buf.data(), static_cast<int>(byteLength)) != 1) {
        return ""; // entropy source failure — extremely rare
    }

    // Encode the raw bytes as hex so they're safely storable as plain text.
    std::ostringstream oss;
    for (unsigned char byte : buf) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

bool storePassword(const std::string& username, const std::string& password, HashAlgorithm algo) {
    std::string salt = generateSalt();
    if (salt.empty()) return false;

    // Hash the concatenation of salt + password.
    // Prepending the salt (rather than appending) is a common convention,
    // but either works as long as verify uses the same order.
    std::string salted = salt + password;
    std::string digest = hashText(salted, algo);
    if (digest.empty()) return false;

    auto records = loadRecords();

    // Overwrite existing record for this username if present.
    for (auto& rec : records) {
        if (rec.username == username) {
            rec.salt      = salt;
            rec.hexDigest = digest;
            return saveRecords(records);
        }
    }

    records.push_back({username, salt, digest});
    return saveRecords(records);
}

bool verifyPassword(
    const std::string& username,
    const std::string& attempt,
    HashAlgorithm algo,
    std::string& errorMsg)
{
    auto records = loadRecords();

    auto it = std::find_if(records.begin(), records.end(),
        [&](const PasswordRecord& rec) { return rec.username == username; });

    if (it == records.end()) {
        errorMsg = "No stored password for user '" + username + "'";
        return false;
    }

    // Reconstruct the same salt+password string used during storage.
    std::string salted = it->salt + attempt;
    std::string digest = hashText(salted, algo);

    if (digest.empty()) {
        errorMsg = "Hashing failed during verification";
        return false;
    }

    return digest == it->hexDigest;
}
