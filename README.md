# Cryptographic Hash Function Tool

A command-line tool written in C++17 that implements cryptographic hashing for file integrity verification, password storage, and batch processing. Built as part of the Operating Systems Lab (6th Semester, BSAI 2026) at Bahria University.

---

## Features

- **File hashing** — Hash any file using MD5, SHA-1, or SHA-256 via POSIX system calls
- **Text/password hashing** — Hash arbitrary strings with hex output
- **Integrity verification** — Store a file's hash and detect modifications later
- **Salted password storage** — Store and verify passwords using cryptographically random salts
- **Parallel batch hashing** — Hash multiple files simultaneously using `fork()` and pipes
- **Signal handling** — Graceful Ctrl+C interruption during long batch operations

---

## OS Concepts Demonstrated

| Concept | Where Used |
|---|---|
| POSIX File I/O (`open`, `read`, `close`) | `file_io.cpp` — reads files in 4KB chunks |
| Process creation (`fork()`) | `batch.cpp` — spawns one child per file |
| Inter-Process Communication (pipes) | `batch.cpp` — children send results to parent |
| Zombie prevention (`waitpid()`) | `batch.cpp` — parent reaps every child |
| Signal handling (`SIGINT`) | `batch.cpp` — graceful Ctrl+C |
| Dynamic memory management | OpenSSL EVP context allocation/deallocation |

---

## Dependencies

- **g++** with C++17 support
- **OpenSSL** (`libssl-dev`)
- **make**

Install on Ubuntu:
```bash
sudo apt install g++ make libssl-dev
```

---

## Building

```bash
git clone https://github.com/Talha-Shahid-07/cryptographic-hash-function.git
cd cryptographic-hash-function
make
```

Clean build artifacts:
```bash
make clean
```

---

## Usage

### Hash a file
```bash
./hashtool --sha256 --file report.pdf
./hashtool --md5   --file report.pdf
./hashtool --sha1  --file report.pdf
```

### Hash text or a password
```bash
./hashtool --sha256 --text "hello world"
```

### Store a file's hash (for later integrity checks)
```bash
./hashtool --sha256 --store report.pdf
```
Saves the hash to `hashes.db` in the current directory.

### Verify a file against its stored hash
```bash
./hashtool --sha256 --verify report.pdf
```
Prints `MATCH` or `MISMATCH`.

### Verify against a manually provided hash
```bash
./hashtool --sha256 --verify report.pdf --against d2a84f...
```

### Store a hashed password
```bash
./hashtool --sha256 --store-password alice secret123
```
Stores `alice:randomsalt:hexdigest` in `passwords.db`.

### Verify a password
```bash
./hashtool --sha256 --check-password alice secret123
```

### Batch hash multiple files (parallel)
```bash
./hashtool --sha256 --batch file1.txt file2.txt file3.txt
./hashtool --sha256 --batch file1.txt file2.txt --output results.log
```

---

## File Structure

```
cryptographic-hash-function/
├── src/
│   ├── main.cpp        # CLI entry point and argument parsing
│   ├── hasher.h/.cpp   # OpenSSL EVP wrapper (MD5, SHA-1, SHA-256)
│   ├── file_io.h/.cpp  # POSIX chunked file reading
│   ├── integrity.h/.cpp# Hash record storage and comparison
│   ├── password.h/.cpp # Salted password hashing and verification
│   └── batch.h/.cpp    # Parallel hashing via fork() + pipes
├── Makefile
└── README.md
```

### Generated at runtime
```
hashes.db       # Stores file hash records (filepath:algorithm:hash)
passwords.db    # Stores password records (username:salt:hash)
```

---

## How Salting Works

Without salting, two users with the same password produce identical hashes — an attacker with the database can reverse them using precomputed lookup tables (rainbow tables).

This tool generates a 16-byte cryptographically random salt using `RAND_bytes()` (OpenSSL's interface to `/dev/urandom`) for every password stored. The salt is prepended to the password before hashing and stored in plaintext alongside the hash:

```
alice:a3f9bc12...(32 hex chars)...:d2a84f...(64 hex chars)...
```

On verification, the stored salt is retrieved and the same computation is repeated. The salt does not need to be secret — its purpose is uniqueness, not secrecy.

---

## How Parallel Batch Hashing Works

For each file in a batch:

1. Parent calls `pipe()` — creates a read end and a write end
2. Parent calls `fork()` — OS creates a child with a copy of the process
3. Child closes the read end, hashes its assigned file, writes `filepath:hash` to the write end, then calls `_exit()`
4. Parent closes the write end, stores the read end file descriptor

After all children are spawned, the parent reads from each pipe and calls `waitpid()` on each child PID. `waitpid()` is mandatory — without it, exited children remain as zombie processes in the kernel's process table until the parent terminates.

---

## Limitations

- No GUI — CLI only
- No network functionality
- No encryption (hashing only — one-way, not reversible)
- Filepaths containing `:` characters will break the DB record format
- Windows not supported (POSIX `fork()`/`pipe()` are Linux-only)