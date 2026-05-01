#pragma once

#include "hasher.h"
#include <string>
#include <vector>

// Result for a single file's batch hash operation.
struct BatchResult {
    std::string filepath;
    std::string hexDigest; // empty if hashing failed
    std::string error;     // non-empty if hashing failed
    bool success;
};

// Hashes multiple files in parallel using fork() + pipes.
//
// Architecture:
//   For each file, the parent:
//     1. Creates a pipe (pipefd[0] = read end, pipefd[1] = write end)
//     2. Calls fork() — OS creates a child process with a copy of our address space
//     3. Child closes the read end, hashes the file, writes "filepath:hexdigest\n"
//        or "filepath:ERROR:message\n" into the write end, then exits.
//     4. Parent closes the write end, records the read end fd for later.
//   After all children are spawned, parent:
//     5. Reads each pipe (collecting results)
//     6. Calls waitpid() on each child PID to reap it (prevents zombie processes)
//
// Why not just a loop?
//   fork() lets the OS schedule all child processes concurrently. For I/O-bound
//   work (reading large files), this gives real parallelism — child 2 reads from
//   disk while child 1 is still reading. For small files the overhead dominates,
//   but the OS concept demonstration is the point here.
//
// If outputPath is non-empty, results are also written to that file.
std::vector<BatchResult> batchHashFiles(
    const std::vector<std::string>& filepaths,
    HashAlgorithm algo,
    const std::string& outputPath // pass "" to skip file output
);
