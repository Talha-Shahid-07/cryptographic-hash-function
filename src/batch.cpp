#include "batch.h"
#include "file_io.h"

#include <unistd.h>     // fork(), pipe(), read(), write(), close()
#include <sys/wait.h>   // waitpid()
#include <sys/signal.h> // SIGINT
#include <csignal>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

// Maximum bytes we read from a child's pipe in one go.
// A hash hex string is at most 64 chars + filepath + delimiters — 4096 is generous.
static constexpr size_t PIPE_BUF_SIZE = 4096;

// Flag set by SIGINT handler so the parent loop can exit cleanly.
static volatile sig_atomic_t g_interrupted = 0;

static void handleSigint(int /*signal*/) {
    g_interrupted = 1;
}

// ─── Child protocol ───────────────────────────────────────────────────────────
// Child writes exactly one line to its pipe write-end, then exits.
// Success format: "filepath:hexdigest\n"
// Failure format: "filepath:ERROR:message\n"
// The parent splits on ':' to determine which case it received.

static void runChild(int writeFd, const std::string& filepath, HashAlgorithm algo) {
    std::string errorMsg;
    std::string digest = hashFile(filepath, algo, errorMsg);

    std::string message;
    if (digest.empty()) {
        message = filepath + ":ERROR:" + errorMsg + "\n";
    } else {
        message = filepath + ":" + digest + "\n";
    }

    // write() is a POSIX syscall — write the full message in one call.
    // We ignore partial write errors here because a failure to report results
    // back to the parent will be caught when the parent reads an empty pipe.
    write(writeFd, message.c_str(), message.size());
    close(writeFd);

    // _exit() instead of exit() — avoids flushing parent's stdio buffers
    // that were inherited at fork() time, which would cause double-flush bugs.
    _exit(0);
}

// ─── Public API ───────────────────────────────────────────────────────────────

std::vector<BatchResult> batchHashFiles(
    const std::vector<std::string>& filepaths,
    HashAlgorithm algo,
    const std::string& outputPath)
{
    // Install SIGINT handler so Ctrl+C during long batch is caught gracefully.
    struct sigaction sa{};
    sa.sa_handler = handleSigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);

    struct ChildInfo {
        pid_t pid;
        int readFd;
        std::string filepath; // kept for error reporting if child dies abnormally
    };

    std::vector<ChildInfo> children;
    children.reserve(filepaths.size());

    // ── Phase 1: spawn all children ──────────────────────────────────────────
    for (const auto& filepath : filepaths) {
        if (g_interrupted) break;

        int pipefd[2];
        if (pipe(pipefd) == -1) {
            std::cerr << "[batch] pipe() failed for " << filepath
                      << ": " << strerror(errno) << "\n";
            continue;
        }

        pid_t pid = fork();

        if (pid == -1) {
            // fork() failed — OS out of resources. Close pipe and skip this file.
            std::cerr << "[batch] fork() failed for " << filepath
                      << ": " << strerror(errno) << "\n";
            close(pipefd[0]);
            close(pipefd[1]);
            continue;
        }

        if (pid == 0) {
            // ── Child process ────────────────────────────────────────────────
            // Close the read end — child only writes.
            close(pipefd[0]);
            runChild(pipefd[1], filepath, algo);
            // runChild calls _exit() — nothing below executes in the child.
        }

        // ── Parent process continues here ────────────────────────────────────
        // Close the write end — parent only reads.
        close(pipefd[1]);
        children.push_back({pid, pipefd[0], filepath});
    }

    // ── Phase 2: collect results from all children ────────────────────────────
    std::vector<BatchResult> results;
    results.reserve(children.size());

    for (auto& child : children) {
        // Read the child's output from the pipe.
        char buf[PIPE_BUF_SIZE] = {};
        ssize_t bytesRead = read(child.readFd, buf, PIPE_BUF_SIZE - 1);
        close(child.readFd);

        // Reap the child — mandatory to prevent zombie processes.
        // A zombie is a process that has exited but whose exit status hasn't been
        // collected yet. waitpid() collects it, freeing the kernel's process table entry.
        int status;
        waitpid(child.pid, &status, 0);

        BatchResult result;
        result.filepath = child.filepath;

        if (bytesRead <= 0) {
            result.success = false;
            result.error   = "No output from child process";
            results.push_back(result);
            continue;
        }

        std::string line(buf);
        // Remove trailing newline for clean parsing.
        if (!line.empty() && line.back() == '\n') line.pop_back();

        // Parse child protocol: filepath:ERROR:message or filepath:hexdigest
        // Find the first ':' to skip past the filepath portion.
        size_t firstColon = line.find(':');
        if (firstColon == std::string::npos) {
            result.success = false;
            result.error   = "Malformed child output";
            results.push_back(result);
            continue;
        }

        std::string rest = line.substr(firstColon + 1);

        if (rest.substr(0, 6) == "ERROR:") {
            result.success = false;
            result.error   = rest.substr(6);
        } else {
            result.success   = true;
            result.hexDigest = rest;
        }

        results.push_back(result);
    }

    // ── Phase 3: write output log if requested ────────────────────────────────
    if (!outputPath.empty()) {
        std::ofstream logFile(outputPath, std::ios::trunc);
        if (logFile.is_open()) {
            for (const auto& r : results) {
                if (r.success) {
                    logFile << r.filepath << "  " << r.hexDigest << "\n";
                } else {
                    logFile << r.filepath << "  ERROR: " << r.error << "\n";
                }
            }
        } else {
            std::cerr << "[batch] Could not open output log: " << outputPath << "\n";
        }
    }

    if (g_interrupted) {
        std::cerr << "\n[batch] Interrupted by user. Partial results shown.\n";
    }

    return results;
}
