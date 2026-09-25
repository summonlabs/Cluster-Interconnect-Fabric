// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Independent OS process control. Threads are not multiprocess proof, so the
// durability and fencing claims in this repository are demonstrated with real
// child processes that are killed with a genuine hard kill (TerminateProcess on
// Windows, SIGKILL on POSIX) at chosen lifecycle boundaries.
#ifndef CIF_PROCESS_HPP
#define CIF_PROCESS_HPP

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "cif/status.hpp"

namespace cif {

struct ProcessOptions {
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::filesystem::path working_directory;
  /// When set, the child's stdout and stderr are redirected to this file so a
  /// test can read them after the child dies. Pipes are deliberately not used:
  /// a full pipe buffer would block the child and turn a test into a hang.
  std::filesystem::path output_file;
};

/// A child process. Non-copyable; destruction does not implicitly kill the
/// child, because silently terminating a process is never a good default.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;

  [[nodiscard]] static Status spawn(const ProcessOptions& options, ChildProcess& out);

  [[nodiscard]] bool running();
  [[nodiscard]] std::uint32_t process_id() const noexcept { return process_id_; }

  /// Waits until the child exits. Returns the platform exit status.
  [[nodiscard]] Status wait(std::uint32_t& out_exit_code);

  /// Hard kill: TerminateProcess / SIGKILL. No destructors run in the child, no
  /// buffers are flushed. This is the mechanism the durability tests use.
  [[nodiscard]] Status terminate(std::uint32_t exit_code);

  [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] std::string read_output() const;

 private:
  struct Impl;
  std::shared_ptr<Impl> handle_;
  std::uint32_t process_id_ = 0;
};

/// Best-effort lookup of the executable that contains the running code, used by
/// tests to find a sibling tool (cifd next to the test binary).
[[nodiscard]] std::filesystem::path current_executable_path();

/// Directory containing the running executable.
[[nodiscard]] std::filesystem::path current_executable_directory();

/// Looks for 'name' next to the running executable and in the parent bin/lib
/// directories that CMake produces. Returns an empty path when not found.
[[nodiscard]] std::filesystem::path find_sibling_tool(const std::string& name);

/// Polls a file until it exists and is non-empty, or the deadline passes.
[[nodiscard]] Status wait_for_file(const std::filesystem::path& path, std::uint64_t timeout_millis);

/// Reads a small text file (used for ready files).
[[nodiscard]] Status read_text_file(const std::filesystem::path& path, std::string& out);

/// Parses "key value" lines produced by cifd's ready file.
[[nodiscard]] bool lookup_ready_value(const std::string& text, const std::string& key,
                                      std::string& out);

}  // namespace cif

#endif  // CIF_PROCESS_HPP
