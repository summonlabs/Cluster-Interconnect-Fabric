// Cluster Interconnect Fabric (CIF) -- internal.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Thin, honest platform layer. This is part of the installed public API: a
// downstream consumer that writes its own persistence can reuse the same
// durability primitives the runtime uses. Everything here is deliberately small: if a
// guarantee is not available on a platform the function reports failure rather
// than pretending.
#ifndef CIF_PLATFORM_HPP
#define CIF_PLATFORM_HPP

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "cif/status.hpp"

namespace cif::platform {

/// Flushes stdio buffers and then asks the operating system to make the bytes
/// durable (fsync / _commit). Returns IoFailure when the platform refuses.
[[nodiscard]] Status sync_file(std::FILE* file);

/// Atomically replaces 'target' with 'source'. On success 'source' no longer
/// exists under its original name.
[[nodiscard]] Status atomic_replace(const std::filesystem::path& source,
                                    const std::filesystem::path& target);

[[nodiscard]] Status remove_file(const std::filesystem::path& path);
[[nodiscard]] bool file_exists(const std::filesystem::path& path) noexcept;
[[nodiscard]] std::uint64_t file_size_bytes(const std::filesystem::path& path);

/// Truncates a file to 'size' bytes. Used to discard a torn journal tail.
[[nodiscard]] Status truncate_file(const std::filesystem::path& path, std::uint64_t size);

/// Reads at most 'max_bytes'; returns LimitExceeded when the file is larger.
[[nodiscard]] Status read_file(const std::filesystem::path& path,
                               std::vector<std::uint8_t>& out,
                               std::uint64_t max_bytes);

[[nodiscard]] Status ensure_parent_directory(const std::filesystem::path& path);

[[nodiscard]] std::uint64_t monotonic_nanos() noexcept;
void sleep_millis(std::uint64_t millis) noexcept;
[[nodiscard]] std::uint32_t current_process_id() noexcept;

/// 1 MiB probe: reports true when the working directory can actually create and
/// remove a durable file. Used by tooling to avoid claiming durability it cannot
/// demonstrate.
[[nodiscard]] bool durability_probe(const std::filesystem::path& directory);

}  // namespace cif::platform

#endif  // CIF_PLATFORM_HPP
