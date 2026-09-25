// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Version and build identification for the CIF runtime. This header is part of
// the installed public API surface (cif::core).
#ifndef CIF_VERSION_HPP
#define CIF_VERSION_HPP

#include <cstdint>
#include <string>

#define CIF_VERSION_MAJOR 1
#define CIF_VERSION_MINOR 0
#define CIF_VERSION_PATCH 0
#define CIF_VERSION_STRING "1.0.0"

// Monotonic on-disk / on-wire format versions. These are independent of the
// library version and may only be bumped with a documented compatibility plan.
#define CIF_JOURNAL_FORMAT_VERSION 1u
#define CIF_SNAPSHOT_FORMAT_VERSION 1u
#define CIF_WIRE_PROTOCOL_VERSION 1u

namespace cif {

/// Human readable library version ("MAJOR.MINOR.PATCH").
[[nodiscard]] const char* version_string() noexcept;

/// Compiler/standard description captured at build time. Reported by 'cif version'.
[[nodiscard]] const char* build_toolchain() noexcept;

/// "Release" / "Debug" / ... as configured at build time.
[[nodiscard]] const char* build_configuration() noexcept;

/// True when the binary was compiled with the test-only crash hooks enabled.
[[nodiscard]] bool test_hooks_enabled() noexcept;

/// On-disk format versions actually understood by this binary.
[[nodiscard]] std::uint32_t journal_format_version() noexcept;
[[nodiscard]] std::uint32_t wire_protocol_version() noexcept;

/// Machine readable one-line description used by tooling and for digest stability.
[[nodiscard]] std::string version_banner();

}  // namespace cif

#endif  // CIF_VERSION_HPP
