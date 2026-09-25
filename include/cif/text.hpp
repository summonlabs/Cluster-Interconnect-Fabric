// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CIF_TEXT_HPP
#define CIF_TEXT_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace cif {

/// Strict UTF-8 validation: rejects overlong encodings, UTF-16 surrogate code
/// points, code points above U+10FFFF, truncated sequences and embedded NUL.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

/// True when 'text' contains a literal NUL byte.
[[nodiscard]] bool contains_nul(std::string_view text) noexcept;

/// Identifier grammar: 1..max_len bytes, ASCII only, characters
/// [A-Za-z0-9], plus '-', '_', '.', ':', '@', '+', '/'.
[[nodiscard]] bool is_valid_identifier(std::string_view text, std::size_t max_len) noexcept;

/// Replaces every byte outside printable ASCII with a '?', and escapes control
/// characters. Used when rendering untrusted strings into diagnostics so that
/// terminal escape sequences cannot be smuggled through explanations.
[[nodiscard]] std::string sanitise_for_display(std::string_view text, std::size_t max_len);

/// Deterministic, locale-independent decimal conversion.
[[nodiscard]] std::string to_decimal(std::uint64_t value);
[[nodiscard]] bool parse_decimal_u64(std::string_view text, std::uint64_t& out) noexcept;

/// True when 'value' is a finite double usable as a benchmark statistic.
[[nodiscard]] bool is_finite(double value) noexcept;

/// Render 'value' with fixed 3 decimals without relying on the stream locale.
[[nodiscard]] std::string format_fixed3(double value);

}  // namespace cif

#endif  // CIF_TEXT_HPP
