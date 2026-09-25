// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Canonical binary encoding. Every digest in CIF is taken over the canonical
// encoding produced by ByteWriter, so digests are stable across platforms,
// compilers and standard libraries. Decoding is total: every read is bounds
// checked and every failure is reported rather than throwing.
#ifndef CIF_BYTES_HPP
#define CIF_BYTES_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "cif/hash.hpp"
#include "cif/limits.hpp"
#include "cif/status.hpp"

namespace cif {

using Bytes = std::vector<std::uint8_t>;

// ---------------------------------------------------------------------------
// Checked arithmetic. Nothing in CIF adds, subtracts or multiplies untrusted
// quantities without going through these helpers.
// ---------------------------------------------------------------------------
[[nodiscard]] constexpr bool checked_add(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (a > std::numeric_limits<std::uint64_t>::max() - b) {
    return false;
  }
  out = a + b;
  return true;
}

[[nodiscard]] constexpr bool checked_sub(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (b > a) {
    return false;
  }
  out = a - b;
  return true;
}

[[nodiscard]] constexpr bool checked_mul(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
    return false;
  }
  out = a * b;
  return true;
}

/// Narrowing conversion that reports failure instead of truncating.
template <typename To, typename From>
[[nodiscard]] constexpr bool checked_narrow(From value, To& out) noexcept {
  static_assert(std::is_integral_v<To> && std::is_integral_v<From>, "integral types required");
  static_assert(!std::is_signed_v<To>, "target must be unsigned");
  if constexpr (std::is_signed_v<From>) {
    if (value < 0) {
      return false;
    }
  }
  using UnsignedFrom = std::make_unsigned_t<From>;
  const UnsignedFrom unsigned_value = static_cast<UnsignedFrom>(value);
  if constexpr (sizeof(To) >= sizeof(From)) {
    out = static_cast<To>(unsigned_value);
    return true;
  } else {
    const UnsignedFrom limit = static_cast<UnsignedFrom>(std::numeric_limits<To>::max());
    if (unsigned_value > limit) {
      return false;
    }
    out = static_cast<To>(unsigned_value);
    return true;
  }
}

// ---------------------------------------------------------------------------
// Canonical writer: little-endian fixed width integers, LEB128 varints for
// counts and lengths, length-prefixed byte strings.
// ---------------------------------------------------------------------------
class ByteWriter {
 public:
  ByteWriter() = default;
  explicit ByteWriter(Bytes& sink) noexcept : sink_(&sink) {}

  void attach(Bytes& sink) noexcept { sink_ = &sink; }

  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void varint(std::uint64_t value);
  void boolean(bool value) { u8(value ? std::uint8_t{1} : std::uint8_t{0}); }

  /// Length-prefixed with a varint (used for counts as well).
  void count(std::size_t value) { varint(static_cast<std::uint64_t>(value)); }

  void raw(std::span<const std::uint8_t> bytes);
  void blob(std::span<const std::uint8_t> bytes);
  void text(std::string_view value);
  void digest(const Digest256& value);

  [[nodiscard]] std::size_t size() const noexcept { return sink_ != nullptr ? sink_->size() : 0; }
  [[nodiscard]] bool valid() const noexcept { return sink_ != nullptr; }

 private:
  Bytes* sink_ = nullptr;
};

/// Total, bounds-checked canonical reader. The first failure is retained and
/// every later read fails fast; callers consult failure() to obtain a typed
/// Status.
class ByteReader {
 public:
  ByteReader() = default;
  explicit ByteReader(std::span<const std::uint8_t> data) noexcept : data_(data) {}

  [[nodiscard]] bool u8(std::uint8_t& out);
  [[nodiscard]] bool u16(std::uint16_t& out);
  [[nodiscard]] bool u32(std::uint32_t& out);
  [[nodiscard]] bool u64(std::uint64_t& out);
  [[nodiscard]] bool varint(std::uint64_t& out);
  [[nodiscard]] bool boolean(bool& out);

  /// Reads a count and rejects anything above 'max_count' before the caller
  /// allocates. This is the single defence against oversized-count attacks.
  [[nodiscard]] bool count(std::size_t max_count, std::size_t& out);

  [[nodiscard]] bool raw(std::size_t length, std::span<const std::uint8_t>& out);
  [[nodiscard]] bool blob(Bytes& out, std::size_t max_length);
  [[nodiscard]] bool text(std::string& out, std::size_t max_length);
  [[nodiscard]] bool digest(Digest256& out);

  [[nodiscard]] bool skip(std::size_t length);
  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
  [[nodiscard]] bool at_end() const noexcept { return offset_ == data_.size(); }
  [[nodiscard]] std::size_t total() const noexcept { return data_.size(); }

  [[nodiscard]] bool failed() const noexcept { return !failure_.ok(); }
  [[nodiscard]] const Status& failure() const noexcept { return failure_; }
  void fail(StatusCode code, std::string message);

  /// Positions the reader for a nested structure and reports how many bytes it
  /// consumed, so callers can detect trailing garbage inside a sub-record.
  [[nodiscard]] std::size_t mark() const noexcept { return offset_; }

 private:
  [[nodiscard]] bool ensure(std::size_t length);

  std::span<const std::uint8_t> data_{};
  std::size_t offset_ = 0;
  Status failure_{};
};

[[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> bytes);
[[nodiscard]] bool hex_decode(std::string_view hex, Bytes& out) noexcept;

/// Canonical digest of a byte buffer, domain separated.
[[nodiscard]] Digest256 canonical_digest(std::string_view domain, std::span<const std::uint8_t> payload);

}  // namespace cif

#endif  // CIF_BYTES_HPP
