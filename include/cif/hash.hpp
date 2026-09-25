// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic content addressing. CIF uses SHA-256 for identity digests and
// CRC-32C for framing/journal integrity. Both are implemented in-tree so that
// digests are byte-identical on every platform, compiler and standard library.
#ifndef CIF_HASH_HPP
#define CIF_HASH_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cif {

using Bytes = std::vector<std::uint8_t>;

/// 256-bit content digest. Zero digest is reserved to mean "absent".
class Digest256 {
 public:
  static constexpr std::size_t kSize = 32;

  Digest256() noexcept = default;

  [[nodiscard]] static Digest256 zero() noexcept { return Digest256{}; }

  /// Parse 64 lowercase or uppercase hex characters. Returns false on any
  /// deviation (wrong length, non-hex byte, embedded NUL).
  [[nodiscard]] static bool parse(std::string_view hex, Digest256& out) noexcept;

  [[nodiscard]] const std::array<std::uint8_t, kSize>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::uint8_t* data() noexcept { return bytes_.data(); }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return bytes_.data(); }

  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string hex() const;

  friend bool operator==(const Digest256& a, const Digest256& b) noexcept {
    return a.bytes_ == b.bytes_;
  }
  friend bool operator!=(const Digest256& a, const Digest256& b) noexcept {
    return !(a == b);
  }
  friend bool operator<(const Digest256& a, const Digest256& b) noexcept {
    return a.bytes_ < b.bytes_;
  }

  static Digest256 from_bytes(std::span<const std::uint8_t, kSize> in) noexcept;

 private:
  std::array<std::uint8_t, kSize> bytes_{};
};

/// Streaming SHA-256 (FIPS 180-4).
class Sha256 {
 public:
  static constexpr std::size_t kDigestSize = 32;
  static constexpr std::size_t kBlockSize = 64;

  Sha256() noexcept { reset(); }

  void reset() noexcept;
  void update(std::span<const std::uint8_t> data) noexcept;
  void update(std::string_view data) noexcept;
  void update(std::uint8_t byte) noexcept;

  /// Finalises and writes the digest. The object must be reset before reuse.
  void finalise(std::uint8_t out[kDigestSize]) noexcept;
  [[nodiscard]] Digest256 digest();

 private:
  void compress(const std::uint8_t block[kBlockSize]) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, kBlockSize> buffer_{};
  std::uint64_t total_bytes_ = 0;
  std::size_t buffer_len_ = 0;
  bool finalised_ = false;
};

/// One-shot SHA-256 over an arbitrary byte span.
[[nodiscard]] Digest256 sha256(std::span<const std::uint8_t> data);
[[nodiscard]] Digest256 sha256(std::string_view data);
[[nodiscard]] std::string sha256_hex(std::string_view data);

/// CRC-32C (Castagnoli), reflected, polynomial 0x1EDC6F41, init/xorout 0xFFFFFFFF.
[[nodiscard]] std::uint32_t crc32c(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::uint32_t crc32c(std::string_view data) noexcept;

/// 64-bit FNV-1a. Used only for non-authoritative bucketing / sharding hints;
/// never for identity or integrity.
[[nodiscard]] std::uint64_t fnv1a64(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::uint64_t fnv1a64(std::string_view data) noexcept;

/// Length-prefixed, domain-separated hash helper: hashes
/// len(domain)||domain||len(part0)||part0||... so that concatenation ambiguity
/// cannot produce colliding digests.
class DomainHasher {
 public:
  explicit DomainHasher(std::string_view domain);
  void add(std::span<const std::uint8_t> part);
  void add(std::string_view part);
  void add_u64(std::uint64_t value) noexcept;
  [[nodiscard]] Digest256 finish();

 private:
  Sha256 hasher_;
};

}  // namespace cif

#endif  // CIF_HASH_HPP
