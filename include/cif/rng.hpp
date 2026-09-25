// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic seeded randomness. Property tests must be reproducible from a
// printed seed alone, so nothing here ever consults an entropy source.
#ifndef CIF_RNG_HPP
#define CIF_RNG_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace cif {

/// PCG-XSH-RR 64/32. Small, fast, and identical on every platform.
class Pcg32 {
 public:
  explicit Pcg32(std::uint64_t seed = 0x853C49E6748FEA9Bull,
                 std::uint64_t stream = 0xDA3E39CB94B95BDBull) noexcept {
    reseed(seed, stream);
  }

  void reseed(std::uint64_t seed, std::uint64_t stream) noexcept;
  void advance(std::uint64_t delta) noexcept;

  [[nodiscard]] std::uint32_t next_u32() noexcept;
  [[nodiscard]] std::uint64_t next_u64() noexcept;

  /// Uniform-ish integer in [0, bound). Returns 0 when bound == 0. Uses
  /// rejection sampling so the result is exactly uniform for small bounds.
  [[nodiscard]] std::uint64_t bounded(std::uint64_t bound) noexcept;

  /// Uniform-ish integer in [low, high] inclusive.
  [[nodiscard]] std::uint64_t range(std::uint64_t low, std::uint64_t high) noexcept;

  [[nodiscard]] bool chance(std::uint32_t numerator, std::uint32_t denominator) noexcept;

  /// Deterministic identifier with the given prefix, e.g. "m-7f3a91c2".
  [[nodiscard]] std::string identifier(std::string_view prefix, std::uint32_t max_suffix = 0xFFFFFFFFu);

  [[nodiscard]] std::uint64_t state() const noexcept { return state_; }
  [[nodiscard]] std::uint64_t stream() const noexcept { return stream_; }

 private:
  std::uint64_t state_ = 0;
  std::uint64_t stream_ = 1;
};

/// SplitMix64: used to derive independent sub-streams from one seed so that a
/// multi-part property test can be reproduced from a single number.
class SplitMix64 {
 public:
  explicit SplitMix64(std::uint64_t seed = 0) noexcept : state_(seed) {}
  [[nodiscard]] std::uint64_t next() noexcept;
  [[nodiscard]] Pcg32 make_stream() noexcept;

 private:
  std::uint64_t state_;
};

}  // namespace cif

#endif  // CIF_RNG_HPP
