#include "cif/rng.hpp"

namespace cif {
namespace {

constexpr std::uint64_t kMultiplier = 6364136223846793005ull;

}  // namespace

void Pcg32::reseed(std::uint64_t seed, std::uint64_t stream) noexcept {
  state_ = 0;
  stream_ = (stream << 1u) | 1u;
  static_cast<void>(next_u32());
  state_ += seed;
  static_cast<void>(next_u32());
}

void Pcg32::advance(std::uint64_t delta) noexcept {
  std::uint64_t accumulator = 0;
  std::uint64_t multiplier = kMultiplier;
  std::uint64_t delta_local = delta;
  std::uint64_t current = state_;
  while (delta_local != 0) {
    if ((delta_local & 1u) != 0u) {
      accumulator = accumulator * multiplier + current;
    }
    current = current * multiplier + stream_;
    multiplier *= multiplier;
    delta_local >>= 1u;
  }
  state_ = accumulator;
}

std::uint32_t Pcg32::next_u32() noexcept {
  const std::uint64_t previous = state_;
  state_ = previous * kMultiplier + stream_;
  const std::uint32_t xorshifted = static_cast<std::uint32_t>(((previous >> 18u) ^ previous) >> 27u);
  const std::uint32_t rotation = static_cast<std::uint32_t>(previous >> 59u);
  return (xorshifted >> rotation) | (xorshifted << ((32u - rotation) & 31u));
}

std::uint64_t Pcg32::next_u64() noexcept {
  const std::uint64_t high = static_cast<std::uint64_t>(next_u32());
  const std::uint64_t low = static_cast<std::uint64_t>(next_u32());
  return (high << 32u) | low;
}

std::uint64_t Pcg32::bounded(std::uint64_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  const std::uint64_t threshold = (0ull - bound) % bound;
  for (;;) {
    const std::uint64_t value = next_u64();
    if (value >= threshold) {
      return value % bound;
    }
  }
}

std::uint64_t Pcg32::range(std::uint64_t low, std::uint64_t high) noexcept {
  if (high <= low) {
    return low;
  }
  const std::uint64_t span = high - low + 1u;
  if (span == 0) {
    return next_u64();  // full 64-bit range
  }
  return low + bounded(span);
}

bool Pcg32::chance(std::uint32_t numerator, std::uint32_t denominator) noexcept {
  if (denominator == 0) {
    return false;
  }
  return bounded(denominator) < numerator;
}

std::string Pcg32::identifier(std::string_view prefix, std::uint32_t max_suffix) {
  static constexpr char kHex[] = "0123456789abcdef";
  const std::uint32_t value = max_suffix == 0xFFFFFFFFu ? next_u32() : static_cast<std::uint32_t>(bounded(max_suffix + 1u));
  std::string out(prefix);
  for (int i = 7; i >= 0; --i) {
    out.push_back(kHex[(value >> (i * 4)) & 0x0Fu]);
  }
  return out;
}

std::uint64_t SplitMix64::next() noexcept {
  state_ += 0x9E3779B97F4A7C15ull;
  std::uint64_t z = state_;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

Pcg32 SplitMix64::make_stream() noexcept { return Pcg32(next(), next() | 1u); }

}  // namespace cif
