#include "cif/identity.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <random>
#include <thread>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace cif {
namespace {

[[nodiscard]] std::uint64_t process_id() noexcept {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(::_getpid());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

/// SplitsMix64: a cheap, well-distributed mixing function used to derive an
/// incarnation from entropy plus process identity. Not a cryptographic
/// primitive; incarnation values only need to be unique, not unpredictable.
[[nodiscard]] constexpr std::uint64_t splitmix64(std::uint64_t& state) noexcept {
  state += 0x9E3779B97F4A7C15ull;
  std::uint64_t z = state;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

[[nodiscard]] constexpr int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

IncarnationBits IncarnationBits::generate() noexcept {
  static std::atomic<std::uint64_t> counter{0};
  std::random_device device;
  std::uint64_t state = 0;
  state ^= static_cast<std::uint64_t>(device()) << 32;
  state ^= static_cast<std::uint64_t>(device());
  state ^= static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  state ^= process_id() << 17;
  state ^= counter.fetch_add(1) * 0x9E3779B97F4A7C15ull;
  state ^= static_cast<std::uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));

  IncarnationBits bits;
  for (int i = 0; i < 2; ++i) {
    const std::uint64_t chunk = splitmix64(state);
    for (int b = 0; b < 8; ++b) {
      bits.bytes_[static_cast<std::size_t>(i * 8 + b)] =
          static_cast<std::uint8_t>((chunk >> (b * 8)) & 0xFFu);
    }
  }
  if (bits.is_zero()) {
    // Astronomically unlikely; make it impossible rather than improbable.
    bits.bytes_[0] = 1;
  }
  return bits;
}

IncarnationBits IncarnationBits::from_seed(std::uint64_t seed) noexcept {
  std::uint64_t state = seed;
  IncarnationBits bits;
  for (int i = 0; i < 2; ++i) {
    const std::uint64_t chunk = splitmix64(state);
    for (int b = 0; b < 8; ++b) {
      bits.bytes_[static_cast<std::size_t>(i * 8 + b)] =
          static_cast<std::uint8_t>((chunk >> (b * 8)) & 0xFFu);
    }
  }
  if (bits.is_zero()) {
    bits.bytes_[15] = 1;
  }
  return bits;
}

bool IncarnationBits::parse(std::string_view hex, IncarnationBits& out) noexcept {
  if (hex.size() != kSize * 2) {
    return false;
  }
  IncarnationBits parsed;
  for (std::size_t i = 0; i < kSize; ++i) {
    const int hi = hex_value(hex[i * 2]);
    const int lo = hex_value(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    parsed.bytes_[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  out = parsed;
  return true;
}

std::string IncarnationBits::hex() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(kSize * 2);
  for (std::size_t i = 0; i < kSize; ++i) {
    out[i * 2] = kHex[(bytes_[i] >> 4) & 0x0Fu];
    out[i * 2 + 1] = kHex[bytes_[i] & 0x0Fu];
  }
  return out;
}

bool IncarnationBits::is_zero() const noexcept {
  for (std::uint8_t byte : bytes_) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

void encode_provenance(ByteWriter& writer, const Provenance& provenance) {
  encode_id(writer, provenance.client);
  writer.text(provenance.origin);
  writer.text(provenance.correlation_id);
  writer.u64(provenance.ingress_sequence);
  encode_counter(writer, provenance.observed_tick);
}

bool decode_provenance(ByteReader& reader, Provenance& out) {
  Provenance parsed;
  if (!decode_id(reader, parsed.client)) {
    return false;
  }
  if (!reader.text(parsed.origin, limits::kMaxIdentifierBytes)) {
    return false;
  }
  if (!reader.text(parsed.correlation_id, limits::kMaxIdentifierBytes)) {
    return false;
  }
  if (!reader.u64(parsed.ingress_sequence)) {
    return false;
  }
  if (!decode_counter(reader, parsed.observed_tick)) {
    return false;
  }
  if (!is_valid_utf8(parsed.origin) || !is_valid_utf8(parsed.correlation_id)) {
    reader.fail(StatusCode::Corruption, "provenance text is not valid UTF-8");
    return false;
  }
  out = std::move(parsed);
  return true;
}

void encode_controller_identity(ByteWriter& writer, const ControllerIdentity& identity) {
  encode_id(writer, identity.cluster);
  encode_counter(writer, identity.generation);
  encode_counter(writer, identity.epoch);
  encode_counter(writer, identity.policy);
  encode_incarnation(writer, identity.incarnation);
}

}  // namespace cif
