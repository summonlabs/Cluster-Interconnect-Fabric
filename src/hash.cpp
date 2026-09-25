#include "cif/hash.hpp"

#include <cstring>
#include <vector>

namespace cif {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

constexpr std::uint32_t kSha256Initial[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                             0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
  return (x >> n) | (x << (32u - n));
}

[[nodiscard]] constexpr std::uint32_t big_endian_u32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void store_big_endian_u32(std::uint32_t value, std::uint8_t* out) noexcept {
  out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  out[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

// CRC-32C software table (256 entries, generated once at first use).
struct Crc32cTable {
  std::uint32_t entries[256]{};
  Crc32cTable() noexcept {
    constexpr std::uint32_t kPoly = 0x82F63B78u;  // reflected 0x1EDC6F41
    for (std::uint32_t i = 0; i < 256u; ++i) {
      std::uint32_t crc = i;
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc & 1u) != 0u ? (crc >> 1) ^ kPoly : (crc >> 1);
      }
      entries[i] = crc;
    }
  }
};

[[nodiscard]] const Crc32cTable& crc32c_table() noexcept {
  static const Crc32cTable table;
  return table;
}

[[nodiscard]] std::string hex_of(std::span<const std::uint8_t> data) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(data.size() * 2);
  for (std::size_t i = 0; i < data.size(); ++i) {
    out[i * 2] = kHex[(data[i] >> 4) & 0x0Fu];
    out[i * 2 + 1] = kHex[data[i] & 0x0Fu];
  }
  return out;
}

[[nodiscard]] int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

Digest256 Digest256::from_bytes(std::span<const std::uint8_t, kSize> in) noexcept {
  Digest256 d;
  for (std::size_t i = 0; i < kSize; ++i) {
    d.bytes_[i] = in[i];
  }
  return d;
}

bool Digest256::parse(std::string_view hex, Digest256& out) noexcept {
  if (hex.size() != kSize * 2) {
    return false;
  }
  Digest256 parsed;
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

bool Digest256::is_zero() const noexcept {
  for (std::uint8_t b : bytes_) {
    if (b != 0) {
      return false;
    }
  }
  return true;
}

std::string Digest256::hex() const { return hex_of(std::span<const std::uint8_t>(bytes_.data(), bytes_.size())); }

void Sha256::reset() noexcept {
  state_ = {kSha256Initial[0], kSha256Initial[1], kSha256Initial[2], kSha256Initial[3],
            kSha256Initial[4], kSha256Initial[5], kSha256Initial[6], kSha256Initial[7]};
  buffer_.fill(0);
  total_bytes_ = 0;
  buffer_len_ = 0;
  finalised_ = false;
}

void Sha256::compress(const std::uint8_t block[kBlockSize]) noexcept {
  std::uint32_t w[64];
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = big_endian_u32(block + i * 4);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) noexcept {
  if (finalised_ || data.empty()) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(data.size());
  std::size_t offset = 0;
  if (buffer_len_ > 0) {
    while (offset < data.size() && buffer_len_ < kBlockSize) {
      buffer_[buffer_len_++] = data[offset++];
    }
    if (buffer_len_ == kBlockSize) {
      compress(buffer_.data());
      buffer_len_ = 0;
    }
  }
  while (data.size() - offset >= kBlockSize) {
    compress(data.data() + offset);
    offset += kBlockSize;
  }
  while (offset < data.size()) {
    buffer_[buffer_len_++] = data[offset++];
  }
}

void Sha256::update(std::string_view data) noexcept {
  update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

void Sha256::update(std::uint8_t byte) noexcept {
  const std::uint8_t one[1] = {byte};
  update(std::span<const std::uint8_t>(one, 1));
}

void Sha256::finalise(std::uint8_t out[kDigestSize]) noexcept {
  if (!finalised_) {
    const std::uint64_t bit_length = total_bytes_ * 8u;
    std::uint8_t pad = 0x80u;
    update(std::span<const std::uint8_t>(&pad, 1));
    const std::uint8_t zero = 0x00u;
    while (buffer_len_ != 56) {
      update(std::span<const std::uint8_t>(&zero, 1));
    }
    std::uint8_t length_bytes[8];
    for (std::size_t i = 0; i < 8; ++i) {
      length_bytes[7 - i] = static_cast<std::uint8_t>((bit_length >> (i * 8)) & 0xFFu);
    }
    // total_bytes_ counts padding bytes too; only the length field matters here,
    // so write the pre-padding bit length captured above.
    buffer_len_ = 56;
    for (std::size_t i = 0; i < 8; ++i) {
      buffer_[56 + i] = length_bytes[i];
    }
    compress(buffer_.data());
    buffer_len_ = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      store_big_endian_u32(state_[i], out + i * 4);
    }
    finalised_ = true;
  }
}

Digest256 Sha256::digest() {
  std::uint8_t raw[kDigestSize];
  finalise(raw);
  return Digest256::from_bytes(std::span<const std::uint8_t, kDigestSize>(raw, kDigestSize));
}

Digest256 sha256(std::span<const std::uint8_t> data) {
  Sha256 h;
  h.update(data);
  return h.digest();
}

Digest256 sha256(std::string_view data) {
  Sha256 h;
  h.update(data);
  return h.digest();
}

std::string sha256_hex(std::string_view data) { return sha256(data).hex(); }

std::uint32_t crc32c(std::span<const std::uint8_t> data) noexcept {
  const Crc32cTable& table = crc32c_table();
  std::uint32_t crc = 0xFFFFFFFFu;
  for (std::uint8_t byte : data) {
    crc = table.entries[(crc ^ byte) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

std::uint32_t crc32c(std::string_view data) noexcept {
  return crc32c(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

std::uint64_t fnv1a64(std::span<const std::uint8_t> data) noexcept {
  std::uint64_t hash = 1469598103934665603ull;
  for (std::uint8_t byte : data) {
    hash ^= byte;
    hash *= 1099511628211ull;
  }
  return hash;
}

std::uint64_t fnv1a64(std::string_view data) noexcept {
  return fnv1a64(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

DomainHasher::DomainHasher(std::string_view domain) {
  const std::uint64_t n = static_cast<std::uint64_t>(domain.size());
  for (int i = 0; i < 8; ++i) {
    hasher_.update(static_cast<std::uint8_t>((n >> (i * 8)) & 0xFFu));
  }
  hasher_.update(domain);
}

void DomainHasher::add(std::span<const std::uint8_t> part) {
  const std::uint64_t n = static_cast<std::uint64_t>(part.size());
  for (int i = 0; i < 8; ++i) {
    hasher_.update(static_cast<std::uint8_t>((n >> (i * 8)) & 0xFFu));
  }
  hasher_.update(part);
}

void DomainHasher::add(std::string_view part) {
  add(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(part.data()), part.size()));
}

void DomainHasher::add_u64(std::uint64_t value) noexcept {
  const std::uint8_t raw[8] = {
      static_cast<std::uint8_t>(value & 0xFFu),         static_cast<std::uint8_t>((value >> 8) & 0xFFu),
      static_cast<std::uint8_t>((value >> 16) & 0xFFu), static_cast<std::uint8_t>((value >> 24) & 0xFFu),
      static_cast<std::uint8_t>((value >> 32) & 0xFFu), static_cast<std::uint8_t>((value >> 40) & 0xFFu),
      static_cast<std::uint8_t>((value >> 48) & 0xFFu), static_cast<std::uint8_t>((value >> 56) & 0xFFu)};
  hasher_.update(std::span<const std::uint8_t>(raw, 8));
}

Digest256 DomainHasher::finish() { return hasher_.digest(); }

}  // namespace cif
