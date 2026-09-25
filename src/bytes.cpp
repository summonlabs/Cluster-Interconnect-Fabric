#include "cif/bytes.hpp"

#include <cstring>

namespace cif {

// ---------------------------------------------------------------------------
// ByteWriter
// ---------------------------------------------------------------------------
void ByteWriter::u8(std::uint8_t value) {
  if (sink_ != nullptr) {
    sink_->push_back(value);
  }
}

void ByteWriter::u16(std::uint16_t value) {
  u8(static_cast<std::uint8_t>(value & 0xFFu));
  u8(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void ByteWriter::u32(std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    u8(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void ByteWriter::u64(std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    u8(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void ByteWriter::varint(std::uint64_t value) {
  while (value >= 0x80u) {
    u8(static_cast<std::uint8_t>((value & 0x7Fu) | 0x80u));
    value >>= 7;
  }
  u8(static_cast<std::uint8_t>(value));
}

void ByteWriter::raw(std::span<const std::uint8_t> bytes) {
  if (sink_ != nullptr) {
    sink_->insert(sink_->end(), bytes.begin(), bytes.end());
  }
}

void ByteWriter::blob(std::span<const std::uint8_t> bytes) {
  varint(static_cast<std::uint64_t>(bytes.size()));
  raw(bytes);
}

void ByteWriter::text(std::string_view value) {
  varint(static_cast<std::uint64_t>(value.size()));
  if (sink_ != nullptr) {
    const auto* first = reinterpret_cast<const std::uint8_t*>(value.data());
    sink_->insert(sink_->end(), first, first + value.size());
  }
}

void ByteWriter::digest(const Digest256& value) { raw(value.bytes()); }

// ---------------------------------------------------------------------------
// ByteReader
// ---------------------------------------------------------------------------
void ByteReader::fail(StatusCode code, std::string message) {
  if (failure_.ok()) {
    failure_ = Status::error(code, std::move(message));
  }
}

bool ByteReader::ensure(std::size_t length) {
  if (!failure_.ok()) {
    return false;
  }
  if (length > remaining()) {
    fail(StatusCode::Truncated, "canonical read past end of buffer");
    return false;
  }
  return true;
}

bool ByteReader::u8(std::uint8_t& out) {
  if (!ensure(1)) {
    return false;
  }
  out = data_[offset_];
  ++offset_;
  return true;
}

bool ByteReader::u16(std::uint16_t& out) {
  if (!ensure(2)) {
    return false;
  }
  out = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[offset_]) |
                                   (static_cast<std::uint16_t>(data_[offset_ + 1]) << 8));
  offset_ += 2;
  return true;
}

bool ByteReader::u32(std::uint32_t& out) {
  if (!ensure(4)) {
    return false;
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data_[offset_ + static_cast<std::size_t>(i)]) << (i * 8);
  }
  offset_ += 4;
  out = value;
  return true;
}

bool ByteReader::u64(std::uint64_t& out) {
  if (!ensure(8)) {
    return false;
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data_[offset_ + static_cast<std::size_t>(i)]) << (i * 8);
  }
  offset_ += 8;
  out = value;
  return true;
}

bool ByteReader::varint(std::uint64_t& out) {
  std::uint64_t value = 0;
  int shift = 0;
  for (int i = 0; i < 10; ++i) {
    std::uint8_t byte = 0;
    if (!u8(byte)) {
      return false;
    }
    if (shift == 63 && (byte & 0x7Fu) > 1u) {
      fail(StatusCode::Corruption, "varint overflows 64 bits");
      return false;
    }
    value |= static_cast<std::uint64_t>(byte & 0x7Fu) << shift;
    if ((byte & 0x80u) == 0u) {
      // Reject overlong encodings: a canonical varint never has a trailing
      // zero continuation group.
      if (i > 0 && byte == 0u) {
        fail(StatusCode::Corruption, "non-canonical varint encoding");
        return false;
      }
      out = value;
      return true;
    }
    shift += 7;
  }
  fail(StatusCode::Corruption, "varint longer than 10 bytes");
  return false;
}

bool ByteReader::boolean(bool& out) {
  std::uint8_t raw = 0;
  if (!u8(raw)) {
    return false;
  }
  if (raw > 1u) {
    fail(StatusCode::Corruption, "non-canonical boolean encoding");
    return false;
  }
  out = raw == 1u;
  return true;
}

bool ByteReader::count(std::size_t max_count, std::size_t& out) {
  std::uint64_t raw = 0;
  if (!varint(raw)) {
    return false;
  }
  if (raw > static_cast<std::uint64_t>(max_count)) {
    fail(StatusCode::CapacityExhausted, "declared count exceeds configured limit");
    return false;
  }
  out = static_cast<std::size_t>(raw);
  return true;
}

bool ByteReader::raw(std::size_t length, std::span<const std::uint8_t>& out) {
  if (!ensure(length)) {
    return false;
  }
  out = data_.subspan(offset_, length);
  offset_ += length;
  return true;
}

bool ByteReader::blob(Bytes& out, std::size_t max_length) {
  std::uint64_t length = 0;
  if (!varint(length)) {
    return false;
  }
  if (length > static_cast<std::uint64_t>(max_length)) {
    fail(StatusCode::CapacityExhausted, "declared blob length exceeds configured limit");
    return false;
  }
  std::span<const std::uint8_t> view;
  if (!raw(static_cast<std::size_t>(length), view)) {
    return false;
  }
  out.assign(view.begin(), view.end());
  return true;
}

bool ByteReader::text(std::string& out, std::size_t max_length) {
  std::uint64_t length = 0;
  if (!varint(length)) {
    return false;
  }
  if (length > static_cast<std::uint64_t>(max_length)) {
    fail(StatusCode::CapacityExhausted, "declared string length exceeds configured limit");
    return false;
  }
  std::span<const std::uint8_t> view;
  if (!raw(static_cast<std::size_t>(length), view)) {
    return false;
  }
  out.assign(reinterpret_cast<const char*>(view.data()), view.size());
  return true;
}

bool ByteReader::digest(Digest256& out) {
  std::span<const std::uint8_t> view;
  if (!raw(Digest256::kSize, view)) {
    return false;
  }
  std::uint8_t copy[Digest256::kSize];
  for (std::size_t i = 0; i < Digest256::kSize; ++i) {
    copy[i] = view[i];
  }
  out = Digest256::from_bytes(std::span<const std::uint8_t, Digest256::kSize>(copy, Digest256::kSize));
  return true;
}

bool ByteReader::skip(std::size_t length) {
  std::span<const std::uint8_t> view;
  return raw(length, view);
}

std::string hex_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kHex[(bytes[i] >> 4) & 0x0Fu];
    out[i * 2 + 1] = kHex[bytes[i] & 0x0Fu];
  }
  return out;
}

bool hex_decode(std::string_view hex, Bytes& out) noexcept {
  if (hex.size() % 2 != 0) {
    return false;
  }
  Bytes decoded;
  decoded.reserve(hex.size() / 2);
  const auto value = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = value(hex[i]);
    const int lo = value(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    decoded.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  out = std::move(decoded);
  return true;
}

Digest256 canonical_digest(std::string_view domain, std::span<const std::uint8_t> payload) {
  DomainHasher hasher(domain);
  hasher.add(payload);
  return hasher.finish();
}

}  // namespace cif
