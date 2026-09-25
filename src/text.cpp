#include "cif/text.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>

namespace cif {
namespace {

/// Decodes one UTF-8 scalar starting at 'i'. Returns the number of bytes
/// consumed, or 0 on any malformed sequence.
[[nodiscard]] std::size_t decode_scalar(std::string_view text, std::size_t i, std::uint32_t& cp) noexcept {
  const auto byte = [&](std::size_t k) -> std::uint32_t {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(text[k]));
  };
  const std::uint32_t b0 = byte(i);
  if (b0 < 0x80u) {
    cp = b0;
    return 1;
  }
  if (b0 >= 0xC2u && b0 <= 0xDFu) {
    if (i + 1 >= text.size()) return 0;
    const std::uint32_t b1 = byte(i + 1);
    if ((b1 & 0xC0u) != 0x80u) return 0;
    cp = ((b0 & 0x1Fu) << 6) | (b1 & 0x3Fu);
    return 2;
  }
  if (b0 >= 0xE0u && b0 <= 0xEFu) {
    if (i + 2 >= text.size()) return 0;
    const std::uint32_t b1 = byte(i + 1);
    const std::uint32_t b2 = byte(i + 2);
    if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u) return 0;
    // Reject overlong encodings (E0 A0..BF) and surrogates (ED A0..BF).
    if (b0 == 0xE0u && b1 < 0xA0u) return 0;
    if (b0 == 0xEDu && b1 >= 0xA0u) return 0;
    cp = ((b0 & 0x0Fu) << 12) | ((b1 & 0x3Fu) << 6) | (b2 & 0x3Fu);
    return 3;
  }
  if (b0 >= 0xF0u && b0 <= 0xF4u) {
    if (i + 3 >= text.size()) return 0;
    const std::uint32_t b1 = byte(i + 1);
    const std::uint32_t b2 = byte(i + 2);
    const std::uint32_t b3 = byte(i + 3);
    if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u || (b3 & 0xC0u) != 0x80u) return 0;
    if (b0 == 0xF0u && b1 < 0x90u) return 0;   // overlong
    if (b0 == 0xF4u && b1 > 0x8Fu) return 0;   // > U+10FFFF
    cp = ((b0 & 0x07u) << 18) | ((b1 & 0x3Fu) << 12) | ((b2 & 0x3Fu) << 6) | (b3 & 0x3Fu);
    return 4;
  }
  return 0;
}

}  // namespace

bool contains_nul(std::string_view text) noexcept {
  return text.find('\0') != std::string_view::npos;
}

bool is_valid_utf8(std::string_view text) noexcept {
  std::size_t i = 0;
  while (i < text.size()) {
    std::uint32_t cp = 0;
    const std::size_t consumed = decode_scalar(text, i, cp);
    if (consumed == 0) {
      return false;
    }
    if (cp == 0) {
      return false;  // embedded NUL is never valid in CIF text
    }
    i += consumed;
  }
  return true;
}

bool is_valid_identifier(std::string_view text, std::size_t max_len) noexcept {
  if (text.empty() || text.size() > max_len) {
    return false;
  }
  for (char c : text) {
    const bool alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    const bool punct = c == '-' || c == '_' || c == '.' || c == ':' || c == '@' || c == '+' || c == '/';
    if (!alnum && !punct) {
      return false;
    }
  }
  return true;
}

std::string sanitise_for_display(std::string_view text, std::size_t max_len) {
  std::string out;
  out.reserve(text.size() < max_len ? text.size() : max_len);
  for (char raw : text) {
    if (out.size() >= max_len) {
      break;
    }
    const unsigned char c = static_cast<unsigned char>(raw);
    if (c < 0x20u || c == 0x7Fu || c >= 0x80u) {
      out.push_back('?');
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  return out;
}

std::string to_decimal(std::uint64_t value) {
  if (value == 0) {
    return "0";
  }
  char buffer[24];
  std::size_t pos = sizeof(buffer);
  while (value != 0) {
    buffer[--pos] = static_cast<char>('0' + static_cast<int>(value % 10u));
    value /= 10u;
  }
  return std::string(buffer + pos, sizeof(buffer) - pos);
}

bool parse_decimal_u64(std::string_view text, std::uint64_t& out) noexcept {
  if (text.empty() || text.size() > 20) {
    return false;
  }
  std::uint64_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      return false;  // overflow
    }
    value = value * 10u + digit;
  }
  out = value;
  return true;
}

bool is_finite(double value) noexcept { return std::isfinite(value) != 0; }

std::string format_fixed3(double value) {
  if (!(value == value) || value > 1.0e18 || value < -1.0e18) {  // NOLINT(misc-confusable-identifiers)
    return "n/a";
  }
  char buffer[64];
  const int written = std::snprintf(buffer, sizeof(buffer), "%.3f", value);
  if (written <= 0) {
    return "n/a";
  }
  return std::string(buffer, static_cast<std::size_t>(written));
}

}  // namespace cif
