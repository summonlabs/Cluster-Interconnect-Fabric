// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Strongly typed identities. Every distinct concept gets a distinct C++ type so
// that a member id can never be passed where a path id is expected, and a
// generation can never be compared against an epoch. Nothing here is a bare
// integer or a bare std::string at an API boundary.
#ifndef CIF_IDENTITY_HPP
#define CIF_IDENTITY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "cif/bytes.hpp"
#include "cif/hash.hpp"
#include "cif/limits.hpp"
#include "cif/text.hpp"

namespace cif {

// ---------------------------------------------------------------------------
// Tagged opaque identifier
// ---------------------------------------------------------------------------
template <typename Tag>
class TypedId {
 public:
  using tag_type = Tag;

  TypedId() = default;

  [[nodiscard]] static bool is_valid(std::string_view text) noexcept {
    return is_valid_identifier(text, limits::kMaxIdentifierBytes);
  }

  [[nodiscard]] static bool parse(std::string_view text, TypedId& out) {
    if (!is_valid(text)) {
      return false;
    }
    out.value_.assign(text);
    return true;
  }

  /// Constructs from an already-validated string. Returns an empty id when the
  /// input is invalid, which callers must treat as "absent".
  [[nodiscard]] static TypedId from_validated(std::string_view text) {
    TypedId id;
    if (is_valid(text)) {
      id.value_.assign(text);
    }
    return id;
  }

  [[nodiscard]] const std::string& value() const noexcept { return value_; }
  [[nodiscard]] std::string_view view() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return value_.size(); }
  [[nodiscard]] std::string to_string() const { return value_; }

  friend bool operator==(const TypedId& a, const TypedId& b) noexcept { return a.value_ == b.value_; }
  friend bool operator!=(const TypedId& a, const TypedId& b) noexcept { return !(a == b); }
  friend bool operator<(const TypedId& a, const TypedId& b) noexcept { return a.value_ < b.value_; }

 private:
  std::string value_;
};

#define CIF_IDENTIFIER_TYPE(alias_name, tag_name) \
  struct tag_name {};                             \
  using alias_name = TypedId<tag_name>

CIF_IDENTIFIER_TYPE(ClusterId, ClusterIdTag);
CIF_IDENTIFIER_TYPE(MemberId, MemberIdTag);
CIF_IDENTIFIER_TYPE(MemberDomainId, MemberDomainIdTag);
CIF_IDENTIFIER_TYPE(EndpointId, EndpointIdTag);
CIF_IDENTIFIER_TYPE(ServiceGroupId, ServiceGroupIdTag);
CIF_IDENTIFIER_TYPE(PathId, PathIdTag);
CIF_IDENTIFIER_TYPE(ResourceId, ResourceIdTag);
CIF_IDENTIFIER_TYPE(ContractId, ContractIdTag);
CIF_IDENTIFIER_TYPE(ObligationId, ObligationIdTag);
CIF_IDENTIFIER_TYPE(ExclusionId, ExclusionIdTag);
CIF_IDENTIFIER_TYPE(GrantId, GrantIdTag);
CIF_IDENTIFIER_TYPE(LeaseId, LeaseIdTag);
CIF_IDENTIFIER_TYPE(AttemptId, AttemptIdTag);
CIF_IDENTIFIER_TYPE(RequestId, RequestIdTag);
CIF_IDENTIFIER_TYPE(ClientId, ClientIdTag);

#undef CIF_IDENTIFIER_TYPE

// ---------------------------------------------------------------------------
// Tagged monotonic counter: generations and epochs
// ---------------------------------------------------------------------------
template <typename Tag>
class Counter {
 public:
  using value_type = std::uint64_t;
  static constexpr value_type kMax = std::numeric_limits<value_type>::max();

  constexpr Counter() noexcept = default;
  explicit constexpr Counter(value_type value) noexcept : value_(value) {}

  [[nodiscard]] constexpr value_type value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }
  [[nodiscard]] constexpr bool at_max() const noexcept { return value_ == kMax; }
  [[nodiscard]] constexpr bool can_advance() const noexcept { return value_ != kMax; }

  /// Saturating increment. Saturation is observable so that callers can refuse
  /// to mint new state rather than silently wrapping.
  [[nodiscard]] constexpr Counter advanced() const noexcept {
    return Counter(value_ == kMax ? kMax : value_ + 1);
  }

  [[nodiscard]] std::string to_string() const { return to_decimal(value_); }

  friend constexpr bool operator==(Counter a, Counter b) noexcept { return a.value_ == b.value_; }
  friend constexpr bool operator!=(Counter a, Counter b) noexcept { return a.value_ != b.value_; }
  friend constexpr bool operator<(Counter a, Counter b) noexcept { return a.value_ < b.value_; }
  friend constexpr bool operator<=(Counter a, Counter b) noexcept { return a.value_ <= b.value_; }
  friend constexpr bool operator>(Counter a, Counter b) noexcept { return a.value_ > b.value_; }
  friend constexpr bool operator>=(Counter a, Counter b) noexcept { return a.value_ >= b.value_; }

 private:
  value_type value_ = 0;
};

#define CIF_COUNTER_TYPE(alias_name, tag_name) \
  struct tag_name {};                          \
  using alias_name = Counter<tag_name>

CIF_COUNTER_TYPE(ClusterGeneration, ClusterGenerationTag);
CIF_COUNTER_TYPE(ClusterEpoch, ClusterEpochTag);
CIF_COUNTER_TYPE(PolicyGeneration, PolicyGenerationTag);
CIF_COUNTER_TYPE(MemberGeneration, MemberGenerationTag);
CIF_COUNTER_TYPE(PathGeneration, PathGenerationTag);
CIF_COUNTER_TYPE(ReservationGeneration, ReservationGenerationTag);
CIF_COUNTER_TYPE(ContractGeneration, ContractGenerationTag);
CIF_COUNTER_TYPE(AttemptSequence, AttemptSequenceTag);
CIF_COUNTER_TYPE(Tick, TickTag);

#undef CIF_COUNTER_TYPE

// ---------------------------------------------------------------------------
// Incarnation: 128-bit process/controller identity, regenerated on every start
// ---------------------------------------------------------------------------
class IncarnationBits {
 public:
  static constexpr std::size_t kSize = 16;

  IncarnationBits() noexcept = default;

  /// Fresh incarnation derived from OS entropy mixed with the steady clock and
  /// the process id. Never all-zero.
  [[nodiscard]] static IncarnationBits generate() noexcept;

  [[nodiscard]] static bool parse(std::string_view hex, IncarnationBits& out) noexcept;

  /// Deterministic construction used by tests and by the reference model.
  [[nodiscard]] static IncarnationBits from_seed(std::uint64_t seed) noexcept;

  [[nodiscard]] const std::array<std::uint8_t, kSize>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::string hex() const;
  [[nodiscard]] bool is_zero() const noexcept;

  friend bool operator==(const IncarnationBits& a, const IncarnationBits& b) noexcept {
    return a.bytes_ == b.bytes_;
  }
  friend bool operator!=(const IncarnationBits& a, const IncarnationBits& b) noexcept { return !(a == b); }
  friend bool operator<(const IncarnationBits& a, const IncarnationBits& b) noexcept {
    return a.bytes_ < b.bytes_;
  }

 private:
  std::array<std::uint8_t, kSize> bytes_{};
};

template <typename Tag>
class IncarnationT {
 public:
  IncarnationT() = default;
  explicit IncarnationT(IncarnationBits bits) noexcept : bits_(bits) {}

  [[nodiscard]] static IncarnationT generate() noexcept { return IncarnationT(IncarnationBits::generate()); }
  [[nodiscard]] static IncarnationT from_seed(std::uint64_t seed) noexcept {
    return IncarnationT(IncarnationBits::from_seed(seed));
  }
  [[nodiscard]] static bool parse(std::string_view hex, IncarnationT& out) noexcept {
    IncarnationBits bits;
    if (!IncarnationBits::parse(hex, bits)) {
      return false;
    }
    out = IncarnationT(bits);
    return true;
  }

  [[nodiscard]] const IncarnationBits& bits() const noexcept { return bits_; }
  [[nodiscard]] std::string hex() const { return bits_.hex(); }
  [[nodiscard]] bool is_zero() const noexcept { return bits_.is_zero(); }

  friend bool operator==(const IncarnationT& a, const IncarnationT& b) noexcept { return a.bits_ == b.bits_; }
  friend bool operator!=(const IncarnationT& a, const IncarnationT& b) noexcept { return !(a == b); }
  friend bool operator<(const IncarnationT& a, const IncarnationT& b) noexcept { return a.bits_ < b.bits_; }

 private:
  IncarnationBits bits_{};
};

struct ControllerIncarnationTag {};
struct ProcessIncarnationTag {};
using ControllerIncarnation = IncarnationT<ControllerIncarnationTag>;
using ProcessIncarnation = IncarnationT<ProcessIncarnationTag>;

// ---------------------------------------------------------------------------
// Provenance: who asked, in what context, at what ingress position
// ---------------------------------------------------------------------------
struct Provenance {
  ClientId client;
  std::string origin;          ///< Free-form but sanitised origin label.
  std::string correlation_id;  ///< Caller supplied correlation, echoed back.
  std::uint64_t ingress_sequence = 0;  ///< Controller-assigned ingress order.
  Tick observed_tick{};

  [[nodiscard]] bool empty() const noexcept {
    return client.empty() && origin.empty() && correlation_id.empty() && ingress_sequence == 0;
  }
};

// ---------------------------------------------------------------------------
// Canonical codecs for the tagged primitives. Declared here so every model type
// encodes identities and counters identically.
// ---------------------------------------------------------------------------
template <typename Tag>
void encode_id(ByteWriter& writer, const TypedId<Tag>& id) {
  writer.text(id.view());
}

/// Decodes an identifier. The empty string is a legitimate encoding of "absent"
/// -- many model fields (endpoints, resources, renewal targets) are optional --
/// so it decodes to an empty id rather than being rejected. Whether a given id
/// is *required* is a semantic question answered by the type's validate_shape(),
/// never by the codec.
template <typename Tag>
[[nodiscard]] bool decode_id(ByteReader& reader, TypedId<Tag>& out) {
  std::string raw;
  if (!reader.text(raw, limits::kMaxIdentifierBytes)) {
    return false;
  }
  if (raw.empty()) {
    out = TypedId<Tag>{};
    return true;
  }
  if (!TypedId<Tag>::parse(raw, out)) {
    reader.fail(StatusCode::Corruption, "identifier does not satisfy the CIF identifier grammar");
    return false;
  }
  return true;
}

template <typename Tag>
void encode_counter(ByteWriter& writer, Counter<Tag> counter) {
  writer.u64(counter.value());
}

template <typename Tag>
[[nodiscard]] bool decode_counter(ByteReader& reader, Counter<Tag>& out) {
  std::uint64_t raw = 0;
  if (!reader.u64(raw)) {
    return false;
  }
  out = Counter<Tag>(raw);
  return true;
}

inline void encode_incarnation(ByteWriter& writer, const IncarnationBits& bits) {
  writer.raw(bits.bytes());
}

[[nodiscard]] inline bool decode_incarnation(ByteReader& reader, IncarnationBits& out) {
  std::span<const std::uint8_t> view;
  if (!reader.raw(IncarnationBits::kSize, view)) {
    return false;
  }
  std::string hex;
  hex.reserve(IncarnationBits::kSize * 2);
  static constexpr char kHexDigits[] = "0123456789abcdef";
  for (std::uint8_t byte : view) {
    hex.push_back(kHexDigits[(byte >> 4) & 0x0Fu]);
    hex.push_back(kHexDigits[byte & 0x0Fu]);
  }
  return IncarnationBits::parse(hex, out);
}

template <typename Tag>
void encode_incarnation(ByteWriter& writer, const IncarnationT<Tag>& value) {
  encode_incarnation(writer, value.bits());
}

template <typename Tag>
[[nodiscard]] bool decode_incarnation(ByteReader& reader, IncarnationT<Tag>& out) {
  IncarnationBits bits;
  if (!decode_incarnation(reader, bits)) {
    return false;
  }
  out = IncarnationT<Tag>(bits);
  return true;
}

void encode_provenance(ByteWriter& writer, const Provenance& provenance);
[[nodiscard]] bool decode_provenance(ByteReader& reader, Provenance& out);

/// The full authority coordinate of a controller: everything a caller must
/// echo back for its request to be considered against *this* controller state.
struct ControllerIdentity {
  ClusterId cluster;
  ClusterGeneration generation{};
  ClusterEpoch epoch{};
  PolicyGeneration policy{};
  ControllerIncarnation incarnation{};

  friend bool operator==(const ControllerIdentity& a, const ControllerIdentity& b) noexcept {
    return a.cluster == b.cluster && a.generation == b.generation && a.epoch == b.epoch &&
           a.policy == b.policy && a.incarnation == b.incarnation;
  }
  friend bool operator!=(const ControllerIdentity& a, const ControllerIdentity& b) noexcept {
    return !(a == b);
  }
};

void encode_controller_identity(ByteWriter& writer, const ControllerIdentity& identity);

}  // namespace cif

#endif  // CIF_IDENTITY_HPP
