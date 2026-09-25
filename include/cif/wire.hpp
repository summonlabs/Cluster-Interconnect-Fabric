// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The CIF wire protocol: a fixed 32-byte frame header, a bounded payload and a
// trailing payload CRC-32C. The protocol is versioned, and a peer that speaks a
// version this build does not understand is refused rather than guessed at.
#ifndef CIF_WIRE_HPP
#define CIF_WIRE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "cif/authority.hpp"
#include "cif/bytes.hpp"
#include "cif/contract.hpp"
#include "cif/grant.hpp"
#include "cif/identity.hpp"
#include "cif/journal.hpp"
#include "cif/model.hpp"
#include "cif/request.hpp"
#include "cif/status.hpp"

namespace cif {

enum class MessageType : std::uint16_t {
  Invalid = 0,
  Hello = 1,
  HelloAck = 2,
  Submit = 3,
  Release = 4,
  Resolve = 5,
  Acknowledge = 6,
  Cancel = 7,
  Decision = 8,
  Admin = 9,
  AdminResult = 10,
  Query = 11,
  QueryResult = 12,
  Error = 13,
  Ping = 14,
  Pong = 15,
  Bye = 16,
};

[[nodiscard]] const char* to_string(MessageType type) noexcept;

/// Administrative spec mutations, carried over the wire.
enum class AdminKind : std::uint16_t {
  None = 0,
  UpsertMember = 1,
  RemoveMember = 2,
  SetMemberLifecycle = 3,
  UpsertPath = 4,
  RemovePath = 5,
  SetPathState = 6,
  UpsertExclusion = 7,
  RemoveExclusion = 8,
  UpsertObligation = 9,
  RemoveObligation = 10,
  UpsertContract = 11,
  RemoveContract = 12,
  SetPolicy = 13,
  AdvanceTick = 14,
  FenceAll = 15,
  ExpireLeases = 16,
  Revalidate = 17,
  Compact = 18,
  SelfCheck = 19,
};

[[nodiscard]] const char* to_string(AdminKind kind) noexcept;
[[nodiscard]] bool parse_admin_kind(std::string_view text, AdminKind& out) noexcept;

enum class QueryKind : std::uint16_t {
  None = 0,
  Controller = 1,
  State = 2,
  Audit = 3,
  Member = 4,
  Path = 5,
  Grant = 6,
  Attempt = 7,
  Recovery = 8,
  Verify = 9,
  Version = 10,
};

[[nodiscard]] const char* to_string(QueryKind kind) noexcept;
[[nodiscard]] bool parse_query_kind(std::string_view text, QueryKind& out) noexcept;

struct AdminCommand {
  AdminKind kind = AdminKind::None;
  std::string detail;

  /// Optimistic concurrency: when non-zero, the command is refused unless the
  /// controller is at exactly this cluster generation.
  ClusterGeneration expect_generation{};
  bool has_expectation = false;

  Member member;
  MemberId member_id;
  MemberLifecycle lifecycle = MemberLifecycle::Enlisted;

  Path path;
  PathId path_id;
  PathState path_state = PathState::Operational;

  MaintenanceExclusion exclusion;
  ExclusionId exclusion_id;

  CapacityObligation obligation;
  ObligationId obligation_id;

  CommunicationContract contract;
  ContractId contract_id;

  PolicyGeneration policy{};
  Tick tick{};
  ReasonCode fence_reason = ReasonCode::ControllerRestarted;

  [[nodiscard]] Status validate_shape() const;
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AdminCommand& out);
};

struct AdminResult {
  StatusCode code = StatusCode::Ok;
  std::string message;
  ClusterGeneration generation{};
  ClusterEpoch epoch{};
  ControllerIncarnation incarnation{};
  Digest256 state_digest{};

  [[nodiscard]] bool ok() const noexcept { return code == StatusCode::Ok; }
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AdminResult& out);
};

struct QueryCommand {
  QueryKind kind = QueryKind::None;
  MemberId member_id;
  PathId path_id;
  GrantId grant_id;
  AttemptId attempt_id;
  bool include_terminal = false;

  [[nodiscard]] Status validate_shape() const;
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, QueryCommand& out);
};

struct QueryResult {
  StatusCode code = StatusCode::Ok;
  std::string message;
  std::string text;
  ClusterId cluster_id;
  ClusterGeneration generation{};
  ClusterEpoch epoch{};
  PolicyGeneration policy{};
  ControllerIncarnation incarnation{};
  Digest256 state_digest{};
  /// Digest of the whole specification, including the epoch and incarnation.
  Digest256 spec_digest{};
  /// Digest of the declared cluster only -- members, paths, exclusions and
  /// obligations -- excluding who is ruling. This is the digest that must be
  /// byte-identical across a restart, and the one an operator uses to prove that
  /// a restart did not silently rewrite the cluster.
  Digest256 topology_digest{};

  [[nodiscard]] bool ok() const noexcept { return code == StatusCode::Ok; }
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, QueryResult& out);
};

/// One frame: header fields plus a bounded payload.
struct Frame {
  MessageType type = MessageType::Invalid;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;
  Bytes payload;

  static constexpr std::size_t kHeaderSize = 32;
  static constexpr std::uint32_t kMagic = 0x57464943u;  // 'C','I','F','W'
};

/// Decoded message. A flat struct: the message set is closed and small, and a
/// flat struct keeps the codec auditable in one place.
struct WireMessage {
  MessageType type = MessageType::Invalid;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;

  std::string banner;
  ClientId client;

  std::string error_code;
  std::string error_message;

  AuthorityRequest request;
  ReleaseRequest release;
  ResolveRequest resolve;
  AcknowledgeRequest acknowledge;
  CancelRequest cancel;
  AuthorityDecision decision;
  AdminCommand admin;
  AdminResult admin_result;
  QueryCommand query;
  QueryResult query_result;

  ClusterId cluster_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  PolicyGeneration policy{};
  ControllerIncarnation incarnation{};
  Digest256 state_digest{};

  /// Encodes the payload for this message's type.
  void encode(ByteWriter& writer) const;

  /// Decodes a payload. The caller must set exactly one field on 'out' before
  /// calling: 'type', which selects the payload schema. Every other field of
  /// 'out' is overwritten.
  [[nodiscard]] static bool decode(ByteReader& reader, WireMessage& out);
};

/// Encodes a frame (header + payload + CRC) into 'out'.
[[nodiscard]] Status encode_frame(const Frame& frame, Bytes& out);

/// Reports whether 'buffer' begins with a complete frame, and how long it is.
/// Safe to call on a partial buffer of any length.
[[nodiscard]] Status frame_size(std::span<const std::uint8_t> buffer, std::size_t& out_size);

/// Decodes a complete frame from 'buffer'.
[[nodiscard]] Status decode_frame(std::span<const std::uint8_t> buffer, Frame& out);

/// Convenience: turn a message into a frame and back.
[[nodiscard]] Status pack_message(const WireMessage& message, Frame& out);
[[nodiscard]] Status unpack_message(const Frame& frame, WireMessage& out);

[[nodiscard]] WireMessage make_error_message(std::string code, std::string text);

}  // namespace cif

#endif  // CIF_WIRE_HPP
