// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Authority requests. A request is a *claim about the world* ("this member is
// at generation N with digest D, this path is at generation P") plus a demand
// ("give me U units under contract C"). The engine either corroborates the
// claim against its own state or refuses; it never upgrades a claim into a fact
// because the claimant sounded confident.
#ifndef CIF_REQUEST_HPP
#define CIF_REQUEST_HPP

#include <cstdint>
#include <string>

#include "cif/bytes.hpp"
#include "cif/identity.hpp"
#include "cif/status.hpp"

namespace cif {

/// Everything a caller must assert for an authority decision.
struct AuthorityRequest {
  RequestId request_id;

  ContractId contract_id;
  ContractGeneration contract_generation{};

  ClusterId cluster_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  ControllerIncarnation incarnation{};
  PolicyGeneration policy_generation{};

  MemberId source_member;
  MemberGeneration source_member_generation{};
  Digest256 source_member_digest{};

  MemberId destination_member;
  MemberGeneration destination_member_generation{};
  Digest256 destination_member_digest{};

  EndpointId source_endpoint;
  EndpointId destination_endpoint;

  PathId path_id;
  PathGeneration path_generation{};

  ResourceId resource_id;
  ReservationGeneration reservation_generation{};

  std::uint64_t requested_units = 0;
  std::uint64_t lease_ticks = 0;

  AttemptId attempt_id;
  Provenance provenance;

  /// Caller consents to DEGRADED instead of REFUSED when the full scope is not
  /// available. Without this the engine refuses rather than silently reducing.
  bool allow_degraded = false;

  /// Renewal of an existing grant: same attempt identity, new lease.
  bool renewal = false;
  GrantId renewal_of;
  LeaseId renewal_lease;

  /// Structural validation: identifier grammar, bounds, overflow, UTF-8.
  /// Never consults cluster state.
  [[nodiscard]] Status validate_shape() const;

  /// True when the caller supplied the member digests the contract needs. A
  /// request missing digests is INCOMPLETE, not REFUSED: the engine cannot tell
  /// whether the members match.
  [[nodiscard]] bool has_member_digests() const noexcept {
    return !source_member_digest.is_zero() && !destination_member_digest.is_zero();
  }

  [[nodiscard]] bool has_path_claim() const noexcept { return !path_id.empty(); }
  [[nodiscard]] bool has_resource_claim() const noexcept { return !resource_id.empty(); }

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AuthorityRequest& out);
  [[nodiscard]] Digest256 digest() const;
};

/// Idempotent, exactly-once release of a grant.
struct ReleaseRequest {
  RequestId request_id;
  GrantId grant_id;
  AttemptId attempt_id;
  LeaseId lease_id;
  ClusterId cluster_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  ControllerIncarnation incarnation{};
  Provenance provenance;

  /// Administrative override: release even if the caller cannot prove it owns
  /// the lease. Recorded distinctly in the audit trail.
  bool administrative = false;

  [[nodiscard]] Status validate_shape() const;
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, ReleaseRequest& out);
};

/// Ask the controller what actually happened to an attempt. This is the
/// reconciliation path for commit-before-acknowledge ambiguity.
struct ResolveRequest {
  RequestId request_id;
  AttemptId attempt_id;
  ClusterId cluster_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  ControllerIncarnation incarnation{};
  Provenance provenance;

  [[nodiscard]] Status validate_shape() const;
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, ResolveRequest& out);
};

/// Acknowledge that the caller has *observed* a committed grant. Acknowledgement
/// is evidence of delivery, never evidence of effect.
struct AcknowledgeRequest {
  RequestId request_id;
  GrantId grant_id;
  LeaseId lease_id;
  AttemptId attempt_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  ControllerIncarnation incarnation{};
  Provenance provenance;

  [[nodiscard]] Status validate_shape() const;
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AcknowledgeRequest& out);
};

/// Cancel an attempt (client withdrew, or an operator fenced it).
struct CancelRequest {
  RequestId request_id;
  AttemptId attempt_id;
  GrantId grant_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  ControllerIncarnation incarnation{};
  std::string reason;
  Provenance provenance;

  [[nodiscard]] Status validate_shape() const;
  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, CancelRequest& out);
};

}  // namespace cif

#endif  // CIF_REQUEST_HPP
