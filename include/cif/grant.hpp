// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Grants, leases and attempts.
//
// A grant is the only artifact that carries cluster-wide communication
// authority. It binds, in one indivisible statement:
//   * source and destination scope (member id + generation + digest, endpoint)
//   * the topology path and its generation
//   * the resource reservation and its generation (when capacity is reserved)
//   * the cluster generation, epoch, policy generation and the incarnation of
//     the controller that minted it
//   * the lease, the attempt and the durability position of the commit
//
// Eligibility is not authority. Acknowledgement is not verified effect: it
// records that a caller *saw* the grant, and is stored separately from the
// commit that produced it.
#ifndef CIF_GRANT_HPP
#define CIF_GRANT_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "cif/bytes.hpp"
#include "cif/identity.hpp"
#include "cif/model.hpp"
#include "cif/request.hpp"
#include "cif/status.hpp"

namespace cif {

/// Lifecycle of a grant. Transitions are one-way; the engine never moves a
/// grant backwards.
enum class GrantState : std::uint8_t {
  Prepared = 0,   ///< Intent recorded; not yet authoritative.
  Committed,      ///< Durable, authoritative, awaiting (or already past) acknowledgement.
  Acknowledged,   ///< Caller has confirmed it observed the committed grant.
  /// The controller proved a durable commit but cannot prove the caller ever
  /// received it (crash between commit and acknowledgement). Capacity stays
  /// quarantined: it is never handed out twice, and the caller must reconcile.
  Ambiguous,
  Released,       ///< Explicitly released; capacity returned exactly once.
  Expired,        ///< Lease elapsed.
  Fenced,         ///< Superseded by a newer epoch/incarnation/generation.
  Revoked,        ///< Cancelled by an administrator or by a partition event.
  Superseded,     ///< Replaced by a renewal under the same attempt.
};

/// Durability position of the commit record. Kept separate from GrantState so
/// that "we decided" and "we made it durable" can never be conflated.
enum class CommitState : std::uint8_t {
  None = 0,     ///< Nothing written.
  Prepared,     ///< Prepare record durable; commit not yet written.
  Committed,    ///< Commit record durable: the decision survives a crash.
  Acknowledged, ///< Commit durable and caller acknowledged.
  Ambiguous,    ///< A prepare is durable but the commit record is torn or absent.
};

[[nodiscard]] const char* to_string(GrantState state) noexcept;
[[nodiscard]] const char* to_string(CommitState state) noexcept;
/// Live states hold capacity. Quarantined states hold capacity but carry no
/// usable authority.
[[nodiscard]] bool is_live(GrantState state) noexcept;
[[nodiscard]] bool is_quarantined(GrantState state) noexcept;
[[nodiscard]] bool holds_capacity(GrantState state) noexcept;
[[nodiscard]] bool is_terminal(GrantState state) noexcept;

struct AuthorityGrant {
  GrantId grant_id;

  ClusterId cluster_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  PolicyGeneration policy_generation{};
  ControllerIncarnation incarnation{};

  ContractId contract_id;
  ContractGeneration contract_generation{};

  ServiceGroupId source_service;
  ServiceGroupId destination_service;

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
  /// Units actually authorised, never more than were requested. Zero means a
  /// *permission grant*: the relationship is authorised and nothing is
  /// reserved, which is the correct answer when no capacity was asked for.
  std::uint64_t capacity_units = 0;
  std::uint32_t distinct_failure_domains = 0;

  LeaseId lease_id;
  Tick lease_issued{};
  Tick lease_expiry{};  ///< Zero means "no expiry requested".

  AttemptId attempt_id;
  MemberDomainId source_domain;
  MemberDomainId destination_domain;

  AuthorityOutcome outcome = AuthorityOutcome::Granted;
  GrantState state = GrantState::Prepared;
  CommitState commit = CommitState::None;

  std::uint64_t prepare_sequence = 0;  ///< Journal sequence of the prepare record.
  std::uint64_t commit_sequence = 0;   ///< Journal sequence of the commit record.
  std::uint64_t release_sequence = 0;  ///< Journal sequence of the release record.
  std::uint64_t acknowledgement_sequence = 0;

  bool acknowledged = false;
  bool degraded = false;
  bool capacity_reserved = false;

  std::vector<Reason> reductions;  ///< Why the grant was reduced, in a stable order.
  Provenance provenance;

  [[nodiscard]] bool expired_at(Tick now) const noexcept {
    return !lease_expiry.is_zero() && now >= lease_expiry;
  }

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AuthorityGrant& out);
};

/// Durable record of an attempt. This is what makes grant issuance exactly-once:
/// an attempt id is bound to the request digest that created it, and a repeat of
/// the same (attempt, digest) returns the original decision instead of minting a
/// second grant.
struct AttemptRecord {
  AttemptId attempt_id;
  RequestId request_id;
  Digest256 request_digest{};
  GrantId grant_id;
  LeaseId lease_id;
  AuthorityOutcome outcome = AuthorityOutcome::Invalid;
  ReasonCode primary_reason = ReasonCode::None;
  Tick first_seen{};
  Tick terminal_tick{};
  bool released = false;
  bool cancelled = false;

  [[nodiscard]] bool terminal() const noexcept { return released || cancelled; }

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AttemptRecord& out);
};

/// The engine's answer. Always carries the controller coordinate it was decided
/// against, so a caller can tell a stale answer from a fresh one.
struct AuthorityDecision {
  RequestId request_id;
  AttemptId attempt_id;
  AuthorityOutcome outcome = AuthorityOutcome::Invalid;
  std::vector<Reason> reasons;

  std::optional<AuthorityGrant> grant;

  ClusterId cluster_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  PolicyGeneration policy_generation{};
  ControllerIncarnation incarnation{};

  Digest256 spec_digest{};
  Digest256 state_digest{};
  Digest256 decision_digest{};

  std::uint64_t decision_sequence = 0;
  Tick decided_at{};

  /// True when this decision is a byte-identical replay of an earlier decision
  /// for the same attempt.
  bool idempotent_replay = false;

  /// True when the engine could not prove whether a commit happened. The caller
  /// must reconcile with a ResolveRequest before acting.
  bool requires_reconciliation = false;

  std::string explanation;

  [[nodiscard]] ReasonCode primary_reason() const noexcept {
    for (const Reason& reason : reasons) {
      if (reason.code != ReasonCode::None) {
        return reason.code;
      }
    }
    return ReasonCode::None;
  }

  [[nodiscard]] bool authoritative() const noexcept { return is_authoritative(outcome); }

  /// Stable, deterministic, human-readable rendering. Two runs of the same
  /// input against the same state produce byte-identical explanations.
  [[nodiscard]] std::string render() const;

  /// Digest over the decision excluding the digest field itself and excluding
  /// the free-text explanation (which is derived from the same inputs).
  [[nodiscard]] Digest256 compute_digest() const;

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AuthorityDecision& out);
};

/// Monotonic counters owned by the authority. Persisted so that identifiers are
/// never reissued after a restart, and so that a recovery can prove it did not
/// reuse an earlier identity.
struct AuthorityCounters {
  std::uint64_t decisions = 0;
  std::uint64_t grants = 0;
  std::uint64_t leases = 0;
  std::uint64_t attempts = 0;
  std::uint64_t fences = 0;
  std::uint64_t refusals = 0;
  std::uint64_t releases = 0;
  std::uint64_t expiries = 0;
  std::uint64_t recoveries = 0;
  std::uint64_t compactions = 0;

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, AuthorityCounters& out);
};

[[nodiscard]] Digest256 grant_digest(const AuthorityGrant& grant);
[[nodiscard]] Digest256 attempt_digest(const AttemptRecord& attempt);

/// Canonical rendering helpers shared by the CLI, the daemon and the tests.
[[nodiscard]] std::string render_grant(const AuthorityGrant& grant);
[[nodiscard]] std::string render_decision(const AuthorityDecision& decision);
[[nodiscard]] std::string render_attempt(const AttemptRecord& attempt);

}  // namespace cif

#endif  // CIF_GRANT_HPP
