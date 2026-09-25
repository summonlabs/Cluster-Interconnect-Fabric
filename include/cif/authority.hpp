// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The authority engine. This is a *single-threaded reducer*: exactly one thread
// owns the state at a time, and every mutation arrives as a method call on that
// thread. There is no internal locking, by design -- the runtime layer owns the
// concurrency, and the engine's invariants are therefore checkable by reading
// one file.
//
// The engine answers exactly one question: given the cluster as declared, the
// contracts in force, the capacity declared, the maintenance windows active,
// the failures observed and the caller's own claims about member generations,
// which communication relationships carry authority *right now*?
#ifndef CIF_AUTHORITY_HPP
#define CIF_AUTHORITY_HPP

#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "cif/contract.hpp"
#include "cif/grant.hpp"
#include "cif/identity.hpp"
#include "cif/journal.hpp"
#include "cif/model.hpp"
#include "cif/request.hpp"
#include "cif/status.hpp"

namespace cif {

/// Sink for durable transitions. The engine writes the transition *before* it
/// changes in-memory state, so a crash can only ever lose work that was never
/// authorised.
class DurabilitySink {
 public:
  virtual ~DurabilitySink() = default;
  /// Records one transition and stamps 'entry.sequence' with the position the
  /// record occupies in the durable log. Callers bind that position into the
  /// artifacts they create, which is how a grant can prove *when* it became
  /// durable.
  [[nodiscard]] virtual Status append(JournalEntry& entry, bool durable) = 0;
  [[nodiscard]] virtual Status compact(const JournalEntry& snapshot) = 0;
  [[nodiscard]] virtual bool durable() const noexcept = 0;
  [[nodiscard]] virtual bool should_compact() const noexcept = 0;
};

/// In-memory sink. Reports durable() == false so that no caller can mistake an
/// unsaved decision for a durable one.
class NullDurabilitySink final : public DurabilitySink {
 public:
  [[nodiscard]] Status append(JournalEntry& entry, bool durable) override;
  [[nodiscard]] Status compact(const JournalEntry& snapshot) override;
  [[nodiscard]] bool durable() const noexcept override { return false; }
  [[nodiscard]] bool should_compact() const noexcept override { return false; }
  [[nodiscard]] std::uint64_t records() const noexcept { return records_; }

 private:
  std::uint64_t records_ = 0;
};

/// Journal-backed sink.
class JournalDurabilitySink final : public DurabilitySink {
 public:
  explicit JournalDurabilitySink(Journal& journal) noexcept : journal_(&journal) {}
  [[nodiscard]] Status append(JournalEntry& entry, bool durable) override;
  [[nodiscard]] Status compact(const JournalEntry& snapshot) override;
  [[nodiscard]] bool durable() const noexcept override { return true; }
  [[nodiscard]] bool should_compact() const noexcept override;

 private:
  Journal* journal_;
};

/// Recovery policy applied to grants that were live when the controller stopped.
enum class RecoveryPolicy : std::uint8_t {
  /// Acknowledged grants are re-validated and re-issued under the new epoch.
  /// Committed-but-unacknowledged grants are quarantined as ambiguous.
  RevalidateAcknowledged = 0,
  /// Every recovered live grant is fenced. Maximally conservative; used when an
  /// operator cannot tolerate any continuity assumption across a restart.
  FenceAll,
};

struct AuthorityOptions {
  bool require_member_digests = true;
  bool require_path_binding = true;
  bool reject_unknown_capabilities = true;
  bool enforce_capacity = true;
  std::uint64_t default_lease_ticks = 4096;
  std::uint64_t max_lease_ticks = limits::kMaxLeaseTicks;
  std::size_t audit_history = limits::kMaxHistoryEntries;
  RecoveryPolicy recovery_policy = RecoveryPolicy::RevalidateAcknowledged;
  bool durable = true;

  /// Whether every decision carries the digest of the whole authoritative state.
  ///
  /// That digest is a pure function of the state, so producing it costs
  /// O(state). For a cluster with thousands of live grants and a decision rate
  /// in the thousands per second it dominates everything else. Turning it off
  /// leaves decisions fully deterministic -- outcome, reasons, grant and
  /// coordinates are all covered by the decision digest -- and the full-state
  /// digest remains available on demand through a State query. It is on by
  /// default, because "which state was this answer against?" is worth paying for
  /// until it is measured not to be.
  bool decision_state_digest = true;
};

/// A compact audit record. Diagnostic only: it is not persisted, and after a
/// restart the engine reports the history as empty rather than replaying
/// remembered decisions as if they were current.
struct AuditEntry {
  std::uint64_t sequence = 0;
  Tick tick{};
  std::string operation;
  RequestId request_id;
  AttemptId attempt_id;
  GrantId grant_id;
  AuthorityOutcome outcome = AuthorityOutcome::Invalid;
  ReasonCode reason = ReasonCode::None;
  std::string detail;
};

class AuthorityCore {
 public:
  explicit AuthorityCore(AuthorityOptions options = {});

  AuthorityCore(const AuthorityCore&) = delete;
  AuthorityCore& operator=(const AuthorityCore&) = delete;

  // -- lifecycle -----------------------------------------------------------
  /// Creates a brand-new authority. Binds the cluster identity, mints epoch 1
  /// and a fresh incarnation.
  [[nodiscard]] Status initialize(const ClusterId& cluster,
                                  ControllerIncarnation incarnation,
                                  PolicyGeneration policy,
                                  Tick tick,
                                  DurabilitySink* sink);

  /// Adopts state that survived a restart. Advances the epoch, binds a new
  /// incarnation, applies the recovery policy, and records the recovered
  /// evidence as historical. Never presents recovered state as freshly
  /// observed.
  [[nodiscard]] Status recover(const ClusterSpec& spec,
                               const ContractSet& contracts,
                               std::vector<AuthorityGrant> grants,
                               std::vector<AttemptRecord> attempts,
                               const AuthorityCounters& counters,
                               const RecoveryReport& report,
                               ControllerIncarnation incarnation,
                               Tick tick);

  /// Binds a sink without creating state. Passing nullptr restores the
  /// non-durable in-memory sink; the engine never runs without one.
  void attach_sink(DurabilitySink* sink) noexcept {
    sink_ = (sink != nullptr) ? sink : &default_sink_;
  }

  /// Discards every piece of state and rebinds the options, keeping whatever
  /// durability sink is currently attached. Used by the daemon when it
  /// re-initialises, and by tests that build several clusters in one process.
  void reset(AuthorityOptions options = {});

  // -- spec mutation -------------------------------------------------------
  [[nodiscard]] Status upsert_member(Member member);
  [[nodiscard]] Status remove_member(const MemberId& id);
  [[nodiscard]] Status set_member_lifecycle(const MemberId& id, MemberLifecycle lifecycle);
  [[nodiscard]] Status upsert_path(Path path);
  [[nodiscard]] Status remove_path(const PathId& id);
  [[nodiscard]] Status set_path_state(const PathId& id, PathState state);
  [[nodiscard]] Status upsert_exclusion(MaintenanceExclusion exclusion);
  [[nodiscard]] Status remove_exclusion(const ExclusionId& id);
  [[nodiscard]] Status upsert_obligation(CapacityObligation obligation);
  [[nodiscard]] Status remove_obligation(const ObligationId& id);
  [[nodiscard]] Status upsert_contract(CommunicationContract contract);
  [[nodiscard]] Status remove_contract(const ContractId& id);
  [[nodiscard]] Status set_policy_generation(PolicyGeneration policy);
  [[nodiscard]] Status advance_tick(Tick tick);

  /// Fences every live grant (partition, administrative fence, epoch roll).
  [[nodiscard]] Status fence_all(ReasonCode reason, std::string detail);

  /// Expires every live grant whose lease has elapsed at the current tick.
  [[nodiscard]] Status expire_leases();

  /// Re-evaluates every live grant against current member/path state. Grants
  /// whose members moved generation, were removed, or whose path vanished are
  /// revoked and their capacity returned.
  [[nodiscard]] Status revalidate_live_grants();

  // -- authority -----------------------------------------------------------
  [[nodiscard]] AuthorityDecision submit(const AuthorityRequest& request);
  [[nodiscard]] AuthorityDecision release(const ReleaseRequest& request);
  [[nodiscard]] AuthorityDecision resolve(const ResolveRequest& request);
  [[nodiscard]] AuthorityDecision acknowledge(const AcknowledgeRequest& request);
  [[nodiscard]] AuthorityDecision cancel(const CancelRequest& request);

  // -- inspection ----------------------------------------------------------
  [[nodiscard]] const AuthorityOptions& options() const noexcept { return options_; }
  [[nodiscard]] const ClusterSpec& spec() const noexcept { return spec_; }
  [[nodiscard]] const ContractSet& contracts() const noexcept { return contracts_; }
  [[nodiscard]] const std::vector<AuthorityGrant>& grants() const noexcept { return grants_; }
  [[nodiscard]] const std::vector<AttemptRecord>& attempts() const noexcept { return attempts_; }
  [[nodiscard]] const AuthorityCounters& counters() const noexcept { return counters_; }
  [[nodiscard]] const RecoveryReport& recovery() const noexcept { return recovery_; }
  [[nodiscard]] const std::deque<AuditEntry>& audit() const noexcept { return audit_; }
  [[nodiscard]] bool initialized() const noexcept { return initialized_; }
  [[nodiscard]] bool recovered() const noexcept { return !recovery_.fresh; }

  [[nodiscard]] const AuthorityGrant* find_grant(const GrantId& id) const noexcept;
  [[nodiscard]] const AttemptRecord* find_attempt(const AttemptId& id) const noexcept;
  [[nodiscard]] std::vector<const AuthorityGrant*> live_grants_for_path(const PathId& path) const;
  [[nodiscard]] std::vector<const AuthorityGrant*> live_grants_for_service(const ServiceGroupId& service) const;

  /// Units currently held (live or quarantined) against a resource. Never
  /// exceeds the declared total.
  [[nodiscard]] std::uint64_t reserved_units(const ResourceId& resource) const noexcept;
  [[nodiscard]] std::uint64_t path_committed_units(const PathId& path) const noexcept;
  [[nodiscard]] std::uint64_t quarantined_units() const noexcept;

  [[nodiscard]] ControllerIdentity controller_identity() const;
  [[nodiscard]] Digest256 state_digest() const;
  [[nodiscard]] Digest256 live_state_digest() const;

  /// Deterministic, complete rendering of everything that carries authority.
  [[nodiscard]] std::string render_state() const;
  [[nodiscard]] std::string render_audit() const;

  /// Full snapshot record for journal compaction.
  [[nodiscard]] JournalEntry make_snapshot() const;
  [[nodiscard]] Status maybe_compact();

  /// Verifies the engine's structural invariants without mutating anything:
  /// tables sorted and unique, capacity accounting non-negative and within
  /// declared totals, no live grant referencing a missing member or path, no
  /// attempt pointing at a grant that does not exist. Returns the first
  /// violation. Used by tests, by the CLI ('cif verify') and by the daemon's
  /// periodic self-check.
  [[nodiscard]] Status self_check() const;

 private:
  struct EligibilityResult {
    AuthorityOutcome outcome = AuthorityOutcome::Invalid;
    std::vector<Reason> reasons;
    std::vector<Reason> degradations;
    const Member* source_member = nullptr;
    const Member* destination_member = nullptr;
    const Path* path = nullptr;
    const CommunicationContract* contract = nullptr;
    const Resource* resource = nullptr;
    std::uint64_t authorised_units = 0;
    std::uint32_t distinct_failure_domains = 0;
    ReasonCode obligation_reason = ReasonCode::None;
    std::string obligation_detail;
  };

  [[nodiscard]] AuthorityDecision decide_impl(const AuthorityRequest& request);
  [[nodiscard]] EligibilityResult evaluate(const AuthorityRequest& request,
                                           const CommunicationContract& contract);
  [[nodiscard]] AuthorityDecision renew(const AuthorityRequest& request,
                                        const CommunicationContract& contract);
  [[nodiscard]] const Path* select_path(const AuthorityRequest& request) const;
  [[nodiscard]] AuthorityDecision replay_attempt(const AttemptRecord& attempt,
                                                 const AuthorityRequest& request);
  [[nodiscard]] AuthorityDecision make_decision(const RequestId& request_id,
                                                const AttemptId& attempt_id,
                                                AuthorityOutcome outcome,
                                                std::vector<Reason> reasons);
  [[nodiscard]] AuthorityDecision malformed_decision(const RequestId& request_id,
                                                     const AttemptId& attempt_id,
                                                     const Status& status);
  void finalize_decision(AuthorityDecision& decision, const char* operation);
  [[nodiscard]] Status commit_grant(AuthorityGrant grant, AuthorityDecision& decision);
  [[nodiscard]] Status terminate_grant(AuthorityGrant& grant, GrantState state, ReasonCode reason,
                                       const std::string& detail, bool release_capacity);
  [[nodiscard]] Status journal_entry(JournalEntry& entry, bool durable = true);
  [[nodiscard]] AuthorityGrant* mutable_grant(const GrantId& id) noexcept;
  [[nodiscard]] AttemptRecord* mutable_attempt(const AttemptId& id) noexcept;
  [[nodiscard]] Status upsert_grant(const AuthorityGrant& grant);
  [[nodiscard]] Status upsert_attempt(const AttemptRecord& attempt);
  [[nodiscard]] std::string mint_grant_id();
  [[nodiscard]] std::string mint_lease_id();
  void record_audit(std::string operation, const RequestId& request, const AttemptId& attempt,
                    const GrantId& grant, AuthorityOutcome outcome, ReasonCode reason,
                    std::string detail);
  void apply_recovery_policy();

  /// Guarantees that every recovered grant has an attempt record.
  ///
  /// A crash can leave a grant whose attempt record was never written (the
  /// commit is durable, the terminal record is not). Recovery must not depend on
  /// that write having happened: the repair pass reconstructs a conservative
  /// attempt from the grant itself and records it, so an operator can always ask
  /// "what happened to this attempt?" and get a truthful answer.
  void reconcile_attempts();
  [[nodiscard]] Status revalidate_grant(AuthorityGrant& grant, bool allow_reissue);

  AuthorityOptions options_{};
  NullDurabilitySink default_sink_{};
  DurabilitySink* sink_ = &default_sink_;
  mutable Digest256 cached_state_digest_{};
  mutable bool state_digest_valid_ = false;

  ClusterSpec spec_{};
  ContractSet contracts_{};
  std::vector<AuthorityGrant> grants_;      ///< Sorted by grant id.
  std::vector<AttemptRecord> attempts_;     ///< Sorted by attempt id.
  AuthorityCounters counters_{};
  RecoveryReport recovery_{};
  std::deque<AuditEntry> audit_;
  bool initialized_ = false;
  std::uint64_t grant_serial_ = 0;
  std::uint64_t lease_serial_ = 0;
  Digest256 decision_request_digest_{};  ///< Digest of the in-flight request during commit.
};

/// True when a capability name denotes hardware or transport semantics that CIF
/// deliberately does not model. Used to distinguish UNSUPPORTED
/// (HARDWARE_SEMANTICS_UNSUPPORTED) from UNSUPPORTED (UNSUPPORTED_CAPABILITY).
[[nodiscard]] bool is_hardware_capability(std::string_view capability) noexcept;

/// True when a capability name denotes inter-cluster connectivity, which is a
/// different runtime's responsibility.
[[nodiscard]] bool is_inter_cluster_capability(std::string_view capability) noexcept;

}  // namespace cif

#endif  // CIF_AUTHORITY_HPP
