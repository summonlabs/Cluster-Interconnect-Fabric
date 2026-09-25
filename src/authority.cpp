#include "cif/authority.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <utility>

#include "cif/render.hpp"
#include "cif/text.hpp"

namespace cif {
namespace {

constexpr const char* kHardwareMarkers[] = {
    "rdma",  "roce",   "infiniband", "ib-fabric", "nvlink", "nvswitch", "cuda",
    "pcie",  "optical", "asic",      "switch",    "serdes", "lane",     "nic",
    "dpu",   "phy",    "transceiver", "fabric-hardware", "qos-hw"};

constexpr const char* kInterClusterMarkers[] = {"inter-cluster", "intercluster", "cross-cluster",
                                                "wan", "site-to-site"};

[[nodiscard]] bool contains_marker(std::string_view text,
                                   const char* const* markers,
                                   std::size_t count) noexcept {
  std::string lowered;
  lowered.reserve(text.size());
  for (char c : text) {
    lowered.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
  }
  for (std::size_t i = 0; i < count; ++i) {
    if (lowered.find(markers[i]) != std::string::npos) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] std::uint64_t serial_suffix(const std::string& id) noexcept {
  std::uint64_t value = 0;
  std::size_t index = id.size();
  while (index > 0) {
    const char c = id[index - 1];
    if (c < '0' || c > '9') {
      break;
    }
    --index;
  }
  if (index == id.size()) {
    return 0;
  }
  for (std::size_t i = index; i < id.size(); ++i) {
    const std::uint64_t digit = static_cast<std::uint64_t>(id[i] - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      return UINT64_MAX;
    }
    value = value * 10u + digit;
  }
  return value;
}

void append_bounded(std::string& target, std::string_view text) {
  if (target.size() >= limits::kMaxExplanationBytes) {
    return;
  }
  const std::size_t room = limits::kMaxExplanationBytes - target.size();
  target.append(text.substr(0, room));
}

[[nodiscard]] std::string build_explanation(const AuthorityDecision& decision) {
  std::string out;
  append_bounded(out, to_string(decision.outcome));
  append_bounded(out, " request=");
  append_bounded(out, decision.request_id.to_string());
  append_bounded(out, " attempt=");
  append_bounded(out, decision.attempt_id.to_string());
  append_bounded(out, " reasons=");
  append_bounded(out, render_reasons(decision.reasons));
  if (decision.grant.has_value()) {
    append_bounded(out, " grant=");
    append_bounded(out, decision.grant->grant_id.to_string());
    append_bounded(out, " grant_state=");
    append_bounded(out, to_string(decision.grant->state));
  }
  return out;
}

[[nodiscard]] AuthorityOutcome outcome_for_status(const Status& status) noexcept {
  switch (status.code()) {
    case StatusCode::InvalidArgument:
    case StatusCode::Corruption:
    case StatusCode::Truncated:
      return AuthorityOutcome::Invalid;
    case StatusCode::LimitExceeded:
    case StatusCode::CapacityExhausted:
      return AuthorityOutcome::Invalid;
    case StatusCode::Unsupported:
      return AuthorityOutcome::Unsupported;
    case StatusCode::VersionMismatch:
      return AuthorityOutcome::Unsupported;
    default:
      return AuthorityOutcome::Invalid;
  }
}

[[nodiscard]] ReasonCode reason_for_status(const Status& status) noexcept {
  switch (status.code()) {
    case StatusCode::LimitExceeded:
    case StatusCode::CapacityExhausted:
      return ReasonCode::LimitExceeded;
    case StatusCode::Unsupported:
    case StatusCode::VersionMismatch:
      return ReasonCode::UnsupportedCapability;
    default:
      return ReasonCode::MalformedRequest;
  }
}

[[nodiscard]] AuthorityOutcome outcome_for_reason(ReasonCode reason) noexcept {
  return default_outcome_for(reason);
}

}  // namespace

bool is_hardware_capability(std::string_view capability) noexcept {
  return contains_marker(capability, kHardwareMarkers, std::size(kHardwareMarkers));
}

bool is_inter_cluster_capability(std::string_view capability) noexcept {
  return contains_marker(capability, kInterClusterMarkers, std::size(kInterClusterMarkers));
}

// ---------------------------------------------------------------------------
// Durability sinks
// ---------------------------------------------------------------------------
Status NullDurabilitySink::append(JournalEntry& entry, bool durable) {
  if (entry.kind == JournalRecordKind::Invalid) {
    return Status::error(StatusCode::InvalidArgument, "cannot record an INVALID transition");
  }
  static_cast<void>(durable);
  // The in-memory sink still assigns positions so that provenance fields are
  // populated identically in durable and non-durable runs.
  entry.sequence = records_;
  ++records_;
  return Status::success();
}

Status NullDurabilitySink::compact(const JournalEntry& snapshot) {
  if (snapshot.kind != JournalRecordKind::Snapshot) {
    return Status::error(StatusCode::InvalidArgument, "compaction requires a SNAPSHOT record");
  }
  records_ = 1;
  return Status::success();
}

Status JournalDurabilitySink::append(JournalEntry& entry, bool durable) {
  if (journal_ == nullptr || !journal_->is_open()) {
    return Status::error(StatusCode::Closed, "journal is not open");
  }
  return journal_->append(entry, durable);
}

Status JournalDurabilitySink::compact(const JournalEntry& snapshot) {
  if (journal_ == nullptr || !journal_->is_open()) {
    return Status::error(StatusCode::Closed, "journal is not open");
  }
  return journal_->compact(snapshot);
}

bool JournalDurabilitySink::should_compact() const noexcept {
  return journal_ != nullptr && journal_->is_open() && journal_->should_compact();
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
AuthorityCore::AuthorityCore(AuthorityOptions options) : options_(options) {
  if (options_.max_lease_ticks == 0 || options_.max_lease_ticks > limits::kMaxLeaseTicks) {
    options_.max_lease_ticks = limits::kMaxLeaseTicks;
  }
  if (options_.audit_history == 0 || options_.audit_history > limits::kMaxHistoryEntries) {
    options_.audit_history = limits::kMaxHistoryEntries;
  }
}

void AuthorityCore::reset(AuthorityOptions options) {
  if (options.max_lease_ticks == 0 || options.max_lease_ticks > limits::kMaxLeaseTicks) {
    options.max_lease_ticks = limits::kMaxLeaseTicks;
  }
  if (options.audit_history == 0 || options.audit_history > limits::kMaxHistoryEntries) {
    options.audit_history = limits::kMaxHistoryEntries;
  }
  options_ = options;
  spec_ = ClusterSpec{};
  contracts_.clear();
  grants_.clear();
  attempts_.clear();
  counters_ = AuthorityCounters{};
  recovery_ = RecoveryReport{};
  audit_.clear();
  grant_serial_ = 0;
  lease_serial_ = 0;
  state_digest_valid_ = false;
  initialized_ = false;
}

Status AuthorityCore::upsert_grant(const AuthorityGrant& grant) {
  const auto slot = std::lower_bound(
      grants_.begin(), grants_.end(), grant.grant_id,
      [](const AuthorityGrant& existing, const GrantId& key) { return existing.grant_id < key; });
  if (slot != grants_.end() && slot->grant_id == grant.grant_id) {
    *slot = grant;
    state_digest_valid_ = false;
    return Status::success();
  }
  if (grants_.size() >= limits::kMaxGrants) {
    return Status::error(StatusCode::CapacityExhausted, "grant table is full");
  }
  grants_.insert(slot, grant);
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::upsert_attempt(const AttemptRecord& attempt) {
  const auto slot =
      std::lower_bound(attempts_.begin(), attempts_.end(), attempt.attempt_id,
                       [](const AttemptRecord& existing, const AttemptId& key) {
                         return existing.attempt_id < key;
                       });
  if (slot != attempts_.end() && slot->attempt_id == attempt.attempt_id) {
    *slot = attempt;
    state_digest_valid_ = false;
    return Status::success();
  }
  if (attempts_.size() >= limits::kMaxAttempts) {
    return Status::error(StatusCode::CapacityExhausted, "attempt table is full");
  }
  attempts_.insert(slot, attempt);
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::initialize(const ClusterId& cluster, ControllerIncarnation incarnation,
                                 PolicyGeneration policy, Tick tick, DurabilitySink* sink) {
  if (cluster.empty()) {
    return Status::error(StatusCode::InvalidArgument, "cluster id must not be empty");
  }
  if (sink != nullptr) {
    sink_ = sink;
  }
  spec_ = ClusterSpec{};
  contracts_.clear();
  grants_.clear();
  attempts_.clear();
  counters_ = AuthorityCounters{};
  recovery_ = RecoveryReport{};
  audit_.clear();
  grant_serial_ = 0;
  lease_serial_ = 0;
  state_digest_valid_ = false;

  CIF_TRY(spec_.set_cluster_id(cluster));
  spec_.set_incarnation(incarnation);
  spec_.set_tick(tick);

  JournalEntry binding;
  binding.kind = JournalRecordKind::SetController;
  binding.tick = tick;
  binding.cluster_id = cluster;
  binding.cluster_generation = ClusterGeneration{0};
  binding.epoch = ClusterEpoch{0};
  binding.policy_generation = policy;
  binding.incarnation = incarnation;
  CIF_TRY(journal_entry(binding));

  spec_.set_policy_generation(policy);
  CIF_TRY(spec_.begin_epoch(incarnation, policy));

  // The first epoch is journaled explicitly so that replay reproduces the exact
  // same generation/epoch pair without re-deriving it.
  JournalEntry epoch_entry;
  epoch_entry.kind = JournalRecordKind::EpochBegin;
  epoch_entry.tick = tick;
  epoch_entry.cluster_id = cluster;
  epoch_entry.cluster_generation = spec_.generation();
  epoch_entry.epoch = spec_.epoch();
  epoch_entry.policy_generation = spec_.policy_generation();
  epoch_entry.incarnation = incarnation;
  CIF_TRY(journal_entry(epoch_entry));
  initialized_ = true;
  recovery_.fresh = true;
  recovery_.detail = "controller initialised with fresh state";
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::recover(const ClusterSpec& spec, const ContractSet& contracts,
                              std::vector<AuthorityGrant> grants,
                              std::vector<AttemptRecord> attempts,
                              const AuthorityCounters& counters, const RecoveryReport& report,
                              ControllerIncarnation incarnation, Tick tick) {
  spec_ = spec;
  contracts_ = contracts;
  grants_ = std::move(grants);
  attempts_ = std::move(attempts);
  counters_ = counters;
  recovery_ = report;
  recovery_.records_applied = recovery_.records_read;
  recovery_.fresh = false;
  audit_.clear();
  state_digest_valid_ = false;

  std::sort(grants_.begin(), grants_.end(),
            [](const AuthorityGrant& a, const AuthorityGrant& b) { return a.grant_id < b.grant_id; });
  std::sort(attempts_.begin(), attempts_.end(), [](const AttemptRecord& a, const AttemptRecord& b) {
    return a.attempt_id < b.attempt_id;
  });

  if (spec_.cluster_id().empty()) {
    return Status::error(StatusCode::Corruption, "recovered state has no cluster identity");
  }

  grant_serial_ = 0;
  lease_serial_ = 0;
  for (const AuthorityGrant& grant : grants_) {
    grant_serial_ = std::max(grant_serial_, serial_suffix(grant.grant_id.value()));
    lease_serial_ = std::max(lease_serial_, serial_suffix(grant.lease_id.value()));
  }
  counters_.grants = std::max(counters_.grants, grant_serial_);
  counters_.leases = std::max(counters_.leases, lease_serial_);
  counters_.recoveries += 1;

  // Bind the new incarnation and advance the epoch: this is the fence that
  // makes every recovered artifact visibly historical. Logical time never moves
  // backwards across a restart.
  spec_.set_tick(tick > spec_.tick() ? tick : spec_.tick());
  CIF_TRY(spec_.begin_epoch(incarnation, spec_.policy_generation()));

  JournalEntry entry;
  entry.kind = JournalRecordKind::EpochBegin;
  entry.tick = tick;
  entry.cluster_id = spec_.cluster_id();
  entry.cluster_generation = spec_.generation();
  entry.epoch = spec_.epoch();
  entry.policy_generation = spec_.policy_generation();
  entry.incarnation = incarnation;
  CIF_TRY(journal_entry(entry));

  apply_recovery_policy();
  initialized_ = true;
  state_digest_valid_ = false;
  return Status::success();
}

void AuthorityCore::apply_recovery_policy() {
  const Tick now = spec_.tick();
  for (AuthorityGrant& grant : grants_) {
    if (!is_live(grant.state)) {
      continue;
    }
    const AttemptRecord* attempt = find_attempt(grant.attempt_id);
    const bool acknowledged = grant.acknowledged || grant.state == GrantState::Acknowledged;

    if (grant.commit == CommitState::Prepared) {
      // The prepare is durable but no commit record exists: the controller can
      // prove the grant was never authorised. This is a definite answer, not an
      // ambiguity.
      grant.state = GrantState::Released;
      grant.capacity_reserved = false;
      grant.release_sequence = 0;
      grant.commit = CommitState::Prepared;
      grant.reductions.push_back(
          Reason(ReasonCode::CommitNotDurable, "controller restarted before the commit record"));
      (void)terminate_grant(grant, GrantState::Released, ReasonCode::CommitNotDurable,
                            "recovered prepare without a durable commit", false);
      AttemptRecord updated;
      if (attempt != nullptr) {
        updated = *attempt;
      }
      updated.attempt_id = grant.attempt_id;
      updated.grant_id = grant.grant_id;
      updated.lease_id = grant.lease_id;
      updated.outcome = AuthorityOutcome::Refused;
      updated.primary_reason = ReasonCode::CommitNotDurable;
      updated.terminal_tick = now;
      JournalEntry attempt_entry;
      attempt_entry.kind = JournalRecordKind::AttemptTerminal;
      attempt_entry.tick = now;
      attempt_entry.attempt = updated;
      static_cast<void>(journal_entry(attempt_entry));
      static_cast<void>(upsert_attempt(updated));
      continue;
    }

    if (!acknowledged || options_.recovery_policy == RecoveryPolicy::FenceAll) {
      // A durable commit whose acknowledgement was never recorded is genuinely
      // ambiguous: the caller may or may not have received it. Quarantine the
      // capacity so it can never be handed out twice, and require the caller to
      // reconcile. Under FenceAll every recovered grant is treated this way.
      grant.state = GrantState::Ambiguous;
      grant.commit = CommitState::Ambiguous;
      grant.capacity_reserved = holds_capacity(GrantState::Ambiguous);
      grant.reductions.push_back(Reason(
          ReasonCode::CommitAmbiguous,
          "durable commit without a recorded acknowledgement; caller must reconcile"));
      JournalEntry entry;
      entry.kind = JournalRecordKind::GrantTerminal;
      entry.tick = now;
      entry.grant = grant;
      entry.grant_state = grant.state;
      static_cast<void>(journal_entry(entry));
      AttemptRecord quarantined;
      // The quarantine is durable too: without it a second restart would have to
      // reconstruct the attempt record from the grant.
      JournalEntry quarantine_attempt;
      if (attempt != nullptr) {
        quarantined = *attempt;
      }
      quarantined.attempt_id = grant.attempt_id;
      quarantined.grant_id = grant.grant_id;
      quarantined.lease_id = grant.lease_id;
      quarantined.outcome = AuthorityOutcome::Indeterminate;
      quarantined.primary_reason = ReasonCode::CommitAmbiguous;
      quarantine_attempt.kind = JournalRecordKind::AttemptTerminal;
      quarantine_attempt.tick = now;
      quarantine_attempt.attempt = quarantined;
      static_cast<void>(journal_entry(quarantine_attempt));
      static_cast<void>(upsert_attempt(quarantined));
      continue;
    }

    // Acknowledged: the caller demonstrably observed the grant. Re-validate it
    // against the recovered specification and, when it is still sound, re-issue
    // it under the new epoch. If anything moved, it is revoked and its capacity
    // returned.
    static_cast<void>(revalidate_grant(grant, true));
  }
  counters_.fences += 1;
  reconcile_attempts();
}

void AuthorityCore::reconcile_attempts() {
  const Tick now = spec_.tick();
  for (const AuthorityGrant& grant : grants_) {
    if (grant.attempt_id.empty() || find_attempt(grant.attempt_id) != nullptr) {
      continue;
    }
    AttemptRecord repaired;
    repaired.attempt_id = grant.attempt_id;
    repaired.grant_id = grant.grant_id;
    repaired.lease_id = grant.lease_id;
    repaired.first_seen = now;
    repaired.terminal_tick = now;
    // The original request bytes are not recoverable from a grant, so the
    // digest stays zero. A later submit carrying this attempt id is therefore
    // refused as CONFLICTING rather than replayed: refusing is the conservative
    // direction, and resolve() still answers truthfully.
    repaired.request_digest = Digest256::zero();
    switch (grant.state) {
      case GrantState::Ambiguous:
        repaired.outcome = AuthorityOutcome::Indeterminate;
        repaired.primary_reason = ReasonCode::CommitAmbiguous;
        break;
      case GrantState::Released:
        repaired.outcome = AuthorityOutcome::Refused;
        repaired.released = true;
        repaired.primary_reason = grant.reductions.empty()
                                      ? ReasonCode::CommitNotDurable
                                      : grant.reductions.front().code;
        break;
      case GrantState::Expired:
        repaired.outcome = AuthorityOutcome::Refused;
        repaired.primary_reason = ReasonCode::GrantExpired;
        break;
      case GrantState::Fenced:
      case GrantState::Revoked:
        repaired.outcome = AuthorityOutcome::Fenced;
        repaired.primary_reason = grant.reductions.empty() ? ReasonCode::GrantFenced
                                                           : grant.reductions.front().code;
        break;
      case GrantState::Prepared:
        repaired.outcome = AuthorityOutcome::Refused;
        repaired.released = true;
        repaired.primary_reason = ReasonCode::CommitNotDurable;
        break;
      case GrantState::Committed:
      case GrantState::Acknowledged:
        repaired.outcome = grant.outcome;
        repaired.primary_reason = ReasonCode::CommitDurable;
        break;
      case GrantState::Superseded:
        repaired.outcome = AuthorityOutcome::Refused;
        repaired.primary_reason = ReasonCode::GrantAlreadyReleased;
        break;
    }
    JournalEntry entry;
    entry.kind = JournalRecordKind::AttemptTerminal;
    entry.tick = now;
    entry.attempt = repaired;
    static_cast<void>(journal_entry(entry));
    static_cast<void>(upsert_attempt(repaired));
  }
}

// ---------------------------------------------------------------------------
// Spec mutation
// ---------------------------------------------------------------------------
Status AuthorityCore::journal_entry(JournalEntry& entry, bool durable) {
  if (sink_ == nullptr) {
    return Status::error(StatusCode::Internal, "no durability sink is attached");
  }
  entry.tick = spec_.tick();
  return sink_->append(entry, durable && options_.durable);
}

Status AuthorityCore::upsert_member(Member member) {
  Member copy = member;
  const MemberId id = copy.id;
  JournalEntry entry;
  entry.kind = JournalRecordKind::MemberUpsert;
  entry.member = copy;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.upsert_member(std::move(copy)));
  state_digest_valid_ = false;
  CIF_TRY(revalidate_live_grants());
  return Status::success();
}

Status AuthorityCore::remove_member(const MemberId& id) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::MemberRemove;
  entry.member_id = id;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.remove_member(id));
  state_digest_valid_ = false;
  return revalidate_live_grants();
}

Status AuthorityCore::set_member_lifecycle(const MemberId& id, MemberLifecycle lifecycle) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::MemberLifecycle;
  entry.member_id = id;
  entry.lifecycle = lifecycle;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.set_member_lifecycle(id, lifecycle, spec_.tick()));
  state_digest_valid_ = false;
  CIF_TRY(revalidate_live_grants());
  if (lifecycle == MemberLifecycle::Partitioned || lifecycle == MemberLifecycle::Faulted) {
    counters_.fences += 1;
  }
  return Status::success();
}

Status AuthorityCore::upsert_path(Path path) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::PathUpsert;
  entry.path = path;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.upsert_path(std::move(path)));
  state_digest_valid_ = false;
  return revalidate_live_grants();
}

Status AuthorityCore::remove_path(const PathId& id) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::PathRemove;
  entry.path_id = id;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.remove_path(id));
  state_digest_valid_ = false;
  return revalidate_live_grants();
}

Status AuthorityCore::set_path_state(const PathId& id, PathState state) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::PathState;
  entry.path_id = id;
  entry.path_state = state;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.set_path_state(id, state));
  state_digest_valid_ = false;
  return revalidate_live_grants();
}

Status AuthorityCore::upsert_exclusion(MaintenanceExclusion exclusion) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::ExclusionUpsert;
  entry.exclusion = exclusion;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.upsert_exclusion(std::move(exclusion)));
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::remove_exclusion(const ExclusionId& id) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::ExclusionRemove;
  entry.exclusion_id = id;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.remove_exclusion(id));
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::upsert_obligation(CapacityObligation obligation) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::ObligationUpsert;
  entry.obligation = obligation;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.upsert_obligation(std::move(obligation)));
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::remove_obligation(const ObligationId& id) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::ObligationRemove;
  entry.obligation_id = id;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(spec_.remove_obligation(id));
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::upsert_contract(CommunicationContract contract) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::ContractUpsert;
  entry.contract = contract;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(contracts_.upsert(std::move(contract)));
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::remove_contract(const ContractId& id) {
  JournalEntry entry;
  entry.kind = JournalRecordKind::ContractRemove;
  entry.contract_id = id;
  CIF_TRY(journal_entry(entry));
  CIF_TRY(contracts_.remove(id));
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::set_policy_generation(PolicyGeneration policy) {
  if (policy < spec_.policy_generation()) {
    return Status::error(StatusCode::StateMismatch,
                         "policy generation must not move backwards; policy is append-only");
  }
  JournalEntry entry;
  entry.kind = JournalRecordKind::PolicySet;
  entry.policy_generation = policy;
  CIF_TRY(journal_entry(entry));
  spec_.set_policy_generation(policy);
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::advance_tick(Tick tick) {
  if (tick < spec_.tick()) {
    return Status::error(StatusCode::StateMismatch, "the logical clock must not move backwards");
  }
  if (tick == spec_.tick()) {
    return Status::success();
  }
  // Logical time is not a durable transition of its own: every journal record
  // already carries the tick it was made at, so the recovered tick is exactly
  // the tick of the last durable record. Writing a record per tick would grow
  // the log without adding a single bit of authority.
  spec_.set_tick(tick);
  state_digest_valid_ = false;
  return Status::success();
}

// ---------------------------------------------------------------------------
// Grant termination
// ---------------------------------------------------------------------------
AuthorityGrant* AuthorityCore::mutable_grant(const GrantId& id) noexcept {
  const auto it = std::lower_bound(grants_.begin(), grants_.end(), id,
                                   [](const AuthorityGrant& grant, const GrantId& key) {
                                     return grant.grant_id < key;
                                   });
  if (it == grants_.end() || it->grant_id != id) {
    return nullptr;
  }
  return &*it;
}

const AuthorityGrant* AuthorityCore::find_grant(const GrantId& id) const noexcept {
  const auto it = std::lower_bound(grants_.begin(), grants_.end(), id,
                                   [](const AuthorityGrant& grant, const GrantId& key) {
                                     return grant.grant_id < key;
                                   });
  if (it == grants_.end() || it->grant_id != id) {
    return nullptr;
  }
  return &*it;
}

AttemptRecord* AuthorityCore::mutable_attempt(const AttemptId& id) noexcept {
  const auto it = std::lower_bound(attempts_.begin(), attempts_.end(), id,
                                   [](const AttemptRecord& attempt, const AttemptId& key) {
                                     return attempt.attempt_id < key;
                                   });
  if (it == attempts_.end() || it->attempt_id != id) {
    return nullptr;
  }
  return &*it;
}

const AttemptRecord* AuthorityCore::find_attempt(const AttemptId& id) const noexcept {
  const auto it = std::lower_bound(attempts_.begin(), attempts_.end(), id,
                                   [](const AttemptRecord& attempt, const AttemptId& key) {
                                     return attempt.attempt_id < key;
                                   });
  if (it == attempts_.end() || it->attempt_id != id) {
    return nullptr;
  }
  return &*it;
}

Status AuthorityCore::terminate_grant(AuthorityGrant& grant, GrantState state, ReasonCode reason,
                                      const std::string& detail, bool release_capacity) {
  // Write-ahead: the durable record carries the state the grant is about to
  // enter, never the state it is leaving. A crash between the two must leave the
  // log describing the transition that was requested, and recovery adopts
  // exactly what the log says.
  AuthorityGrant updated = grant;
  updated.state = state;
  if (release_capacity) {
    updated.capacity_reserved = false;
  }
  if (reason != ReasonCode::None) {
    bool present = false;
    for (const Reason& existing : updated.reductions) {
      if (existing.code == reason) {
        present = true;
        break;
      }
    }
    if (!present && updated.reductions.size() < limits::kMaxReasons) {
      updated.reductions.push_back(Reason(reason, detail));
    }
  }

  JournalEntry entry;
  entry.kind = JournalRecordKind::GrantTerminal;
  entry.grant = updated;
  entry.grant_state = state;
  CIF_TRY(journal_entry(entry));
  updated.release_sequence = entry.sequence;

  if (release_capacity) {
    counters_.releases += (state == GrantState::Released) ? 1u : 0u;
    counters_.expiries += (state == GrantState::Expired) ? 1u : 0u;
    counters_.fences += (state == GrantState::Fenced || state == GrantState::Revoked) ? 1u : 0u;
  }
  grant = std::move(updated);
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::fence_all(ReasonCode reason, std::string detail) {
  for (AuthorityGrant& grant : grants_) {
    if (!holds_capacity(grant.state)) {
      continue;
    }
    CIF_TRY(terminate_grant(grant, GrantState::Fenced, reason, detail, true));
  }
  counters_.fences += 1;
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::expire_leases() {
  const Tick now = spec_.tick();
  for (AuthorityGrant& grant : grants_) {
    if (!is_live(grant.state)) {
      continue;
    }
    if (!grant.expired_at(now)) {
      continue;
    }
    CIF_TRY(terminate_grant(grant, GrantState::Expired, ReasonCode::LeaseExpired,
                            "lease elapsed at tick " + now.to_string(), true));
    AttemptRecord expired;
    if (const AttemptRecord* attempt = find_attempt(grant.attempt_id)) {
      expired = *attempt;
    }
    expired.attempt_id = grant.attempt_id;
    expired.grant_id = grant.grant_id;
    expired.lease_id = grant.lease_id;
    expired.primary_reason = ReasonCode::LeaseExpired;
    JournalEntry entry;
    entry.kind = JournalRecordKind::AttemptTerminal;
    entry.attempt = expired;
    CIF_TRY(journal_entry(entry));
    CIF_TRY(upsert_attempt(expired));
  }
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::revalidate_grant(AuthorityGrant& grant, bool allow_reissue) {
  const Member* source = spec_.find_member(grant.source_member);
  const Member* destination = spec_.find_member(grant.destination_member);
  if (source == nullptr || destination == nullptr) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::MemberNotFound,
                           "a member named by this grant no longer exists", true);
  }
  if (!is_present(source->lifecycle) || !is_present(destination->lifecycle)) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::MemberDeleted,
                           "a member named by this grant was retired", true);
  }
  if (source->generation != grant.source_member_generation ||
      destination->generation != grant.destination_member_generation) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::MemberGenerationStale,
                           "a member was replaced: generation moved past this grant", true);
  }
  if (!source->digest.is_zero() && source->digest != grant.source_member_digest) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::MemberDigestMismatch,
                           "source member digest changed under this grant", true);
  }
  if (!destination->digest.is_zero() && destination->digest != grant.destination_member_digest) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::MemberDigestMismatch,
                           "destination member digest changed under this grant", true);
  }
  const Path* path = spec_.find_path(grant.path_id);
  if (path == nullptr) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::PathNotFound,
                           "the bound path no longer exists", true);
  }
  if (path->generation != grant.path_generation) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::PathGenerationStale,
                           "the bound path was re-declared at a new generation", true);
  }
  if (path->state == PathState::Down || path->state == PathState::Unknown) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::PathNotOperational,
                           std::string("path is ") + to_string(path->state), true);
  }
  if (grant.capacity_units > path->capacity_units) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::CapacityInsufficient,
                           "path capacity shrank below this grant's reservation", true);
  }

  const CommunicationContract* contract = contracts_.find(grant.contract_id);
  if (contract == nullptr) {
    return terminate_grant(grant, GrantState::Revoked, ReasonCode::ContractNotFound,
                           "the contract this grant was issued under no longer exists", true);
  }

  // A member that is no longer fully active either degrades the grant (when the
  // contract permits that degree of degradation) or revokes it outright. This is
  // what makes a partition or a maintenance window an *event* rather than a
  // silent change of meaning.
  AuthorityGrant updated = grant;
  const Member* participants[2] = {source, destination};
  for (const Member* member : participants) {
    ReasonCode revoke_reason = ReasonCode::None;
    ReasonCode degrade_reason = ReasonCode::None;
    switch (member->lifecycle) {
      case MemberLifecycle::Active:
        continue;
      case MemberLifecycle::Enlisted:
        revoke_reason = ReasonCode::MemberNotActive;
        break;
      case MemberLifecycle::Draining:
        if (contract->allow_draining) {
          degrade_reason = ReasonCode::DegradedByMemberState;
        } else {
          revoke_reason = ReasonCode::MemberDraining;
        }
        break;
      case MemberLifecycle::Maintenance:
        if (contract->maintenance_mode == MaintenanceMode::Allow) {
          continue;
        }
        if (contract->maintenance_mode == MaintenanceMode::Degrade) {
          degrade_reason = ReasonCode::DegradedByMaintenance;
        } else {
          revoke_reason = ReasonCode::MemberMaintenance;
        }
        break;
      case MemberLifecycle::Faulted:
        if (contract->allow_faulted) {
          degrade_reason = ReasonCode::DegradedByMemberState;
        } else {
          revoke_reason = ReasonCode::MemberFaulted;
        }
        break;
      case MemberLifecycle::Partitioned:
        if (contract->allow_partitioned) {
          degrade_reason = ReasonCode::DegradedByMemberState;
        } else {
          revoke_reason = ReasonCode::MemberPartitioned;
        }
        break;
      case MemberLifecycle::Removed:
        revoke_reason = ReasonCode::MemberDeleted;
        break;
    }
    if (revoke_reason != ReasonCode::None) {
      return terminate_grant(grant, GrantState::Revoked, revoke_reason,
                             "member " + member->id.to_string() + " is " +
                                 to_string(member->lifecycle),
                             true);
    }
    bool present = false;
    for (const Reason& existing : updated.reductions) {
      if (existing.code == degrade_reason) {
        present = true;
        break;
      }
    }
    if (!present && updated.reductions.size() < limits::kMaxReasons) {
      updated.reductions.push_back(Reason(degrade_reason, "member " + member->id.to_string() +
                                                             " is " +
                                                             to_string(member->lifecycle)));
    }
    updated.degraded = true;
    updated.outcome = AuthorityOutcome::Degraded;
  }

  const bool state_changed = updated.degraded != grant.degraded ||
                             !(updated.reductions.size() == grant.reductions.size());
  if (!state_changed && !allow_reissue) {
    return Status::success();
  }

  if (allow_reissue) {
    // Sound: re-issue under the current epoch and incarnation.
    updated.epoch = spec_.epoch();
    updated.incarnation = spec_.incarnation();
    updated.policy_generation = spec_.policy_generation();
    updated.cluster_generation = spec_.generation();
    updated.commit = CommitState::Committed;
    updated.state = GrantState::Committed;
    updated.capacity_reserved = holds_capacity(updated.state);
  }

  JournalEntry entry;
  entry.kind = JournalRecordKind::GrantCommitted;
  entry.grant = updated;
  entry.grant_state = updated.state;
  CIF_TRY(journal_entry(entry));
  if (allow_reissue) {
    updated.commit_sequence = entry.sequence;
  }
  grant = std::move(updated);
  state_digest_valid_ = false;
  return Status::success();
}

Status AuthorityCore::revalidate_live_grants() {
  for (AuthorityGrant& grant : grants_) {
    if (!is_live(grant.state)) {
      continue;
    }
    CIF_TRY(revalidate_grant(grant, true));
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------
std::uint64_t AuthorityCore::reserved_units(const ResourceId& resource) const noexcept {
  std::uint64_t total = 0;
  for (const AuthorityGrant& grant : grants_) {
    if (grant.resource_id != resource || !holds_capacity(grant.state)) {
      continue;
    }
    std::uint64_t next = 0;
    if (!checked_add(total, grant.capacity_units, next)) {
      return UINT64_MAX;
    }
    total = next;
  }
  return total;
}

std::uint64_t AuthorityCore::path_committed_units(const PathId& path) const noexcept {
  std::uint64_t total = 0;
  for (const AuthorityGrant& grant : grants_) {
    if (grant.path_id != path || !holds_capacity(grant.state)) {
      continue;
    }
    std::uint64_t next = 0;
    if (!checked_add(total, grant.capacity_units, next)) {
      return UINT64_MAX;
    }
    total = next;
  }
  return total;
}

std::uint64_t AuthorityCore::quarantined_units() const noexcept {
  std::uint64_t total = 0;
  for (const AuthorityGrant& grant : grants_) {
    if (!is_quarantined(grant.state)) {
      continue;
    }
    std::uint64_t next = 0;
    if (!checked_add(total, grant.capacity_units, next)) {
      return UINT64_MAX;
    }
    total = next;
  }
  return total;
}

std::vector<const AuthorityGrant*> AuthorityCore::live_grants_for_path(const PathId& path) const {
  std::vector<const AuthorityGrant*> out;
  for (const AuthorityGrant& grant : grants_) {
    if (grant.path_id == path && holds_capacity(grant.state)) {
      out.push_back(&grant);
    }
  }
  return out;
}

std::vector<const AuthorityGrant*> AuthorityCore::live_grants_for_service(
    const ServiceGroupId& service) const {
  std::vector<const AuthorityGrant*> out;
  for (const AuthorityGrant& grant : grants_) {
    if (grant.destination_service == service && holds_capacity(grant.state)) {
      out.push_back(&grant);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------
void AuthorityCore::record_audit(std::string operation, const RequestId& request,
                                 const AttemptId& attempt, const GrantId& grant,
                                 AuthorityOutcome outcome, ReasonCode reason, std::string detail) {
  AuditEntry entry;
  entry.sequence = counters_.decisions;
  entry.tick = spec_.tick();
  entry.operation = std::move(operation);
  entry.request_id = request;
  entry.attempt_id = attempt;
  entry.grant_id = grant;
  entry.outcome = outcome;
  entry.reason = reason;
  entry.detail = sanitise_for_display(detail, limits::kMaxReasonDetailBytes);
  audit_.push_back(std::move(entry));
  while (audit_.size() > options_.audit_history) {
    audit_.pop_front();
  }
}

std::string AuthorityCore::mint_grant_id() {
  ++grant_serial_;
  counters_.grants = std::max(counters_.grants, grant_serial_);
  return "g-" + to_decimal(grant_serial_);
}

std::string AuthorityCore::mint_lease_id() {
  ++lease_serial_;
  counters_.leases = std::max(counters_.leases, lease_serial_);
  return "l-" + to_decimal(lease_serial_);
}


// ---------------------------------------------------------------------------
// Decision construction
// ---------------------------------------------------------------------------
void AuthorityCore::finalize_decision(AuthorityDecision& decision, const char* operation) {
  decision.explanation = build_explanation(decision);
  decision.decision_digest = decision.compute_digest();
  const GrantId grant_id = decision.grant.has_value() ? decision.grant->grant_id : GrantId{};
  record_audit(operation, decision.request_id, decision.attempt_id, grant_id, decision.outcome,
               decision.primary_reason(),
               decision.reasons.empty() ? std::string{} : decision.reasons.front().detail);
}

AuthorityDecision AuthorityCore::make_decision(const RequestId& request_id,
                                               const AttemptId& attempt_id,
                                               AuthorityOutcome outcome,
                                               std::vector<Reason> reasons) {
  AuthorityDecision decision;
  decision.request_id = request_id;
  decision.attempt_id = attempt_id;
  decision.outcome = outcome;
  decision.reasons = std::move(reasons);
  decision.cluster_id = spec_.cluster_id();
  decision.cluster_generation = spec_.generation();
  decision.epoch = spec_.epoch();
  decision.policy_generation = spec_.policy_generation();
  decision.incarnation = spec_.incarnation();
  decision.spec_digest = spec_.digest();
  if (options_.decision_state_digest) {
    decision.state_digest = state_digest();
  }
  decision.decided_at = spec_.tick();
  decision.decision_sequence = ++counters_.decisions;
  return decision;
}

AuthorityDecision AuthorityCore::malformed_decision(const RequestId& request_id,
                                                    const AttemptId& attempt_id,
                                                    const Status& status) {
  AuthorityDecision decision;
  decision.request_id = request_id;
  decision.attempt_id = attempt_id;
  decision.outcome = outcome_for_status(status);
  decision.reasons.push_back(Reason(reason_for_status(status), status.message()));
  decision.cluster_id = spec_.cluster_id();
  decision.cluster_generation = spec_.generation();
  decision.epoch = spec_.epoch();
  decision.policy_generation = spec_.policy_generation();
  decision.incarnation = spec_.incarnation();
  decision.spec_digest = spec_.digest();
  if (options_.decision_state_digest) {
    decision.state_digest = state_digest();
  }
  decision.decided_at = spec_.tick();
  // A malformed request consumes no decision sequence and writes no audit
  // record: it cannot have changed controller state, so it is safe to replay
  // and it must not be able to exhaust the audit ring.
  decision.explanation = build_explanation(decision);
  decision.decision_digest = decision.compute_digest();
  return decision;
}

AuthorityDecision AuthorityCore::replay_attempt(const AttemptRecord& attempt,
                                                const AuthorityRequest& request) {
  // A zero digest means the record was reconstructed during recovery and the
  // original request bytes are not recoverable. Refusing is the conservative
  // direction: the caller must use a fresh attempt identity rather than being
  // told an answer that might belong to different content.
  if (attempt.request_digest.is_zero() && !attempt.grant_id.empty()) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Conflicting,
        {Reason(ReasonCode::AttemptConflict,
                "this attempt survived a controller restart and its original request bytes are no "
                "longer recoverable; resolve it, or re-request under a fresh attempt id")});
    decision.requires_reconciliation = true;
    decision.idempotent_replay = true;
    if (const AuthorityGrant* grant = find_grant(attempt.grant_id)) {
      decision.grant = *grant;
      if (grant->state == GrantState::Ambiguous) {
        decision.outcome = AuthorityOutcome::Indeterminate;
        decision.reasons = {Reason(ReasonCode::CommitAmbiguous,
                                   "a durable commit exists but no acknowledgement was recorded")};
      }
    }
    finalize_decision(decision, "submit");
    return decision;
  }

  const Digest256 digest = request.digest();
  if (!(attempt.request_digest == digest)) {
    return make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Conflicting,
                         {Reason(ReasonCode::AttemptConflict,
                                 "this attempt id was already used for different request content")});
  }
  if (attempt.cancelled) {
    AuthorityDecision decision = make_decision(request.request_id, request.attempt_id,
                                               AuthorityOutcome::Cancelled,
                                               {Reason(ReasonCode::AttemptCancelled,
                                                       "this attempt was cancelled")});
    decision.idempotent_replay = true;
    finalize_decision(decision, "submit");
    return decision;
  }
  if (attempt.released) {
    AuthorityDecision decision = make_decision(request.request_id, request.attempt_id,
                                               AuthorityOutcome::Refused,
                                               {Reason(ReasonCode::AttemptAlreadyReleased,
                                                       "this attempt was released")});
    decision.idempotent_replay = true;
    decision.grant = {};
    if (!attempt.grant_id.empty()) {
      if (const AuthorityGrant* grant = find_grant(attempt.grant_id)) {
        decision.grant = *grant;
      }
    }
    finalize_decision(decision, "submit");
    return decision;
  }

  AuthorityDecision decision =
      make_decision(request.request_id, request.attempt_id, attempt.outcome,
                    {Reason(attempt.primary_reason == ReasonCode::None ? ReasonCode::AttemptAlreadyCommitted
                                                                      : attempt.primary_reason,
                            "this attempt was already decided; attempt ids are exactly-once")});
  decision.idempotent_replay = true;

  const AuthorityGrant* grant =
      attempt.grant_id.empty() ? nullptr : find_grant(attempt.grant_id);
  if (grant != nullptr) {
    decision.grant = *grant;
    if (is_quarantined(grant->state)) {
      decision.outcome = AuthorityOutcome::Indeterminate;
      decision.requires_reconciliation = true;
      decision.reasons = {Reason(ReasonCode::CommitAmbiguous,
                                 "a durable commit exists but no acknowledgement was recorded; "
                                 "the caller must acknowledge or cancel before this capacity is reusable")};
    } else if (grant->state == GrantState::Released) {
      decision.outcome = AuthorityOutcome::Refused;
      decision.reasons = {Reason(ReasonCode::GrantAlreadyReleased, "the granted lease was released")};
    } else if (grant->state == GrantState::Expired) {
      decision.outcome = AuthorityOutcome::Refused;
      decision.reasons = {Reason(ReasonCode::GrantExpired, "the granted lease has expired")};
    } else if (grant->state == GrantState::Fenced || grant->state == GrantState::Revoked) {
      decision.outcome = AuthorityOutcome::Fenced;
      decision.requires_reconciliation = true;
      decision.reasons = {Reason(grant->reductions.empty() ? ReasonCode::GrantFenced
                                                           : grant->reductions.front().code,
                                 "the granted authority was superseded and is no longer usable")};
    } else {
      decision.outcome = grant->outcome;
      decision.reasons = {Reason(ReasonCode::AttemptAlreadyCommitted,
                                 "returning the previously committed grant for this attempt")};
    }
  }
  finalize_decision(decision, "submit");
  return decision;
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------
const Path* AuthorityCore::select_path(const AuthorityRequest& request) const {
  const Path* best = nullptr;
  for (const Path& path : spec_.paths()) {
    if (path.source_member != request.source_member) {
      continue;
    }
    if (path.destination_member != request.destination_member) {
      continue;
    }
    if (path.state == PathState::Down || path.state == PathState::Unknown) {
      continue;
    }
    if (!request.source_endpoint.empty() && !path.source_endpoint.empty() &&
        path.source_endpoint != request.source_endpoint) {
      continue;
    }
    if (!request.destination_endpoint.empty() && !path.destination_endpoint.empty() &&
        path.destination_endpoint != request.destination_endpoint) {
      continue;
    }
    if (best == nullptr || path.id < best->id) {
      best = &path;
    }
  }
  return best;
}

AuthorityCore::EligibilityResult AuthorityCore::evaluate(const AuthorityRequest& request,
                                                         const CommunicationContract& contract) {
  EligibilityResult result;
  result.contract = &contract;
  result.outcome = AuthorityOutcome::Granted;

  const auto hard_fail = [&result](ReasonCode code, std::string detail, AuthorityOutcome outcome) {
    result.outcome = outcome;
    if (result.reasons.size() < limits::kMaxReasons) {
      result.reasons.push_back(Reason(code, std::move(detail)));
    }
  };
  const auto degrade = [&result](ReasonCode code, std::string detail) {
    result.degradations.push_back(Reason(code, std::move(detail)));
  };

  // -- members ------------------------------------------------------------
  const Member* source = spec_.find_member(request.source_member);
  const Member* destination = spec_.find_member(request.destination_member);
  if (source == nullptr) {
    hard_fail(ReasonCode::MemberNotFound,
              "source member " + request.source_member.to_string() + " is not declared",
              AuthorityOutcome::Unknown);
    return result;
  }
  if (destination == nullptr) {
    hard_fail(ReasonCode::MemberNotFound,
              "destination member " + request.destination_member.to_string() + " is not declared",
              AuthorityOutcome::Unknown);
    return result;
  }
  result.source_member = source;
  result.destination_member = destination;

  if (is_terminal(source->lifecycle)) {
    hard_fail(ReasonCode::MemberDeleted, "source member is retired", AuthorityOutcome::Refused);
    return result;
  }
  if (is_terminal(destination->lifecycle)) {
    hard_fail(ReasonCode::MemberDeleted, "destination member is retired", AuthorityOutcome::Refused);
    return result;
  }

  if (request.source_member_generation < source->generation) {
    hard_fail(ReasonCode::MemberGenerationStale,
              "source member is at generation " + source->generation.to_string() + ", request claims " +
                  request.source_member_generation.to_string(),
              AuthorityOutcome::Fenced);
    return result;
  }
  if (request.source_member_generation > source->generation) {
    hard_fail(ReasonCode::MemberGenerationAhead,
              "source member generation is ahead of this controller", AuthorityOutcome::Fenced);
    return result;
  }
  if (request.destination_member_generation < destination->generation) {
    hard_fail(ReasonCode::MemberGenerationStale,
              "destination member is at generation " + destination->generation.to_string() +
                  ", request claims " + request.destination_member_generation.to_string(),
              AuthorityOutcome::Fenced);
    return result;
  }
  if (request.destination_member_generation > destination->generation) {
    hard_fail(ReasonCode::MemberGenerationAhead,
              "destination member generation is ahead of this controller", AuthorityOutcome::Fenced);
    return result;
  }

  if (options_.require_member_digests && !request.has_member_digests()) {
    hard_fail(ReasonCode::MemberDigestMissing,
              request.source_member_digest.is_zero() ? "source member digest was not supplied"
                                                     : "destination member digest was not supplied",
              AuthorityOutcome::Incomplete);
    return result;
  }
  if (!source->digest.is_zero() && !(request.source_member_digest == source->digest)) {
    hard_fail(ReasonCode::MemberDigestMismatch,
              "source member digest does not match the declared member", AuthorityOutcome::Fenced);
    return result;
  }
  if (!destination->digest.is_zero() && !(request.destination_member_digest == destination->digest)) {
    hard_fail(ReasonCode::MemberDigestMismatch,
              "destination member digest does not match the declared member",
              AuthorityOutcome::Fenced);
    return result;
  }

  if (!request.source_endpoint.empty() && source->find_endpoint(request.source_endpoint) == nullptr) {
    hard_fail(ReasonCode::EndpointNotFound,
              "source endpoint " + request.source_endpoint.to_string() + " is not declared on " +
                  source->id.to_string(),
              AuthorityOutcome::Unknown);
    return result;
  }
  if (!request.destination_endpoint.empty() &&
      destination->find_endpoint(request.destination_endpoint) == nullptr) {
    hard_fail(ReasonCode::EndpointNotFound,
              "destination endpoint " + request.destination_endpoint.to_string() +
                  " is not declared on " + destination->id.to_string(),
              AuthorityOutcome::Unknown);
    return result;
  }
  if (!source->serves(contract.source_service)) {
    hard_fail(ReasonCode::ServiceGroupNotServed,
              "source member does not serve service group " + contract.source_service.to_string(),
              AuthorityOutcome::Refused);
    return result;
  }
  if (!destination->serves(contract.destination_service)) {
    hard_fail(ReasonCode::ServiceGroupNotServed,
              "destination member does not serve service group " +
                  contract.destination_service.to_string(),
              AuthorityOutcome::Refused);
    return result;
  }

  // -- lifecycle ----------------------------------------------------------
  const auto lifecycle_ok = [&](const Member& member, const char* role) {
    switch (member.lifecycle) {
      case MemberLifecycle::Active:
        return true;
      case MemberLifecycle::Draining:
        if (contract.allow_draining) {
          degrade(ReasonCode::DegradedByMemberState,
                  std::string(role) + " member is draining");
          return true;
        }
        hard_fail(ReasonCode::MemberDraining, std::string(role) + " member is draining",
                  AuthorityOutcome::Refused);
        return false;
      case MemberLifecycle::Maintenance:
        if (contract.maintenance_mode == MaintenanceMode::Allow) {
          return true;
        }
        if (contract.maintenance_mode == MaintenanceMode::Degrade) {
          degrade(ReasonCode::DegradedByMaintenance,
                  std::string(role) + " member is in maintenance");
          return true;
        }
        hard_fail(ReasonCode::MemberMaintenance, std::string(role) + " member is in maintenance",
                  AuthorityOutcome::Refused);
        return false;
      case MemberLifecycle::Faulted:
        if (contract.allow_faulted) {
          degrade(ReasonCode::DegradedByMemberState, std::string(role) + " member is faulted");
          return true;
        }
        hard_fail(ReasonCode::MemberFaulted, std::string(role) + " member is faulted",
                  AuthorityOutcome::Refused);
        return false;
      case MemberLifecycle::Partitioned:
        if (contract.allow_partitioned) {
          degrade(ReasonCode::DegradedByMemberState, std::string(role) + " member is partitioned");
          return true;
        }
        hard_fail(ReasonCode::MemberPartitioned, std::string(role) + " member is partitioned",
                  AuthorityOutcome::Refused);
        return false;
      case MemberLifecycle::Enlisted:
        hard_fail(ReasonCode::MemberNotActive, std::string(role) + " member is not active",
                  AuthorityOutcome::Refused);
        return false;
      case MemberLifecycle::Removed:
        hard_fail(ReasonCode::MemberDeleted, std::string(role) + " member is retired",
                  AuthorityOutcome::Refused);
        return false;
    }
    return false;
  };
  if (!lifecycle_ok(*source, "source")) {
    return result;
  }
  if (!lifecycle_ok(*destination, "destination")) {
    return result;
  }

  const Member* participants[2] = {source, destination};
  for (const Member* member : participants) {
    const MaintenanceExclusion* exclusion = spec_.exclusion_for_member(*member);
    if (exclusion == nullptr) {
      continue;
    }
    if (exclusion->mode == MaintenanceMode::Allow) {
      continue;
    }
    if (exclusion->mode == MaintenanceMode::Degrade) {
      degrade(ReasonCode::DegradedByMaintenance,
              "maintenance exclusion " + exclusion->id.to_string() + " covers " +
                  member->id.to_string());
      continue;
    }
    hard_fail(ReasonCode::MaintenanceExclusionActive,
              "maintenance exclusion " + exclusion->id.to_string() + " refuses new authority for " +
                  member->id.to_string(),
              AuthorityOutcome::Refused);
    return result;
  }

  // -- path ---------------------------------------------------------------
  const Path* path = nullptr;
  if (!request.path_id.empty()) {
    path = spec_.find_path(request.path_id);
    if (path == nullptr) {
      hard_fail(ReasonCode::PathNotFound,
                "path " + request.path_id.to_string() + " is not declared", AuthorityOutcome::Unknown);
      return result;
    }
    if (!(request.path_generation == path->generation)) {
      hard_fail(ReasonCode::PathGenerationStale,
                "path is at generation " + path->generation.to_string() + ", request claims " +
                    request.path_generation.to_string(),
                AuthorityOutcome::Stale);
      return result;
    }
    if (!(path->source_member == request.source_member) ||
        !(path->destination_member == request.destination_member)) {
      hard_fail(ReasonCode::ContractUnsatisfied,
                "the named path does not join the requested members", AuthorityOutcome::Refused);
      return result;
    }
    if (!request.source_endpoint.empty() && !path->source_endpoint.empty() &&
        !(path->source_endpoint == request.source_endpoint)) {
      hard_fail(ReasonCode::ContractUnsatisfied, "the named path starts at a different endpoint",
                AuthorityOutcome::Refused);
      return result;
    }
    if (!request.destination_endpoint.empty() && !path->destination_endpoint.empty() &&
        !(path->destination_endpoint == request.destination_endpoint)) {
      hard_fail(ReasonCode::ContractUnsatisfied, "the named path ends at a different endpoint",
                AuthorityOutcome::Refused);
      return result;
    }
  } else if (options_.require_path_binding) {
    path = select_path(request);
    if (path == nullptr) {
      hard_fail(ReasonCode::NoEligiblePath,
                "no operational path joins the requested members", AuthorityOutcome::Refused);
      return result;
    }
  }
  result.path = path;

  if (path != nullptr) {
    switch (path->state) {
      case PathState::Operational:
        break;
      case PathState::Degraded:
        degrade(ReasonCode::DegradedByRedundancyLoss,
                "path " + path->id.to_string() + " is declared degraded");
        break;
      case PathState::Maintenance:
        if (contract.maintenance_mode == MaintenanceMode::Allow) {
          break;
        }
        if (contract.maintenance_mode == MaintenanceMode::Degrade) {
          degrade(ReasonCode::DegradedByMaintenance,
                  "path " + path->id.to_string() + " is in maintenance");
          break;
        }
        hard_fail(ReasonCode::PathNotOperational,
                  "path " + path->id.to_string() + " is in maintenance", AuthorityOutcome::Refused);
        return result;
      case PathState::Down:
      case PathState::Unknown:
        hard_fail(ReasonCode::PathNotOperational,
                  "path " + path->id.to_string() + " is " + to_string(path->state),
                  AuthorityOutcome::Refused);
        return result;
    }
    const MaintenanceExclusion* exclusion = spec_.exclusion_for_path(*path);
    if (exclusion != nullptr && exclusion->mode == MaintenanceMode::Refuse) {
      hard_fail(ReasonCode::MaintenanceExclusionActive,
                "maintenance exclusion " + exclusion->id.to_string() + " refuses new authority for "
                "path " + path->id.to_string(),
                AuthorityOutcome::Refused);
      return result;
    }
    if (exclusion != nullptr && exclusion->mode == MaintenanceMode::Degrade) {
      degrade(ReasonCode::DegradedByMaintenance,
              "maintenance exclusion " + exclusion->id.to_string() + " covers path " +
                  path->id.to_string());
    }
  }

  // -- locality / failure domains ----------------------------------------
  const std::size_t level = contract.failure_domain_level;
  const std::string source_domain_key = source->locality.domain_key(level);
  const std::string destination_domain_key = destination->locality.domain_key(level);
  const std::uint32_t distinct =
      source_domain_key == destination_domain_key ? std::uint32_t{1} : std::uint32_t{2};
  result.distinct_failure_domains = distinct;
  if (contract.min_distinct_failure_domains > distinct) {
    hard_fail(ReasonCode::LocalityConstraintViolated,
              "contract requires " + to_decimal(contract.min_distinct_failure_domains) +
                  " distinct failure domains at level " + to_decimal(level) +
                  " but source and destination share one",
              AuthorityOutcome::Refused);
    return result;
  }

  // -- capacity -----------------------------------------------------------
  const auto committed_on_path = [this, &request](const PathId& path_id) {
    std::uint64_t total = 0;
    for (const AuthorityGrant& grant : grants_) {
      if (!(grant.path_id == path_id) || !holds_capacity(grant.state)) {
        continue;
      }
      if (request.renewal && !request.renewal_of.empty() && grant.grant_id == request.renewal_of) {
        continue;  // a renewal must not count its own reservation twice
      }
      std::uint64_t next = 0;
      if (!checked_add(total, grant.capacity_units, next)) {
        return UINT64_MAX;
      }
      total = next;
    }
    return total;
  };
  const auto reserved_on_resource = [this, &request](const ResourceId& resource_id) {
    std::uint64_t total = 0;
    for (const AuthorityGrant& grant : grants_) {
      if (!(grant.resource_id == resource_id) || !holds_capacity(grant.state)) {
        continue;
      }
      if (request.renewal && !request.renewal_of.empty() && grant.grant_id == request.renewal_of) {
        continue;
      }
      std::uint64_t next = 0;
      if (!checked_add(total, grant.capacity_units, next)) {
        return UINT64_MAX;
      }
      total = next;
    }
    return total;
  };

  std::uint64_t want = request.requested_units;
  if (want == 0) {
    want = contract.min_capacity_units;
  }
  if (contract.max_capacity_units != 0 && want > contract.max_capacity_units) {
    degrade(ReasonCode::DegradedByCapacity,
            "contract ceilings capacity at " + to_decimal(contract.max_capacity_units) + " units");
    want = contract.max_capacity_units;
  }
  if (want < contract.min_capacity_units) {
    hard_fail(ReasonCode::CapacityInsufficient,
              "requested " + to_decimal(want) + " units but the contract requires at least " +
                  to_decimal(contract.min_capacity_units),
              AuthorityOutcome::Refused);
    return result;
  }
  std::uint64_t authorised = want;

  if (path != nullptr && options_.enforce_capacity) {
    // Exclusivity is checked first: an exclusive path cannot be shared at all,
    // so offering a reduced share of it would be a false promise.
    if (path->exclusive) {
      for (const AuthorityGrant* holder : live_grants_for_path(path->id)) {
        if (holder->attempt_id == request.attempt_id) {
          continue;
        }
        if (request.renewal && holder->grant_id == request.renewal_of) {
          continue;
        }
        hard_fail(ReasonCode::PathAlreadyBound,
                  "path " + path->id.to_string() + " is exclusive and already bound by grant " +
                      holder->grant_id.to_string(),
                  AuthorityOutcome::Conflicting);
        return result;
      }
    }
    const std::uint64_t committed = committed_on_path(path->id);
    const std::uint64_t available = path->capacity_units > committed ? path->capacity_units - committed : 0;
    if (authorised > available) {
      const bool can_reduce = available > 0 && available >= contract.min_capacity_units &&
                              contract.allow_degraded && request.allow_degraded;
      if (can_reduce) {
        degrade(ReasonCode::DegradedByCapacity,
                "path " + path->id.to_string() + " has " + to_decimal(available) +
                    " units free of " + to_decimal(path->capacity_units));
        authorised = available;
      } else {
        hard_fail(ReasonCode::CapacityExhausted,
                  "path " + path->id.to_string() + " has " + to_decimal(available) +
                      " units free; " + to_decimal(authorised) + " requested",
                  AuthorityOutcome::Refused);
        return result;
      }
    }
  }

  if (!request.resource_id.empty()) {
    const Resource* resource = source->find_resource(request.resource_id);
    if (resource == nullptr) {
      hard_fail(ReasonCode::ResourceNotFound,
                "resource " + request.resource_id.to_string() + " is not declared on " +
                    source->id.to_string(),
                AuthorityOutcome::Unknown);
      return result;
    }
    result.resource = resource;
    if (!(request.reservation_generation == resource->reservation_generation)) {
      hard_fail(ReasonCode::ReservationGenerationStale,
                "resource reservation generation is " + resource->reservation_generation.to_string() +
                    ", request claims " + request.reservation_generation.to_string(),
                AuthorityOutcome::Stale);
      return result;
    }
    if (!resource->reservable) {
      hard_fail(ReasonCode::ContractUnsatisfied,
                "resource " + resource->id.to_string() + " is declared non-reservable",
                AuthorityOutcome::Refused);
      return result;
    }
    if (options_.enforce_capacity) {
      const std::uint64_t reserved = reserved_on_resource(resource->id);
      const std::uint64_t available =
          resource->total_units > reserved ? resource->total_units - reserved : 0;
      if (authorised > available) {
        const bool can_reduce = available > 0 && available >= contract.min_capacity_units &&
                                contract.allow_degraded && request.allow_degraded;
        if (can_reduce) {
          degrade(ReasonCode::DegradedByCapacity,
                  "resource " + resource->id.to_string() + " has " + to_decimal(available) +
                      " units free of " + to_decimal(resource->total_units));
          authorised = available;
        } else {
          hard_fail(ReasonCode::CapacityExhausted,
                    "resource " + resource->id.to_string() + " has " + to_decimal(available) +
                        " units free; " + to_decimal(authorised) + " requested",
                    AuthorityOutcome::Refused);
          return result;
        }
      }
    }
  } else if (options_.enforce_capacity && request.requested_units > 0 && path != nullptr &&
             !path->resources.empty()) {
    hard_fail(ReasonCode::ReservationGenerationMissing,
              "path " + path->id.to_string() +
                  " carries reservable resources but the request names no resource reservation",
              AuthorityOutcome::Incomplete);
    return result;
  }

  // -- capacity obligations ----------------------------------------------
  for (const CapacityObligation& obligation : spec_.obligations()) {
    if (!obligation.enabled || !(obligation.service == contract.destination_service)) {
      continue;
    }
    std::map<std::string, std::uint64_t> per_domain;
    for (const AuthorityGrant& grant : grants_) {
      if (!holds_capacity(grant.state) || !(grant.destination_service == obligation.service)) {
        continue;
      }
      const Member* holder = spec_.find_member(grant.destination_member);
      if (holder == nullptr) {
        continue;
      }
      std::uint64_t next = 0;
      const std::string key = holder->locality.domain_key(obligation.failure_domain_level);
      if (!checked_add(per_domain[key], grant.capacity_units, next)) {
        next = UINT64_MAX;
      }
      per_domain[key] = next;
    }
    const auto domains_meeting = [&obligation](const std::map<std::string, std::uint64_t>& map) {
      std::size_t count = 0;
      for (const auto& entry : map) {
        if (entry.second > 0 && entry.second >= obligation.min_units_per_domain) {
          ++count;
        }
      }
      return count;
    };
    const std::size_t before = domains_meeting(per_domain);
    std::uint64_t updated = 0;
    if (!checked_add(per_domain[destination_domain_key], authorised, updated)) {
      updated = UINT64_MAX;
    }
    per_domain[destination_domain_key] = updated;
    const std::size_t after = domains_meeting(per_domain);
    if (after < obligation.min_distinct_failure_domains) {
      if (after <= before) {
        hard_fail(ReasonCode::ContractUnsatisfied,
                  "capacity obligation " + obligation.id.to_string() + " requires " +
                      to_decimal(obligation.min_distinct_failure_domains) +
                      " distinct failure domains with at least " +
                      to_decimal(obligation.min_units_per_domain) +
                      " units each, and this relationship does not improve the count",
                  AuthorityOutcome::Refused);
        return result;
      }
      degrade(ReasonCode::DegradedByRedundancyLoss,
              "capacity obligation " + obligation.id.to_string() + " remains unmet after this grant");
    }
  }

  if (request.renewal) {
    const AuthorityGrant* existing = find_grant(request.renewal_of);
    if (existing == nullptr) {
      hard_fail(ReasonCode::GrantNotFound,
                "renewal names grant " + request.renewal_of.to_string() + ", which is not present",
                AuthorityOutcome::Unknown);
      return result;
    }
    if (!(existing->lease_id == request.renewal_lease)) {
      hard_fail(ReasonCode::LeaseUnknown,
                "renewal names a lease that does not belong to grant " +
                    request.renewal_of.to_string(),
                AuthorityOutcome::Conflicting);
      return result;
    }
    if (!(existing->attempt_id == request.attempt_id)) {
      hard_fail(ReasonCode::AttemptMismatch,
                "a renewal must reuse the attempt id of the grant it renews",
                AuthorityOutcome::Conflicting);
      return result;
    }
    if (is_terminal(existing->state)) {
      hard_fail(ReasonCode::GrantAlreadyReleased,
                "grant " + request.renewal_of.to_string() + " is " + to_string(existing->state) +
                    " and cannot be renewed",
                AuthorityOutcome::Refused);
      return result;
    }
  }

  result.authorised_units = authorised;
  result.outcome = AuthorityOutcome::Granted;
  return result;
}

// ---------------------------------------------------------------------------
// commit / renew
// ---------------------------------------------------------------------------
Status AuthorityCore::commit_grant(AuthorityGrant grant, AuthorityDecision& decision) {
  const Tick now = spec_.tick();
  grant.lease_issued = now;
  grant.state = GrantState::Prepared;
  grant.commit = CommitState::Prepared;

  JournalEntry prepare;
  prepare.kind = JournalRecordKind::GrantPrepared;
  prepare.grant = grant;
  prepare.grant_state = GrantState::Prepared;
  const Status prepared = journal_entry(prepare);
  if (!prepared.ok()) {
    // A durability failure before the commit record means the controller can
    // prove nothing. Report INDETERMINATE and require reconciliation rather
    // than inventing an answer.
    decision.outcome = AuthorityOutcome::Indeterminate;
    decision.requires_reconciliation = true;
    decision.reasons = {Reason(ReasonCode::CommitIndeterminate,
                               "the prepare record could not be made durable: " +
                                   prepared.to_string())};
    return Status::success();
  }
  grant.prepare_sequence = prepare.sequence;
  grant.state = GrantState::Committed;
  grant.commit = CommitState::Committed;

  JournalEntry commit;
  commit.kind = JournalRecordKind::GrantCommitted;
  commit.grant = grant;
  commit.grant_state = GrantState::Committed;
  const Status committed = journal_entry(commit);
  if (!committed.ok()) {
    decision.outcome = AuthorityOutcome::Indeterminate;
    decision.requires_reconciliation = true;
    decision.reasons = {Reason(ReasonCode::CommitAmbiguous,
                               "the commit record could not be made durable: " +
                                   committed.to_string())};
    return Status::success();
  }
  grant.commit_sequence = commit.sequence;
  grant.capacity_reserved = holds_capacity(grant.state);

  CIF_TRY(upsert_grant(grant));

  AttemptRecord attempt;
  attempt.attempt_id = grant.attempt_id;
  attempt.request_id = decision.request_id;
  attempt.request_digest = decision_request_digest_;
  attempt.grant_id = grant.grant_id;
  attempt.lease_id = grant.lease_id;
  attempt.outcome = grant.outcome;
  attempt.primary_reason = grant.degraded ? ReasonCode::DegradedByMemberState : ReasonCode::None;
  attempt.first_seen = now;
  if (grant.degraded && !grant.reductions.empty()) {
    attempt.primary_reason = grant.reductions.front().code;
  }
  CIF_TRY(upsert_attempt(attempt));

  JournalEntry terminal;
  terminal.kind = JournalRecordKind::AttemptTerminal;
  terminal.attempt = attempt;
  CIF_TRY(journal_entry(terminal));

  decision.outcome = grant.outcome;
  decision.grant = grant;
  state_digest_valid_ = false;
  return Status::success();
}

AuthorityDecision AuthorityCore::renew(const AuthorityRequest& request,
                                       const CommunicationContract& contract) {
  AuthorityCore::EligibilityResult result = evaluate(request, contract);
  if (result.outcome != AuthorityOutcome::Granted) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, result.outcome, result.reasons);
    finalize_decision(decision, "renew");
    return decision;
  }
  AuthorityGrant* grant = mutable_grant(request.renewal_of);
  if (grant == nullptr) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Unknown,
        {Reason(ReasonCode::GrantNotFound, "the grant to renew disappeared during evaluation")});
    finalize_decision(decision, "renew");
    return decision;
  }

  AuthorityOutcome outcome = AuthorityOutcome::Granted;
  if (!result.degradations.empty()) {
    if (contract.allow_degraded && request.allow_degraded) {
      outcome = AuthorityOutcome::Degraded;
    } else {
      AuthorityDecision decision =
          make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Refused,
                        result.degradations);
      finalize_decision(decision, "renew");
      return decision;
    }
  }

  AuthorityGrant updated = *grant;
  updated.requested_units = request.requested_units;
  updated.capacity_units = result.authorised_units;
  updated.lease_issued = spec_.tick();
  updated.lease_expiry = request.lease_ticks == 0
                             ? Tick{}
                             : Tick{spec_.tick().value() + request.lease_ticks};
  updated.epoch = spec_.epoch();
  updated.incarnation = spec_.incarnation();
  updated.policy_generation = spec_.policy_generation();
  updated.cluster_generation = spec_.generation();
  updated.outcome = outcome;
  updated.degraded = outcome == AuthorityOutcome::Degraded;
  updated.reductions = result.degradations;
  updated.distinct_failure_domains = result.distinct_failure_domains;

  JournalEntry entry;
  entry.kind = JournalRecordKind::GrantCommitted;
  entry.grant = updated;
  entry.grant_state = GrantState::Committed;
  const Status journaled = journal_entry(entry);
  if (!journaled.ok()) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Indeterminate,
        {Reason(ReasonCode::CommitAmbiguous,
                "the renewal record could not be made durable: " + journaled.to_string())});
    decision.requires_reconciliation = true;
    finalize_decision(decision, "renew");
    return decision;
  }
  updated.commit_sequence = entry.sequence;
  *grant = updated;
  state_digest_valid_ = false;

  AuthorityDecision decision =
      make_decision(request.request_id, request.attempt_id, outcome, result.degradations);
  decision.grant = *grant;
  finalize_decision(decision, "renew");
  return decision;
}

// ---------------------------------------------------------------------------
// submit
// ---------------------------------------------------------------------------
AuthorityDecision AuthorityCore::submit(const AuthorityRequest& request) {
  const Status shape = request.validate_shape();
  if (!shape.ok()) {
    return malformed_decision(request.request_id, request.attempt_id, shape);
  }
  if (!spec_.cluster_id().empty() && !(request.cluster_id == spec_.cluster_id())) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Unknown,
                      {Reason(ReasonCode::ClusterNotFound,
                              "this controller rules cluster " + spec_.cluster_id().to_string())});
    finalize_decision(decision, "submit");
    return decision;
  }

  const auto reject = [&](ReasonCode code, std::string detail, AuthorityOutcome outcome) {
    AuthorityDecision decision = make_decision(request.request_id, request.attempt_id, outcome,
                                               {Reason(code, std::move(detail))});
    finalize_decision(decision, "submit");
    return decision;
  };

  if (request.cluster_generation > spec_.generation()) {
    return reject(ReasonCode::ClusterGenerationAhead,
                  "request claims cluster generation " + request.cluster_generation.to_string() +
                      " but this controller is at " + spec_.generation().to_string(),
                  AuthorityOutcome::Invalid);
  }
  if (request.cluster_generation < spec_.generation()) {
    return reject(ReasonCode::ClusterGenerationStale,
                  "request is against cluster generation " +
                      request.cluster_generation.to_string() + "; current is " +
                      spec_.generation().to_string(),
                  AuthorityOutcome::Stale);
  }
  if (request.epoch > spec_.epoch()) {
    return reject(ReasonCode::EpochAhead,
                  "request claims epoch " + request.epoch.to_string() +
                      " which is ahead of this controller",
                  AuthorityOutcome::Invalid);
  }
  if (request.epoch < spec_.epoch()) {
    return reject(ReasonCode::EpochStale,
                  "request is against epoch " + request.epoch.to_string() + "; current is " +
                      spec_.epoch().to_string(),
                  AuthorityOutcome::Fenced);
  }
  if (!(request.incarnation == spec_.incarnation())) {
    return reject(ReasonCode::IncarnationStale,
                  "request is against controller incarnation " + request.incarnation.hex() +
                      "; current is " + spec_.incarnation().hex(),
                  AuthorityOutcome::Fenced);
  }
  if (request.policy_generation < spec_.policy_generation()) {
    return reject(ReasonCode::PolicyGenerationStale,
                  "request is against policy generation " +
                      request.policy_generation.to_string() + "; current is " +
                      spec_.policy_generation().to_string(),
                  AuthorityOutcome::Stale);
  }
  if (request.policy_generation > spec_.policy_generation()) {
    return reject(ReasonCode::PolicyGenerationStale,
                  "request claims a policy generation newer than this controller holds",
                  AuthorityOutcome::Stale);
  }

  // Exactly-once replay happens *after* the coordinate fence, deliberately. A
  // caller from a previous epoch cannot be trusted to interpret an answer, even
  // the answer to a request it already made: it may not know that the controller
  // restarted, and a grant it once held may have been fenced in the meantime.
  // The reconciliation path (resolve) is the one that is deliberately *not*
  // epoch-fenced, and it exists precisely so this fence is recoverable.
  if (!request.renewal) {
    if (const AttemptRecord* existing = find_attempt(request.attempt_id)) {
      return replay_attempt(*existing, request);
    }
  }

  const CommunicationContract* contract = contracts_.find(request.contract_id);
  if (contract == nullptr) {
    return reject(ReasonCode::ContractNotFound,
                  "contract " + request.contract_id.to_string() + " is not declared",
                  AuthorityOutcome::Unknown);
  }
  if (!(request.contract_generation == contract->generation)) {
    return reject(ReasonCode::ContractGenerationStale,
                  "contract is at generation " + contract->generation.to_string() +
                      ", request claims " + request.contract_generation.to_string(),
                  AuthorityOutcome::Stale);
  }
  if (!contract->enabled) {
    return reject(ReasonCode::ContractUnsatisfied,
                  "contract " + contract->id.to_string() + " is disabled",
                  AuthorityOutcome::Refused);
  }
  if (options_.reject_unknown_capabilities) {
    const std::vector<std::string> unsupported = contract->unsupported_capabilities();
    if (!unsupported.empty()) {
      const std::string& first = unsupported.front();
      if (is_inter_cluster_capability(first)) {
        return reject(ReasonCode::InterClusterUnsupported,
                      "contract requires capability '" + sanitise_for_display(first, 128) +
                          "', which belongs to a separate inter-cluster runtime",
                      AuthorityOutcome::Unsupported);
      }
      if (is_hardware_capability(first)) {
        return reject(ReasonCode::HardwareSemanticsUnsupported,
                      "contract requires capability '" + sanitise_for_display(first, 128) +
                          "', which is physical hardware behaviour this runtime does not model",
                      AuthorityOutcome::Unsupported);
      }
      return reject(ReasonCode::UnsupportedCapability,
                    "contract requires capability '" + sanitise_for_display(first, 128) +
                        "', which this build does not implement",
                    AuthorityOutcome::Unsupported);
    }
  }

  decision_request_digest_ = request.digest();
  if (request.renewal) {
    return renew(request, *contract);
  }

  AuthorityCore::EligibilityResult result = evaluate(request, *contract);
  if (result.outcome != AuthorityOutcome::Granted) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, result.outcome, result.reasons);
    counters_.refusals += 1;
    finalize_decision(decision, "submit");
    return decision;
  }

  AuthorityOutcome outcome = AuthorityOutcome::Granted;
  std::vector<Reason> reasons;
  if (!result.degradations.empty()) {
    if (contract->allow_degraded && request.allow_degraded) {
      outcome = AuthorityOutcome::Degraded;
      reasons = result.degradations;
    } else {
      AuthorityDecision decision =
          make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Refused,
                        result.degradations);
      counters_.refusals += 1;
      finalize_decision(decision, "submit");
      return decision;
    }
  }

  AuthorityGrant grant;
  grant.grant_id = GrantId::from_validated(mint_grant_id());
  grant.lease_id = LeaseId::from_validated(mint_lease_id());
  grant.attempt_id = request.attempt_id;
  grant.cluster_id = spec_.cluster_id();
  grant.cluster_generation = spec_.generation();
  grant.epoch = spec_.epoch();
  grant.policy_generation = spec_.policy_generation();
  grant.incarnation = spec_.incarnation();
  grant.contract_id = contract->id;
  grant.contract_generation = contract->generation;
  grant.source_service = contract->source_service;
  grant.destination_service = contract->destination_service;
  grant.source_member = result.source_member->id;
  grant.source_member_generation = result.source_member->generation;
  grant.source_member_digest = result.source_member->digest;
  grant.source_domain = result.source_member->domain;
  grant.destination_member = result.destination_member->id;
  grant.destination_member_generation = result.destination_member->generation;
  grant.destination_member_digest = result.destination_member->digest;
  grant.destination_domain = result.destination_member->domain;
  grant.source_endpoint = request.source_endpoint;
  grant.destination_endpoint = request.destination_endpoint;
  if (result.path != nullptr) {
    grant.path_id = result.path->id;
    grant.path_generation = result.path->generation;
    if (grant.source_endpoint.empty()) {
      grant.source_endpoint = result.path->source_endpoint;
    }
    if (grant.destination_endpoint.empty()) {
      grant.destination_endpoint = result.path->destination_endpoint;
    }
  }
  if (result.resource != nullptr) {
    grant.resource_id = result.resource->id;
    grant.reservation_generation = result.resource->reservation_generation;
  }
  grant.requested_units = request.requested_units == 0 ? contract->min_capacity_units
                                                       : request.requested_units;
  grant.capacity_units = result.authorised_units;
  grant.distinct_failure_domains = result.distinct_failure_domains;
  grant.outcome = outcome;
  grant.degraded = outcome == AuthorityOutcome::Degraded;
  grant.reductions = reasons;
  grant.provenance = request.provenance;
  const std::uint64_t lease_ticks = request.lease_ticks == 0 ? options_.default_lease_ticks
                                                             : request.lease_ticks;
  if (lease_ticks > options_.max_lease_ticks) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Refused,
        {Reason(ReasonCode::LimitExceeded, "requested lease exceeds the configured maximum")});
    counters_.refusals += 1;
    finalize_decision(decision, "submit");
    return decision;
  }
  grant.lease_expiry = Tick{spec_.tick().value() + lease_ticks};

  AuthorityDecision decision;
  const Status committed = commit_grant(std::move(grant), decision);
  if (!committed.ok()) {
    AuthorityDecision failure =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Refused,
                      {Reason(ReasonCode::LimitExceeded, committed.message())});
    finalize_decision(failure, "submit");
    return failure;
  }
  decision.request_id = request.request_id;
  decision.attempt_id = request.attempt_id;
  // A DEGRADED decision must explain the reduction at the decision level, not
  // only inside the grant: a caller that logs the outcome and discards the
  // grant must still learn why it got less than it asked for.
  if (decision.outcome == AuthorityOutcome::Degraded) {
    decision.reasons = reasons;
  }
  finalize_decision(decision, "submit");
  return decision;
}

// ---------------------------------------------------------------------------
// release / resolve / acknowledge / cancel
// ---------------------------------------------------------------------------
AuthorityDecision AuthorityCore::release(const ReleaseRequest& request) {
  const Status shape = request.validate_shape();
  if (!shape.ok()) {
    return malformed_decision(request.request_id, request.attempt_id, shape);
  }
  AuthorityGrant* grant = nullptr;
  if (!request.grant_id.empty()) {
    grant = mutable_grant(request.grant_id);
  }
  if (grant == nullptr && !request.attempt_id.empty()) {
    if (const AttemptRecord* attempt = find_attempt(request.attempt_id)) {
      if (!attempt->grant_id.empty()) {
        grant = mutable_grant(attempt->grant_id);
      }
    }
  }
  if (grant == nullptr) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Unknown,
                      {Reason(ReasonCode::GrantNotFound,
                              "no grant matches the identity supplied to release")});
    finalize_decision(decision, "release");
    return decision;
  }
  if (!request.lease_id.empty() && !(grant->lease_id == request.lease_id) && !request.administrative) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Conflicting,
        {Reason(ReasonCode::LeaseUnknown,
                "the supplied lease does not belong to grant " + grant->grant_id.to_string())});
    decision.grant = *grant;
    finalize_decision(decision, "release");
    return decision;
  }

  if (is_terminal(grant->state)) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Granted,
        {Reason(ReasonCode::GrantAlreadyReleased,
                "the release was already applied; capacity was returned exactly once")});
    decision.grant = *grant;
    decision.idempotent_replay = true;
    finalize_decision(decision, "release");
    return decision;
  }

  const GrantId grant_id = grant->grant_id;
  const AttemptId attempt_id = grant->attempt_id;
  const Status terminated = terminate_grant(*grant, GrantState::Released, ReasonCode::None, std::string{}, true);
  if (!terminated.ok()) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Indeterminate,
                      {Reason(ReasonCode::CommitIndeterminate, terminated.message())});
    decision.requires_reconciliation = true;
    finalize_decision(decision, "release");
    return decision;
  }
  if (AttemptRecord* attempt = mutable_attempt(attempt_id)) {
    attempt->released = true;
    attempt->terminal_tick = spec_.tick();
    JournalEntry entry;
    entry.kind = JournalRecordKind::AttemptTerminal;
    entry.attempt = *attempt;
    const Status journaled = journal_entry(entry);
    if (!journaled.ok()) {
      AuthorityDecision failure = make_decision(
          request.request_id, request.attempt_id, AuthorityOutcome::Indeterminate,
          {Reason(ReasonCode::CommitIndeterminate,
                  "the grant was released but the attempt record could not be made durable: " +
                      journaled.to_string())});
      failure.requires_reconciliation = true;
      finalize_decision(failure, "release");
      return failure;
    }
  }

  AuthorityDecision decision =
      make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Granted, {});
  if (const AuthorityGrant* updated = find_grant(grant_id)) {
    decision.grant = *updated;
  }
  finalize_decision(decision, "release");
  return decision;
}

AuthorityDecision AuthorityCore::resolve(const ResolveRequest& request) {
  const Status shape = request.validate_shape();
  if (!shape.ok()) {
    return malformed_decision(request.request_id, request.attempt_id, shape);
  }
  const AttemptRecord* attempt = find_attempt(request.attempt_id);
  if (attempt == nullptr) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Unknown,
                      {Reason(ReasonCode::AttemptUnknown,
                              "this controller has no record of that attempt")});
    finalize_decision(decision, "resolve");
    return decision;
  }

  AuthorityDecision decision;
  if (attempt->cancelled) {
    decision = make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Cancelled,
                             {Reason(ReasonCode::AttemptCancelled, "the attempt was cancelled")});
  } else if (attempt->released) {
    decision = make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Refused,
                             {Reason(ReasonCode::AttemptAlreadyReleased,
                                     "the attempt was granted and then released")});
  } else {
    decision = make_decision(request.request_id, request.attempt_id, attempt->outcome, {});
  }
  decision.idempotent_replay = true;
  // Once an attempt is cancelled or released, that is the answer. The artifact
  // it once produced may be in any terminal state; the grant must not be allowed
  // to talk over the attempt-level fact.
  const bool attempt_is_terminal = attempt->cancelled || attempt->released;

  const AuthorityGrant* grant =
      attempt->grant_id.empty() ? nullptr : find_grant(attempt->grant_id);
  if (grant != nullptr) {
    decision.grant = *grant;
    if (attempt_is_terminal) {
      decision.outcome = attempt->cancelled ? AuthorityOutcome::Cancelled
                                            : AuthorityOutcome::Refused;
      decision.requires_reconciliation = false;
    } else if (is_quarantined(grant->state)) {
      decision.outcome = AuthorityOutcome::Indeterminate;
      decision.requires_reconciliation = true;
      decision.reasons = {Reason(
          ReasonCode::CommitAmbiguous,
          "a durable commit exists but no acknowledgement was ever recorded; acknowledge it if you "
          "observed it, otherwise cancel it so the quarantined capacity is returned")};
    } else if (grant->state == GrantState::Released) {
      // "Released" is a fact about the artifact; *why* it was released is what
      // the caller needs. A release caused by a non-durable commit reports
      // COMMIT_NOT_DURABLE, not a bland "already released".
      decision.outcome = AuthorityOutcome::Refused;
      const ReasonCode reason = grant->reductions.empty() ? ReasonCode::GrantAlreadyReleased
                                                          : grant->reductions.front().code;
      decision.reasons = {Reason(reason, "the grant is no longer live (state RELEASED)")};
    } else if (grant->state == GrantState::Expired) {
      decision.outcome = AuthorityOutcome::Refused;
      decision.reasons = {Reason(ReasonCode::GrantExpired, "the lease elapsed")};
    } else if (grant->state == GrantState::Fenced || grant->state == GrantState::Revoked) {
      decision.outcome = AuthorityOutcome::Fenced;
      decision.requires_reconciliation = true;
      decision.reasons = {Reason(grant->reductions.empty() ? ReasonCode::GrantFenced
                                                           : grant->reductions.front().code,
                                 "the grant was superseded and must not be used")};
    } else {
      decision.outcome = grant->outcome;
      decision.reasons = {Reason(ReasonCode::CommitDurable,
                                 "the grant for this attempt is durable and currently "
                                 + std::string(to_string(grant->state)))};
    }
  } else if (!attempt->cancelled && !attempt->released) {
    decision.reasons = {Reason(attempt->primary_reason == ReasonCode::None
                                   ? ReasonCode::AttemptUnknown
                                   : attempt->primary_reason,
                               "this attempt never produced a grant")};
  }
  finalize_decision(decision, "resolve");
  return decision;
}

AuthorityDecision AuthorityCore::acknowledge(const AcknowledgeRequest& request) {
  const Status shape = request.validate_shape();
  if (!shape.ok()) {
    return malformed_decision(request.request_id, request.attempt_id, shape);
  }
  AuthorityGrant* grant = mutable_grant(request.grant_id);
  if (grant == nullptr) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Unknown,
                      {Reason(ReasonCode::GrantNotFound,
                              "grant " + request.grant_id.to_string() + " is not present")});
    finalize_decision(decision, "acknowledge");
    return decision;
  }
  if (!(grant->lease_id == request.lease_id)) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Conflicting,
        {Reason(ReasonCode::LeaseUnknown,
                "the supplied lease does not belong to grant " + grant->grant_id.to_string())});
    decision.grant = *grant;
    finalize_decision(decision, "acknowledge");
    return decision;
  }

  if (grant->state == GrantState::Released || grant->state == GrantState::Expired ||
      grant->state == GrantState::Fenced || grant->state == GrantState::Revoked) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Refused,
        {Reason(ReasonCode::GrantAlreadyReleased,
                "the grant is " + std::string(to_string(grant->state)) +
                    " and no longer carries authority")});
    decision.grant = *grant;
    finalize_decision(decision, "acknowledge");
    return decision;
  }

  if (grant->acknowledged && grant->state == GrantState::Acknowledged) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Granted,
        {Reason(ReasonCode::CommitDurable, "the grant was already acknowledged")});
    decision.grant = *grant;
    decision.idempotent_replay = true;
    finalize_decision(decision, "acknowledge");
    return decision;
  }

  if (is_quarantined(grant->state)) {
    // The caller has proved it observed the commit. Re-validate against the
    // recovered specification and, if sound, lift the quarantine.
    const Status revalidated = revalidate_grant(*grant, true);
    if (!revalidated.ok()) {
      AuthorityDecision failure = make_decision(
          request.request_id, request.attempt_id, AuthorityOutcome::Indeterminate,
          {Reason(ReasonCode::CommitIndeterminate,
                  "the quarantined grant could not be revalidated: " + revalidated.to_string())});
      failure.requires_reconciliation = true;
      finalize_decision(failure, "acknowledge");
      return failure;
    }
    if (grant->state != GrantState::Committed) {
      AuthorityDecision decision = make_decision(
          request.request_id, request.attempt_id, AuthorityOutcome::Fenced,
          {Reason(grant->reductions.empty() ? ReasonCode::GrantFenced
                                            : grant->reductions.front().code,
                  "the quarantined grant could not be revalidated against current state")});
      decision.grant = *grant;
      decision.requires_reconciliation = true;
      finalize_decision(decision, "acknowledge");
      return decision;
    }
  }

  JournalEntry entry;
  entry.kind = JournalRecordKind::GrantAcknowledged;
  entry.grant = *grant;
  entry.grant_state = GrantState::Acknowledged;
  const Status journaled = journal_entry(entry);
  if (!journaled.ok()) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Indeterminate,
                      {Reason(ReasonCode::CommitIndeterminate, journaled.message())});
    decision.requires_reconciliation = true;
    finalize_decision(decision, "acknowledge");
    return decision;
  }
  grant->acknowledged = true;
  grant->state = GrantState::Acknowledged;
  grant->commit = CommitState::Acknowledged;
  grant->acknowledgement_sequence = entry.sequence;
  state_digest_valid_ = false;

  AuthorityDecision decision = make_decision(
      request.request_id, request.attempt_id, grant->outcome,
      {Reason(ReasonCode::CommitDurable, "the caller has confirmed it observed this grant")});
  decision.grant = *grant;
  finalize_decision(decision, "acknowledge");
  return decision;
}

AuthorityDecision AuthorityCore::cancel(const CancelRequest& request) {
  const Status shape = request.validate_shape();
  if (!shape.ok()) {
    return malformed_decision(request.request_id, request.attempt_id, shape);
  }
  AttemptRecord* attempt = nullptr;
  if (!request.attempt_id.empty()) {
    attempt = mutable_attempt(request.attempt_id);
  }
  AuthorityGrant* grant = nullptr;
  if (!request.grant_id.empty()) {
    grant = mutable_grant(request.grant_id);
  }
  if (grant == nullptr && attempt != nullptr && !attempt->grant_id.empty()) {
    grant = mutable_grant(attempt->grant_id);
  }
  if (attempt == nullptr && grant == nullptr) {
    AuthorityDecision decision =
        make_decision(request.request_id, request.attempt_id, AuthorityOutcome::Unknown,
                      {Reason(ReasonCode::AttemptUnknown,
                              "neither the attempt nor the grant named by this cancel is known")});
    finalize_decision(decision, "cancel");
    return decision;
  }

  if (attempt != nullptr && attempt->cancelled) {
    AuthorityDecision decision = make_decision(
        request.request_id, request.attempt_id, AuthorityOutcome::Cancelled,
        {Reason(ReasonCode::AttemptCancelled, "the attempt was already cancelled")});
    if (grant != nullptr) {
      decision.grant = *grant;
    }
    decision.idempotent_replay = true;
    finalize_decision(decision, "cancel");
    return decision;
  }

  if (grant != nullptr && holds_capacity(grant->state)) {
    const Status revoked = terminate_grant(*grant, GrantState::Revoked, ReasonCode::AttemptCancelled,
                                           request.reason.empty() ? "cancelled" : request.reason, true);
    if (!revoked.ok()) {
      AuthorityDecision failure = make_decision(
          request.request_id, request.attempt_id, AuthorityOutcome::Indeterminate,
          {Reason(ReasonCode::CommitIndeterminate,
                  "the cancel could not be made durable: " + revoked.to_string())});
      failure.requires_reconciliation = true;
      finalize_decision(failure, "cancel");
      return failure;
    }
  }
  if (attempt == nullptr && grant != nullptr) {
    attempt = mutable_attempt(grant->attempt_id);
  }
  if (attempt != nullptr) {
    JournalEntry entry;
    entry.kind = JournalRecordKind::AttemptCancelled;
    entry.attempt_id = attempt->attempt_id;
    entry.note = request.reason;
    const Status journaled = journal_entry(entry);
    if (!journaled.ok()) {
      AuthorityDecision failure = make_decision(
          request.request_id, request.attempt_id, AuthorityOutcome::Indeterminate,
          {Reason(ReasonCode::CommitIndeterminate,
                  "the cancel could not be made durable: " + journaled.to_string())});
      failure.requires_reconciliation = true;
      finalize_decision(failure, "cancel");
      return failure;
    }
    attempt->cancelled = true;
    attempt->terminal_tick = spec_.tick();
    attempt->primary_reason = ReasonCode::AttemptCancelled;
  }
  state_digest_valid_ = false;

  AuthorityDecision decision = make_decision(
      request.request_id, request.attempt_id, AuthorityOutcome::Cancelled,
      {Reason(ReasonCode::AttemptCancelled,
              request.reason.empty() ? "the attempt is cancelled" : request.reason)});
  if (grant != nullptr) {
    decision.grant = *grant;
  }
  finalize_decision(decision, "cancel");
  return decision;
}

// ---------------------------------------------------------------------------
// Digests, rendering, snapshots
// ---------------------------------------------------------------------------
ControllerIdentity AuthorityCore::controller_identity() const {
  ControllerIdentity identity;
  identity.cluster = spec_.cluster_id();
  identity.generation = spec_.generation();
  identity.epoch = spec_.epoch();
  identity.policy = spec_.policy_generation();
  identity.incarnation = spec_.incarnation();
  return identity;
}

Digest256 AuthorityCore::state_digest() const {
  if (state_digest_valid_) {
    return cached_state_digest_;
  }
  // Composed from the cached component digests rather than re-encoding the whole
  // specification. The result is still a pure function of the canonical
  // encoding -- spec_ and contracts_ are digested over exactly the bytes their
  // encode() would produce -- but a decision no longer pays for re-encoding a
  // cluster with thousands of members and paths on every call.
  Bytes buffer;
  ByteWriter writer(buffer);
  writer.digest(spec_.digest());
  writer.digest(contracts_.digest());
  writer.count(grants_.size());
  for (const AuthorityGrant& grant : grants_) {
    grant.encode(writer);
  }
  writer.count(attempts_.size());
  for (const AttemptRecord& attempt : attempts_) {
    attempt.encode(writer);
  }
  // Only identity allocation is part of authoritative state. Diagnostic
  // counters (decisions, refusals, fences) are deliberately excluded so that
  // the digest answers "what is authoritative?" rather than "how busy were we?".
  writer.u64(grant_serial_);
  writer.u64(lease_serial_);
  cached_state_digest_ = canonical_digest("cif.authority.state.v2", buffer);
  state_digest_valid_ = true;
  return cached_state_digest_;
}

Digest256 AuthorityCore::live_state_digest() const {
  Bytes buffer;
  ByteWriter writer(buffer);
  for (const AuthorityGrant& grant : grants_) {
    if (!holds_capacity(grant.state)) {
      continue;
    }
    grant.encode(writer);
  }
  return canonical_digest("cif.authority.live.v1", buffer);
}

std::string AuthorityCore::render_state() const {
  std::string out;
  out += render_controller(controller_identity());
  out += "  spec_digest = " + spec_.digest().hex() + "\n";
  out += "  topology_digest = " + spec_.topology_digest().hex() + "\n";
  out += "  contract_digest = " + contracts_.digest().hex() + "\n";
  out += "  state_digest = " + state_digest().hex() + "\n";
  out += "  live_state_digest = " + live_state_digest().hex() + "\n";
  out += "  tick = " + spec_.tick().to_string() + "\n";
  out += "  durable = ";
  out += (sink_ != nullptr && sink_->durable()) ? "true\n" : "false\n";
  out += "  members = " + to_decimal(spec_.member_count()) + "\n";
  out += "  paths = " + to_decimal(spec_.path_count()) + "\n";
  out += "  contracts = " + to_decimal(contracts_.size()) + "\n";
  out += "  grants = " + to_decimal(grants_.size()) + "\n";
  out += "  attempts = " + to_decimal(attempts_.size()) + "\n";
  out += "  quarantined_units = " + to_decimal(quarantined_units()) + "\n";
  out += "  counters.decisions = " + to_decimal(counters_.decisions) + "\n";
  out += "  counters.grants = " + to_decimal(counters_.grants) + "\n";
  out += "  counters.refusals = " + to_decimal(counters_.refusals) + "\n";
  out += "  counters.fences = " + to_decimal(counters_.fences) + "\n";
  out += "  counters.recoveries = " + to_decimal(counters_.recoveries) + "\n";
  for (const Member& member : spec_.members()) {
    out += render_member(member);
  }
  for (const Path& path : spec_.paths()) {
    out += render_path(path);
  }
  for (const MaintenanceExclusion& exclusion : spec_.exclusions()) {
    out += render_exclusion(exclusion);
  }
  for (const CapacityObligation& obligation : spec_.obligations()) {
    out += render_obligation(obligation);
  }
  for (const CommunicationContract& contract : contracts_.all()) {
    out += render_contract(contract);
  }
  for (const AuthorityGrant& grant : grants_) {
    if (holds_capacity(grant.state)) {
      out += render_grant(grant);
    }
  }
  return out;
}

std::string AuthorityCore::render_audit() const {
  std::string out;
  if (audit_.empty()) {
    out += "AUDIT (empty)\n";
    out += "  note = audit history is diagnostic and is deliberately not persisted; a freshly "
           "recovered controller reports it as empty\n";
    return out;
  }
  for (const AuditEntry& entry : audit_) {
    out += "AUDIT " + to_decimal(entry.sequence) + " " + entry.operation + " " +
           to_string(entry.outcome) + " " + to_string(entry.reason) + " request=" +
           entry.request_id.to_string() + " attempt=" + entry.attempt_id.to_string() + " grant=" +
           entry.grant_id.to_string() + " tick=" + entry.tick.to_string();
    if (!entry.detail.empty()) {
      out += " detail=" + entry.detail;
    }
    out += "\n";
  }
  return out;
}

JournalEntry AuthorityCore::make_snapshot() const {
  JournalEntry entry;
  entry.kind = JournalRecordKind::Snapshot;
  entry.tick = spec_.tick();
  entry.snapshot_spec = spec_;
  entry.snapshot_contracts = contracts_;
  entry.snapshot_grants = grants_;
  entry.snapshot_attempts = attempts_;
  entry.snapshot_counters = counters_;
  return entry;
}

Status AuthorityCore::maybe_compact() {
  if (sink_ == nullptr || !sink_->should_compact()) {
    return Status::success();
  }
  CIF_TRY(sink_->compact(make_snapshot()));
  counters_.compactions += 1;
  JournalEntry counters_entry;
  counters_entry.kind = JournalRecordKind::CountersSync;
  counters_entry.snapshot_counters = counters_;
  CIF_TRY(journal_entry(counters_entry, false));
  return Status::success();
}

// ---------------------------------------------------------------------------
// Self-check
// ---------------------------------------------------------------------------
Status AuthorityCore::self_check() const {
  if (!initialized_) {
    return Status::error(StatusCode::StateMismatch, "authority has not been initialised");
  }
  CIF_TRY(spec_.validate());
  CIF_TRY(contracts_.validate());

  for (std::size_t i = 1; i < grants_.size(); ++i) {
    if (!(grants_[i - 1].grant_id < grants_[i].grant_id)) {
      return Status::error(StatusCode::Internal, "grant table is not strictly sorted by id");
    }
  }
  for (std::size_t i = 1; i < attempts_.size(); ++i) {
    if (!(attempts_[i - 1].attempt_id < attempts_[i].attempt_id)) {
      return Status::error(StatusCode::Internal, "attempt table is not strictly sorted by id");
    }
  }
  if (grants_.size() > limits::kMaxGrants) {
    return Status::error(StatusCode::Internal, "grant table exceeds its configured bound");
  }
  if (attempts_.size() > limits::kMaxAttempts) {
    return Status::error(StatusCode::Internal, "attempt table exceeds its configured bound");
  }

  std::map<std::string, std::uint64_t> per_resource;
  for (const AuthorityGrant& grant : grants_) {
    if (holds_capacity(grant.state) != grant.capacity_reserved) {
      return Status::error(StatusCode::Internal,
                           "grant " + grant.grant_id.to_string() +
                               " disagrees with itself about whether it holds capacity");
    }
    // A zero-unit grant is a *permission grant*: the relationship is
    // authorised, nothing is reserved against any pool. That is legal, and it is
    // the correct answer when neither the contract nor the caller asked for
    // capacity. What is never legal is claiming a reservation against a
    // concrete resource pool while reserving nothing.
    if (holds_capacity(grant.state) && grant.capacity_units == 0 && !grant.resource_id.empty()) {
      return Status::error(StatusCode::Internal,
                           "grant " + grant.grant_id.to_string() +
                               " names resource " + grant.resource_id.to_string() +
                               " but reserves zero units");
    }
    if (grant.capacity_units > grant.requested_units && grant.requested_units > 0) {
      return Status::error(StatusCode::Internal,
                           "grant " + grant.grant_id.to_string() +
                               " authorises more units than were requested");
    }
    if (grant.capacity_units > limits::kMaxCapacityUnits) {
      return Status::error(StatusCode::Internal,
                           "grant " + grant.grant_id.to_string() + " exceeds the capacity bound");
    }
    if (!grant.source_member.empty() && spec_.find_member(grant.source_member) == nullptr) {
      return Status::error(StatusCode::Internal,
                           "live grant " + grant.grant_id.to_string() +
                               " references a member that no longer exists");
    }
    if (!grant.attempt_id.empty() && find_attempt(grant.attempt_id) == nullptr) {
      return Status::error(StatusCode::Internal,
                           "grant " + grant.grant_id.to_string() + " has no attempt record");
    }
    if (!grant.capacity_reserved) {
      continue;
    }
    if (!grant.resource_id.empty()) {
      std::uint64_t next = 0;
      if (!checked_add(per_resource[grant.resource_id.value()], grant.capacity_units, next)) {
        return Status::error(StatusCode::Internal, "resource accounting overflowed");
      }
      per_resource[grant.resource_id.value()] = next;
    }
  }
  for (const auto& entry : per_resource) {
    const Member* owner = nullptr;
    for (const Member& member : spec_.members()) {
      if (member.find_resource(ResourceId::from_validated(entry.first)) != nullptr) {
        owner = &member;
        break;
      }
    }
    if (owner == nullptr) {
      return Status::error(StatusCode::Internal,
                           "capacity is reserved against unknown resource " + entry.first);
    }
    const Resource* resource = owner->find_resource(ResourceId::from_validated(entry.first));
    if (resource != nullptr && entry.second > resource->total_units) {
      return Status::error(StatusCode::Internal,
                           "resource " + entry.first + " is over-committed: " +
                               to_decimal(entry.second) + " reserved of " +
                               to_decimal(resource->total_units));
    }
  }
  if (grant_serial_ < counters_.grants && counters_.grants != 0 && grant_serial_ != 0) {
    // Not fatal, but worth surfacing: allocation must never move backwards.
    if (grant_serial_ < counters_.grants) {
      return Status::error(StatusCode::Internal, "grant allocation counter moved backwards");
    }
  }
  return Status::success();
}

}  // namespace cif
