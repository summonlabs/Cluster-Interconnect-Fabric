// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Typed outcomes. CIF keeps "we do not know", "we cannot support this",
// "your evidence is stale", "someone else holds it", "your request was
// incomplete", "the result is genuinely indeterminate", "we refuse", "it was
// cancelled" and "your request was malformed" strictly distinct. Collapsing any
// of these into success (or into each other) is a defect, not a simplification.
#ifndef CIF_STATUS_HPP
#define CIF_STATUS_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace cif {

/// Result of an API/driver operation (as opposed to an authority *decision*).
enum class StatusCode : std::uint8_t {
  Ok = 0,
  InvalidArgument,     ///< Caller supplied a value that cannot be interpreted.
  NotFound,            ///< Referenced entity is not present.
  AlreadyExists,       ///< Entity already present where uniqueness is required.
  DuplicateIdentity,   ///< Same identity presented twice with different content.
  CapacityExhausted,   ///< A bounded resource (capacity/queue/history) is full.
  LimitExceeded,       ///< A declared quantity exceeds a configured bound.
  IntegrityFailure,    ///< Stored bytes failed their integrity check.
  Corruption,          ///< Structurally invalid stored bytes.
  Truncated,           ///< Input ended earlier than the format requires.
  VersionMismatch,     ///< Format/protocol version not understood by this build.
  IoFailure,           ///< Underlying storage/transport operation failed.
  Unsupported,         ///< Explicitly out of scope for this runtime.
  Conflict,            ///< Concurrent/competing state blocks the operation.
  StateMismatch,       ///< Caller expectations contradict current state.
  Fenced,              ///< Artifact was fenced and must not be used.
  Cancelled,           ///< Operation was cancelled before completion.
  Indeterminate,       ///< Outcome cannot be determined from available evidence.
  Busy,                ///< Temporarily unable to proceed; retry is meaningful.
  Backpressure,        ///< Bounded ingress refused the work item.
  Closed,              ///< Handle/endpoint was closed.
  Timeout,             ///< Deadline expired.
  RemoteError,         ///< A peer reported a typed failure of its own.
  Internal,            ///< Invariant violation inside the runtime (a bug).
};

[[nodiscard]] const char* to_string(StatusCode code) noexcept;

/// Decision outcomes produced by the authority engine.
///
/// Granted/Degraded are the only outcomes that carry authority. Degraded means
/// "authoritative but reduced": the grant is real, its scope is smaller than
/// requested, and the reduction is recorded explicitly.
enum class AuthorityOutcome : std::uint8_t {
  Granted = 0,     ///< Full requested scope authorised.
  Degraded,        ///< Authorised with explicitly reduced scope.
  Refused,         ///< Policy/capacity/constraints deny authority.
  Fenced,          ///< Referenced authority artifact is fenced (stale epoch/incarnation/generation).
  Stale,           ///< Caller's view of cluster state is older than current.
  Conflicting,     ///< A competing grant/lease already holds the relationship.
  Incomplete,      ///< Required evidence was not supplied.
  Indeterminate,   ///< Commit ambiguity: neither committed nor not-committed is provable.
  Unknown,         ///< Referenced entity/identity was never seen by this controller.
  Unsupported,     ///< Explicitly outside the modelled domain (e.g. hardware semantics).
  Cancelled,       ///< Cancelled by client or administrator.
  Invalid,         ///< Malformed request; nothing was evaluated.
};

[[nodiscard]] const char* to_string(AuthorityOutcome outcome) noexcept;

/// True only for outcomes that carry authority.
[[nodiscard]] bool is_authoritative(AuthorityOutcome outcome) noexcept;

/// True when the caller may obtain a different answer by refreshing state and
/// retrying (as opposed to the request being permanently wrong).
[[nodiscard]] bool is_retryable(AuthorityOutcome outcome) noexcept;

/// Typed reasons. Every decision carries at least one reason; the first reason
/// is the primary cause and determines the outcome.
enum class ReasonCode : std::uint16_t {
  None = 0,

  // -- cluster identity / versioning -------------------------------------
  ClusterNotFound,
  ClusterGenerationStale,
  ClusterGenerationAhead,
  PolicyGenerationStale,
  EpochStale,
  EpochAhead,
  IncarnationStale,
  IncarnationUnknown,

  // -- membership ---------------------------------------------------------
  MemberNotFound,
  MemberDeleted,
  MemberNotActive,
  MemberDraining,
  MemberMaintenance,
  MemberFaulted,
  MemberPartitioned,
  MemberGenerationStale,
  MemberGenerationAhead,
  MemberDigestMismatch,
  MemberDigestMissing,
  MemberDomainUnknown,
  MemberDomainMismatch,

  // -- topology / services ------------------------------------------------
  EndpointNotFound,
  ServiceGroupNotFound,
  ServiceGroupNotServed,
  PathNotFound,
  PathGenerationStale,
  PathNotOperational,
  PathAlreadyBound,
  NoEligiblePath,

  // -- resources / capacity ----------------------------------------------
  ResourceNotFound,
  ReservationGenerationStale,
  ReservationGenerationMissing,
  CapacityExhausted,
  CapacityInsufficient,
  CapacityOverCommitted,
  CapacityAccountedToOtherGrant,

  // -- contracts / constraints -------------------------------------------
  ContractNotFound,
  ContractGenerationStale,
  ContractUnsatisfied,
  LocalityConstraintViolated,
  FailureDomainConflict,
  MaintenanceExclusionActive,

  // -- grants / leases / attempts ----------------------------------------
  GrantNotFound,
  GrantAlreadyActive,
  GrantAlreadyReleased,
  GrantExpired,
  GrantFenced,
  LeaseExpired,
  LeaseUnknown,
  AttemptUnknown,
  AttemptAlreadyCommitted,
  AttemptAlreadyReleased,
  AttemptCancelled,
  AttemptConflict,
  AttemptMismatch,

  // -- commit ambiguity ---------------------------------------------------
  CommitAmbiguous,
  CommitIndeterminate,
  CommitDurable,
  CommitNotDurable,

  // -- recovery -----------------------------------------------------------
  RecoveredHistoricalState,
  RecoveryTruncatedJournal,
  RecoveryIntegrityFailure,
  ControllerRestarted,

  // -- scope / limits -----------------------------------------------------
  UnsupportedCapability,
  HardwareSemanticsUnsupported,
  InterClusterUnsupported,
  ProtocolVersionUnsupported,
  MalformedRequest,
  LimitExceeded,
  ArithmeticOverflow,
  ReservedIdentity,

  // -- degradation causes -------------------------------------------------
  DegradedByMemberState,
  DegradedByCapacity,
  DegradedByLocality,
  DegradedByMaintenance,
  DegradedByRedundancyLoss,
};

[[nodiscard]] const char* to_string(ReasonCode code) noexcept;

/// Conservative default outcome for a reason, used by the reference model and
/// to keep control-plane and data-plane explanations consistent.
[[nodiscard]] AuthorityOutcome default_outcome_for(ReasonCode code) noexcept;

/// A single explanation clause: typed code plus optional human detail.
struct Reason {
  ReasonCode code = ReasonCode::None;
  std::string detail;

  Reason() = default;
  explicit Reason(ReasonCode c) : code(c) {}
  Reason(ReasonCode c, std::string d) : code(c), detail(std::move(d)) {}

  [[nodiscard]] bool empty() const noexcept { return code == ReasonCode::None; }
  [[nodiscard]] std::string to_string() const;
};

/// Operation status: code plus diagnostic message. Constructed Ok by default.
class Status {
 public:
  Status() noexcept = default;

  static Status success() noexcept { return Status{}; }
  static Status error(StatusCode code, std::string message) {
    Status s;
    s.code_ = code;
    s.message_ = std::move(message);
    return s;
  }

  [[nodiscard]] bool ok() const noexcept { return code_ == StatusCode::Ok; }
  [[nodiscard]] StatusCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }
  [[nodiscard]] std::string to_string() const;

  /// True when code_ == expect. Useful in tests and call sites that must branch
  /// on the exact failure class rather than on "not ok".
  [[nodiscard]] bool is(StatusCode expect) const noexcept { return code_ == expect; }

 private:
  StatusCode code_ = StatusCode::Ok;
  std::string message_;
};

/// Helper used by drivers: propagate the first failure.
#define CIF_TRY(expr)                        \
  do {                                       \
    ::cif::Status cif_try_status = (expr);   \
    if (!cif_try_status.ok()) {              \
      return cif_try_status;                 \
    }                                        \
  } while (false)

}  // namespace cif

#endif  // CIF_STATUS_HPP
