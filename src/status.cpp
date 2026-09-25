#include "cif/status.hpp"

#include <string>

namespace cif {

const char* to_string(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Ok: return "OK";
    case StatusCode::InvalidArgument: return "INVALID_ARGUMENT";
    case StatusCode::NotFound: return "NOT_FOUND";
    case StatusCode::AlreadyExists: return "ALREADY_EXISTS";
    case StatusCode::DuplicateIdentity: return "DUPLICATE_IDENTITY";
    case StatusCode::CapacityExhausted: return "CAPACITY_EXHAUSTED";
    case StatusCode::LimitExceeded: return "LIMIT_EXCEEDED";
    case StatusCode::IntegrityFailure: return "INTEGRITY_FAILURE";
    case StatusCode::Corruption: return "CORRUPTION";
    case StatusCode::Truncated: return "TRUNCATED";
    case StatusCode::VersionMismatch: return "VERSION_MISMATCH";
    case StatusCode::IoFailure: return "IO_FAILURE";
    case StatusCode::Unsupported: return "UNSUPPORTED";
    case StatusCode::Conflict: return "CONFLICT";
    case StatusCode::StateMismatch: return "STATE_MISMATCH";
    case StatusCode::Fenced: return "FENCED";
    case StatusCode::Cancelled: return "CANCELLED";
    case StatusCode::Indeterminate: return "INDETERMINATE";
    case StatusCode::Busy: return "BUSY";
    case StatusCode::Backpressure: return "BACKPRESSURE";
    case StatusCode::Closed: return "CLOSED";
    case StatusCode::Timeout: return "TIMEOUT";
    case StatusCode::RemoteError: return "REMOTE_ERROR";
    case StatusCode::Internal: return "INTERNAL";
  }
  return "UNRECOGNISED_STATUS";
}

const char* to_string(AuthorityOutcome outcome) noexcept {
  switch (outcome) {
    case AuthorityOutcome::Granted: return "GRANTED";
    case AuthorityOutcome::Degraded: return "DEGRADED";
    case AuthorityOutcome::Refused: return "REFUSED";
    case AuthorityOutcome::Fenced: return "FENCED";
    case AuthorityOutcome::Stale: return "STALE";
    case AuthorityOutcome::Conflicting: return "CONFLICTING";
    case AuthorityOutcome::Incomplete: return "INCOMPLETE";
    case AuthorityOutcome::Indeterminate: return "INDETERMINATE";
    case AuthorityOutcome::Unknown: return "UNKNOWN";
    case AuthorityOutcome::Unsupported: return "UNSUPPORTED";
    case AuthorityOutcome::Cancelled: return "CANCELLED";
    case AuthorityOutcome::Invalid: return "INVALID";
  }
  return "UNRECOGNISED_OUTCOME";
}

bool is_authoritative(AuthorityOutcome outcome) noexcept {
  return outcome == AuthorityOutcome::Granted || outcome == AuthorityOutcome::Degraded;
}

bool is_retryable(AuthorityOutcome outcome) noexcept {
  switch (outcome) {
    case AuthorityOutcome::Degraded:
    case AuthorityOutcome::Stale:
    case AuthorityOutcome::Conflicting:
    case AuthorityOutcome::Incomplete:
    case AuthorityOutcome::Indeterminate:
    case AuthorityOutcome::Refused:
      return true;
    case AuthorityOutcome::Granted:
    case AuthorityOutcome::Fenced:
    case AuthorityOutcome::Unknown:
    case AuthorityOutcome::Unsupported:
    case AuthorityOutcome::Cancelled:
    case AuthorityOutcome::Invalid:
      return false;
  }
  return false;
}

const char* to_string(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::None: return "NONE";
    case ReasonCode::ClusterNotFound: return "CLUSTER_NOT_FOUND";
    case ReasonCode::ClusterGenerationStale: return "CLUSTER_GENERATION_STALE";
    case ReasonCode::ClusterGenerationAhead: return "CLUSTER_GENERATION_AHEAD";
    case ReasonCode::PolicyGenerationStale: return "POLICY_GENERATION_STALE";
    case ReasonCode::EpochStale: return "EPOCH_STALE";
    case ReasonCode::EpochAhead: return "EPOCH_AHEAD";
    case ReasonCode::IncarnationStale: return "INCARNATION_STALE";
    case ReasonCode::IncarnationUnknown: return "INCARNATION_UNKNOWN";
    case ReasonCode::MemberNotFound: return "MEMBER_NOT_FOUND";
    case ReasonCode::MemberDeleted: return "MEMBER_DELETED";
    case ReasonCode::MemberNotActive: return "MEMBER_NOT_ACTIVE";
    case ReasonCode::MemberDraining: return "MEMBER_DRAINING";
    case ReasonCode::MemberMaintenance: return "MEMBER_MAINTENANCE";
    case ReasonCode::MemberFaulted: return "MEMBER_FAULTED";
    case ReasonCode::MemberPartitioned: return "MEMBER_PARTITIONED";
    case ReasonCode::MemberGenerationStale: return "MEMBER_GENERATION_STALE";
    case ReasonCode::MemberGenerationAhead: return "MEMBER_GENERATION_AHEAD";
    case ReasonCode::MemberDigestMismatch: return "MEMBER_DIGEST_MISMATCH";
    case ReasonCode::MemberDigestMissing: return "MEMBER_DIGEST_MISSING";
    case ReasonCode::MemberDomainUnknown: return "MEMBER_DOMAIN_UNKNOWN";
    case ReasonCode::MemberDomainMismatch: return "MEMBER_DOMAIN_MISMATCH";
    case ReasonCode::EndpointNotFound: return "ENDPOINT_NOT_FOUND";
    case ReasonCode::ServiceGroupNotFound: return "SERVICE_GROUP_NOT_FOUND";
    case ReasonCode::ServiceGroupNotServed: return "SERVICE_GROUP_NOT_SERVED";
    case ReasonCode::PathNotFound: return "PATH_NOT_FOUND";
    case ReasonCode::PathGenerationStale: return "PATH_GENERATION_STALE";
    case ReasonCode::PathNotOperational: return "PATH_NOT_OPERATIONAL";
    case ReasonCode::PathAlreadyBound: return "PATH_ALREADY_BOUND";
    case ReasonCode::NoEligiblePath: return "NO_ELIGIBLE_PATH";
    case ReasonCode::ResourceNotFound: return "RESOURCE_NOT_FOUND";
    case ReasonCode::ReservationGenerationStale: return "RESERVATION_GENERATION_STALE";
    case ReasonCode::ReservationGenerationMissing: return "RESERVATION_GENERATION_MISSING";
    case ReasonCode::CapacityExhausted: return "CAPACITY_EXHAUSTED";
    case ReasonCode::CapacityInsufficient: return "CAPACITY_INSUFFICIENT";
    case ReasonCode::CapacityOverCommitted: return "CAPACITY_OVER_COMMITTED";
    case ReasonCode::CapacityAccountedToOtherGrant: return "CAPACITY_ACCOUNTED_TO_OTHER_GRANT";
    case ReasonCode::ContractNotFound: return "CONTRACT_NOT_FOUND";
    case ReasonCode::ContractGenerationStale: return "CONTRACT_GENERATION_STALE";
    case ReasonCode::ContractUnsatisfied: return "CONTRACT_UNSATISFIED";
    case ReasonCode::LocalityConstraintViolated: return "LOCALITY_CONSTRAINT_VIOLATED";
    case ReasonCode::FailureDomainConflict: return "FAILURE_DOMAIN_CONFLICT";
    case ReasonCode::MaintenanceExclusionActive: return "MAINTENANCE_EXCLUSION_ACTIVE";
    case ReasonCode::GrantNotFound: return "GRANT_NOT_FOUND";
    case ReasonCode::GrantAlreadyActive: return "GRANT_ALREADY_ACTIVE";
    case ReasonCode::GrantAlreadyReleased: return "GRANT_ALREADY_RELEASED";
    case ReasonCode::GrantExpired: return "GRANT_EXPIRED";
    case ReasonCode::GrantFenced: return "GRANT_FENCED";
    case ReasonCode::LeaseExpired: return "LEASE_EXPIRED";
    case ReasonCode::LeaseUnknown: return "LEASE_UNKNOWN";
    case ReasonCode::AttemptUnknown: return "ATTEMPT_UNKNOWN";
    case ReasonCode::AttemptAlreadyCommitted: return "ATTEMPT_ALREADY_COMMITTED";
    case ReasonCode::AttemptAlreadyReleased: return "ATTEMPT_ALREADY_RELEASED";
    case ReasonCode::AttemptCancelled: return "ATTEMPT_CANCELLED";
    case ReasonCode::AttemptConflict: return "ATTEMPT_CONFLICT";
    case ReasonCode::AttemptMismatch: return "ATTEMPT_MISMATCH";
    case ReasonCode::CommitAmbiguous: return "COMMIT_AMBIGUOUS";
    case ReasonCode::CommitIndeterminate: return "COMMIT_INDETERMINATE";
    case ReasonCode::CommitDurable: return "COMMIT_DURABLE";
    case ReasonCode::CommitNotDurable: return "COMMIT_NOT_DURABLE";
    case ReasonCode::RecoveredHistoricalState: return "RECOVERED_HISTORICAL_STATE";
    case ReasonCode::RecoveryTruncatedJournal: return "RECOVERY_TRUNCATED_JOURNAL";
    case ReasonCode::RecoveryIntegrityFailure: return "RECOVERY_INTEGRITY_FAILURE";
    case ReasonCode::ControllerRestarted: return "CONTROLLER_RESTARTED";
    case ReasonCode::UnsupportedCapability: return "UNSUPPORTED_CAPABILITY";
    case ReasonCode::HardwareSemanticsUnsupported: return "HARDWARE_SEMANTICS_UNSUPPORTED";
    case ReasonCode::InterClusterUnsupported: return "INTER_CLUSTER_UNSUPPORTED";
    case ReasonCode::ProtocolVersionUnsupported: return "PROTOCOL_VERSION_UNSUPPORTED";
    case ReasonCode::MalformedRequest: return "MALFORMED_REQUEST";
    case ReasonCode::LimitExceeded: return "LIMIT_EXCEEDED";
    case ReasonCode::ArithmeticOverflow: return "ARITHMETIC_OVERFLOW";
    case ReasonCode::ReservedIdentity: return "RESERVED_IDENTITY";
    case ReasonCode::DegradedByMemberState: return "DEGRADED_BY_MEMBER_STATE";
    case ReasonCode::DegradedByCapacity: return "DEGRADED_BY_CAPACITY";
    case ReasonCode::DegradedByLocality: return "DEGRADED_BY_LOCALITY";
    case ReasonCode::DegradedByMaintenance: return "DEGRADED_BY_MAINTENANCE";
    case ReasonCode::DegradedByRedundancyLoss: return "DEGRADED_BY_REDUNDANCY_LOSS";
  }
  return "UNRECOGNISED_REASON";
}

AuthorityOutcome default_outcome_for(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::None:
    case ReasonCode::CommitDurable:
      return AuthorityOutcome::Granted;

    case ReasonCode::DegradedByMemberState:
    case ReasonCode::DegradedByCapacity:
    case ReasonCode::DegradedByLocality:
    case ReasonCode::DegradedByMaintenance:
    case ReasonCode::DegradedByRedundancyLoss:
      return AuthorityOutcome::Degraded;

    case ReasonCode::ClusterGenerationStale:
    case ReasonCode::PolicyGenerationStale:
    case ReasonCode::MemberGenerationStale:
    case ReasonCode::MemberDeleted:
    case ReasonCode::PathGenerationStale:
    case ReasonCode::ReservationGenerationStale:
    case ReasonCode::ContractGenerationStale:
    case ReasonCode::RecoveredHistoricalState:
    case ReasonCode::ControllerRestarted:
      return AuthorityOutcome::Stale;

    case ReasonCode::EpochStale:
    case ReasonCode::IncarnationStale:
    case ReasonCode::GrantFenced:
    case ReasonCode::MemberGenerationAhead:
    case ReasonCode::MemberDigestMismatch:
      return AuthorityOutcome::Fenced;

    case ReasonCode::PathAlreadyBound:
    case ReasonCode::GrantAlreadyActive:
    case ReasonCode::AttemptConflict:
    case ReasonCode::FailureDomainConflict:
    case ReasonCode::CapacityAccountedToOtherGrant:
      return AuthorityOutcome::Conflicting;

    case ReasonCode::MemberNotActive:
    case ReasonCode::MemberDraining:
    case ReasonCode::MemberMaintenance:
    case ReasonCode::MemberFaulted:
    case ReasonCode::MemberPartitioned:
    case ReasonCode::MemberDomainMismatch:
    case ReasonCode::PathNotOperational:
    case ReasonCode::CapacityExhausted:
    case ReasonCode::CapacityInsufficient:
    case ReasonCode::CapacityOverCommitted:
    case ReasonCode::ContractUnsatisfied:
    case ReasonCode::LocalityConstraintViolated:
    case ReasonCode::MaintenanceExclusionActive:
    case ReasonCode::ServiceGroupNotServed:
    case ReasonCode::GrantExpired:
    case ReasonCode::LeaseExpired:
    case ReasonCode::NoEligiblePath:
    case ReasonCode::ReservedIdentity:
      return AuthorityOutcome::Refused;

    case ReasonCode::MemberDigestMissing:
    case ReasonCode::ReservationGenerationMissing:
      return AuthorityOutcome::Incomplete;

    case ReasonCode::CommitAmbiguous:
    case ReasonCode::CommitIndeterminate:
      return AuthorityOutcome::Indeterminate;

    case ReasonCode::ClusterNotFound:
    case ReasonCode::MemberNotFound:
    case ReasonCode::MemberDomainUnknown:
    case ReasonCode::EndpointNotFound:
    case ReasonCode::ServiceGroupNotFound:
    case ReasonCode::PathNotFound:
    case ReasonCode::ResourceNotFound:
    case ReasonCode::ContractNotFound:
    case ReasonCode::GrantNotFound:
    case ReasonCode::LeaseUnknown:
    case ReasonCode::AttemptUnknown:
    case ReasonCode::IncarnationUnknown:
      return AuthorityOutcome::Unknown;

    case ReasonCode::UnsupportedCapability:
    case ReasonCode::HardwareSemanticsUnsupported:
    case ReasonCode::InterClusterUnsupported:
    case ReasonCode::ProtocolVersionUnsupported:
      return AuthorityOutcome::Unsupported;

    case ReasonCode::AttemptCancelled:
      return AuthorityOutcome::Cancelled;

    case ReasonCode::MalformedRequest:
    case ReasonCode::LimitExceeded:
    case ReasonCode::ArithmeticOverflow:
      return AuthorityOutcome::Invalid;

    // A caller that believes it is *ahead* of the controller is either talking to
    // the wrong controller or has been fed fabricated state. Neither is a stale
    // read: it is a malformed request.
    case ReasonCode::ClusterGenerationAhead:
    case ReasonCode::EpochAhead:
      return AuthorityOutcome::Invalid;

    case ReasonCode::AttemptAlreadyCommitted:
    case ReasonCode::AttemptAlreadyReleased:
    case ReasonCode::AttemptMismatch:
    case ReasonCode::GrantAlreadyReleased:
    case ReasonCode::CommitNotDurable:
    case ReasonCode::RecoveryTruncatedJournal:
    case ReasonCode::RecoveryIntegrityFailure:
      return AuthorityOutcome::Refused;
  }
  return AuthorityOutcome::Invalid;
}

std::string Reason::to_string() const {
  std::string out = cif::to_string(code);
  if (!detail.empty()) {
    out += ": ";
    out += detail;
  }
  return out;
}

std::string Status::to_string() const {
  if (ok()) {
    return "OK";
  }
  std::string out = cif::to_string(code_);
  if (!message_.empty()) {
    out += ": ";
    out += message_;
  }
  return out;
}

}  // namespace cif
