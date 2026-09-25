#include "cif/grant.hpp"

#include <utility>

#include "cif/render.hpp"

namespace cif {
namespace {

void encode_reasons(ByteWriter& writer, const std::vector<Reason>& reasons) {
  const std::size_t bounded = reasons.size() < limits::kMaxReasons ? reasons.size() : limits::kMaxReasons;
  writer.count(bounded);
  for (std::size_t i = 0; i < bounded; ++i) {
    writer.u16(static_cast<std::uint16_t>(reasons[i].code));
    writer.text(reasons[i].detail);
  }
}

bool decode_reasons(ByteReader& reader, std::vector<Reason>& out) {
  std::size_t count = 0;
  if (!reader.count(limits::kMaxReasons, count)) {
    return false;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    std::uint16_t raw_code = 0;
    if (!reader.u16(raw_code)) {
      return false;
    }
    if (raw_code > static_cast<std::uint16_t>(ReasonCode::DegradedByRedundancyLoss)) {
      reader.fail(StatusCode::Corruption, "reason code out of range");
      return false;
    }
    Reason reason(static_cast<ReasonCode>(raw_code));
    if (!reader.text(reason.detail, limits::kMaxReasonDetailBytes)) {
      return false;
    }
    if (!is_valid_utf8(reason.detail)) {
      reader.fail(StatusCode::Corruption, "reason detail is not valid UTF-8");
      return false;
    }
    out.push_back(std::move(reason));
  }
  return true;
}

void encode_decision_body(ByteWriter& writer, const AuthorityDecision& decision) {
  encode_id(writer, decision.request_id);
  encode_id(writer, decision.attempt_id);
  writer.u8(static_cast<std::uint8_t>(decision.outcome));
  encode_reasons(writer, decision.reasons);
  writer.boolean(decision.grant.has_value());
  if (decision.grant.has_value()) {
    decision.grant->encode(writer);
  }
  encode_id(writer, decision.cluster_id);
  encode_counter(writer, decision.cluster_generation);
  encode_counter(writer, decision.epoch);
  encode_counter(writer, decision.policy_generation);
  encode_incarnation(writer, decision.incarnation);
  writer.digest(decision.spec_digest);
  writer.digest(decision.state_digest);
  writer.u64(decision.decision_sequence);
  encode_counter(writer, decision.decided_at);
  writer.boolean(decision.idempotent_replay);
  writer.boolean(decision.requires_reconciliation);
}

}  // namespace

const char* to_string(GrantState state) noexcept {
  switch (state) {
    case GrantState::Prepared: return "PREPARED";
    case GrantState::Committed: return "COMMITTED";
    case GrantState::Acknowledged: return "ACKNOWLEDGED";
    case GrantState::Ambiguous: return "AMBIGUOUS";
    case GrantState::Released: return "RELEASED";
    case GrantState::Expired: return "EXPIRED";
    case GrantState::Fenced: return "FENCED";
    case GrantState::Revoked: return "REVOKED";
    case GrantState::Superseded: return "SUPERSEDED";
  }
  return "UNRECOGNISED_GRANT_STATE";
}

const char* to_string(CommitState state) noexcept {
  switch (state) {
    case CommitState::None: return "NONE";
    case CommitState::Prepared: return "PREPARED";
    case CommitState::Committed: return "COMMITTED";
    case CommitState::Acknowledged: return "ACKNOWLEDGED";
    case CommitState::Ambiguous: return "AMBIGUOUS";
  }
  return "UNRECOGNISED_COMMIT_STATE";
}

bool is_live(GrantState state) noexcept {
  return state == GrantState::Prepared || state == GrantState::Committed ||
         state == GrantState::Acknowledged;
}

bool is_quarantined(GrantState state) noexcept { return state == GrantState::Ambiguous; }

bool holds_capacity(GrantState state) noexcept {
  // PREPARED is deliberately excluded: a prepare is an intention, not a
  // reservation. Only a durable commit (or a quarantine holding a durable
  // commit) may count against capacity.
  return state == GrantState::Committed || state == GrantState::Acknowledged ||
         is_quarantined(state);
}

bool is_terminal(GrantState state) noexcept {
  return state == GrantState::Released || state == GrantState::Expired ||
         state == GrantState::Fenced || state == GrantState::Revoked ||
         state == GrantState::Superseded;
}

// ---------------------------------------------------------------------------
// AuthorityGrant
// ---------------------------------------------------------------------------
void AuthorityGrant::encode(ByteWriter& writer) const {
  encode_id(writer, grant_id);
  encode_id(writer, cluster_id);
  encode_counter(writer, cluster_generation);
  encode_counter(writer, epoch);
  encode_counter(writer, policy_generation);
  encode_incarnation(writer, incarnation);
  encode_id(writer, contract_id);
  encode_counter(writer, contract_generation);
  encode_id(writer, source_service);
  encode_id(writer, destination_service);
  encode_id(writer, source_member);
  encode_counter(writer, source_member_generation);
  writer.digest(source_member_digest);
  encode_id(writer, destination_member);
  encode_counter(writer, destination_member_generation);
  writer.digest(destination_member_digest);
  encode_id(writer, source_endpoint);
  encode_id(writer, destination_endpoint);
  encode_id(writer, path_id);
  encode_counter(writer, path_generation);
  encode_id(writer, resource_id);
  encode_counter(writer, reservation_generation);
  writer.u64(requested_units);
  writer.u64(capacity_units);
  writer.u32(distinct_failure_domains);
  encode_id(writer, lease_id);
  encode_counter(writer, lease_issued);
  encode_counter(writer, lease_expiry);
  encode_id(writer, attempt_id);
  encode_id(writer, source_domain);
  encode_id(writer, destination_domain);
  writer.u8(static_cast<std::uint8_t>(outcome));
  writer.u8(static_cast<std::uint8_t>(state));
  writer.u8(static_cast<std::uint8_t>(commit));
  writer.u64(prepare_sequence);
  writer.u64(commit_sequence);
  writer.u64(release_sequence);
  writer.u64(acknowledgement_sequence);
  writer.boolean(acknowledged);
  writer.boolean(degraded);
  writer.boolean(capacity_reserved);
  encode_reasons(writer, reductions);
  encode_provenance(writer, provenance);
}

bool AuthorityGrant::decode(ByteReader& reader, AuthorityGrant& out) {
  AuthorityGrant grant;
  if (!decode_id(reader, grant.grant_id)) return false;
  if (!decode_id(reader, grant.cluster_id)) return false;
  if (!decode_counter(reader, grant.cluster_generation)) return false;
  if (!decode_counter(reader, grant.epoch)) return false;
  if (!decode_counter(reader, grant.policy_generation)) return false;
  if (!decode_incarnation(reader, grant.incarnation)) return false;
  if (!decode_id(reader, grant.contract_id)) return false;
  if (!decode_counter(reader, grant.contract_generation)) return false;
  if (!decode_id(reader, grant.source_service)) return false;
  if (!decode_id(reader, grant.destination_service)) return false;
  if (!decode_id(reader, grant.source_member)) return false;
  if (!decode_counter(reader, grant.source_member_generation)) return false;
  if (!reader.digest(grant.source_member_digest)) return false;
  if (!decode_id(reader, grant.destination_member)) return false;
  if (!decode_counter(reader, grant.destination_member_generation)) return false;
  if (!reader.digest(grant.destination_member_digest)) return false;
  if (!decode_id(reader, grant.source_endpoint)) return false;
  if (!decode_id(reader, grant.destination_endpoint)) return false;
  if (!decode_id(reader, grant.path_id)) return false;
  if (!decode_counter(reader, grant.path_generation)) return false;
  if (!decode_id(reader, grant.resource_id)) return false;
  if (!decode_counter(reader, grant.reservation_generation)) return false;
  if (!reader.u64(grant.requested_units)) return false;
  if (!reader.u64(grant.capacity_units)) return false;
  if (!reader.u32(grant.distinct_failure_domains)) return false;
  if (!decode_id(reader, grant.lease_id)) return false;
  if (!decode_counter(reader, grant.lease_issued)) return false;
  if (!decode_counter(reader, grant.lease_expiry)) return false;
  if (!decode_id(reader, grant.attempt_id)) return false;
  if (!decode_id(reader, grant.source_domain)) return false;
  if (!decode_id(reader, grant.destination_domain)) return false;

  std::uint8_t outcome = 0;
  if (!reader.u8(outcome)) return false;
  if (outcome > static_cast<std::uint8_t>(AuthorityOutcome::Invalid)) {
    reader.fail(StatusCode::Corruption, "grant outcome byte out of range");
    return false;
  }
  grant.outcome = static_cast<AuthorityOutcome>(outcome);

  std::uint8_t state = 0;
  if (!reader.u8(state)) return false;
  if (state > static_cast<std::uint8_t>(GrantState::Superseded)) {
    reader.fail(StatusCode::Corruption, "grant state byte out of range");
    return false;
  }
  grant.state = static_cast<GrantState>(state);

  std::uint8_t commit = 0;
  if (!reader.u8(commit)) return false;
  if (commit > static_cast<std::uint8_t>(CommitState::Ambiguous)) {
    reader.fail(StatusCode::Corruption, "commit state byte out of range");
    return false;
  }
  grant.commit = static_cast<CommitState>(commit);

  if (!reader.u64(grant.prepare_sequence)) return false;
  if (!reader.u64(grant.commit_sequence)) return false;
  if (!reader.u64(grant.release_sequence)) return false;
  if (!reader.u64(grant.acknowledgement_sequence)) return false;
  if (!reader.boolean(grant.acknowledged)) return false;
  if (!reader.boolean(grant.degraded)) return false;
  if (!reader.boolean(grant.capacity_reserved)) return false;
  if (!decode_reasons(reader, grant.reductions)) return false;
  if (!decode_provenance(reader, grant.provenance)) return false;
  out = std::move(grant);
  return true;
}

// ---------------------------------------------------------------------------
// AttemptRecord
// ---------------------------------------------------------------------------
void AttemptRecord::encode(ByteWriter& writer) const {
  encode_id(writer, attempt_id);
  encode_id(writer, request_id);
  writer.digest(request_digest);
  encode_id(writer, grant_id);
  encode_id(writer, lease_id);
  writer.u8(static_cast<std::uint8_t>(outcome));
  writer.u16(static_cast<std::uint16_t>(primary_reason));
  encode_counter(writer, first_seen);
  encode_counter(writer, terminal_tick);
  writer.boolean(released);
  writer.boolean(cancelled);
}

bool AttemptRecord::decode(ByteReader& reader, AttemptRecord& out) {
  AttemptRecord attempt;
  if (!decode_id(reader, attempt.attempt_id)) return false;
  if (!decode_id(reader, attempt.request_id)) return false;
  if (!reader.digest(attempt.request_digest)) return false;
  if (!decode_id(reader, attempt.grant_id)) return false;
  if (!decode_id(reader, attempt.lease_id)) return false;
  std::uint8_t outcome = 0;
  if (!reader.u8(outcome)) return false;
  if (outcome > static_cast<std::uint8_t>(AuthorityOutcome::Invalid)) {
    reader.fail(StatusCode::Corruption, "attempt outcome byte out of range");
    return false;
  }
  attempt.outcome = static_cast<AuthorityOutcome>(outcome);
  std::uint16_t reason = 0;
  if (!reader.u16(reason)) return false;
  if (reason > static_cast<std::uint16_t>(ReasonCode::DegradedByRedundancyLoss)) {
    reader.fail(StatusCode::Corruption, "attempt primary reason out of range");
    return false;
  }
  attempt.primary_reason = static_cast<ReasonCode>(reason);
  if (!decode_counter(reader, attempt.first_seen)) return false;
  if (!decode_counter(reader, attempt.terminal_tick)) return false;
  if (!reader.boolean(attempt.released)) return false;
  if (!reader.boolean(attempt.cancelled)) return false;
  out = std::move(attempt);
  return true;
}

// ---------------------------------------------------------------------------
// AuthorityDecision
// ---------------------------------------------------------------------------
Digest256 AuthorityDecision::compute_digest() const {
  Bytes buffer;
  ByteWriter writer(buffer);
  encode_decision_body(writer, *this);
  return canonical_digest("cif.authority.decision.v1", buffer);
}

void AuthorityDecision::encode(ByteWriter& writer) const {
  encode_decision_body(writer, *this);
  writer.digest(decision_digest);
}

bool AuthorityDecision::decode(ByteReader& reader, AuthorityDecision& out) {
  AuthorityDecision decision;
  if (!decode_id(reader, decision.request_id)) return false;
  if (!decode_id(reader, decision.attempt_id)) return false;
  std::uint8_t outcome = 0;
  if (!reader.u8(outcome)) return false;
  if (outcome > static_cast<std::uint8_t>(AuthorityOutcome::Invalid)) {
    reader.fail(StatusCode::Corruption, "decision outcome byte out of range");
    return false;
  }
  decision.outcome = static_cast<AuthorityOutcome>(outcome);
  if (!decode_reasons(reader, decision.reasons)) return false;
  bool has_grant = false;
  if (!reader.boolean(has_grant)) return false;
  if (has_grant) {
    AuthorityGrant grant;
    if (!AuthorityGrant::decode(reader, grant)) return false;
    decision.grant = std::move(grant);
  }
  if (!decode_id(reader, decision.cluster_id)) return false;
  if (!decode_counter(reader, decision.cluster_generation)) return false;
  if (!decode_counter(reader, decision.epoch)) return false;
  if (!decode_counter(reader, decision.policy_generation)) return false;
  if (!decode_incarnation(reader, decision.incarnation)) return false;
  if (!reader.digest(decision.spec_digest)) return false;
  if (!reader.digest(decision.state_digest)) return false;
  if (!reader.u64(decision.decision_sequence)) return false;
  if (!decode_counter(reader, decision.decided_at)) return false;
  if (!reader.boolean(decision.idempotent_replay)) return false;
  if (!reader.boolean(decision.requires_reconciliation)) return false;
  if (!reader.digest(decision.decision_digest)) return false;
  out = std::move(decision);
  return true;
}

std::string AuthorityDecision::render() const { return render_decision(*this); }

void AuthorityCounters::encode(ByteWriter& writer) const {
  writer.u64(decisions);
  writer.u64(grants);
  writer.u64(leases);
  writer.u64(attempts);
  writer.u64(fences);
  writer.u64(refusals);
  writer.u64(releases);
  writer.u64(expiries);
  writer.u64(recoveries);
  writer.u64(compactions);
}

bool AuthorityCounters::decode(ByteReader& reader, AuthorityCounters& out) {
  AuthorityCounters counters;
  if (!reader.u64(counters.decisions)) return false;
  if (!reader.u64(counters.grants)) return false;
  if (!reader.u64(counters.leases)) return false;
  if (!reader.u64(counters.attempts)) return false;
  if (!reader.u64(counters.fences)) return false;
  if (!reader.u64(counters.refusals)) return false;
  if (!reader.u64(counters.releases)) return false;
  if (!reader.u64(counters.expiries)) return false;
  if (!reader.u64(counters.recoveries)) return false;
  if (!reader.u64(counters.compactions)) return false;
  out = counters;
  return true;
}

Digest256 grant_digest(const AuthorityGrant& grant) {
  Bytes buffer;
  ByteWriter writer(buffer);
  grant.encode(writer);
  return canonical_digest("cif.authority.grant.v1", buffer);
}

Digest256 attempt_digest(const AttemptRecord& attempt) {
  Bytes buffer;
  ByteWriter writer(buffer);
  attempt.encode(writer);
  return canonical_digest("cif.authority.attempt.v1", buffer);
}

}  // namespace cif
