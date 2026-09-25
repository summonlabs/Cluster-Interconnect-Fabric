#include "cif/request.hpp"

namespace cif {
namespace {

[[nodiscard]] bool ok_identifier(const auto& id) { return !id.empty(); }

}  // namespace

Status AuthorityRequest::validate_shape() const {
  if (request_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "request id must not be empty");
  }
  if (!ok_identifier(contract_id)) {
    return Status::error(StatusCode::InvalidArgument, "request must name a contract");
  }
  if (!ok_identifier(cluster_id)) {
    return Status::error(StatusCode::InvalidArgument, "request must name a cluster");
  }
  if (!ok_identifier(source_member) || !ok_identifier(destination_member)) {
    return Status::error(StatusCode::InvalidArgument,
                         "request must name both a source and a destination member");
  }
  if (source_member == destination_member && source_endpoint == destination_endpoint &&
      !source_endpoint.empty()) {
    return Status::error(StatusCode::InvalidArgument,
                         "request source and destination are the same endpoint");
  }
  if (!ok_identifier(attempt_id)) {
    return Status::error(StatusCode::InvalidArgument,
                         "request must carry an attempt id so it can be made idempotent");
  }
  if (requested_units > limits::kMaxRequestedUnits) {
    return Status::error(StatusCode::LimitExceeded, "requested units exceed the configured bound");
  }
  if (lease_ticks > limits::kMaxLeaseTicks) {
    return Status::error(StatusCode::LimitExceeded, "lease length exceeds the configured bound");
  }
  if (renewal && (renewal_of.empty() || renewal_lease.empty())) {
    return Status::error(StatusCode::InvalidArgument,
                         "a renewal must name the grant and lease it renews");
  }
  if (!renewal && (!renewal_of.empty() || !renewal_lease.empty())) {
    return Status::error(StatusCode::InvalidArgument,
                         "a non-renewal request must not name a grant or lease to renew");
  }
  if (!is_valid_utf8(provenance.origin) || !is_valid_utf8(provenance.correlation_id)) {
    return Status::error(StatusCode::InvalidArgument, "provenance text must be valid UTF-8");
  }
  if (provenance.origin.size() > limits::kMaxIdentifierBytes ||
      provenance.correlation_id.size() > limits::kMaxIdentifierBytes) {
    return Status::error(StatusCode::LimitExceeded, "provenance text exceeds the configured bound");
  }
  return Status::success();
}

void AuthorityRequest::encode(ByteWriter& writer) const {
  encode_id(writer, request_id);
  encode_id(writer, contract_id);
  encode_counter(writer, contract_generation);
  encode_id(writer, cluster_id);
  encode_counter(writer, cluster_generation);
  encode_counter(writer, epoch);
  encode_incarnation(writer, incarnation);
  encode_counter(writer, policy_generation);
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
  writer.u64(lease_ticks);
  encode_id(writer, attempt_id);
  encode_provenance(writer, provenance);
  writer.boolean(allow_degraded);
  writer.boolean(renewal);
  encode_id(writer, renewal_of);
  encode_id(writer, renewal_lease);
}

bool AuthorityRequest::decode(ByteReader& reader, AuthorityRequest& out) {
  AuthorityRequest request;
  if (!decode_id(reader, request.request_id)) return false;
  if (!decode_id(reader, request.contract_id)) return false;
  if (!decode_counter(reader, request.contract_generation)) return false;
  if (!decode_id(reader, request.cluster_id)) return false;
  if (!decode_counter(reader, request.cluster_generation)) return false;
  if (!decode_counter(reader, request.epoch)) return false;
  if (!decode_incarnation(reader, request.incarnation)) return false;
  if (!decode_counter(reader, request.policy_generation)) return false;
  if (!decode_id(reader, request.source_member)) return false;
  if (!decode_counter(reader, request.source_member_generation)) return false;
  if (!reader.digest(request.source_member_digest)) return false;
  if (!decode_id(reader, request.destination_member)) return false;
  if (!decode_counter(reader, request.destination_member_generation)) return false;
  if (!reader.digest(request.destination_member_digest)) return false;
  if (!decode_id(reader, request.source_endpoint)) return false;
  if (!decode_id(reader, request.destination_endpoint)) return false;
  if (!decode_id(reader, request.path_id)) return false;
  if (!decode_counter(reader, request.path_generation)) return false;
  if (!decode_id(reader, request.resource_id)) return false;
  if (!decode_counter(reader, request.reservation_generation)) return false;
  if (!reader.u64(request.requested_units)) return false;
  if (!reader.u64(request.lease_ticks)) return false;
  if (!decode_id(reader, request.attempt_id)) return false;
  if (!decode_provenance(reader, request.provenance)) return false;
  if (!reader.boolean(request.allow_degraded)) return false;
  if (!reader.boolean(request.renewal)) return false;
  if (!decode_id(reader, request.renewal_of)) return false;
  if (!decode_id(reader, request.renewal_lease)) return false;
  out = std::move(request);
  return true;
}

Digest256 AuthorityRequest::digest() const {
  Bytes buffer;
  ByteWriter writer(buffer);
  encode(writer);
  return canonical_digest("cif.authority.request.v1", buffer);
}

Status ReleaseRequest::validate_shape() const {
  if (request_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "request id must not be empty");
  }
  if (grant_id.empty() && attempt_id.empty()) {
    return Status::error(StatusCode::InvalidArgument,
                         "release must name a grant or an attempt to identify its target");
  }
  return Status::success();
}

void ReleaseRequest::encode(ByteWriter& writer) const {
  encode_id(writer, request_id);
  encode_id(writer, grant_id);
  encode_id(writer, attempt_id);
  encode_id(writer, lease_id);
  encode_id(writer, cluster_id);
  encode_counter(writer, cluster_generation);
  encode_counter(writer, epoch);
  encode_incarnation(writer, incarnation);
  encode_provenance(writer, provenance);
  writer.boolean(administrative);
}

bool ReleaseRequest::decode(ByteReader& reader, ReleaseRequest& out) {
  ReleaseRequest request;
  if (!decode_id(reader, request.request_id)) return false;
  if (!decode_id(reader, request.grant_id)) return false;
  if (!decode_id(reader, request.attempt_id)) return false;
  if (!decode_id(reader, request.lease_id)) return false;
  if (!decode_id(reader, request.cluster_id)) return false;
  if (!decode_counter(reader, request.cluster_generation)) return false;
  if (!decode_counter(reader, request.epoch)) return false;
  if (!decode_incarnation(reader, request.incarnation)) return false;
  if (!decode_provenance(reader, request.provenance)) return false;
  if (!reader.boolean(request.administrative)) return false;
  out = std::move(request);
  return true;
}

Status ResolveRequest::validate_shape() const {
  if (request_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "request id must not be empty");
  }
  if (attempt_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "resolve must name the attempt to resolve");
  }
  return Status::success();
}

void ResolveRequest::encode(ByteWriter& writer) const {
  encode_id(writer, request_id);
  encode_id(writer, attempt_id);
  encode_id(writer, cluster_id);
  encode_counter(writer, cluster_generation);
  encode_counter(writer, epoch);
  encode_incarnation(writer, incarnation);
  encode_provenance(writer, provenance);
}

bool ResolveRequest::decode(ByteReader& reader, ResolveRequest& out) {
  ResolveRequest request;
  if (!decode_id(reader, request.request_id)) return false;
  if (!decode_id(reader, request.attempt_id)) return false;
  if (!decode_id(reader, request.cluster_id)) return false;
  if (!decode_counter(reader, request.cluster_generation)) return false;
  if (!decode_counter(reader, request.epoch)) return false;
  if (!decode_incarnation(reader, request.incarnation)) return false;
  if (!decode_provenance(reader, request.provenance)) return false;
  out = std::move(request);
  return true;
}

Status AcknowledgeRequest::validate_shape() const {
  if (request_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "request id must not be empty");
  }
  if (grant_id.empty() || lease_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "acknowledgement must name a grant and its lease");
  }
  return Status::success();
}

void AcknowledgeRequest::encode(ByteWriter& writer) const {
  encode_id(writer, request_id);
  encode_id(writer, grant_id);
  encode_id(writer, lease_id);
  encode_id(writer, attempt_id);
  encode_counter(writer, cluster_generation);
  encode_counter(writer, epoch);
  encode_incarnation(writer, incarnation);
  encode_provenance(writer, provenance);
}

bool AcknowledgeRequest::decode(ByteReader& reader, AcknowledgeRequest& out) {
  AcknowledgeRequest request;
  if (!decode_id(reader, request.request_id)) return false;
  if (!decode_id(reader, request.grant_id)) return false;
  if (!decode_id(reader, request.lease_id)) return false;
  if (!decode_id(reader, request.attempt_id)) return false;
  if (!decode_counter(reader, request.cluster_generation)) return false;
  if (!decode_counter(reader, request.epoch)) return false;
  if (!decode_incarnation(reader, request.incarnation)) return false;
  if (!decode_provenance(reader, request.provenance)) return false;
  out = std::move(request);
  return true;
}

Status CancelRequest::validate_shape() const {
  if (request_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "request id must not be empty");
  }
  if (attempt_id.empty() && grant_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "cancel must name an attempt or a grant");
  }
  if (!is_valid_utf8(reason)) {
    return Status::error(StatusCode::InvalidArgument, "cancel reason must be valid UTF-8");
  }
  if (reason.size() > limits::kMaxNoteBytes) {
    return Status::error(StatusCode::LimitExceeded, "cancel reason exceeds the configured bound");
  }
  return Status::success();
}

void CancelRequest::encode(ByteWriter& writer) const {
  encode_id(writer, request_id);
  encode_id(writer, attempt_id);
  encode_id(writer, grant_id);
  encode_counter(writer, cluster_generation);
  encode_counter(writer, epoch);
  encode_incarnation(writer, incarnation);
  writer.text(reason);
  encode_provenance(writer, provenance);
}

bool CancelRequest::decode(ByteReader& reader, CancelRequest& out) {
  CancelRequest request;
  if (!decode_id(reader, request.request_id)) return false;
  if (!decode_id(reader, request.attempt_id)) return false;
  if (!decode_id(reader, request.grant_id)) return false;
  if (!decode_counter(reader, request.cluster_generation)) return false;
  if (!decode_counter(reader, request.epoch)) return false;
  if (!decode_incarnation(reader, request.incarnation)) return false;
  if (!reader.text(request.reason, limits::kMaxNoteBytes)) return false;
  if (!decode_provenance(reader, request.provenance)) return false;
  out = std::move(request);
  return true;
}

}  // namespace cif
