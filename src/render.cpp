#include "cif/render.hpp"

#include "cif/contract.hpp"
#include "cif/grant.hpp"
#include "cif/model.hpp"
#include "cif/text.hpp"

namespace cif {
namespace {

void append_field(std::string& out, std::string_view key, std::string_view value) {
  out += "  ";
  out += key;
  out += " = ";
  out += value;
  out += "\n";
}

void append_field(std::string& out, std::string_view key, std::uint64_t value) {
  append_field(out, key, to_decimal(value));
}

[[nodiscard]] std::string quoted(std::string_view value) {
  std::string out;
  out.reserve(value.size() + 2);
  out.push_back('"');
  out += sanitise_for_display(value, limits::kMaxNoteBytes);
  out.push_back('"');
  return out;
}

}  // namespace

std::string render_reasons(const std::vector<Reason>& reasons) {
  std::string out;
  for (std::size_t i = 0; i < reasons.size(); ++i) {
    if (i != 0) {
      out += ", ";
    }
    out += to_string(reasons[i].code);
    if (!reasons[i].detail.empty()) {
      out += "(";
      out += sanitise_for_display(reasons[i].detail, limits::kMaxReasonDetailBytes);
      out += ")";
    }
  }
  if (out.empty()) {
    out = "NONE";
  }
  return out;
}

std::string render_grant(const AuthorityGrant& grant) {
  std::string out;
  out += "GRANT ";
  out += grant.grant_id.to_string();
  out += "\n";
  append_field(out, "outcome", to_string(grant.outcome));
  append_field(out, "state", to_string(grant.state));
  append_field(out, "commit", to_string(grant.commit));
  append_field(out, "acknowledged", grant.acknowledged ? "true" : "false");
  append_field(out, "degraded", grant.degraded ? "true" : "false");
  append_field(out, "cluster", grant.cluster_id.to_string());
  append_field(out, "cluster_generation", grant.cluster_generation.value());
  append_field(out, "epoch", grant.epoch.value());
  append_field(out, "policy_generation", grant.policy_generation.value());
  append_field(out, "incarnation", grant.incarnation.hex());
  append_field(out, "contract", grant.contract_id.to_string());
  append_field(out, "contract_generation", grant.contract_generation.value());
  append_field(out, "source_service", grant.source_service.to_string());
  append_field(out, "destination_service", grant.destination_service.to_string());
  append_field(out, "source_member", grant.source_member.to_string());
  append_field(out, "source_member_generation", grant.source_member_generation.value());
  append_field(out, "source_member_digest", grant.source_member_digest.hex());
  append_field(out, "source_domain", grant.source_domain.to_string());
  append_field(out, "destination_member", grant.destination_member.to_string());
  append_field(out, "destination_member_generation", grant.destination_member_generation.value());
  append_field(out, "destination_member_digest", grant.destination_member_digest.hex());
  append_field(out, "destination_domain", grant.destination_domain.to_string());
  append_field(out, "source_endpoint", grant.source_endpoint.to_string());
  append_field(out, "destination_endpoint", grant.destination_endpoint.to_string());
  append_field(out, "path", grant.path_id.to_string());
  append_field(out, "path_generation", grant.path_generation.value());
  append_field(out, "resource", grant.resource_id.to_string());
  append_field(out, "reservation_generation", grant.reservation_generation.value());
  append_field(out, "capacity_reserved", grant.capacity_reserved ? "true" : "false");
  append_field(out, "requested_units", grant.requested_units);
  append_field(out, "capacity_units", grant.capacity_units);
  append_field(out, "distinct_failure_domains", static_cast<std::uint64_t>(grant.distinct_failure_domains));
  append_field(out, "lease", grant.lease_id.to_string());
  append_field(out, "lease_issued", grant.lease_issued.value());
  append_field(out, "lease_expiry", grant.lease_expiry.value());
  append_field(out, "attempt", grant.attempt_id.to_string());
  append_field(out, "prepare_sequence", grant.prepare_sequence);
  append_field(out, "commit_sequence", grant.commit_sequence);
  append_field(out, "release_sequence", grant.release_sequence);
  append_field(out, "acknowledgement_sequence", grant.acknowledgement_sequence);
  if (!grant.reductions.empty()) {
    append_field(out, "reductions", render_reasons(grant.reductions));
  }
  append_field(out, "digest", grant_digest(grant).hex());
  return out;
}

std::string render_attempt(const AttemptRecord& attempt) {
  std::string out;
  out += "ATTEMPT ";
  out += attempt.attempt_id.to_string();
  out += "\n";
  append_field(out, "request", attempt.request_id.to_string());
  append_field(out, "request_digest", attempt.request_digest.hex());
  append_field(out, "grant", attempt.grant_id.to_string());
  append_field(out, "lease", attempt.lease_id.to_string());
  append_field(out, "outcome", to_string(attempt.outcome));
  append_field(out, "primary_reason", to_string(attempt.primary_reason));
  append_field(out, "first_seen", attempt.first_seen.value());
  append_field(out, "terminal_tick", attempt.terminal_tick.value());
  append_field(out, "released", attempt.released ? "true" : "false");
  append_field(out, "cancelled", attempt.cancelled ? "true" : "false");
  return out;
}

std::string render_decision(const AuthorityDecision& decision) {
  std::string out;
  out += "DECISION ";
  out += to_string(decision.outcome);
  out += "\n";
  append_field(out, "request", decision.request_id.to_string());
  append_field(out, "attempt", decision.attempt_id.to_string());
  append_field(out, "reasons", render_reasons(decision.reasons));
  append_field(out, "cluster", decision.cluster_id.to_string());
  append_field(out, "cluster_generation", decision.cluster_generation.value());
  append_field(out, "epoch", decision.epoch.value());
  append_field(out, "policy_generation", decision.policy_generation.value());
  append_field(out, "incarnation", decision.incarnation.hex());
  append_field(out, "decision_sequence", decision.decision_sequence);
  append_field(out, "decided_at", decision.decided_at.value());
  append_field(out, "idempotent_replay", decision.idempotent_replay ? "true" : "false");
  append_field(out, "requires_reconciliation", decision.requires_reconciliation ? "true" : "false");
  append_field(out, "spec_digest", decision.spec_digest.hex());
  append_field(out, "state_digest", decision.state_digest.hex());
  append_field(out, "decision_digest", decision.decision_digest.hex());
  if (decision.grant.has_value()) {
    out += render_grant(*decision.grant);
  }
  return out;
}

std::string render_member(const Member& member) {
  std::string out;
  out += "MEMBER ";
  out += member.id.to_string();
  out += "\n";
  append_field(out, "domain", member.domain.to_string());
  append_field(out, "generation", member.generation.value());
  append_field(out, "digest", member.digest.hex());
  append_field(out, "lifecycle", to_string(member.lifecycle));
  append_field(out, "locality", member.locality.to_string());
  append_field(out, "last_observed", member.last_observed.value());
  append_field(out, "state_digest", member_state_digest(member).hex());
  for (const Endpoint& endpoint : member.endpoints) {
    append_field(out, "endpoint", endpoint.id.to_string() + " locality=" +
                                       (endpoint.locality.empty() ? member.locality.to_string()
                                                                  : endpoint.locality.to_string()));
  }
  for (const ServiceGroupId& service : member.services) {
    append_field(out, "service", service.to_string());
  }
  for (const Resource& resource : member.resources) {
    append_field(out, "resource",
                 resource.id.to_string() + " kind=" + quoted(resource.kind) +
                     " units=" + to_decimal(resource.total_units) +
                     " reservation_generation=" + resource.reservation_generation.to_string());
  }
  return out;
}

std::string render_path(const Path& path) {
  std::string out;
  out += "PATH ";
  out += path.id.to_string();
  out += "\n";
  append_field(out, "generation", path.generation.value());
  append_field(out, "state", to_string(path.state));
  append_field(out, "source_member", path.source_member.to_string());
  append_field(out, "source_endpoint", path.source_endpoint.to_string());
  append_field(out, "destination_member", path.destination_member.to_string());
  append_field(out, "destination_endpoint", path.destination_endpoint.to_string());
  append_field(out, "capacity_units", path.capacity_units);
  append_field(out, "exclusive", path.exclusive ? "true" : "false");
  append_field(out, "declared_hops", static_cast<std::uint64_t>(path.declared_hops));
  for (const ResourceId& resource : path.resources) {
    append_field(out, "resource", resource.to_string());
  }
  return out;
}

std::string render_exclusion(const MaintenanceExclusion& exclusion) {
  std::string out;
  out += "EXCLUSION ";
  out += exclusion.id.to_string();
  out += "\n";
  append_field(out, "mode", to_string(exclusion.mode));
  append_field(out, "enabled", exclusion.enabled ? "true" : "false");
  append_field(out, "domain_prefix", exclusion.domain_prefix.to_string());
  append_field(out, "valid_from", exclusion.valid_from.value());
  append_field(out, "valid_to", exclusion.valid_to.value());
  append_field(out, "reason", quoted(exclusion.reason));
  for (const MemberId& member : exclusion.members) {
    append_field(out, "member", member.to_string());
  }
  for (const PathId& path : exclusion.paths) {
    append_field(out, "path", path.to_string());
  }
  return out;
}

std::string render_obligation(const CapacityObligation& obligation) {
  std::string out;
  out += "OBLIGATION ";
  out += obligation.id.to_string();
  out += "\n";
  append_field(out, "service", obligation.service.to_string());
  append_field(out, "min_distinct_failure_domains",
               static_cast<std::uint64_t>(obligation.min_distinct_failure_domains));
  append_field(out, "failure_domain_level", static_cast<std::uint64_t>(obligation.failure_domain_level));
  append_field(out, "min_units_per_domain", obligation.min_units_per_domain);
  append_field(out, "enabled", obligation.enabled ? "true" : "false");
  return out;
}

std::string render_contract(const CommunicationContract& contract) {
  std::string out;
  out += "CONTRACT ";
  out += contract.id.to_string();
  out += "\n";
  append_field(out, "generation", contract.generation.value());
  append_field(out, "source_service", contract.source_service.to_string());
  append_field(out, "destination_service", contract.destination_service.to_string());
  append_field(out, "min_capacity_units", contract.min_capacity_units);
  append_field(out, "max_capacity_units", contract.max_capacity_units);
  append_field(out, "min_distinct_failure_domains",
               static_cast<std::uint64_t>(contract.min_distinct_failure_domains));
  append_field(out, "failure_domain_level", static_cast<std::uint64_t>(contract.failure_domain_level));
  append_field(out, "require_exclusive_path", contract.require_exclusive_path ? "true" : "false");
  append_field(out, "maintenance_mode", to_string(contract.maintenance_mode));
  append_field(out, "allow_draining", contract.allow_draining ? "true" : "false");
  append_field(out, "allow_faulted", contract.allow_faulted ? "true" : "false");
  append_field(out, "allow_partitioned", contract.allow_partitioned ? "true" : "false");
  append_field(out, "allow_degraded", contract.allow_degraded ? "true" : "false");
  append_field(out, "enabled", contract.enabled ? "true" : "false");
  for (const std::string& capability : contract.required_capabilities) {
    append_field(out, "capability", quoted(capability));
  }
  const std::vector<std::string> unsupported = contract.unsupported_capabilities();
  for (const std::string& capability : unsupported) {
    append_field(out, "unsupported_capability", quoted(capability));
  }
  append_field(out, "digest", contract.digest().hex());
  return out;
}

std::string render_controller(const ControllerIdentity& identity) {
  std::string out;
  out += "CONTROLLER\n";
  append_field(out, "cluster", identity.cluster.to_string());
  append_field(out, "cluster_generation", identity.generation.value());
  append_field(out, "epoch", identity.epoch.value());
  append_field(out, "policy_generation", identity.policy.value());
  append_field(out, "incarnation", identity.incarnation.hex());
  return out;
}

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 8);
  for (char raw : text) {
    const unsigned char c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20u || c >= 0x7Fu) {
          out.push_back('?');
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

void JsonWriter::separate() {
  if (after_key_) {
    after_key_ = false;
    return;
  }
  if (!first_) {
    *sink_ += ",";
  }
  first_ = false;
}

void JsonWriter::begin_object() {
  separate();
  *sink_ += "{";
  first_ = true;
}

void JsonWriter::end_object() {
  *sink_ += "}";
  first_ = false;
}

void JsonWriter::begin_array() {
  separate();
  *sink_ += "[";
  first_ = true;
}

void JsonWriter::end_array() {
  *sink_ += "]";
  first_ = false;
}

void JsonWriter::key(std::string_view name) {
  separate();
  *sink_ += "\"";
  *sink_ += json_escape(name);
  *sink_ += "\":";
  after_key_ = true;
}

void JsonWriter::string_value(std::string_view value) {
  separate();
  *sink_ += "\"";
  *sink_ += json_escape(value);
  *sink_ += "\"";
}

void JsonWriter::number_value(std::uint64_t value) {
  separate();
  *sink_ += to_decimal(value);
}

void JsonWriter::bool_value(bool value) {
  separate();
  *sink_ += value ? "true" : "false";
}

void JsonWriter::raw_value(std::string_view value) {
  separate();
  *sink_ += value;
}

}  // namespace cif
