// Cluster Interconnect Fabric (CIF) -- example: an authority walkthrough.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Declares a small cluster, obtains authority over one relationship, and shows
// exactly what the engine says when it refuses, degrades or fences. Every value
// printed here is derived from the engine's own output.
#include <cstdio>
#include <string>

#include "cif/authority.hpp"
#include "cif/render.hpp"

namespace {

cif::Member make_member(const std::string& id, const std::string& domain, const std::string& locality,
                        const std::string& service) {
  cif::Member member;
  member.id = cif::MemberId::from_validated(id);
  member.domain = cif::MemberDomainId::from_validated(domain);
  member.generation = cif::MemberGeneration{1};
  member.digest = cif::sha256("member:" + id);
  member.lifecycle = cif::MemberLifecycle::Active;
  static_cast<void>(cif::LocalityPath::parse(locality, member.locality));
  member.services.push_back(cif::ServiceGroupId::from_validated(service));
  return member;
}

cif::AuthorityRequest make_request(const cif::AuthorityCore& core, const cif::ContractId& contract,
                                   const cif::MemberId& source_id,
                                   const cif::MemberId& destination_id, const cif::PathId& path,
                                   const std::string& attempt, std::uint64_t units,
                                   bool allow_degraded) {
  cif::AuthorityRequest request;
  request.request_id = cif::RequestId::from_validated("req-" + attempt);
  request.attempt_id = cif::AttemptId::from_validated(attempt);
  request.contract_id = contract;
  request.contract_generation = core.contracts().find(contract)->generation;
  request.cluster_id = core.spec().cluster_id();
  request.cluster_generation = core.spec().generation();
  request.epoch = core.spec().epoch();
  request.incarnation = core.spec().incarnation();
  request.policy_generation = core.spec().policy_generation();
  request.source_member = source_id;
  request.destination_member = destination_id;
  request.path_id = path;
  request.path_generation = core.spec().find_path(path)->generation;
  request.requested_units = units;
  request.lease_ticks = 256;
  request.allow_degraded = allow_degraded;
  const cif::Member* source = core.spec().find_member(source_id);
  const cif::Member* destination = core.spec().find_member(destination_id);
  request.source_member_generation = source->generation;
  request.source_member_digest = source->digest;
  request.destination_member_generation = destination->generation;
  request.destination_member_digest = destination->digest;
  request.provenance.client = cif::ClientId::from_validated("example");
  request.provenance.origin = "authority_walkthrough";
  return request;
}

void show(const char* label, const cif::AuthorityDecision& decision) {
  std::printf("--- %s\n", label);
  std::printf("    outcome  : %s\n", cif::to_string(decision.outcome));
  std::printf("    reason   : %s\n", cif::to_string(decision.primary_reason()));
  if (decision.grant.has_value()) {
    std::printf("    grant    : %s state=%s units=%llu path=%s path-gen=%s\n",
                decision.grant->grant_id.to_string().c_str(),
                cif::to_string(decision.grant->state), static_cast<unsigned long long>(decision.grant->capacity_units),
                decision.grant->path_id.to_string().c_str(),
                decision.grant->path_generation.to_string().c_str());
  }
  std::printf("    digest   : %s\n", decision.decision_digest.hex().c_str());
}

}  // namespace

int main() {
  cif::AuthorityCore core;
  if (!core.initialize(cif::ClusterId::from_validated("example-cluster"),
                       cif::ControllerIncarnation::generate(), cif::PolicyGeneration{1},
                       cif::Tick{1}, nullptr)
           .ok()) {
    std::printf("initialize failed\n");
    return 1;
  }

  const cif::MemberId source_id = cif::MemberId::from_validated("trainer-0");
  const cif::MemberId destination_id = cif::MemberId::from_validated("server-0");
  const cif::PathId path_id = cif::PathId::from_validated("path-0");
  const cif::ContractId contract_id = cif::ContractId::from_validated("collective");

  static_cast<void>(core.upsert_member(
      make_member("trainer-0", "rack-domain-1", "dc/room-a/rack-1/pod-1", "trainers")));
  static_cast<void>(core.upsert_member(
      make_member("server-0", "rack-domain-2", "dc/room-b/rack-2/pod-2", "servers")));

  cif::Path path;
  path.id = path_id;
  path.generation = cif::PathGeneration{1};
  path.source_member = source_id;
  path.destination_member = destination_id;
  path.capacity_units = 16;
  path.exclusive = true;
  static_cast<void>(core.upsert_path(path));

  cif::CommunicationContract contract;
  contract.id = contract_id;
  contract.generation = cif::ContractGeneration{1};
  contract.source_service = cif::ServiceGroupId::from_validated("trainers");
  contract.destination_service = cif::ServiceGroupId::from_validated("servers");
  contract.min_capacity_units = 4;
  contract.min_distinct_failure_domains = 2;
  contract.failure_domain_level = 2;
  static_cast<void>(core.upsert_contract(contract));

  std::printf("controller:\n%s", cif::render_controller(core.controller_identity()).c_str());
  std::printf("topology digest : %s\n", core.spec().topology_digest().hex().c_str());
  std::printf("state digest    : %s\n\n", core.state_digest().hex().c_str());

  // 1. Eligibility is not authority: satisfying the contract is only the
  //    precondition for asking.
  show("first request",
       core.submit(make_request(core, contract_id, source_id, destination_id, path_id, "att-1", 8,
                                false)));

  // 2. Reusing the attempt id returns the recorded answer, not a second grant.
  show("same attempt again",
       core.submit(make_request(core, contract_id, source_id, destination_id, path_id, "att-1", 8,
                                false)));

  // 3. The path is exclusive, so a competing attempt is told it lost.
  show("competing attempt",
       core.submit(make_request(core, contract_id, source_id, destination_id, path_id, "att-2", 8,
                                false)));

  // 4. A member that is replaced invalidates the grant that named it.
  cif::Member replacement = *core.spec().find_member(destination_id);
  replacement.generation = cif::MemberGeneration{2};
  replacement.digest = cif::sha256("member:server-0:v2");
  static_cast<void>(core.upsert_member(replacement));
  std::printf("--- member server-0 replaced at generation 2\n");
  for (const cif::AuthorityGrant& grant : core.grants()) {
    std::printf("    grant %s is now %s (%s)\n", grant.grant_id.to_string().c_str(),
                cif::to_string(grant.state),
                grant.reductions.empty() ? "no recorded cause"
                                         : cif::to_string(grant.reductions.front().code));
  }
  std::printf("    committed units on path-0: %llu\n\n",
              static_cast<unsigned long long>(core.path_committed_units(path_id)));

  // 5. A request that claims the old member generation is fenced.
  cif::AuthorityRequest stale = make_request(core, contract_id, source_id, destination_id, path_id,
                                             "att-3", 8, false);
  stale.destination_member_generation = cif::MemberGeneration{1};
  stale.destination_member_digest = cif::sha256("member:server-0");
  show("stale member generation", core.submit(stale));

  // 6. Invariants hold, and the engine can prove it.
  const cif::Status check = core.self_check();
  std::printf("self check: %s\n", check.ok() ? "ok" : check.to_string().c_str());
  return check.ok() ? 0 : 1;
}
