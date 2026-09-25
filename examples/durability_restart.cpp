// Cluster Interconnect Fabric (CIF) -- example: durability across a restart.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Writes authority to a real journal, closes it, reopens it in a fresh engine,
// and shows what survives, what is fenced, and what must be reconciled. The
// journal is written where the example is run from and removed at the end.
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "cif/authority.hpp"
#include "cif/journal.hpp"
#include "cif/render.hpp"

namespace {

const char* kJournal = "example-durability.cifjournal";

cif::Member make_member(const std::string& id, const std::string& locality,
                        const std::string& service) {
  cif::Member member;
  member.id = cif::MemberId::from_validated(id);
  member.domain = cif::MemberDomainId::from_validated("domain");
  member.generation = cif::MemberGeneration{1};
  member.digest = cif::sha256("member:" + id);
  member.lifecycle = cif::MemberLifecycle::Active;
  static_cast<void>(cif::LocalityPath::parse(locality, member.locality));
  member.services.push_back(cif::ServiceGroupId::from_validated(service));
  return member;
}

void seed(cif::AuthorityCore& core) {
  static_cast<void>(core.upsert_member(make_member("m-a", "dc/room1/rack1/pod1", "trainers")));
  static_cast<void>(core.upsert_member(make_member("m-b", "dc/room2/rack2/pod2", "servers")));
  cif::Path path;
  path.id = cif::PathId::from_validated("p-1");
  path.generation = cif::PathGeneration{1};
  path.source_member = cif::MemberId::from_validated("m-a");
  path.destination_member = cif::MemberId::from_validated("m-b");
  path.capacity_units = 32;
  static_cast<void>(core.upsert_path(path));
  cif::CommunicationContract contract;
  contract.id = cif::ContractId::from_validated("c-1");
  contract.generation = cif::ContractGeneration{1};
  contract.source_service = cif::ServiceGroupId::from_validated("trainers");
  contract.destination_service = cif::ServiceGroupId::from_validated("servers");
  contract.min_capacity_units = 1;
  static_cast<void>(core.upsert_contract(contract));
}

cif::AuthorityRequest request_for(const cif::AuthorityCore& core, const std::string& attempt,
                                  std::uint64_t units) {
  cif::AuthorityRequest request;
  request.request_id = cif::RequestId::from_validated("req-" + attempt);
  request.attempt_id = cif::AttemptId::from_validated(attempt);
  request.contract_id = cif::ContractId::from_validated("c-1");
  request.contract_generation = core.contracts().find(request.contract_id)->generation;
  request.cluster_id = core.spec().cluster_id();
  request.cluster_generation = core.spec().generation();
  request.epoch = core.spec().epoch();
  request.incarnation = core.spec().incarnation();
  request.policy_generation = core.spec().policy_generation();
  request.source_member = cif::MemberId::from_validated("m-a");
  request.destination_member = cif::MemberId::from_validated("m-b");
  request.path_id = cif::PathId::from_validated("p-1");
  request.path_generation = core.spec().find_path(request.path_id)->generation;
  request.requested_units = units;
  request.lease_ticks = 4096;
  request.source_member_generation = core.spec().find_member(request.source_member)->generation;
  request.source_member_digest = core.spec().find_member(request.source_member)->digest;
  request.destination_member_generation =
      core.spec().find_member(request.destination_member)->generation;
  request.destination_member_digest = core.spec().find_member(request.destination_member)->digest;
  return request;
}

}  // namespace

int main() {
  std::error_code error;
  std::filesystem::remove(kJournal, error);

  cif::Digest256 topology_before;
  std::string acknowledged_grant;
  {
    // --- first controller: write authority, then close cleanly -------------
    cif::Journal journal;
    std::vector<cif::JournalEntry> entries;
    cif::RecoveryReport report;
    static_cast<void>(cif::Journal::scan(kJournal, entries, report));
    if (!journal
             .open(kJournal, report.valid_bytes, report.fresh, report.last_chain,
                   report.last_sequence)
             .ok()) {
      std::printf("cannot open journal\n");
      return 1;
    }
    cif::JournalDurabilitySink sink(journal);
    cif::AuthorityCore core;
    static_cast<void>(core.initialize(cif::ClusterId::from_validated("example-durable"),
                                      cif::ControllerIncarnation::generate(),
                                      cif::PolicyGeneration{1}, cif::Tick{1}, &sink));
    seed(core);

    const cif::AuthorityDecision acknowledged = core.submit(request_for(core, "att-acked", 4));
    cif::AuthorityDecision second = core.submit(request_for(core, "att-unacked", 8));
    std::printf("before restart: %s (%s), %s (%s)\n",
                cif::to_string(acknowledged.outcome), cif::to_string(acknowledged.primary_reason()),
                cif::to_string(second.outcome), cif::to_string(second.primary_reason()));

    cif::AcknowledgeRequest acknowledge;
    acknowledge.request_id = cif::RequestId::from_validated("req-ack");
    acknowledge.grant_id = acknowledged.grant->grant_id;
    acknowledge.lease_id = acknowledged.grant->lease_id;
    acknowledge.attempt_id = acknowledged.grant->attempt_id;
    static_cast<void>(core.acknowledge(acknowledge));
    acknowledged_grant = acknowledged.grant->grant_id.to_string();
    topology_before = core.spec().topology_digest();
    std::printf("committed units before restart: %llu\n",
                static_cast<unsigned long long>(core.path_committed_units(
                    cif::PathId::from_validated("p-1"))));
    static_cast<void>(journal.close());
  }

  // --- second controller: recover from the very same journal --------------
  cif::Journal journal;
  std::vector<cif::JournalEntry> entries;
  cif::RecoveryReport report;
  if (!cif::Journal::scan(kJournal, entries, report).ok()) {
    std::printf("scan failed\n");
    return 1;
  }
  cif::RecoveredState recovered;
  if (!cif::replay_journal(entries, recovered).ok()) {
    std::printf("replay failed\n");
    return 1;
  }
  if (!journal
           .open(kJournal, report.valid_bytes, report.fresh, report.last_chain, report.last_sequence)
           .ok()) {
    std::printf("cannot reopen journal\n");
    return 1;
  }
  cif::JournalDurabilitySink sink(journal);
  cif::AuthorityCore core;
  const cif::Tick resume{recovered.tick.is_zero() ? 1 : recovered.tick.value() + 1};
  if (!core
           .recover(recovered.spec, recovered.contracts, std::move(recovered.grants),
                    std::move(recovered.attempts), recovered.counters, report,
                    cif::ControllerIncarnation::generate(), resume)
           .ok()) {
    std::printf("recover failed\n");
    return 1;
  }

  // core.recovery() is the report the engine actually advanced: it records how
  // many recovered records were applied.
  std::printf("\n%s", core.recovery().render().c_str());
  std::printf("topology preserved: %s\n",
              core.spec().topology_digest() == topology_before ? "yes" : "NO");
  std::printf("epoch advanced to %s\n", core.spec().epoch().to_string().c_str());
  std::printf("incarnation is now %s\n", core.spec().incarnation().hex().c_str());

  for (const cif::AuthorityGrant& grant : core.grants()) {
    std::printf("  grant %s: %s units=%llu\n", grant.grant_id.to_string().c_str(),
                cif::to_string(grant.state),
                static_cast<unsigned long long>(grant.capacity_units));
  }
  std::printf("quarantined units: %llu\n",
              static_cast<unsigned long long>(core.quarantined_units()));

  // Reconcile the ambiguous attempt. Resolve is deliberately not fenced by the
  // epoch, which is what makes the restart recoverable in one round trip.
  cif::ResolveRequest resolve;
  resolve.request_id = cif::RequestId::from_validated("req-resolve");
  resolve.attempt_id = cif::AttemptId::from_validated("att-unacked");
  const cif::AuthorityDecision resolved = core.resolve(resolve);
  std::printf("resolve(att-unacked) -> %s (%s) reconcile=%s\n",
              cif::to_string(resolved.outcome), cif::to_string(resolved.primary_reason()),
              resolved.requires_reconciliation ? "required" : "not required");

  // A request carrying the pre-restart coordinate is fenced.
  cif::AuthorityRequest stale = request_for(core, "att-stale", 4);
  stale.epoch = cif::ClusterEpoch{1};
  stale.incarnation = cif::ControllerIncarnation::from_seed(1);
  const cif::AuthorityDecision fenced = core.submit(stale);
  std::printf("stale-coordinate request -> %s (%s)\n", cif::to_string(fenced.outcome),
              cif::to_string(fenced.primary_reason()));
  std::printf("acknowledged grant %s is still present: %s\n", acknowledged_grant.c_str(),
              core.find_grant(cif::GrantId::from_validated(acknowledged_grant)) != nullptr ? "yes"
                                                                                          : "no");

  static_cast<void>(journal.close());
  std::filesystem::remove(kJournal, error);
  const cif::Status check = core.self_check();
  std::printf("self check: %s\n", check.ok() ? "ok" : check.to_string().c_str());
  return check.ok() ? 0 : 1;
}
