// Independent downstream consumer of the installed CIF package.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This program is deliberately written as an ordinary third-party user of the
// installed headers and libraries: it includes <cif/...>, links cif::core and
// cif::net, builds a cluster, obtains authority over it, and verifies the same
// invariants the in-tree tests verify. If the exported package were incomplete
// this file would not compile or link.
#include <cif/authority.hpp>
#include <cif/client.hpp>
#include <cif/journal.hpp>
#include <cif/server.hpp>
#include <cif/version.hpp>

#include <filesystem>
#include <iostream>
#include <string>

namespace {

int g_failures = 0;

void check(bool condition, const char* what) {
  if (!condition) {
    std::cout << "DOWNSTREAM FAIL " << what << "\n";
    ++g_failures;
  }
}

void report(const std::string& line) { std::cout << line << "\n"; }

std::string scratch(const std::string& leaf) {
  const std::filesystem::path base = std::filesystem::temp_directory_path() / "cif-downstream";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  return (base / leaf).string();
}

cif::Member make_member(const std::string& id, const std::string& locality, const std::string& service) {
  cif::Member member;
  member.id = cif::MemberId::from_validated(id);
  member.domain = cif::MemberDomainId::from_validated("domain-a");
  member.generation = cif::MemberGeneration{1};
  member.digest = cif::sha256("member:" + id);
  member.lifecycle = cif::MemberLifecycle::Active;
  cif::LocalityPath path;
  check(cif::LocalityPath::parse(locality, path), "locality parse");
  member.locality = path;
  member.services.push_back(cif::ServiceGroupId::from_validated(service));
  cif::Resource resource;
  resource.id = cif::ResourceId::from_validated("pool");
  resource.kind = "generic";
  resource.total_units = 64;
  resource.reservation_generation = cif::ReservationGeneration{1};
  member.resources.push_back(resource);
  return member;
}

}  // namespace

int main() {
  report("downstream consumer built against " + cif::version_banner());

  cif::AuthorityCore core;
  const cif::Status initialized =
      core.initialize(cif::ClusterId::from_validated("downstream-cluster"),
                      cif::ControllerIncarnation::from_seed(7), cif::PolicyGeneration{1},
                      cif::Tick{1}, nullptr);
  check(initialized.ok(), "initialize");

  check(core.upsert_member(make_member("m-a", "dc/room-a/rack-1/pod-1", "trainers")).ok(), "member a");
  check(core.upsert_member(make_member("m-b", "dc/room-b/rack-2/pod-2", "servers")).ok(), "member b");

  cif::Path path;
  path.id = cif::PathId::from_validated("p-ab");
  path.generation = cif::PathGeneration{1};
  path.source_member = cif::MemberId::from_validated("m-a");
  path.destination_member = cif::MemberId::from_validated("m-b");
  path.capacity_units = 32;
  path.exclusive = true;
  path.state = cif::PathState::Operational;
  check(core.upsert_path(path).ok(), "path");

  cif::CommunicationContract contract;
  contract.id = cif::ContractId::from_validated("c-collective");
  contract.generation = cif::ContractGeneration{1};
  contract.source_service = cif::ServiceGroupId::from_validated("trainers");
  contract.destination_service = cif::ServiceGroupId::from_validated("servers");
  contract.min_capacity_units = 4;
  contract.min_distinct_failure_domains = 2;
  contract.failure_domain_level = 2;
  contract.require_exclusive_path = true;
  check(core.upsert_contract(contract).ok(), "contract");

  cif::AuthorityRequest request;
  request.request_id = cif::RequestId::from_validated("r-1");
  request.attempt_id = cif::AttemptId::from_validated("a-1");
  request.contract_id = contract.id;
  request.contract_generation = contract.generation;
  request.cluster_id = core.spec().cluster_id();
  request.cluster_generation = core.spec().generation();
  request.epoch = core.spec().epoch();
  request.incarnation = core.spec().incarnation();
  request.policy_generation = core.spec().policy_generation();
  request.source_member = path.source_member;
  request.destination_member = path.destination_member;
  request.path_id = path.id;
  request.path_generation = path.generation;
  request.requested_units = 8;
  request.lease_ticks = 100;
  const cif::Member* source = core.spec().find_member(path.source_member);
  const cif::Member* destination = core.spec().find_member(path.destination_member);
  check(source != nullptr && destination != nullptr, "members present");
  if (source != nullptr && destination != nullptr) {
    request.source_member_generation = source->generation;
    request.source_member_digest = source->digest;
    request.destination_member_generation = destination->generation;
    request.destination_member_digest = destination->digest;
  }

  const cif::AuthorityDecision decision = core.submit(request);
  if (decision.outcome != cif::AuthorityOutcome::Granted) {
    report("submit returned " + std::string(cif::to_string(decision.outcome)) + " (" +
           cif::to_string(decision.primary_reason()) + "): " + decision.render());
  }
  check(decision.outcome == cif::AuthorityOutcome::Granted, "granted");
  check(decision.grant.has_value(), "grant present");
  check(core.self_check().ok(), "self check");
  // The request named no resource, so the declared pool stays untouched: a grant
  // only reserves against a pool when the caller asks for one.
  check(core.reserved_units(cif::ResourceId::from_validated("pool")) == 0,
        "no resource reserved when none named");

  // Idempotent replay must not mint a second grant.
  const cif::AuthorityDecision replay = core.submit(request);
  check(replay.idempotent_replay, "replay flagged");
  check(replay.grant.has_value() && decision.grant.has_value() &&
            replay.grant->grant_id == decision.grant->grant_id,
        "same grant id on replay");

  // Durable reopen through the installed headers.
  const std::string journal_path = scratch("downstream.cifjournal");
  std::error_code error;
  std::filesystem::remove(journal_path, error);
  {
    cif::Journal journal;
    std::vector<cif::JournalEntry> entries;
    cif::RecoveryReport report;
    check(cif::Journal::scan(journal_path, entries, report).ok(), "scan empty");
    check(report.fresh, "fresh journal");
    check(journal.open(journal_path, report.valid_bytes, report.fresh, report.last_chain,
                       report.last_sequence)
              .ok(),
          "open journal");
    cif::JournalDurabilitySink sink(journal);
    cif::AuthorityCore durable;
    check(durable
              .initialize(cif::ClusterId::from_validated("downstream-durable"),
                          cif::ControllerIncarnation::from_seed(9), cif::PolicyGeneration{1},
                          cif::Tick{1}, &sink)
              .ok(),
          "durable initialize");
    check(durable.upsert_member(make_member("m-a", "dc/room/rack-1/pod-1", "trainers")).ok(),
          "durable member");
    check(journal.close().ok(), "close journal");
  }
  {
    std::vector<cif::JournalEntry> entries;
    cif::RecoveryReport report;
    check(cif::Journal::scan(journal_path, entries, report).ok(), "rescan");
    check(entries.size() >= 3, "records survived");
    cif::RecoveredState recovered;
    check(cif::replay_journal(entries, recovered).ok(), "replay");
    check(recovered.spec.member_count() == 1, "member survived reopen");
  }
  std::filesystem::remove(journal_path, error);

  // The daemon and client are part of the installed package too.
  cif::ServerOptions server_options;
  server_options.cluster_id = cif::ClusterId::from_validated("downstream-server");
  server_options.housekeeping_period_millis = 0;
  cif::AuthorityServer server(server_options);
  check(server.start().ok(), "server start");
  cif::ClientOptions client_options;
  client_options.host = "127.0.0.1";
  client_options.port = server.port();
  client_options.client = cif::ClientId::from_validated("downstream");
  cif::AuthorityClient client;
  check(client.connect(client_options).ok(), "client connect");
  check(client.server().valid, "handshake");
  cif::QueryCommand query;
  query.kind = cif::QueryKind::Verify;
  cif::QueryResult result;
  check(client.query(query, result).ok() && result.ok(), "remote verify");
  check(client.close().ok(), "client close");
  check(server.stop().ok(), "server stop");

  report(std::string("DOWNSTREAM ") + (g_failures == 0 ? "OK" : "FAILED"));
  return g_failures == 0 ? 0 : 1;
}
