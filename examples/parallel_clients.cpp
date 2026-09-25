// Cluster Interconnect Fabric (CIF) -- example: many clients, one authority.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Hosts a daemon inside this process, points several independent client
// connections at it over loopback TCP, and shows that competing relationships
// are serialised and that capacity closes exactly. The daemon is real: it runs
// its own threads and speaks the real wire protocol.
#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "cif/client.hpp"
#include "cif/server.hpp"

namespace {

constexpr int kClients = 12;
constexpr std::uint64_t kUnits = 8;

void require(bool condition, const char* what, int& failures) {
  if (!condition) {
    std::printf("FAILED: %s\n", what);
    ++failures;
  }
}

}  // namespace

int main() {
  int failures = 0;

  cif::ServerOptions options;
  options.cluster_id = cif::ClusterId::from_validated("example-parallel");
  options.bind_host = "127.0.0.1";
  options.port = 0;
  options.housekeeping_period_millis = 0;

  cif::AuthorityServer server(options);
  require(server.start().ok(), "server start", failures);

  // Seed through the reducer, which is the supported in-process control path.
  cif::AdminCommand command;
  command.kind = cif::AdminKind::UpsertMember;
  cif::Member member;
  member.id = cif::MemberId::from_validated("m-a");
  member.domain = cif::MemberDomainId::from_validated("d-1");
  member.generation = cif::MemberGeneration{1};
  member.digest = cif::sha256("member:a");
  member.lifecycle = cif::MemberLifecycle::Active;
  static_cast<void>(cif::LocalityPath::parse("dc/room1/rack1/pod1", member.locality));
  member.services.push_back(cif::ServiceGroupId::from_validated("trainers"));
  command.member = member;
  cif::AdminResult admin_result;
  require(server.apply(command, admin_result).ok() && admin_result.ok(), "seed member a", failures);

  member.id = cif::MemberId::from_validated("m-b");
  member.domain = cif::MemberDomainId::from_validated("d-2");
  member.digest = cif::sha256("member:b");
  static_cast<void>(cif::LocalityPath::parse("dc/room2/rack2/pod2", member.locality));
  member.services.clear();
  member.services.push_back(cif::ServiceGroupId::from_validated("servers"));
  command.member = member;
  require(server.apply(command, admin_result).ok() && admin_result.ok(), "seed member b", failures);

  cif::Path path;
  path.id = cif::PathId::from_validated("p-1");
  path.generation = cif::PathGeneration{1};
  path.source_member = cif::MemberId::from_validated("m-a");
  path.destination_member = cif::MemberId::from_validated("m-b");
  path.capacity_units = kClients * kUnits;
  path.exclusive = false;
  command.kind = cif::AdminKind::UpsertPath;
  command.path = path;
  require(server.apply(command, admin_result).ok() && admin_result.ok(), "seed path", failures);

  cif::CommunicationContract contract;
  contract.id = cif::ContractId::from_validated("c-1");
  contract.generation = cif::ContractGeneration{1};
  contract.source_service = cif::ServiceGroupId::from_validated("trainers");
  contract.destination_service = cif::ServiceGroupId::from_validated("servers");
  contract.min_capacity_units = kUnits;
  command.kind = cif::AdminKind::UpsertContract;
  command.contract = contract;
  require(server.apply(command, admin_result).ok() && admin_result.ok(), "seed contract", failures);

  std::printf("daemon listening on 127.0.0.1:%u with path capacity %llu\n", server.port(),
              static_cast<unsigned long long>(path.capacity_units));

  std::vector<std::thread> workers;
  std::vector<cif::AuthorityOutcome> outcomes(kClients, cif::AuthorityOutcome::Invalid);
  std::vector<cif::GrantId> grants(kClients);
  std::vector<cif::LeaseId> leases(kClients);
  std::atomic<int> connect_failures{0};

  for (int i = 0; i < kClients; ++i) {
    workers.emplace_back([&, i] {
      cif::AuthorityClient client;
      cif::ClientOptions client_options;
      client_options.host = "127.0.0.1";
      client_options.port = server.port();
      client_options.timeout_millis = 5000;
      client_options.client = cif::ClientId::from_validated("worker-" + std::to_string(i));
      if (!client.connect(client_options).ok()) {
        ++connect_failures;
        return;
      }
      cif::AuthorityRequest request;
      const std::string attempt = "att-" + std::to_string(i);
      request.request_id = cif::RequestId::from_validated("req-" + attempt);
      request.attempt_id = cif::AttemptId::from_validated(attempt);
      request.contract_id = contract.id;
      request.contract_generation = contract.generation;
      request.cluster_id = client.server().cluster_id;
      request.cluster_generation = client.server().generation;
      request.epoch = client.server().epoch;
      request.incarnation = client.server().incarnation;
      request.policy_generation = client.server().policy;
      request.source_member = path.source_member;
      request.destination_member = path.destination_member;
      request.path_id = path.id;
      request.path_generation = path.generation;
      request.requested_units = kUnits;
      request.lease_ticks = 4096;
      request.allow_degraded = false;
      request.source_member_generation = cif::MemberGeneration{1};
      request.source_member_digest = cif::sha256("member:a");
      request.destination_member_generation = cif::MemberGeneration{1};
      request.destination_member_digest = cif::sha256("member:b");

      cif::AuthorityDecision decision;
      if (!client.submit(request, decision).ok()) {
        ++connect_failures;
        return;
      }
      outcomes[static_cast<std::size_t>(i)] = decision.outcome;
      if (decision.grant.has_value()) {
        grants[static_cast<std::size_t>(i)] = decision.grant->grant_id;
        leases[static_cast<std::size_t>(i)] = decision.grant->lease_id;
      }
      static_cast<void>(client.close());
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  require(connect_failures.load() == 0, "every client connected and completed", failures);

  std::size_t granted = 0;
  std::uint64_t granted_units = 0;
  for (int i = 0; i < kClients; ++i) {
    const cif::AuthorityOutcome outcome = outcomes[static_cast<std::size_t>(i)];
    std::printf("  client %2d: %s\n", i, cif::to_string(outcome));
    if (outcome == cif::AuthorityOutcome::Granted) {
      ++granted;
      granted_units += kUnits;
    }
  }
  std::printf("%zu of %d clients were authorised, %llu units of %llu committed\n", granted, kClients,
              static_cast<unsigned long long>(granted_units),
              static_cast<unsigned long long>(path.capacity_units));
  require(granted_units <= path.capacity_units, "capacity was never over-committed", failures);

  // Release every grant concurrently, then re-use the capacity.
  std::vector<std::thread> releasers;
  for (int i = 0; i < kClients; ++i) {
    if (outcomes[static_cast<std::size_t>(i)] != cif::AuthorityOutcome::Granted) {
      continue;
    }
    releasers.emplace_back([&, i] {
      cif::AuthorityClient client;
      cif::ClientOptions client_options;
      client_options.host = "127.0.0.1";
      client_options.port = server.port();
      client_options.timeout_millis = 5000;
      if (!client.connect(client_options).ok()) {
        ++connect_failures;
        return;
      }
      cif::ReleaseRequest release;
      release.request_id = cif::RequestId::from_validated("req-rel-" + std::to_string(i));
      release.grant_id = grants[static_cast<std::size_t>(i)];
      release.lease_id = leases[static_cast<std::size_t>(i)];
      cif::AuthorityDecision decision;
      if (!client.release(release, decision).ok() ||
          decision.outcome != cif::AuthorityOutcome::Granted) {
        ++connect_failures;
      }
      static_cast<void>(client.close());
    });
  }
  for (std::thread& releaser : releasers) {
    releaser.join();
  }
  require(connect_failures.load() == 0, "every release succeeded", failures);

  require(server.stop().ok(), "server stop", failures);
  require(server.core().path_committed_units(path.id) == 0,
          "capacity closed exactly after every release", failures);
  require(server.core().self_check().ok(), "invariants hold", failures);

  std::printf("final: committed=%llu granted-clients=%zu\n",
              static_cast<unsigned long long>(server.core().path_committed_units(path.id)), granted);
  std::printf(failures == 0 ? "example OK\n" : "example FAILED\n");
  return failures == 0 ? 0 : 1;
}
