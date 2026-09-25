// Cluster Interconnect Fabric (CIF) -- completed-work benchmark: transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Measures real loopback TCP round trips through the real frame codec and the
// real daemon. This says nothing about any physical fabric, and is not claimed
// to.
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "cif/client.hpp"
#include "cif/platform.hpp"
#include "cif/version.hpp"
#include "cif/server.hpp"

namespace {

std::string rate(std::uint64_t work, std::uint64_t nanos) {
  if (nanos == 0) {
    return "n/a";
  }
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%.0f", static_cast<double>(work) * 1.0e9 /
                                                   static_cast<double>(nanos));
  return buffer;
}

}  // namespace

int main() {
  cif::ServerOptions options;
  options.cluster_id = cif::ClusterId::from_validated("benchmark-transport");
  options.bind_host = "127.0.0.1";
  options.port = 0;
  options.housekeeping_period_millis = 0;
  cif::AuthorityServer server(options);
  if (!server.start().ok()) {
    std::printf("server start failed\n");
    return 1;
  }

  cif::ClientOptions client_options;
  client_options.host = "127.0.0.1";
  client_options.port = server.port();
  client_options.timeout_millis = 5000;

  std::printf("cif %s -- transport benchmark over loopback TCP (127.0.0.1:%u)\n",
              cif::version_string(), server.port());

  // Sequential round trips on one connection.
  {
    cif::AuthorityClient client;
    if (!client.connect(client_options).ok()) {
      std::printf("connect failed\n");
      return 1;
    }
    constexpr std::size_t kRoundTrips = 20000;
    for (std::size_t i = 0; i < 200; ++i) {
      static_cast<void>(client.ping());
    }
    const std::uint64_t start = cif::platform::monotonic_nanos();
    for (std::size_t i = 0; i < kRoundTrips; ++i) {
      if (!client.ping().ok()) {
        std::printf("ping failed\n");
        return 1;
      }
    }
    const std::uint64_t nanos = cif::platform::monotonic_nanos() - start;
    std::printf("sequential ping round trips : %zu in %.3f ms -> %.2f us each, %s/s\n", kRoundTrips,
                static_cast<double>(nanos) / 1.0e6,
                static_cast<double>(nanos) / 1000.0 / static_cast<double>(kRoundTrips),
                rate(kRoundTrips, nanos).c_str());
    static_cast<void>(client.close());
  }

  // Structured decisions over the wire, with a real cluster behind them.
  {
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
    static_cast<void>(server.apply(command, admin_result));
    member.id = cif::MemberId::from_validated("m-b");
    member.digest = cif::sha256("member:b");
    static_cast<void>(cif::LocalityPath::parse("dc/room2/rack2/pod2", member.locality));
    member.services.clear();
    member.services.push_back(cif::ServiceGroupId::from_validated("servers"));
    command.member = member;
    static_cast<void>(server.apply(command, admin_result));
    cif::Path path;
    path.id = cif::PathId::from_validated("p-1");
    path.generation = cif::PathGeneration{1};
    path.source_member = cif::MemberId::from_validated("m-a");
    path.destination_member = cif::MemberId::from_validated("m-b");
    path.capacity_units = 1u << 20;
    command.kind = cif::AdminKind::UpsertPath;
    command.path = path;
    static_cast<void>(server.apply(command, admin_result));
    cif::CommunicationContract contract;
    contract.id = cif::ContractId::from_validated("c-1");
    contract.generation = cif::ContractGeneration{1};
    contract.source_service = cif::ServiceGroupId::from_validated("trainers");
    contract.destination_service = cif::ServiceGroupId::from_validated("servers");
    contract.min_capacity_units = 1;
    command.kind = cif::AdminKind::UpsertContract;
    command.contract = contract;
    static_cast<void>(server.apply(command, admin_result));

    cif::AuthorityClient client;
    if (!client.connect(client_options).ok()) {
      return 1;
    }
    constexpr std::size_t kDecisions = 10000;
    const std::uint64_t start = cif::platform::monotonic_nanos();
    std::size_t granted = 0;
    for (std::size_t i = 0; i < kDecisions; ++i) {
      cif::AuthorityRequest request;
      const std::string attempt = "att-" + cif::to_decimal(i);
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
      request.requested_units = 1;
      request.lease_ticks = 1u << 20;
      request.source_member_generation = cif::MemberGeneration{1};
      request.source_member_digest = cif::sha256("member:a");
      request.destination_member_generation = cif::MemberGeneration{1};
      request.destination_member_digest = cif::sha256("member:b");
      cif::AuthorityDecision decision;
      if (!client.submit(request, decision).ok()) {
        std::printf("submit failed at %zu\n", i);
        return 1;
      }
      if (cif::is_authoritative(decision.outcome)) {
        ++granted;
      }
    }
    const std::uint64_t nanos = cif::platform::monotonic_nanos() - start;
    std::printf("wire decisions (one client)  : %zu in %.3f ms -> %.2f us each, %s/s (%zu granted)\n",
                kDecisions, static_cast<double>(nanos) / 1.0e6,
                static_cast<double>(nanos) / 1000.0 / static_cast<double>(kDecisions),
                rate(kDecisions, nanos).c_str(), granted);
    static_cast<void>(client.close());
  }

  // Independent connections in parallel, each with its own socket and thread.
  {
    constexpr int kThreads = 8;
    constexpr std::size_t kPerThread = 2000;
    std::vector<std::thread> threads;
    std::vector<std::uint64_t> completed(kThreads, 0);
    const std::uint64_t start = cif::platform::monotonic_nanos();
    for (int t = 0; t < kThreads; ++t) {
      threads.emplace_back([&, t] {
        cif::AuthorityClient client;
        cif::ClientOptions thread_options = client_options;
        thread_options.client = cif::ClientId::from_validated("bench-" + cif::to_decimal(t));
        if (!client.connect(thread_options).ok()) {
          return;
        }
        for (std::size_t i = 0; i < kPerThread; ++i) {
          if (!client.ping().ok()) {
            return;
          }
          ++completed[static_cast<std::size_t>(t)];
        }
        static_cast<void>(client.close());
      });
    }
    for (std::thread& thread : threads) {
      thread.join();
    }
    const std::uint64_t nanos = cif::platform::monotonic_nanos() - start;
    std::uint64_t total = 0;
    for (std::uint64_t value : completed) {
      total += value;
    }
    std::printf("parallel ping (%d connections) : %llu in %.3f ms -> %s/s\n", kThreads,
                static_cast<unsigned long long>(total), static_cast<double>(nanos) / 1.0e6,
                rate(total, nanos).c_str());
  }

  const cif::Status check = server.stop();
  std::printf("server stopped: %s\n", check.ok() ? "ok" : check.to_string().c_str());
  return check.ok() ? 0 : 1;
}
