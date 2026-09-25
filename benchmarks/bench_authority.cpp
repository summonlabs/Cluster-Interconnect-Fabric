// Cluster Interconnect Fabric (CIF) -- completed-work benchmark: authority.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Measures completed work, not promises: real decisions against a real cluster
// of the stated size, with the invariants checked afterwards. Every number
// printed is measured on the machine that runs it; nothing is estimated.
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "cif/authority.hpp"
#include "cif/platform.hpp"
#include "cif/version.hpp"
#include "cif/rng.hpp"

namespace {

std::string decimal(std::uint64_t value) { return cif::to_decimal(value); }

std::string rate(std::uint64_t work, std::uint64_t nanos) {
  if (nanos == 0) {
    return "n/a";
  }
  const double per_second = static_cast<double>(work) * 1.0e9 / static_cast<double>(nanos);
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%.0f", per_second);
  return buffer;
}

struct Cluster {
  cif::AuthorityCore core;
  std::vector<cif::MemberId> members;
  std::vector<cif::PathId> paths;
  cif::ContractId contract = cif::ContractId::from_validated("bench-contract");
  std::uint64_t capacity_per_path = 0;
};

/// Builds a cluster with 'member_count' members and 'path_count' paths, with the
/// fan-out a real rack/pod composition would have.
bool build(Cluster& cluster, std::size_t member_count, std::size_t path_count,
           std::uint64_t capacity_per_path, bool decision_state_digest) {
  // Options are a property of the engine, not of initialize(); they must be
  // installed before the first mutation.
  cif::AuthorityOptions engine_options;
  engine_options.decision_state_digest = decision_state_digest;
  cluster.core.reset(engine_options);
  if (!cluster.core
           .initialize(cif::ClusterId::from_validated("benchmark-cluster"),
                       cif::ControllerIncarnation::from_seed(1), cif::PolicyGeneration{1},
                       cif::Tick{1}, nullptr)
           .ok()) {
    return false;
  }
  cluster.capacity_per_path = capacity_per_path;
  const std::size_t services = 4;
  for (std::size_t i = 0; i < member_count; ++i) {
    cif::Member member;
    member.id = cif::MemberId::from_validated("m-" + decimal(i));
    member.domain = cif::MemberDomainId::from_validated("rack-domain-" + decimal(i % 8));
    member.generation = cif::MemberGeneration{1};
    member.digest = cif::sha256("member:" + decimal(i));
    member.lifecycle = cif::MemberLifecycle::Active;
    if (!cif::LocalityPath::parse("dc/room" + decimal(i % 16) + "/rack" + decimal(i % 64) + "/pod" +
                                      decimal(i),
                                  member.locality)) {
      return false;
    }
    member.services.push_back(
        cif::ServiceGroupId::from_validated("service-" + decimal(i % services)));
    cif::Endpoint endpoint;
    endpoint.id = cif::EndpointId::from_validated("ep-" + decimal(i));
    endpoint.service_groups.push_back(
        cif::ServiceGroupId::from_validated("service-" + decimal(i % services)));
    member.endpoints.push_back(endpoint);
    if (!cluster.core.upsert_member(member).ok()) {
      return false;
    }
    cluster.members.push_back(member.id);
  }
  for (std::size_t i = 0; i < path_count; ++i) {
    cif::Path path;
    path.id = cif::PathId::from_validated("p-" + decimal(i));
    path.generation = cif::PathGeneration{1};
    path.source_member = cluster.members[i % cluster.members.size()];
    path.destination_member = cluster.members[(i * 7 + 1) % cluster.members.size()];
    path.capacity_units = capacity_per_path;
    path.exclusive = false;
    if (!cluster.core.upsert_path(path).ok()) {
      return false;
    }
    cluster.paths.push_back(path.id);
  }
  cif::CommunicationContract contract;
  contract.id = cluster.contract;
  contract.generation = cif::ContractGeneration{1};
  contract.source_service = cif::ServiceGroupId::from_validated("service-0");
  contract.destination_service = cif::ServiceGroupId::from_validated("service-1");
  contract.min_capacity_units = 1;
  contract.maintenance_mode = cif::MaintenanceMode::Degrade;
  return cluster.core.upsert_contract(contract).ok();
}

cif::AuthorityRequest make_request(const Cluster& cluster, std::size_t index,
                                   const std::string& attempt, std::uint64_t units) {
  const cif::PathId path_id = cluster.paths[index % cluster.paths.size()];
  const cif::Path* path = cluster.core.spec().find_path(path_id);
  cif::AuthorityRequest request;
  request.request_id = cif::RequestId::from_validated("req-" + attempt);
  request.attempt_id = cif::AttemptId::from_validated(attempt);
  request.contract_id = cluster.contract;
  request.contract_generation =
      cluster.core.contracts().find(cluster.contract)->generation;
  request.cluster_id = cluster.core.spec().cluster_id();
  request.cluster_generation = cluster.core.spec().generation();
  request.epoch = cluster.core.spec().epoch();
  request.incarnation = cluster.core.spec().incarnation();
  request.policy_generation = cluster.core.spec().policy_generation();
  request.source_member = path->source_member;
  request.destination_member = path->destination_member;
  request.path_id = path_id;
  request.path_generation = path->generation;
  request.requested_units = units;
  request.lease_ticks = 1u << 20;
  request.allow_degraded = false;
  const cif::Member* source = cluster.core.spec().find_member(request.source_member);
  const cif::Member* destination = cluster.core.spec().find_member(request.destination_member);
  request.source_member_generation = source->generation;
  request.source_member_digest = source->digest;
  request.destination_member_generation = destination->generation;
  request.destination_member_digest = destination->digest;
  return request;
}

}  // namespace

int main() {
  struct Shape {
    std::size_t members;
    std::size_t paths;
    std::uint64_t capacity;
  };
  const Shape shapes[] = {{64, 256, 64}, {512, 2048, 64}, {2048, 8192, 64}};

  std::printf("cif %s -- authority benchmark\n", cif::version_string());
  std::printf("%-10s %-8s %-14s %-12s %-14s %-12s\n", "members", "paths", "build_ms",
              "decisions", "granted", "decisions/s");

  for (const Shape& shape : shapes) {
    Cluster cluster;
    const std::uint64_t build_start = cif::platform::monotonic_nanos();
    if (!build(cluster, shape.members, shape.paths, shape.capacity, true)) {
      std::printf("build failed for %zu members\n", shape.members);
      return 1;
    }
    // Digests are computed once here so the reported figure covers building the
    // canonical encoding of the whole cluster.
    const cif::Digest256 topology = cluster.core.spec().topology_digest();
    const std::uint64_t build_nanos = cif::platform::monotonic_nanos() - build_start;

    constexpr std::size_t kDecisions = 20000;
    std::size_t granted = 0;
    std::vector<cif::GrantId> live;
    live.reserve(kDecisions);

    const std::uint64_t decision_start = cif::platform::monotonic_nanos();
    for (std::size_t i = 0; i < kDecisions; ++i) {
      const cif::AuthorityDecision decision =
          cluster.core.submit(make_request(cluster, i, "att-" + decimal(i), 1));
      if (cif::is_authoritative(decision.outcome)) {
        ++granted;
        live.push_back(decision.grant->grant_id);
      }
    }
    const std::uint64_t decision_nanos = cif::platform::monotonic_nanos() - decision_start;

    std::printf("%-10zu %-8zu %-14.3f %-12zu %-14zu %-12s\n", shape.members, shape.paths,
                static_cast<double>(build_nanos) / 1.0e6, kDecisions, granted,
                rate(kDecisions, decision_nanos).c_str());

    if (!cluster.core.self_check().ok()) {
      std::printf("  INVARIANT VIOLATION after the decision loop\n");
      return 1;
    }

    // Release half of the grants and confirm the accounting closes.
    const std::uint64_t release_start = cif::platform::monotonic_nanos();
    for (std::size_t i = 0; i < live.size() / 2; ++i) {
      cif::ReleaseRequest release;
      release.request_id = cif::RequestId::from_validated("req-rel-" + decimal(i));
      release.grant_id = live[i];
      static_cast<void>(cluster.core.release(release));
    }
    const std::uint64_t release_nanos = cif::platform::monotonic_nanos() - release_start;
    std::printf("  release: %zu releases in %.3f ms (%s/s), topology digest %s\n", live.size() / 2,
                static_cast<double>(release_nanos) / 1.0e6,
                rate(live.size() / 2, release_nanos).c_str(), topology.hex().substr(0, 16).c_str());
    if (!cluster.core.self_check().ok()) {
      std::printf("  INVARIANT VIOLATION after releases\n");
      return 1;
    }
  }

  // Canonical encoding cost at scale, measured directly.
  // The per-decision state digest is a pure function of the state, so it costs
  // O(live grants). This measures both settings on a cluster that actually
  // accumulates live authority, which is the only way the comparison means
  // anything. The path here is deliberately roomy so every decision succeeds.
  {
    std::printf("\n%-10s %-8s %-16s %-16s %-10s\n", "members", "paths", "with-digest/s",
                "without-digest/s", "live");
    for (const Shape& shape : shapes) {
      std::uint64_t measured[2] = {0, 0};
      std::uint64_t live = 0;
      for (int mode = 0; mode < 2; ++mode) {
        Cluster cluster;
        // Roomy, shared path: every decision below is authorised.
        if (!build(cluster, shape.members, shape.paths, 1u << 24, mode == 0)) {
          return 1;
        }
        constexpr std::size_t kCount = 4000;
        const std::uint64_t start = cif::platform::monotonic_nanos();
        for (std::size_t i = 0; i < kCount; ++i) {
          const cif::AuthorityDecision decision =
              cluster.core.submit(make_request(cluster, i, "hot-" + decimal(i), 1));
          if (mode == 0 && cif::is_authoritative(decision.outcome)) {
            ++live;
          }
        }
        measured[mode] = cif::platform::monotonic_nanos() - start;
      }
      std::printf("%-10zu %-8zu %-16s %-16s %-10llu\n", shape.members, shape.paths,
                  rate(4000, measured[0]).c_str(), rate(4000, measured[1]).c_str(),
                  static_cast<unsigned long long>(live));
    }
  }

  {
    Cluster cluster;
    if (!build(cluster, 1024, 4096, 64, true)) {
      return 1;
    }
    constexpr std::size_t kDigests = 50;
    const std::uint64_t start = cif::platform::monotonic_nanos();
    cif::Digest256 digest;
    for (std::size_t i = 0; i < kDigests; ++i) {
      digest = cluster.core.spec().digest();
    }
    const std::uint64_t nanos = cif::platform::monotonic_nanos() - start;
    std::printf("canonical spec digest over 1024 members / 4096 paths: %.3f ms each (%s)\n",
                static_cast<double>(nanos) / 1.0e6 / static_cast<double>(kDigests),
                digest.hex().substr(0, 16).c_str());
  }
  return 0;
}
