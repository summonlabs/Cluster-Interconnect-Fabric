// Cluster Interconnect Fabric (CIF) -- seeded property and differential tests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every test here is driven by a seed printed by the harness, so a failure is
// reproducible with --seed <n>. Nothing consults an entropy source.
#include <algorithm>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "cif/authority.hpp"
#include "cif/journal.hpp"
#include "cif/rng.hpp"
#include "harness.hpp"

using namespace cif;

namespace {

const char* kServiceA = "trainers";
const char* kServiceB = "servers";
const char* kPool = "credit-pool";

// ---------------------------------------------------------------------------
// A deliberately naive, independent reference model.
//
// It is written as a flat procedure from the specification and shares no code
// with the engine: if the two agree, they agree for two different reasons. It
// models the subset of the domain the generator produces.
// ---------------------------------------------------------------------------
struct RefMember {
  std::string id;
  std::uint64_t generation = 1;
  Digest256 digest;
  MemberLifecycle lifecycle = MemberLifecycle::Active;
  std::string locality;
  std::string service;
};

struct RefPath {
  std::string id;
  std::uint64_t generation = 1;
  std::string source;
  std::string destination;
  std::uint64_t capacity = 0;
  bool exclusive = false;
  PathState state = PathState::Operational;
};

struct RefContract {
  std::string id;
  std::uint64_t generation = 1;
  std::uint64_t min_units = 0;
  std::uint64_t max_units = 0;
  std::uint32_t min_domains = 1;
  std::uint8_t domain_level = 0;
  MaintenanceMode maintenance = MaintenanceMode::Refuse;
  bool allow_draining = false;
  bool allow_faulted = false;
  bool allow_partitioned = false;
  bool allow_degraded = true;
  bool has_unsupported_capability = false;
};

struct RefWorld {
  std::string cluster;
  std::vector<RefMember> members;
  std::vector<RefPath> paths;
  RefContract contract;
  std::map<std::string, std::uint64_t> committed;  // path id -> units
  Digest256 source_digest;
  Digest256 destination_digest;

  [[nodiscard]] const RefMember* find(const std::string& id) const {
    for (const RefMember& member : members) {
      if (member.id == id) {
        return &member;
      }
    }
    return nullptr;
  }
};

/// Plain-language restatement of the authority rules. Deliberately slow and
/// obvious.
[[nodiscard]] AuthorityOutcome reference_outcome(const RefWorld& world,
                                                 const AuthorityRequest& request) {
  const RefMember* source = world.find(request.source_member.value());
  const RefMember* destination = world.find(request.destination_member.value());
  if (source == nullptr || destination == nullptr) {
    return AuthorityOutcome::Unknown;
  }
  const RefContract& contract = world.contract;

  if (contract.has_unsupported_capability) {
    return AuthorityOutcome::Unsupported;
  }
  if (source->lifecycle == MemberLifecycle::Removed ||
      destination->lifecycle == MemberLifecycle::Removed) {
    return AuthorityOutcome::Refused;
  }
  if (request.source_member_generation.value() != source->generation ||
      request.destination_member_generation.value() != destination->generation) {
    return AuthorityOutcome::Fenced;
  }
  if (request.source_member_digest.is_zero() || request.destination_member_digest.is_zero()) {
    return AuthorityOutcome::Incomplete;
  }
  if (!(request.source_member_digest == source->digest) ||
      !(request.destination_member_digest == destination->digest)) {
    return AuthorityOutcome::Fenced;
  }

  bool degraded = false;
  for (const RefMember* member : {source, destination}) {
    switch (member->lifecycle) {
      case MemberLifecycle::Active:
        break;
      case MemberLifecycle::Enlisted:
        return AuthorityOutcome::Refused;
      case MemberLifecycle::Draining:
        if (!contract.allow_draining) {
          return AuthorityOutcome::Refused;
        }
        degraded = true;
        break;
      case MemberLifecycle::Maintenance:
        if (contract.maintenance == MaintenanceMode::Refuse) {
          return AuthorityOutcome::Refused;
        }
        if (contract.maintenance == MaintenanceMode::Degrade) {
          degraded = true;
        }
        break;
      case MemberLifecycle::Faulted:
        if (!contract.allow_faulted) {
          return AuthorityOutcome::Refused;
        }
        degraded = true;
        break;
      case MemberLifecycle::Partitioned:
        if (!contract.allow_partitioned) {
          return AuthorityOutcome::Refused;
        }
        degraded = true;
        break;
      case MemberLifecycle::Removed:
        return AuthorityOutcome::Refused;
    }
  }

  const RefPath* path = nullptr;
  for (const RefPath& candidate : world.paths) {
    if (candidate.id == request.path_id.value()) {
      path = &candidate;
      break;
    }
  }
  if (path == nullptr) {
    return AuthorityOutcome::Unknown;
  }
  if (request.path_generation.value() != path->generation) {
    return AuthorityOutcome::Stale;
  }
  if (path->source != request.source_member.value() ||
      path->destination != request.destination_member.value()) {
    return AuthorityOutcome::Refused;
  }
  if (path->state == PathState::Down || path->state == PathState::Unknown) {
    return AuthorityOutcome::Refused;
  }
  if (path->state == PathState::Maintenance) {
    if (contract.maintenance == MaintenanceMode::Refuse) {
      return AuthorityOutcome::Refused;
    }
    if (contract.maintenance == MaintenanceMode::Degrade) {
      degraded = true;
    }
  }
  if (path->state == PathState::Degraded) {
    degraded = true;
  }

  // Failure-domain diversity, evaluated as a plain prefix comparison.
  std::string source_domain;
  std::string destination_domain;
  {
    std::size_t start = 0;
    int seen = 0;
    while (start <= source->locality.size() && seen < contract.domain_level) {
      const std::size_t slash = source->locality.find('/', start);
      const std::size_t end = slash == std::string::npos ? source->locality.size() : slash;
      if (seen != 0) {
        source_domain.push_back('/');
      }
      source_domain += source->locality.substr(start, end - start);
      ++seen;
      if (slash == std::string::npos) {
        break;
      }
      start = slash + 1;
    }
    start = 0;
    seen = 0;
    while (start <= destination->locality.size() && seen < contract.domain_level) {
      const std::size_t slash = destination->locality.find('/', start);
      const std::size_t end = slash == std::string::npos ? destination->locality.size() : slash;
      if (seen != 0) {
        destination_domain.push_back('/');
      }
      destination_domain += destination->locality.substr(start, end - start);
      ++seen;
      if (slash == std::string::npos) {
        break;
      }
      start = slash + 1;
    }
  }
  const std::uint32_t distinct = source_domain == destination_domain ? 1u : 2u;
  if (contract.min_domains > distinct) {
    return AuthorityOutcome::Refused;
  }

  std::uint64_t want = request.requested_units;
  if (want == 0) {
    want = contract.min_units;
  }
  if (contract.max_units != 0 && want > contract.max_units) {
    degraded = true;
    want = contract.max_units;
  }
  if (want < contract.min_units) {
    return AuthorityOutcome::Refused;
  }

  const auto it = world.committed.find(path->id);
  const std::uint64_t used = it == world.committed.end() ? 0 : it->second;
  const std::uint64_t available = path->capacity > used ? path->capacity - used : 0;

  if (path->exclusive && used > 0) {
    return AuthorityOutcome::Conflicting;
  }
  if (want > available) {
    const bool can_reduce = available > 0 && available >= contract.min_units &&
                            contract.allow_degraded && request.allow_degraded;
    if (!can_reduce) {
      return AuthorityOutcome::Refused;
    }
    degraded = true;
    want = available;
  }
  static_cast<void>(want);
  if (degraded) {
    // A reduction is only authorised when both the contract and the caller
    // consented to receiving less than they asked for.
    return (contract.allow_degraded && request.allow_degraded) ? AuthorityOutcome::Degraded
                                                              : AuthorityOutcome::Refused;
  }
  return AuthorityOutcome::Granted;
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------
struct Generated {
  RefWorld world;
  Member source_member;
  Member destination_member;
  Path path;
  CommunicationContract contract;
};

[[nodiscard]] std::string locality_for(Pcg32& rng, int index) {
  const int room = static_cast<int>(rng.bounded(2)) + 1;
  return "dc/room" + std::to_string(room) + "/rack" + std::to_string(index + 1) + "/pod" +
         std::to_string(index + 1);
}

/// Builds a deterministic world from a seed. Every member starts Active and the
/// single path starts Operational: perturbations are applied explicitly so the
/// reference model never has to guess an ordering.
[[nodiscard]] Generated generate(Pcg32& rng) {
  Generated generated;
  generated.world.cluster = "cluster-prop";

  generated.source_member.id = MemberId::from_validated("m-a");
  generated.source_member.domain = MemberDomainId::from_validated("domain-1");
  generated.source_member.generation = MemberGeneration{1};
  generated.source_member.digest = sha256("member:m-a");
  generated.source_member.lifecycle = MemberLifecycle::Active;
  CIF_REQUIRE(LocalityPath::parse(locality_for(rng, 0), generated.source_member.locality));
  generated.source_member.services.push_back(ServiceGroupId::from_validated(kServiceA));

  generated.destination_member.id = MemberId::from_validated("m-b");
  generated.destination_member.domain = MemberDomainId::from_validated("domain-2");
  generated.destination_member.generation = MemberGeneration{1};
  generated.destination_member.digest = sha256("member:m-b");
  generated.destination_member.lifecycle = MemberLifecycle::Active;
  CIF_REQUIRE(LocalityPath::parse(locality_for(rng, 1), generated.destination_member.locality));
  generated.destination_member.services.push_back(ServiceGroupId::from_validated(kServiceB));

  generated.path.id = PathId::from_validated("p-ab");
  generated.path.generation = PathGeneration{1};
  generated.path.source_member = generated.source_member.id;
  generated.path.destination_member = generated.destination_member.id;
  generated.path.capacity_units = 8 + rng.bounded(24);
  generated.path.exclusive = rng.chance(1, 4);
  generated.path.state = PathState::Operational;

  generated.contract.id = ContractId::from_validated("c-prop");
  generated.contract.generation = ContractGeneration{1};
  generated.contract.source_service = ServiceGroupId::from_validated(kServiceA);
  generated.contract.destination_service = ServiceGroupId::from_validated(kServiceB);
  generated.contract.min_capacity_units = rng.bounded(6);
  generated.contract.max_capacity_units = 0;
  generated.contract.min_distinct_failure_domains = 1 + static_cast<std::uint32_t>(rng.bounded(2));
  generated.contract.failure_domain_level = 2;
  generated.contract.allow_degraded = true;
  generated.contract.maintenance_mode = MaintenanceMode::Refuse;

  RefMember ref_source;
  ref_source.id = generated.source_member.id.value();
  ref_source.generation = 1;
  ref_source.digest = generated.source_member.digest;
  ref_source.locality = generated.source_member.locality.to_string();
  ref_source.service = kServiceA;
  generated.world.members.push_back(ref_source);

  RefMember ref_destination;
  ref_destination.id = generated.destination_member.id.value();
  ref_destination.generation = 1;
  ref_destination.digest = generated.destination_member.digest;
  ref_destination.locality = generated.destination_member.locality.to_string();
  ref_destination.service = kServiceB;
  generated.world.members.push_back(ref_destination);

  RefPath ref_path;
  ref_path.id = generated.path.id.value();
  ref_path.generation = 1;
  ref_path.source = generated.source_member.id.value();
  ref_path.destination = generated.destination_member.id.value();
  ref_path.capacity = generated.path.capacity_units;
  ref_path.exclusive = generated.path.exclusive;
  ref_path.state = PathState::Operational;
  generated.world.paths.push_back(ref_path);

  generated.world.contract.id = generated.contract.id.value();
  generated.world.contract.generation = 1;
  generated.world.contract.min_units = generated.contract.min_capacity_units;
  generated.world.contract.min_domains = generated.contract.min_distinct_failure_domains;
  generated.world.contract.domain_level = generated.contract.failure_domain_level;
  generated.world.contract.allow_degraded = true;
  return generated;
}

/// Applies perturbation 'kind' to both the engine-facing and reference-facing
/// worlds so that they always describe the same cluster.
void perturb(int kind, Generated& generated) {
  RefWorld& world = generated.world;
  switch (kind) {
    case 0:
      break;
    case 1:  // source is enlisted
      generated.source_member.lifecycle = MemberLifecycle::Enlisted;
      world.members[0].lifecycle = MemberLifecycle::Enlisted;
      break;
    case 2:  // source is draining, contract refuses draining
      generated.source_member.lifecycle = MemberLifecycle::Draining;
      world.members[0].lifecycle = MemberLifecycle::Draining;
      break;
    case 3:  // source is faulted, contract refuses faulted
      generated.source_member.lifecycle = MemberLifecycle::Faulted;
      world.members[0].lifecycle = MemberLifecycle::Faulted;
      break;
    case 4:  // source is partitioned and the contract permits it
      generated.source_member.lifecycle = MemberLifecycle::Partitioned;
      world.members[0].lifecycle = MemberLifecycle::Partitioned;
      generated.contract.allow_partitioned = true;
      world.contract.allow_partitioned = true;
      break;
    case 5:  // destination in maintenance, contract degrades
      generated.destination_member.lifecycle = MemberLifecycle::Maintenance;
      world.members[1].lifecycle = MemberLifecycle::Maintenance;
      generated.contract.maintenance_mode = MaintenanceMode::Degrade;
      world.contract.maintenance = MaintenanceMode::Degrade;
      break;
    case 6:  // path degraded
      generated.path.state = PathState::Degraded;
      world.paths[0].state = PathState::Degraded;
      break;
    case 7:  // path down
      generated.path.state = PathState::Down;
      world.paths[0].state = PathState::Down;
      break;
    case 8:  // failure domains collapse
      CIF_REQUIRE(LocalityPath::parse("dc/room1/rack9/pod9", generated.destination_member.locality));
      world.members[1].locality = "dc/room1/rack9/pod9";
      break;
    default:
      break;
  }
}

[[nodiscard]] AuthorityRequest make_request(const Generated& generated, const std::string& attempt,
                                            std::uint64_t units, bool allow_degraded) {
  AuthorityRequest request;
  request.request_id = RequestId::from_validated("req-" + attempt);
  request.attempt_id = AttemptId::from_validated(attempt);
  request.contract_id = generated.contract.id;
  request.contract_generation = generated.contract.generation;
  request.cluster_id = ClusterId::from_validated(generated.world.cluster);
  request.source_member = generated.source_member.id;
  request.destination_member = generated.destination_member.id;
  request.path_id = generated.path.id;
  request.path_generation = generated.path.generation;
  request.source_member_generation = generated.source_member.generation;
  request.source_member_digest = generated.source_member.digest;
  request.destination_member_generation = generated.destination_member.generation;
  request.destination_member_digest = generated.destination_member.digest;
  request.requested_units = units;
  request.lease_ticks = 1000;
  request.allow_degraded = allow_degraded;
  return request;
}

}  // namespace

// ---------------------------------------------------------------------------
// differential
// ---------------------------------------------------------------------------
CIF_TEST(differential, matches_reference_model) {
  const std::uint64_t base_seed = cif::test::current_seed();
  std::size_t comparisons = 0;
  for (std::uint64_t iteration = 0; iteration < 400; ++iteration) {
    SplitMix64 splitter(base_seed + iteration * 7919u);
    Pcg32 rng = splitter.make_stream();
    for (int perturbation = 0; perturbation <= 8; ++perturbation) {
      Generated generated = generate(rng);
      perturb(perturbation, generated);

      AuthorityCore core;
      CIF_REQUIRE_OK(core.initialize(ClusterId::from_validated(generated.world.cluster),
                                     ControllerIncarnation::from_seed(iteration + 1),
                                     PolicyGeneration{1}, Tick{1}, nullptr));
      CIF_REQUIRE_OK(core.upsert_member(generated.source_member));
      CIF_REQUIRE_OK(core.upsert_member(generated.destination_member));
      CIF_REQUIRE_OK(core.upsert_path(generated.path));
      CIF_REQUIRE_OK(core.upsert_contract(generated.contract));

      const std::uint64_t units = rng.bounded(20);
      const bool allow_degraded = rng.chance(1, 2);
      AuthorityRequest request = make_request(generated, "att-1", units, allow_degraded);
      request.cluster_generation = core.spec().generation();
      request.epoch = core.spec().epoch();
      request.incarnation = core.spec().incarnation();
      request.policy_generation = core.spec().policy_generation();
      request.path_generation = core.spec().find_path(generated.path.id)->generation;
      request.contract_generation = core.contracts().find(generated.contract.id)->generation;

      const AuthorityOutcome expected = reference_outcome(generated.world, request);
      const AuthorityDecision decision = core.submit(request);
      ++comparisons;
      CIF_CHECK_MSG(decision.outcome == expected,
                    "seed=" + std::to_string(base_seed) + " iteration=" +
                        std::to_string(iteration) + " perturbation=" +
                        std::to_string(perturbation) + " units=" + std::to_string(units) +
                        " engine=" + to_string(decision.outcome) +
                        " reference=" + to_string(expected));
      if (decision.outcome != expected) {
        return;
      }
      const Status check = core.self_check();
      CIF_CHECK_MSG(check.ok(), "seed=" + std::to_string(base_seed) + " iteration=" +
                                    std::to_string(iteration) + " perturbation=" +
                                    std::to_string(perturbation) + ": " + check.to_string());
    }
  }
  CIF_CHECK(comparisons >= 3600);
}

// ---------------------------------------------------------------------------
// invariants under randomized operation sequences
// ---------------------------------------------------------------------------
namespace {

struct RandomWorld {
  AuthorityCore core;
  std::vector<MemberId> members;
  std::vector<PathId> paths;
  ContractId contract = ContractId::from_validated("c-rand");
  ResourceId pool = ResourceId::from_validated(kPool);
  std::uint64_t attempts = 0;

  [[nodiscard]] Status build(Pcg32& rng, std::size_t member_count, std::size_t path_count,
                             DurabilitySink* sink = nullptr) {
    core.attach_sink(sink);
    CIF_TRY(core.initialize(ClusterId::from_validated("cluster-rand"),
                            ControllerIncarnation::from_seed(3), PolicyGeneration{1}, Tick{1},
                            sink));
    for (std::size_t i = 0; i < member_count; ++i) {
      Member member;
      member.id = MemberId::from_validated("m-" + std::to_string(i));
      member.domain = MemberDomainId::from_validated("domain-" + std::to_string(i % 3));
      member.generation = MemberGeneration{1};
      member.digest = sha256("member:" + std::to_string(i));
      member.lifecycle = MemberLifecycle::Active;
      LocalityPath locality;
      if (!LocalityPath::parse("dc/room" + std::to_string(i % 4) + "/rack" +
                                   std::to_string(i) + "/pod" + std::to_string(i),
                               locality)) {
        return Status::error(StatusCode::Internal, "generator produced an invalid locality");
      }
      member.locality = locality;
      member.services.push_back(ServiceGroupId::from_validated(i % 2 == 0 ? kServiceA
                                                                          : kServiceB));
      Resource resource;
      resource.id = pool;
      resource.kind = "credit";
      resource.total_units = 64;
      resource.reservation_generation = ReservationGeneration{static_cast<std::uint64_t>(i + 1)};
      member.resources.push_back(resource);
      CIF_TRY(core.upsert_member(member));
      members.push_back(member.id);
    }
    for (std::size_t i = 0; i < path_count; ++i) {
      Path path;
      path.id = PathId::from_validated("p-" + std::to_string(i));
      path.generation = PathGeneration{1};
      path.source_member = members[i % members.size()];
      path.destination_member = members[(i + 1) % members.size()];
      path.capacity_units = 4 + rng.bounded(24);
      path.exclusive = rng.chance(1, 3);
      path.state = PathState::Operational;
      CIF_TRY(core.upsert_path(path));
      paths.push_back(path.id);
    }
    CommunicationContract contract_value;
    contract_value.id = contract;
    contract_value.generation = ContractGeneration{1};
    contract_value.source_service = ServiceGroupId::from_validated(kServiceA);
    contract_value.destination_service = ServiceGroupId::from_validated(kServiceB);
    contract_value.min_capacity_units = 1;
    contract_value.min_distinct_failure_domains = 1;
    contract_value.maintenance_mode = MaintenanceMode::Degrade;
    contract_value.allow_draining = true;
    contract_value.allow_faulted = true;
    contract_value.allow_partitioned = true;
    contract_value.allow_degraded = true;
    CIF_TRY(core.upsert_contract(contract_value));
    return Status::success();
  }
};

}  // namespace

CIF_TEST(property, capacity_never_overcommits) {
  const std::uint64_t base_seed = cif::test::current_seed();
  for (std::uint64_t iteration = 0; iteration < 60; ++iteration) {
    SplitMix64 splitter(base_seed ^ (iteration * 104729u));
    Pcg32 rng = splitter.make_stream();
    RandomWorld world;
    CIF_REQUIRE_OK(world.build(rng, 2 + rng.bounded(4), 1 + rng.bounded(3)));

    std::vector<GrantId> live;
    for (int step = 0; step < 60; ++step) {
      const std::uint64_t action = rng.bounded(10);
      if (action < 5) {
        AuthorityRequest request;
        request.request_id = RequestId::from_validated("req-" + std::to_string(world.attempts));
        request.attempt_id = AttemptId::from_validated("att-" + std::to_string(world.attempts));
        ++world.attempts;
        request.contract_id = world.contract;
        request.contract_generation = world.core.contracts().find(world.contract)->generation;
        request.cluster_id = world.core.spec().cluster_id();
        request.cluster_generation = world.core.spec().generation();
        request.epoch = world.core.spec().epoch();
        request.incarnation = world.core.spec().incarnation();
        request.policy_generation = world.core.spec().policy_generation();
        request.source_member = world.members[rng.bounded(world.members.size())];
        request.destination_member = world.members[rng.bounded(world.members.size())];
        request.path_id = world.paths[rng.bounded(world.paths.size())];
        const Path* path = world.core.spec().find_path(request.path_id);
        request.path_generation = path != nullptr ? path->generation : PathGeneration{};
        const Member* source = world.core.spec().find_member(request.source_member);
        const Member* destination = world.core.spec().find_member(request.destination_member);
        if (source == nullptr || destination == nullptr) {
          continue;
        }
        request.source_member_generation = source->generation;
        request.source_member_digest = source->digest;
        request.destination_member_generation = destination->generation;
        request.destination_member_digest = destination->digest;
        request.requested_units = rng.bounded(12);
        request.lease_ticks = 1 + rng.bounded(50);
        request.allow_degraded = rng.chance(1, 2);
        if (rng.chance(1, 3)) {
          request.resource_id = world.pool;
          const Resource* resource = source->find_resource(world.pool);
          request.reservation_generation =
              resource != nullptr ? resource->reservation_generation : ReservationGeneration{};
        }
        const AuthorityDecision decision = world.core.submit(request);
        if (decision.grant.has_value() && holds_capacity(decision.grant->state)) {
          live.push_back(decision.grant->grant_id);
        }
        if (is_authoritative(decision.outcome)) {
          CIF_CHECK(decision.grant.has_value());
          CIF_CHECK(decision.grant->capacity_units > 0);
          CIF_CHECK(decision.grant->capacity_units <=
                    (request.requested_units == 0 ? 1 : request.requested_units));
        }
      } else if (action < 7 && !live.empty()) {
        const std::size_t index = static_cast<std::size_t>(rng.bounded(live.size()));
        ReleaseRequest release;
        release.request_id = RequestId::from_validated("req-rel-" + std::to_string(step));
        release.grant_id = live[index];
        static_cast<void>(world.core.release(release));
      } else if (action < 8) {
        static_cast<void>(
            world.core.set_member_lifecycle(world.members[rng.bounded(world.members.size())],
                                            static_cast<MemberLifecycle>(rng.bounded(7))));
      } else if (action < 9) {
        static_cast<void>(world.core.set_path_state(
            world.paths[rng.bounded(world.paths.size())],
            static_cast<PathState>(rng.bounded(5))));
      } else {
        static_cast<void>(world.core.advance_tick(
            Tick{world.core.spec().tick().value() + 1 + rng.bounded(30)}));
        static_cast<void>(world.core.expire_leases());
      }

      // Invariants after every single operation.
      CIF_REQUIRE_OK(world.core.self_check());
      for (const MemberId& member_id : world.members) {
        const Member* member = world.core.spec().find_member(member_id);
        if (member == nullptr) {
          continue;
        }
        const std::uint64_t reserved = world.core.reserved_units(world.pool);
        static_cast<void>(reserved);
      }
      for (const PathId& path_id : world.paths) {
        const Path* path = world.core.spec().find_path(path_id);
        if (path == nullptr) {
          continue;
        }
        CIF_CHECK_MSG(world.core.path_committed_units(path_id) <= path->capacity_units,
                      "path " + path_id.to_string() + " over-committed at step " +
                          std::to_string(step) + " seed=" + std::to_string(base_seed));
      }
      // Capacity accounting closure: a resource id names one cluster-wide pool,
      // so the reserved total is exactly the sum of the units held by grants
      // that say they hold capacity -- no more, no less.
      std::uint64_t expected = 0;
      for (const AuthorityGrant& grant : world.core.grants()) {
        if (grant.capacity_reserved && grant.resource_id == world.pool) {
          expected += grant.capacity_units;
        }
      }
      const std::uint64_t actual = world.core.reserved_units(world.pool);
      CIF_CHECK_MSG(expected == actual,
                    "accounting closure broke at step " + std::to_string(step) + " seed=" +
                        std::to_string(base_seed) + " expected=" + std::to_string(expected) +
                        " actual=" + std::to_string(actual));
    }
  }
}

CIF_TEST(property, repeated_identical_requests_are_idempotent) {
  const std::uint64_t base_seed = cif::test::current_seed();
  for (std::uint64_t iteration = 0; iteration < 40; ++iteration) {
    SplitMix64 splitter(base_seed + iteration * 31337u);
    Pcg32 rng = splitter.make_stream();
    RandomWorld world;
    CIF_REQUIRE_OK(world.build(rng, 2 + rng.bounded(3), 1 + rng.bounded(2)));

    AuthorityRequest request;
    request.request_id = RequestId::from_validated("req-idem");
    request.attempt_id = AttemptId::from_validated("att-idem");
    request.contract_id = world.contract;
    request.contract_generation = world.core.contracts().find(world.contract)->generation;
    request.cluster_id = world.core.spec().cluster_id();
    request.cluster_generation = world.core.spec().generation();
    request.epoch = world.core.spec().epoch();
    request.incarnation = world.core.spec().incarnation();
    request.policy_generation = world.core.spec().policy_generation();
    request.source_member = world.members[0];
    request.destination_member = world.members[1];
    request.path_id = world.paths[0];
    const Path* path = world.core.spec().find_path(request.path_id);
    request.path_generation = path != nullptr ? path->generation : PathGeneration{};
    const Member* source = world.core.spec().find_member(request.source_member);
    const Member* destination = world.core.spec().find_member(request.destination_member);
    request.source_member_generation = source->generation;
    request.source_member_digest = source->digest;
    request.destination_member_generation = destination->generation;
    request.destination_member_digest = destination->digest;
    request.requested_units = 1 + rng.bounded(4);
    request.lease_ticks = 500;
    request.allow_degraded = true;

    const AuthorityDecision first = world.core.submit(request);
    const Digest256 digest = world.core.state_digest();
    const std::size_t grant_count = world.core.grants().size();
    for (int repeat = 0; repeat < 6; ++repeat) {
      const AuthorityDecision again = world.core.submit(request);
      CIF_CHECK_MSG(again.idempotent_replay, "seed=" + std::to_string(base_seed));
      CIF_CHECK(again.outcome == first.outcome);
      if (first.grant.has_value()) {
        CIF_REQUIRE(again.grant.has_value());
        CIF_CHECK(again.grant->grant_id == first.grant->grant_id);
      }
      CIF_CHECK(world.core.state_digest() == digest);
      CIF_CHECK_EQ(world.core.grants().size(), grant_count);
    }
  }
}

CIF_TEST(property, independent_engines_agree_byte_for_byte) {
  const std::uint64_t base_seed = cif::test::current_seed();
  for (std::uint64_t iteration = 0; iteration < 25; ++iteration) {
    SplitMix64 left_splitter(base_seed + iteration);
    SplitMix64 right_splitter(base_seed + iteration);
    Pcg32 left_rng = left_splitter.make_stream();
    // A recorded operation script, replayed byte-for-byte into two independent
    // engines. This is what "deterministic" has to mean to be worth anything.
    std::vector<std::uint64_t> script;
    for (int i = 0; i < 80; ++i) {
      script.push_back(left_rng.next_u64());
    }

    AuthorityCore a;
    AuthorityCore b;
    CIF_REQUIRE_OK(a.initialize(ClusterId::from_validated("cluster-det"),
                                ControllerIncarnation::from_seed(5), PolicyGeneration{1}, Tick{1},
                                nullptr));
    CIF_REQUIRE_OK(b.initialize(ClusterId::from_validated("cluster-det"),
                                ControllerIncarnation::from_seed(5), PolicyGeneration{1}, Tick{1},
                                nullptr));
    std::uint64_t generations[4] = {0, 0, 0, 0};
    for (std::size_t step = 0; step < script.size(); ++step) {
      const std::uint64_t value = script[step];
      const std::size_t index = static_cast<std::size_t>(value % 4);
      // Generations only ever move forward: a member is never re-declared at an
      // older generation, because the engine refuses that.
      generations[index] += 1 + (value >> 8) % 2;
      Member member;
      member.id = MemberId::from_validated("m-" + std::to_string(index));
      member.domain = MemberDomainId::from_validated("domain");
      member.generation = MemberGeneration{generations[index]};
      member.digest = sha256("member:" + std::to_string(index) + ":" +
                             std::to_string(generations[index]));
      member.lifecycle = MemberLifecycle::Active;
      LocalityPath locality;
      CIF_REQUIRE(LocalityPath::parse("dc/room" + std::to_string(value % 2) + "/rack1/pod1",
                                      locality));
      member.locality = locality;
      member.services.push_back(ServiceGroupId::from_validated(kServiceA));
      CIF_REQUIRE_OK(a.upsert_member(member));
      CIF_REQUIRE_OK(b.upsert_member(member));
      CIF_CHECK(a.state_digest() == b.state_digest());
    }
    CIF_CHECK(a.render_state() == b.render_state());
    CIF_CHECK(a.state_digest() == b.state_digest());
  }
}

CIF_TEST(property, journal_replay_reproduces_authoritative_state) {
  const std::uint64_t base_seed = cif::test::current_seed();
  for (std::uint64_t iteration = 0; iteration < 15; ++iteration) {
    SplitMix64 splitter(base_seed + iteration * 7919u);
    Pcg32 rng = splitter.make_stream();
    const std::string path =
        cif::test::scratch_path("prop-" + std::to_string(iteration) + ".cifjournal");
    std::error_code error;
    std::filesystem::remove(path, error);

    Digest256 topology;
    std::map<std::string, std::string> grant_states;
    {
      Journal journal;
      std::vector<JournalEntry> entries;
      RecoveryReport report;
      CIF_REQUIRE_OK(Journal::scan(path, entries, report));
      CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                  report.last_sequence));
      JournalDurabilitySink sink(journal);
      RandomWorld world;
      // The sink must be attached before the first mutation so that the whole
      // world is durable.
      RandomWorld durable;
      CIF_REQUIRE_OK(durable.build(rng, 2 + rng.bounded(3), 1 + rng.bounded(2), &sink));
      for (int step = 0; step < 25; ++step) {
        AuthorityRequest request;
        request.request_id = RequestId::from_validated("req-" + std::to_string(step));
        request.attempt_id = AttemptId::from_validated("att-" + std::to_string(step));
        request.contract_id = durable.contract;
        request.contract_generation =
            durable.core.contracts().find(durable.contract)->generation;
        request.cluster_id = durable.core.spec().cluster_id();
        request.cluster_generation = durable.core.spec().generation();
        request.epoch = durable.core.spec().epoch();
        request.incarnation = durable.core.spec().incarnation();
        request.policy_generation = durable.core.spec().policy_generation();
        request.source_member = durable.members[rng.bounded(durable.members.size())];
        request.destination_member = durable.members[rng.bounded(durable.members.size())];
        request.path_id = durable.paths[rng.bounded(durable.paths.size())];
        const Path* path_value = durable.core.spec().find_path(request.path_id);
        request.path_generation = path_value != nullptr ? path_value->generation
                                                       : PathGeneration{};
        const Member* source = durable.core.spec().find_member(request.source_member);
        const Member* destination = durable.core.spec().find_member(request.destination_member);
        if (source == nullptr || destination == nullptr) {
          continue;
        }
        request.source_member_generation = source->generation;
        request.source_member_digest = source->digest;
        request.destination_member_generation = destination->generation;
        request.destination_member_digest = destination->digest;
        request.requested_units = 1 + rng.bounded(6);
        request.lease_ticks = 1000;
        request.allow_degraded = true;
        const AuthorityDecision decision = durable.core.submit(request);
        if (rng.chance(1, 4) && decision.grant.has_value()) {
          ReleaseRequest release;
          release.request_id = RequestId::from_validated("req-rel-" + std::to_string(step));
          release.grant_id = decision.grant->grant_id;
          static_cast<void>(durable.core.release(release));
        }
      }
      topology = durable.core.spec().topology_digest();
      for (const AuthorityGrant& grant : durable.core.grants()) {
        grant_states[grant.grant_id.value()] = to_string(grant.state);
      }
      CIF_REQUIRE_OK(journal.close());
    }

    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    RecoveredState recovered;
    CIF_REQUIRE_OK(replay_journal(entries, recovered));
    CIF_CHECK_MSG(recovered.spec.topology_digest() == topology,
                  "topology digest changed across replay, seed=" + std::to_string(base_seed) +
                      " iteration=" + std::to_string(iteration));
    CIF_CHECK_EQ(recovered.grants.size(), grant_states.size());
    for (const AuthorityGrant& grant : recovered.grants) {
      const auto it = grant_states.find(grant.grant_id.value());
      CIF_REQUIRE(it != grant_states.end());
      CIF_CHECK_MSG(to_string(grant.state) == it->second,
                    "grant " + grant.grant_id.to_string() + " replayed as " +
                        to_string(grant.state) + " but was recorded as " + it->second);
    }
    std::filesystem::remove(path, error);
  }
}
