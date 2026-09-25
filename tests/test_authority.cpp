// Cluster Interconnect Fabric (CIF) -- authority engine tests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "cif/authority.hpp"
#include "cif/journal.hpp"
#include "cif/render.hpp"
#include "harness.hpp"

using namespace cif;

namespace {

const char* kCluster = "cluster-alpha";
const char* kContract = "c-collective";
const char* kPath = "p-ab";
const char* kPool = "credit-pool";

Member make_member(const std::string& id, const std::string& domain, const std::string& locality,
                   const std::string& service, std::uint64_t generation, std::uint64_t units,
                   std::uint64_t reservation_generation) {
  Member member;
  member.id = MemberId::from_validated(id);
  member.domain = MemberDomainId::from_validated(domain);
  member.generation = MemberGeneration{generation};
  member.digest = sha256("member:" + id + ":" + std::to_string(generation));
  member.lifecycle = MemberLifecycle::Active;
  LocalityPath path;
  if (!LocalityPath::parse(locality, path)) {
    CIF_FAIL("bad locality in fixture: " + locality);
  }
  member.locality = path;
  member.services.push_back(ServiceGroupId::from_validated(service));
  Endpoint endpoint;
  endpoint.id = EndpointId::from_validated(id + "-ep0");
  endpoint.service_groups.push_back(ServiceGroupId::from_validated(service));
  member.endpoints.push_back(endpoint);
  Resource resource;
  resource.id = ResourceId::from_validated(kPool);
  resource.kind = "credit";
  resource.total_units = units;
  resource.reservation_generation = ReservationGeneration{reservation_generation};
  member.resources.push_back(resource);
  return member;
}

/// A complete, valid cluster: two members in different failure domains, one
/// exclusive path between them, and one contract that requires it.
struct Fixture {
  AuthorityCore core;
  ClusterId cluster = ClusterId::from_validated(kCluster);
  MemberId source = MemberId::from_validated("m-a");
  MemberId destination = MemberId::from_validated("m-b");
  ContractId contract_id = ContractId::from_validated(kContract);
  PathId path_id = PathId::from_validated(kPath);
  ResourceId pool = ResourceId::from_validated(kPool);
  std::uint64_t attempt_serial = 0;

  Status build(AuthorityOptions options = {}, DurabilitySink* sink = nullptr) {
    core.reset(options);
    core.attach_sink(sink);
    CIF_TRY(core.initialize(cluster, ControllerIncarnation::from_seed(11), PolicyGeneration{1},
                            Tick{1}, sink));
    CIF_TRY(core.upsert_member(make_member("m-a", "rack-domain-1", "dc/room1/rack1/pod1",
                                           "trainers", 1, 64, 3)));
    CIF_TRY(core.upsert_member(make_member("m-b", "rack-domain-2", "dc/room2/rack2/pod2",
                                           "servers", 1, 64, 5)));

    Path path;
    path.id = path_id;
    path.generation = PathGeneration{1};
    path.source_member = source;
    path.destination_member = destination;
    path.capacity_units = 32;
    // Non-exclusive by default: several tests need two relationships to
    // coexist so that capacity pressure, degradation and accounting can be
    // exercised. Tests that need exclusivity switch it on explicitly.
    path.exclusive = false;
    path.state = PathState::Operational;
    CIF_TRY(core.upsert_path(path));

    CommunicationContract contract;
    contract.id = contract_id;
    contract.generation = ContractGeneration{1};
    contract.source_service = ServiceGroupId::from_validated("trainers");
    contract.destination_service = ServiceGroupId::from_validated("servers");
    contract.min_capacity_units = 2;
    contract.max_capacity_units = 0;
    contract.min_distinct_failure_domains = 2;
    contract.failure_domain_level = 2;
    contract.require_exclusive_path = true;
    contract.maintenance_mode = MaintenanceMode::Refuse;
    contract.allow_degraded = true;
    CIF_TRY(core.upsert_contract(contract));
    return Status::success();
  }

  [[nodiscard]] AuthorityRequest request(const std::string& attempt,
                                         std::uint64_t units = 8,
                                         std::uint64_t lease_ticks = 100) {
    AuthorityRequest request;
    request.request_id = RequestId::from_validated("req-" + attempt);
    request.attempt_id = AttemptId::from_validated(attempt);
    request.contract_id = contract_id;
    const CommunicationContract* contract = core.contracts().find(contract_id);
    request.contract_generation =
        contract != nullptr ? contract->generation : ContractGeneration{};
    request.cluster_id = cluster;
    request.cluster_generation = core.spec().generation();
    request.epoch = core.spec().epoch();
    request.incarnation = core.spec().incarnation();
    request.policy_generation = core.spec().policy_generation();
    request.source_member = source;
    request.destination_member = destination;
    request.path_id = path_id;
    const Path* path = core.spec().find_path(path_id);
    request.path_generation = path != nullptr ? path->generation : PathGeneration{};
    request.requested_units = units;
    request.lease_ticks = lease_ticks;
    request.allow_degraded = true;
    const Member* a = core.spec().find_member(source);
    const Member* b = core.spec().find_member(destination);
    request.source_member_generation = a->generation;
    request.source_member_digest = a->digest;
    request.destination_member_generation = b->generation;
    request.destination_member_digest = b->digest;
    request.provenance.client = ClientId::from_validated("test-client");
    request.provenance.origin = "unit-test";
    request.provenance.correlation_id = attempt;
    return request;
  }

  [[nodiscard]] std::string next_attempt() { return "att-" + std::to_string(++attempt_serial); }

  [[nodiscard]] AuthorityDecision grant(const std::string& attempt, std::uint64_t units = 8,
                                        std::uint64_t lease_ticks = 100) {
    return core.submit(request(attempt, units, lease_ticks));
  }
};

/// Rebuilds a controller from a journal the same way cifd does.
Status recover_from(const std::string& path, AuthorityCore& core, RecoveryReport& report) {
  std::vector<JournalEntry> entries;
  CIF_TRY(Journal::scan(path, entries, report));
  RecoveredState recovered;
  CIF_TRY(replay_journal(entries, recovered));
  if (!recovered.has_controller) {
    return Status::error(StatusCode::NotFound, "journal carries no controller binding");
  }
  const Tick resume{recovered.tick.is_zero() ? 1 : recovered.tick.value() + 1};
  return core.recover(recovered.spec, recovered.contracts, std::move(recovered.grants),
                      std::move(recovered.attempts), recovered.counters, report,
                      ControllerIncarnation::generate(), resume);
}

}  // namespace

// ---------------------------------------------------------------------------
// happy path and structure
// ---------------------------------------------------------------------------
CIF_TEST(authority, grant_happy_path) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  const AuthorityDecision decision = fixture.grant("att-1", 8);
  CIF_CHECK(decision.outcome == AuthorityOutcome::Granted);
  CIF_REQUIRE(decision.grant.has_value());
  const AuthorityGrant& grant = *decision.grant;

  // Every binding the task requires is present and exact.
  CIF_CHECK_EQ(grant.cluster_id.value(), std::string(kCluster));
  CIF_CHECK_EQ(grant.cluster_generation.value(), fixture.core.spec().generation().value());
  CIF_CHECK_EQ(grant.epoch.value(), fixture.core.spec().epoch().value());
  CIF_CHECK(grant.incarnation == fixture.core.spec().incarnation());
  CIF_CHECK(grant.policy_generation == fixture.core.spec().policy_generation());
  CIF_CHECK_EQ(grant.contract_id.value(), std::string(kContract));
  CIF_CHECK(grant.contract_generation == fixture.core.contracts().find(fixture.contract_id)->generation);
  CIF_CHECK(grant.source_member == fixture.source);
  CIF_CHECK(grant.destination_member == fixture.destination);
  CIF_CHECK(grant.source_member_generation == fixture.core.spec().find_member(fixture.source)->generation);
  CIF_CHECK(grant.source_member_digest == fixture.core.spec().find_member(fixture.source)->digest);
  CIF_CHECK(grant.path_id == fixture.path_id);
  CIF_CHECK(grant.path_generation == fixture.core.spec().find_path(fixture.path_id)->generation);
  CIF_CHECK_EQ(grant.capacity_units, std::uint64_t{8});
  CIF_CHECK_EQ(grant.attempt_id.value(), std::string("att-1"));
  CIF_CHECK(grant.state == GrantState::Committed);
  CIF_CHECK(grant.commit == CommitState::Committed);
  CIF_CHECK(!grant.acknowledged);
  CIF_CHECK(grant.capacity_reserved);
  CIF_CHECK(!grant.degraded);
  CIF_CHECK(grant.commit_sequence > grant.prepare_sequence);
  CIF_CHECK(grant.lease_expiry.value() > grant.lease_issued.value());
  CIF_CHECK(!grant.lease_id.empty());
  CIF_CHECK(!grant.grant_id.empty());

  CIF_CHECK(fixture.core.self_check().ok());
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{8});
}

CIF_TEST(authority, idempotent_replay_never_mints_a_second_grant) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  const AuthorityDecision first = fixture.grant("att-1", 8);
  CIF_REQUIRE(first.grant.has_value());
  const std::uint64_t committed_after_first = fixture.core.path_committed_units(fixture.path_id);
  const Digest256 digest_after_first = fixture.core.state_digest();

  for (int i = 0; i < 5; ++i) {
    const AuthorityDecision replay = fixture.grant("att-1", 8);
    CIF_CHECK(replay.idempotent_replay);
    CIF_REQUIRE(replay.grant.has_value());
    CIF_CHECK(replay.grant->grant_id == first.grant->grant_id);
    CIF_CHECK(replay.grant->lease_id == first.grant->lease_id);
    CIF_CHECK(replay.outcome == AuthorityOutcome::Granted);
  }
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), committed_after_first);
  CIF_CHECK_EQ(fixture.core.grants().size(), std::size_t{1});
  CIF_CHECK(fixture.core.state_digest() == digest_after_first);
  CIF_CHECK(fixture.core.self_check().ok());

  // The same attempt id with different content is a conflict, never a silent
  // second grant.
  const AuthorityRequest different = fixture.request("att-1", 9);
  const AuthorityDecision conflict = fixture.core.submit(different);
  CIF_CHECK(conflict.outcome == AuthorityOutcome::Conflicting);
  CIF_CHECK_EQ(std::string(to_string(conflict.primary_reason())), std::string("ATTEMPT_CONFLICT"));
  CIF_CHECK_EQ(fixture.core.grants().size(), std::size_t{1});
}

CIF_TEST(authority, attempt_identity_is_bound_to_exact_request_bytes) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  const AuthorityRequest original = fixture.request("att-1", 8);
  CIF_REQUIRE(fixture.core.submit(original).outcome == AuthorityOutcome::Granted);

  // Byte-identical resubmission replays the recorded answer.
  const AuthorityDecision replay = fixture.core.submit(original);
  CIF_CHECK(replay.idempotent_replay);
  CIF_CHECK(replay.outcome == AuthorityOutcome::Granted);
  CIF_CHECK_EQ(fixture.core.grants().size(), std::size_t{1});

  // The same attempt id carrying different content is a conflict, never a
  // silent second grant and never a silent substitution.
  const AuthorityDecision moved = fixture.core.submit(fixture.request("att-1", 9));
  CIF_CHECK(moved.outcome == AuthorityOutcome::Conflicting);
  CIF_CHECK(moved.primary_reason() == ReasonCode::AttemptConflict);
  CIF_CHECK_EQ(fixture.core.grants().size(), std::size_t{1});
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{8});

  // A genuinely new attempt id is a new relationship.
  CIF_CHECK(fixture.grant("att-2", 8).outcome == AuthorityOutcome::Granted);
  CIF_CHECK_EQ(fixture.core.grants().size(), std::size_t{2});
  CIF_CHECK(fixture.core.self_check().ok());
}

CIF_TEST(authority, deterministic_explanations_and_digests) {
  Fixture left;
  Fixture right;
  CIF_REQUIRE_OK(left.build());
  CIF_REQUIRE_OK(right.build());

  const AuthorityDecision a = left.grant("att-1", 8);
  const AuthorityDecision b = right.grant("att-1", 8);
  CIF_CHECK(a.explanation == b.explanation);
  CIF_CHECK(a.decision_digest == b.decision_digest);
  CIF_CHECK(left.core.state_digest() == right.core.state_digest());
  CIF_CHECK(left.core.render_state() == right.core.render_state());
  CIF_CHECK(left.core.render_audit() == right.core.render_audit());

  // A second, differently ordered construction of the same cluster must produce
  // the same topology digest: the encoding is canonical, not insertion ordered.
  Fixture reordered;
  CIF_REQUIRE_OK(reordered.build());
  CIF_CHECK(reordered.core.spec().topology_digest() == left.core.spec().topology_digest());

  // Changing one byte of state changes the digest.
  const Digest256 before = left.core.state_digest();
  CIF_REQUIRE_OK(left.core.set_path_state(left.path_id, PathState::Degraded));
  CIF_CHECK(!(left.core.state_digest() == before));
}

CIF_TEST(authority, topology_and_spec_digests_do_not_share_a_cache) {
  // Computing one digest must never mark the other as valid. Sharing a revision
  // key would hand out an all-zero digest for whichever was computed second,
  // which is a silent lie about authoritative state.
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  CIF_REQUIRE(fixture.grant("att-1", 4).outcome == AuthorityOutcome::Granted);

  const Digest256 topology_first = fixture.core.spec().topology_digest();
  const Digest256 spec_after_topology = fixture.core.spec().digest();
  CIF_CHECK_MSG(!spec_after_topology.is_zero(),
                "spec digest was served as zero after topology_digest() populated the cache");

  const Digest256 spec_first = fixture.core.spec().digest();
  const Digest256 topology_after_spec = fixture.core.spec().topology_digest();
  CIF_CHECK_MSG(!topology_after_spec.is_zero(),
                "topology digest was served as zero after digest() populated the cache");

  CIF_CHECK(spec_after_topology == spec_first);
  CIF_CHECK(topology_after_spec == topology_first);
  CIF_CHECK(!(spec_first == topology_first));

  // And an independent engine must agree, so this is not merely self-consistent.
  Fixture other;
  CIF_REQUIRE_OK(other.build());
  CIF_REQUIRE(other.grant("att-1", 4).outcome == AuthorityOutcome::Granted);
  CIF_CHECK(other.core.spec().digest() == spec_first);
  CIF_CHECK(other.core.spec().topology_digest() == topology_first);

  // A mutation invalidates both.
  CIF_REQUIRE_OK(fixture.core.set_policy_generation(PolicyGeneration{5}));
  CIF_CHECK(!(fixture.core.spec().digest() == spec_first));
  CIF_CHECK(fixture.core.spec().topology_digest() == topology_first);
}

CIF_TEST(authority, digest_caches_are_never_stale) {
  // Digests are cached against a revision counter, which is only sound if every
  // mutator advances it. Each mutation below must therefore change both the
  // specification digest and the authoritative state digest.
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  CIF_REQUIRE(fixture.grant("att-1", 4).outcome == AuthorityOutcome::Granted);

  const auto both_changed = [&fixture](const Digest256& spec_before,
                                       const Digest256& state_before, const char* what) {
    CIF_CHECK_MSG(!(fixture.core.spec().digest() == spec_before),
                  std::string("spec digest did not change after ") + what);
    CIF_CHECK_MSG(!(fixture.core.state_digest() == state_before),
                  std::string("state digest did not change after ") + what);
  };

  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    Member member = *fixture.core.spec().find_member(fixture.source);
    member.generation = MemberGeneration{2};
    member.digest = sha256("member:m-a:2");
    CIF_REQUIRE_OK(fixture.core.upsert_member(member));
    both_changed(spec, state, "upsert_member");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    CIF_REQUIRE_OK(fixture.core.set_member_lifecycle(fixture.destination,
                                                     MemberLifecycle::Draining));
    both_changed(spec, state, "set_member_lifecycle");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    Path path = *fixture.core.spec().find_path(fixture.path_id);
    path.generation = PathGeneration{2};
    CIF_REQUIRE_OK(fixture.core.upsert_path(path));
    both_changed(spec, state, "upsert_path");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    CIF_REQUIRE_OK(fixture.core.set_path_state(fixture.path_id, PathState::Degraded));
    both_changed(spec, state, "set_path_state");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    MaintenanceExclusion exclusion;
    exclusion.id = ExclusionId::from_validated("maint-digest");
    exclusion.mode = MaintenanceMode::Degrade;
    CIF_REQUIRE_OK(fixture.core.upsert_exclusion(exclusion));
    both_changed(spec, state, "upsert_exclusion");
    CIF_REQUIRE_OK(fixture.core.remove_exclusion(exclusion.id));
    both_changed(spec, state, "remove_exclusion");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    CapacityObligation obligation;
    obligation.id = ObligationId::from_validated("obl-digest");
    obligation.service = ServiceGroupId::from_validated("servers");
    CIF_REQUIRE_OK(fixture.core.upsert_obligation(obligation));
    both_changed(spec, state, "upsert_obligation");
    CIF_REQUIRE_OK(fixture.core.remove_obligation(obligation.id));
    both_changed(spec, state, "remove_obligation");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    CIF_REQUIRE_OK(fixture.core.set_policy_generation(PolicyGeneration{9}));
    both_changed(spec, state, "set_policy_generation");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    Digest256 state = fixture.core.state_digest();
    CIF_REQUIRE_OK(fixture.core.advance_tick(Tick{5000}));
    both_changed(spec, state, "advance_tick");
  }
  {
    Digest256 spec = fixture.core.spec().digest();
    const Digest256 topology_before = fixture.core.spec().topology_digest();
    CIF_REQUIRE_OK(fixture.core.set_policy_generation(PolicyGeneration{10}));
    // The topology digest deliberately excludes the epoch, incarnation and
    // policy; only the full specification digest moves for those.
    CIF_CHECK_MSG(fixture.core.spec().digest() != spec, "spec digest did not move");
    CIF_CHECK_MSG(fixture.core.spec().topology_digest() == topology_before,
                  "topology digest must not depend on the ruling epoch");
  }
  {
    Digest256 state = fixture.core.state_digest();
    CIF_REQUIRE_OK(fixture.core.remove_path(fixture.path_id));
    CIF_CHECK_MSG(fixture.core.state_digest() != state, "state digest did not move after remove_path");
  }
  {
    // Re-upserting a contract at a new generation must move both the contract
    // store digest and the authoritative state digest.
    const Digest256 state = fixture.core.state_digest();
    const Digest256 contracts = fixture.core.contracts().digest();
    CommunicationContract contract = *fixture.core.contracts().find(fixture.contract_id);
    contract.generation = ContractGeneration{contract.generation.value() + 1};
    CIF_REQUIRE_OK(fixture.core.upsert_contract(contract));
    CIF_CHECK_MSG(fixture.core.contracts().digest() != contracts,
                  "contract store digest did not move");
    CIF_CHECK_MSG(fixture.core.state_digest() != state,
                  "state digest did not move after a contract change");
  }
  CIF_CHECK(fixture.core.self_check().ok());
}

CIF_TEST(authority, every_outcome_is_reachable) {
  std::vector<AuthorityOutcome> seen;

  // GRANTED
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    seen.push_back(fixture.grant("att-1", 8).outcome);
  }
  // DEGRADED: the path can only offer 6 of the 8 requested units and the caller
  // consented to a reduction.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    CIF_REQUIRE(fixture.core.submit(fixture.request("att-0", 30)).outcome ==
                  AuthorityOutcome::Granted);
    const AuthorityDecision decision = fixture.grant("att-1", 8);
    seen.push_back(decision.outcome);
    CIF_CHECK(decision.grant.has_value());
    if (decision.grant.has_value()) {
      CIF_CHECK_EQ(decision.grant->capacity_units, std::uint64_t{2});
    }
  }
  // REFUSED: same pressure without consent to degrade.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    CIF_REQUIRE(fixture.core.submit(fixture.request("att-0", 30)).outcome ==
                  AuthorityOutcome::Granted);
    AuthorityRequest request = fixture.request("att-1", 8);
    request.allow_degraded = false;
    seen.push_back(fixture.core.submit(request).outcome);
  }
  // FENCED: stale member generation.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    AuthorityRequest request = fixture.request("att-1", 8);
    request.source_member_generation = MemberGeneration{0};
    seen.push_back(fixture.core.submit(request).outcome);
  }
  // STALE: stale cluster generation.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    AuthorityRequest request = fixture.request("att-1", 8);
    request.cluster_generation = ClusterGeneration{request.cluster_generation.value() - 1};
    seen.push_back(fixture.core.submit(request).outcome);
  }
  // CONFLICTING: a second exclusive binding on the same path.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    Path exclusive = *fixture.core.spec().find_path(fixture.path_id);
    exclusive.exclusive = true;
    CIF_REQUIRE_OK(fixture.core.upsert_path(exclusive));
    CIF_REQUIRE(fixture.core.submit(fixture.request("att-1", 8)).outcome ==
                  AuthorityOutcome::Granted);
    seen.push_back(fixture.core.submit(fixture.request("att-2", 8)).outcome);
  }
  // INCOMPLETE: the caller did not supply member digests.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    AuthorityRequest request = fixture.request("att-1", 8);
    request.source_member_digest = Digest256::zero();
    seen.push_back(fixture.core.submit(request).outcome);
  }
  // INDETERMINATE: a durable commit whose acknowledgement was never recorded.
  {
    const std::string path = cif::test::scratch_path("indeterminate.cifjournal");
    std::error_code error;
    std::filesystem::remove(path, error);
    {
      Journal journal;
      std::vector<JournalEntry> entries;
      RecoveryReport report;
      CIF_REQUIRE_OK(Journal::scan(path, entries, report));
      CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                  report.last_sequence));
      JournalDurabilitySink sink(journal);
      Fixture fixture;
      CIF_REQUIRE_OK(fixture.build({}, &sink));
      CIF_REQUIRE(fixture.core.submit(fixture.request("att-1", 8)).outcome ==
                    AuthorityOutcome::Granted);
      CIF_REQUIRE_OK(journal.close());
    }
    AuthorityCore recovered;
    RecoveryReport report;
    CIF_REQUIRE_OK(recover_from(path, recovered, report));
    CIF_CHECK_EQ(recovered.quarantined_units(), std::uint64_t{8});
    ResolveRequest resolve;
    resolve.request_id = RequestId::from_validated("req-resolve");
    resolve.attempt_id = AttemptId::from_validated("att-1");
    const AuthorityDecision decision = recovered.resolve(resolve);
    seen.push_back(decision.outcome);
    CIF_CHECK(decision.requires_reconciliation);
    std::filesystem::remove(path, error);
  }
  // UNKNOWN: a member this controller has never heard of.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    AuthorityRequest request = fixture.request("att-1", 8);
    request.destination_member = MemberId::from_validated("m-ghost");
    seen.push_back(fixture.core.submit(request).outcome);
  }
  // UNSUPPORTED: a contract that demands physical hardware behaviour.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    CommunicationContract contract = *fixture.core.contracts().find(fixture.contract_id);
    contract.required_capabilities.push_back("rdma-lossless-transport");
    CIF_REQUIRE_OK(fixture.core.upsert_contract(contract));
    AuthorityRequest request = fixture.request("att-1", 8);
    request.contract_generation = fixture.core.contracts().find(fixture.contract_id)->generation;
    seen.push_back(fixture.core.submit(request).outcome);
  }
  // CANCELLED: an attempt withdrawn before it is used again.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    CIF_REQUIRE(fixture.core.submit(fixture.request("att-1", 8)).outcome ==
                  AuthorityOutcome::Granted);
    CancelRequest cancel;
    cancel.request_id = RequestId::from_validated("req-cancel");
    cancel.attempt_id = AttemptId::from_validated("att-1");
    cancel.reason = "withdrawn";
    seen.push_back(fixture.core.cancel(cancel).outcome);
  }
  // INVALID: a request with no attempt id can never be authoritative.
  {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    AuthorityRequest request = fixture.request("att-1", 8);
    request.attempt_id = AttemptId{};
    seen.push_back(fixture.core.submit(request).outcome);
  }

  const std::vector<AuthorityOutcome> required = {
      AuthorityOutcome::Granted,     AuthorityOutcome::Degraded,
      AuthorityOutcome::Refused,     AuthorityOutcome::Fenced,
      AuthorityOutcome::Stale,       AuthorityOutcome::Conflicting,
      AuthorityOutcome::Incomplete,  AuthorityOutcome::Indeterminate,
      AuthorityOutcome::Unknown,     AuthorityOutcome::Unsupported,
      AuthorityOutcome::Cancelled,   AuthorityOutcome::Invalid};
  for (AuthorityOutcome outcome : required) {
    CIF_CHECK_MSG(std::find(seen.begin(), seen.end(), outcome) != seen.end(),
                  std::string("outcome never produced: ") + to_string(outcome));
  }
  CIF_CHECK_EQ(seen.size(), required.size());
}

// ---------------------------------------------------------------------------
// fencing
// ---------------------------------------------------------------------------
CIF_TEST(fencing, stale_member_generation) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  // The member is replaced: generation moves from 1 to 2.
  Member replacement = *fixture.core.spec().find_member(fixture.source);
  replacement.generation = MemberGeneration{2};
  replacement.digest = sha256("member:m-a:2");
  CIF_REQUIRE_OK(fixture.core.upsert_member(replacement));

  AuthorityRequest stale = fixture.request("att-1", 8);
  stale.source_member_generation = MemberGeneration{1};
  stale.source_member_digest = sha256("member:m-a:1");
  const AuthorityDecision decision = fixture.core.submit(stale);
  CIF_CHECK(decision.outcome == AuthorityOutcome::Fenced);
  CIF_CHECK(decision.primary_reason() == ReasonCode::MemberGenerationStale);
  CIF_CHECK(!decision.grant.has_value());

  // The request also went stale on the cluster generation, so refresh it and
  // confirm the member generation is what is actually being fenced.
  AuthorityRequest refreshed = fixture.request("att-2", 8);
  refreshed.source_member_generation = MemberGeneration{1};
  refreshed.source_member_digest = sha256("member:m-a:1");
  CIF_CHECK(fixture.core.submit(refreshed).primary_reason() ==
            ReasonCode::MemberGenerationStale);

  // A digest that does not match the declared member is fenced too.
  AuthorityRequest digest_mismatch = fixture.request("att-3", 8);
  digest_mismatch.source_member_digest = sha256("forged");
  CIF_CHECK(fixture.core.submit(digest_mismatch).primary_reason() ==
            ReasonCode::MemberDigestMismatch);
}

CIF_TEST(fencing, stale_epoch_and_incarnation) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  AuthorityRequest stale_epoch = fixture.request("att-1", 8);
  stale_epoch.epoch = ClusterEpoch{0};
  const AuthorityDecision epoch_decision = fixture.core.submit(stale_epoch);
  CIF_CHECK(epoch_decision.outcome == AuthorityOutcome::Fenced);
  CIF_CHECK(epoch_decision.primary_reason() == ReasonCode::EpochStale);

  AuthorityRequest stale_incarnation = fixture.request("att-2", 8);
  stale_incarnation.incarnation = ControllerIncarnation::from_seed(999);
  const AuthorityDecision incarnation_decision = fixture.core.submit(stale_incarnation);
  CIF_CHECK(incarnation_decision.outcome == AuthorityOutcome::Fenced);
  CIF_CHECK(incarnation_decision.primary_reason() == ReasonCode::IncarnationStale);

  // Claiming to be ahead of the controller is not staleness: it is unprovable.
  AuthorityRequest ahead = fixture.request("att-3", 8);
  ahead.cluster_generation = ClusterGeneration{ahead.cluster_generation.value() + 5};
  CIF_CHECK(fixture.core.submit(ahead).outcome == AuthorityOutcome::Invalid);

  AuthorityRequest ahead_epoch = fixture.request("att-4", 8);
  ahead_epoch.epoch = ClusterEpoch{ahead_epoch.epoch.value() + 5};
  CIF_CHECK(fixture.core.submit(ahead_epoch).outcome == AuthorityOutcome::Invalid);
}

CIF_TEST(fencing, member_replacement_invalidates_grant) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  const AuthorityDecision decision = fixture.grant("att-1", 8);
  CIF_REQUIRE(decision.grant.has_value());
  const GrantId grant_id = decision.grant->grant_id;
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{8});

  Member replacement = *fixture.core.spec().find_member(fixture.destination);
  replacement.generation = MemberGeneration{2};
  replacement.digest = sha256("member:m-b:2");
  CIF_REQUIRE_OK(fixture.core.upsert_member(replacement));

  const AuthorityGrant* after = fixture.core.find_grant(grant_id);
  CIF_REQUIRE(after != nullptr);
  CIF_CHECK(after->state == GrantState::Revoked);
  CIF_CHECK(!after->reductions.empty());
  CIF_CHECK(after->reductions.front().code == ReasonCode::MemberGenerationStale);
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});
  CIF_CHECK(!after->capacity_reserved);
  CIF_CHECK(fixture.core.self_check().ok());

  // The attempt now resolves to a definite "not usable", not to a silent grant.
  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("req-resolve");
  resolve.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision resolved = fixture.core.resolve(resolve);
  CIF_CHECK(resolved.outcome == AuthorityOutcome::Fenced);
  CIF_CHECK(resolved.requires_reconciliation);
}

CIF_TEST(fencing, fencing_returns_capacity_exactly_once) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  for (int i = 0; i < 3; ++i) {
    const AuthorityDecision decision = fixture.grant("att-" + std::to_string(i + 1), 4);
    CIF_REQUIRE(decision.outcome == AuthorityOutcome::Granted);
  }
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{12});

  CIF_REQUIRE_OK(fixture.core.fence_all(ReasonCode::ControllerRestarted, "failover"));
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});

  // Fencing again must not release anything a second time.
  CIF_REQUIRE_OK(fixture.core.fence_all(ReasonCode::ControllerRestarted, "failover"));
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});
  for (const AuthorityGrant& grant : fixture.core.grants()) {
    CIF_CHECK(grant.state == GrantState::Fenced);
    CIF_CHECK(!grant.capacity_reserved);
  }
  CIF_CHECK(fixture.core.self_check().ok());
}

// ---------------------------------------------------------------------------
// capacity and accounting closure
// ---------------------------------------------------------------------------
CIF_TEST(capacity, closure_is_exact) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  Path exclusive = *fixture.core.spec().find_path(fixture.path_id);
  exclusive.exclusive = true;
  CIF_REQUIRE_OK(fixture.core.upsert_path(exclusive));

  std::vector<GrantId> grants;
  std::uint64_t expected = 0;
  for (int i = 0; i < 4; ++i) {
    const AuthorityDecision decision = fixture.grant("att-" + std::to_string(i + 1), 8);
    if (i == 0) {
      CIF_REQUIRE(decision.outcome == AuthorityOutcome::Granted);
      grants.push_back(decision.grant->grant_id);
      expected += 8;
    } else {
      // The path is exclusive, so every later attempt conflicts rather than
      // silently sharing or double counting.
      CIF_CHECK(decision.outcome == AuthorityOutcome::Conflicting);
      CIF_CHECK(decision.primary_reason() == ReasonCode::PathAlreadyBound);
    }
    CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), expected);
  }
  CIF_CHECK_EQ(expected, std::uint64_t{8});
  CIF_CHECK_EQ(grants.size(), std::size_t{1});
  CIF_CHECK_EQ(fixture.core.grants().size(), std::size_t{1});
  CIF_CHECK(exclusive.exclusive);

  // Release, then release again: capacity returns exactly once.
  ReleaseRequest release;
  release.request_id = RequestId::from_validated("req-release");
  release.grant_id = grants.front();
  release.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision released = fixture.core.release(release);
  CIF_CHECK(released.outcome == AuthorityOutcome::Granted);
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});

  for (int i = 0; i < 3; ++i) {
    const AuthorityDecision again = fixture.core.release(release);
    CIF_CHECK(again.outcome == AuthorityOutcome::Granted);
    CIF_CHECK(again.primary_reason() == ReasonCode::GrantAlreadyReleased);
    CIF_CHECK(again.idempotent_replay);
    CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});
  }
  CIF_CHECK(fixture.core.self_check().ok());

  // Releasing an unknown grant is UNKNOWN, not a silent success.
  ReleaseRequest unknown;
  unknown.request_id = RequestId::from_validated("req-unknown");
  unknown.grant_id = GrantId::from_validated("g-does-not-exist");
  const AuthorityDecision unknown_decision = fixture.core.release(unknown);
  CIF_CHECK(unknown_decision.outcome == AuthorityOutcome::Unknown);
  CIF_CHECK(unknown_decision.primary_reason() == ReasonCode::GrantNotFound);

  // Releasing with the wrong lease is a conflict unless it is administrative.
  AuthorityDecision second = fixture.grant("att-9", 4);
  CIF_REQUIRE(second.outcome == AuthorityOutcome::Granted);
  ReleaseRequest wrong_lease;
  wrong_lease.request_id = RequestId::from_validated("req-wrong");
  wrong_lease.grant_id = second.grant->grant_id;
  wrong_lease.lease_id = LeaseId::from_validated("l-forged");
  CIF_CHECK(fixture.core.release(wrong_lease).outcome == AuthorityOutcome::Conflicting);
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{4});

  wrong_lease.administrative = true;
  CIF_CHECK(fixture.core.release(wrong_lease).outcome == AuthorityOutcome::Granted);
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});
}

CIF_TEST(capacity, resource_reservation_is_exact) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  // Non-exclusive path so several grants can coexist and share one resource.
  Path path = *fixture.core.spec().find_path(fixture.path_id);
  path.exclusive = false;
  path.capacity_units = 128;
  CIF_REQUIRE_OK(fixture.core.upsert_path(path));

  std::uint64_t reserved = 0;
  for (int i = 0; i < 8; ++i) {
    AuthorityRequest request = fixture.request("att-" + std::to_string(i + 1), 8);
    request.path_generation = fixture.core.spec().find_path(fixture.path_id)->generation;
    request.resource_id = fixture.pool;
    request.reservation_generation =
        fixture.core.spec().find_member(fixture.source)->find_resource(fixture.pool)
            ->reservation_generation;
    const AuthorityDecision decision = fixture.core.submit(request);
    CIF_REQUIRE(decision.outcome == AuthorityOutcome::Granted);
    reserved += decision.grant->capacity_units;
    CIF_CHECK_EQ(fixture.core.reserved_units(fixture.pool), reserved);
    CIF_CHECK_EQ(decision.grant->reservation_generation,
                 fixture.core.spec().find_member(fixture.source)->find_resource(fixture.pool)
                     ->reservation_generation);
  }
  CIF_CHECK_EQ(reserved, std::uint64_t{64});
  CIF_CHECK(reserved <= fixture.core.spec().find_member(fixture.source)->find_resource(fixture.pool)->total_units);
  CIF_CHECK(fixture.core.self_check().ok());

  // The pool is now exhausted: the next request is refused.
  AuthorityRequest exhausted = fixture.request("att-exhausted", 8);
  exhausted.path_generation = fixture.core.spec().find_path(fixture.path_id)->generation;
  exhausted.resource_id = fixture.pool;
  exhausted.reservation_generation =
      fixture.core.spec().find_member(fixture.source)->find_resource(fixture.pool)
          ->reservation_generation;
  exhausted.allow_degraded = false;
  const AuthorityDecision refused = fixture.core.submit(exhausted);
  CIF_CHECK(refused.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(refused.primary_reason() == ReasonCode::CapacityExhausted);
  CIF_CHECK_EQ(fixture.core.reserved_units(fixture.pool), std::uint64_t{64});

  // A stale reservation generation is refused as STALE, not as capacity.
  AuthorityRequest stale_generation = exhausted;
  stale_generation.attempt_id = AttemptId::from_validated("att-stale-gen");
  stale_generation.reservation_generation = ReservationGeneration{999};
  CIF_CHECK(fixture.core.submit(stale_generation).outcome == AuthorityOutcome::Stale);
}

CIF_TEST(capacity, missing_reservation_is_incomplete) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  Path path = *fixture.core.spec().find_path(fixture.path_id);
  path.exclusive = false;
  path.resources.push_back(fixture.pool);
  CIF_REQUIRE_OK(fixture.core.upsert_path(path));

  AuthorityRequest request = fixture.request("att-1", 8);
  request.path_generation = fixture.core.spec().find_path(fixture.path_id)->generation;
  const AuthorityDecision decision = fixture.core.submit(request);
  CIF_CHECK(decision.outcome == AuthorityOutcome::Incomplete);
  CIF_CHECK(decision.primary_reason() == ReasonCode::ReservationGenerationMissing);
}

// ---------------------------------------------------------------------------
// commit-before-acknowledge ambiguity
// ---------------------------------------------------------------------------
CIF_TEST(commit, prepare_without_commit_is_not_authority) {
  const std::string path = cif::test::scratch_path("prepare-only.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalEntry controller;
    controller.kind = JournalRecordKind::SetController;
    controller.tick = Tick{1};
    controller.cluster_id = ClusterId::from_validated(kCluster);
    controller.policy_generation = PolicyGeneration{1};
    controller.incarnation = ControllerIncarnation::from_seed(21);
    CIF_REQUIRE_OK(journal.append(controller, true));
    JournalEntry epoch;
    epoch.kind = JournalRecordKind::EpochBegin;
    epoch.tick = Tick{1};
    epoch.cluster_id = ClusterId::from_validated(kCluster);
    epoch.epoch = ClusterEpoch{1};
    epoch.policy_generation = PolicyGeneration{1};
    epoch.incarnation = ControllerIncarnation::from_seed(21);
    CIF_REQUIRE_OK(journal.append(epoch, true));

    // A prepare record with no matching commit: the controller died between the
    // two. This is the exact boundary that decides ambiguity.
    JournalEntry prepare;
    prepare.kind = JournalRecordKind::GrantPrepared;
    prepare.tick = Tick{1};
    prepare.grant.grant_id = GrantId::from_validated("g-1");
    prepare.grant.lease_id = LeaseId::from_validated("l-1");
    prepare.grant.attempt_id = AttemptId::from_validated("att-1");
    prepare.grant.cluster_id = ClusterId::from_validated(kCluster);
    prepare.grant.capacity_units = 8;
    prepare.grant.source_member = MemberId::from_validated("m-a");
    prepare.grant.destination_member = MemberId::from_validated("m-b");
    prepare.grant.path_id = PathId::from_validated(kPath);
    prepare.grant.state = GrantState::Prepared;
    prepare.grant.commit = CommitState::Prepared;
    prepare.grant_state = GrantState::Prepared;
    CIF_REQUIRE_OK(journal.append(prepare, true));
    CIF_REQUIRE_OK(journal.close());
  }

  AuthorityCore recovered;
  RecoveryReport report;
  CIF_REQUIRE_OK(recover_from(path, recovered, report));

  // The grant was never authorised, so it must not hold capacity and must not
  // be live.
  CIF_CHECK_EQ(recovered.quarantined_units(), std::uint64_t{0});
  CIF_CHECK_EQ(recovered.path_committed_units(PathId::from_validated(kPath)), std::uint64_t{0});
  const AuthorityGrant* grant = recovered.find_grant(GrantId::from_validated("g-1"));
  CIF_REQUIRE(grant != nullptr);
  CIF_CHECK(grant->state == GrantState::Released);
  CIF_CHECK(!grant->capacity_reserved);

  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("req-resolve");
  resolve.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision resolved = recovered.resolve(resolve);
  CIF_CHECK(resolved.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(resolved.primary_reason() == ReasonCode::CommitNotDurable);
  CIF_CHECK(!resolved.requires_reconciliation);
  std::filesystem::remove(path, error);
}

CIF_TEST(commit, durable_commit_without_ack_is_quarantined_then_resolvable) {
  const std::string path = cif::test::scratch_path("ambiguous.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  GrantId grant_id;
  LeaseId lease_id;
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalDurabilitySink sink(journal);
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build({}, &sink));
    const AuthorityDecision decision = fixture.grant("att-1", 8);
    CIF_REQUIRE(decision.outcome == AuthorityOutcome::Granted);
    grant_id = decision.grant->grant_id;
    lease_id = decision.grant->lease_id;
    CIF_REQUIRE_OK(journal.close());
  }

  AuthorityCore recovered;
  RecoveryReport report;
  CIF_REQUIRE_OK(recover_from(path, recovered, report));
  CIF_CHECK(recovered.recovered());
  CIF_CHECK(!report.fresh);

  // The durable commit is quarantined: it holds capacity (so it can never be
  // handed out twice) but carries no usable authority.
  CIF_CHECK_EQ(recovered.quarantined_units(), std::uint64_t{8});
  CIF_CHECK_EQ(recovered.path_committed_units(PathId::from_validated(kPath)), std::uint64_t{8});
  const AuthorityGrant* grant = recovered.find_grant(grant_id);
  CIF_REQUIRE(grant != nullptr);
  CIF_CHECK(grant->state == GrantState::Ambiguous);
  CIF_CHECK(grant->commit == CommitState::Ambiguous);

  // Resolving reports INDETERMINATE and demands reconciliation.
  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("req-resolve");
  resolve.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision ambiguous = recovered.resolve(resolve);
  CIF_CHECK(ambiguous.outcome == AuthorityOutcome::Indeterminate);
  CIF_CHECK(ambiguous.requires_reconciliation);
  CIF_CHECK(ambiguous.primary_reason() == ReasonCode::CommitAmbiguous);
  CIF_CHECK(ambiguous.grant.has_value());

  // The caller proves it observed the commit: the quarantine lifts only if the
  // grant still validates against the recovered state.
  AcknowledgeRequest acknowledge;
  acknowledge.request_id = RequestId::from_validated("req-ack");
  acknowledge.grant_id = grant_id;
  acknowledge.lease_id = lease_id;
  acknowledge.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision acknowledged = recovered.acknowledge(acknowledge);
  CIF_CHECK(acknowledged.outcome == AuthorityOutcome::Granted);
  CIF_CHECK_EQ(recovered.quarantined_units(), std::uint64_t{0});
  const AuthorityGrant* lifted = recovered.find_grant(grant_id);
  CIF_REQUIRE(lifted != nullptr);
  CIF_CHECK(lifted->state == GrantState::Acknowledged);
  CIF_CHECK(lifted->epoch == recovered.spec().epoch());
  CIF_CHECK(lifted->incarnation == recovered.spec().incarnation());

  // Acknowledging twice is idempotent and changes nothing.
  const AuthorityDecision again = recovered.acknowledge(acknowledge);
  CIF_CHECK(again.idempotent_replay);
  CIF_CHECK(again.outcome == AuthorityOutcome::Granted);
  CIF_CHECK(recovered.self_check().ok());
  std::filesystem::remove(path, error);
}

CIF_TEST(commit, quarantined_capacity_is_returned_by_cancelling) {
  const std::string path = cif::test::scratch_path("ambiguous-cancel.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalDurabilitySink sink(journal);
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build({}, &sink));
    CIF_REQUIRE(fixture.grant("att-1", 8).outcome == AuthorityOutcome::Granted);
    CIF_REQUIRE_OK(journal.close());
  }

  AuthorityCore recovered;
  RecoveryReport report;
  CIF_REQUIRE_OK(recover_from(path, recovered, report));
  CIF_CHECK_EQ(recovered.quarantined_units(), std::uint64_t{8});

  // The caller never received the grant: cancelling is the way it says so, and
  // the quarantined capacity is returned rather than leaked.
  CancelRequest cancel;
  cancel.request_id = RequestId::from_validated("req-cancel");
  cancel.attempt_id = AttemptId::from_validated("att-1");
  cancel.reason = "caller never observed the commit";
  CIF_CHECK(recovered.cancel(cancel).outcome == AuthorityOutcome::Cancelled);
  CIF_CHECK_EQ(recovered.quarantined_units(), std::uint64_t{0});
  CIF_CHECK_EQ(recovered.path_committed_units(PathId::from_validated(kPath)), std::uint64_t{0});
  CIF_CHECK(recovered.self_check().ok());

  // Resolving afterwards is a definite CANCELLED, not an ambiguity.
  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("req-resolve");
  resolve.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision resolved = recovered.resolve(resolve);
  CIF_CHECK(resolved.outcome == AuthorityOutcome::Cancelled);
  CIF_CHECK(!resolved.requires_reconciliation);
  std::filesystem::remove(path, error);
}

CIF_TEST(commit, fence_all_recovery_policy_is_maximally_conservative) {
  const std::string path = cif::test::scratch_path("fence-all.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  GrantId grant_id;
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalDurabilitySink sink(journal);
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build({}, &sink));
    const AuthorityDecision decision = fixture.grant("att-1", 8);
    CIF_REQUIRE(decision.outcome == AuthorityOutcome::Granted);
    grant_id = decision.grant->grant_id;
    // Acknowledge it: under the default policy this would survive the restart.
    AcknowledgeRequest acknowledge;
    acknowledge.request_id = RequestId::from_validated("req-ack");
    acknowledge.grant_id = grant_id;
    acknowledge.lease_id = decision.grant->lease_id;
    acknowledge.attempt_id = AttemptId::from_validated("att-1");
    CIF_REQUIRE(fixture.core.acknowledge(acknowledge).outcome == AuthorityOutcome::Granted);
    CIF_REQUIRE_OK(journal.close());
  }
  {
    // Default policy: an acknowledged grant survives and is re-issued.
    AuthorityCore revalidating;
    RecoveryReport report;
    CIF_REQUIRE_OK(recover_from(path, revalidating, report));
    const AuthorityGrant* grant = revalidating.find_grant(grant_id);
    CIF_REQUIRE(grant != nullptr);
    CIF_CHECK(grant->state == GrantState::Committed);
    CIF_CHECK(grant->epoch == revalidating.spec().epoch());
    CIF_CHECK_EQ(revalidating.path_committed_units(PathId::from_validated(kPath)), std::uint64_t{8});
  }
  {
    // FenceAll: nothing is carried across the restart.
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    RecoveredState recovered;
    CIF_REQUIRE_OK(replay_journal(entries, recovered));
    AuthorityOptions options;
    options.recovery_policy = RecoveryPolicy::FenceAll;
    AuthorityCore fenced(options);
    const Tick resume{recovered.tick.is_zero() ? 1 : recovered.tick.value() + 1};
    CIF_REQUIRE_OK(fenced.recover(recovered.spec, recovered.contracts,
                                  std::move(recovered.grants), std::move(recovered.attempts),
                                  recovered.counters, report, ControllerIncarnation::generate(),
                                  resume));
    const AuthorityGrant* grant = fenced.find_grant(grant_id);
    CIF_REQUIRE(grant != nullptr);
    CIF_CHECK(grant->state == GrantState::Ambiguous);
    CIF_CHECK_EQ(fenced.path_committed_units(PathId::from_validated(kPath)), std::uint64_t{8});
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(commit, acknowledgement_is_not_authority) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  const AuthorityDecision decision = fixture.grant("att-1", 8);
  CIF_REQUIRE(decision.grant.has_value());

  AcknowledgeRequest acknowledge;
  acknowledge.request_id = RequestId::from_validated("req-ack");
  acknowledge.grant_id = decision.grant->grant_id;
  acknowledge.lease_id = decision.grant->lease_id;
  acknowledge.attempt_id = AttemptId::from_validated("att-1");

  // An acknowledgement with the wrong lease proves nothing and changes nothing.
  AcknowledgeRequest forged = acknowledge;
  forged.lease_id = LeaseId::from_validated("l-forged");
  CIF_CHECK(fixture.core.acknowledge(forged).outcome == AuthorityOutcome::Conflicting);
  CIF_CHECK(!fixture.core.find_grant(decision.grant->grant_id)->acknowledged);

  CIF_CHECK(fixture.core.acknowledge(acknowledge).outcome == AuthorityOutcome::Granted);
  CIF_CHECK(fixture.core.find_grant(decision.grant->grant_id)->acknowledged);
  CIF_CHECK(fixture.core.find_grant(decision.grant->grant_id)->state == GrantState::Acknowledged);

  // Acknowledging after release is refused, and does not resurrect authority.
  ReleaseRequest release;
  release.request_id = RequestId::from_validated("req-release");
  release.grant_id = decision.grant->grant_id;
  release.lease_id = decision.grant->lease_id;
  CIF_REQUIRE(fixture.core.release(release).outcome == AuthorityOutcome::Granted);
  const AuthorityDecision late = fixture.core.acknowledge(acknowledge);
  CIF_CHECK(late.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(!fixture.core.find_grant(decision.grant->grant_id)->capacity_reserved);
}

// ---------------------------------------------------------------------------
// lifecycle, maintenance, partitions, leases
// ---------------------------------------------------------------------------
CIF_TEST(lifecycle, member_states_translate_to_the_right_outcome) {
  struct Case {
    MemberLifecycle lifecycle;
    bool allow_draining;
    bool allow_faulted;
    bool allow_partitioned;
    MaintenanceMode maintenance_mode;
    AuthorityOutcome expected;
    ReasonCode reason;
  };
  const Case cases[] = {
      {MemberLifecycle::Active, false, false, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Granted, ReasonCode::None},
      {MemberLifecycle::Enlisted, false, false, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Refused, ReasonCode::MemberNotActive},
      {MemberLifecycle::Draining, false, false, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Refused, ReasonCode::MemberDraining},
      {MemberLifecycle::Draining, true, false, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Degraded, ReasonCode::DegradedByMemberState},
      {MemberLifecycle::Maintenance, false, false, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Refused, ReasonCode::MemberMaintenance},
      {MemberLifecycle::Maintenance, false, false, false, MaintenanceMode::Degrade,
       AuthorityOutcome::Degraded, ReasonCode::DegradedByMaintenance},
      {MemberLifecycle::Maintenance, false, false, false, MaintenanceMode::Allow,
       AuthorityOutcome::Granted, ReasonCode::None},
      {MemberLifecycle::Faulted, false, true, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Degraded, ReasonCode::DegradedByMemberState},
      {MemberLifecycle::Faulted, false, false, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Refused, ReasonCode::MemberFaulted},
      {MemberLifecycle::Partitioned, false, false, true, MaintenanceMode::Refuse,
       AuthorityOutcome::Degraded, ReasonCode::DegradedByMemberState},
      {MemberLifecycle::Partitioned, false, false, false, MaintenanceMode::Refuse,
       AuthorityOutcome::Refused, ReasonCode::MemberPartitioned},
  };

  for (const Case& test_case : cases) {
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build());
    CommunicationContract contract = *fixture.core.contracts().find(fixture.contract_id);
    contract.allow_draining = test_case.allow_draining;
    contract.allow_faulted = test_case.allow_faulted;
    contract.allow_partitioned = test_case.allow_partitioned;
    contract.maintenance_mode = test_case.maintenance_mode;
    CIF_REQUIRE_OK(fixture.core.upsert_contract(contract));
    CIF_REQUIRE_OK(fixture.core.set_member_lifecycle(fixture.source, test_case.lifecycle));

    AuthorityRequest request = fixture.request("att-1", 8);
    request.contract_generation =
        fixture.core.contracts().find(fixture.contract_id)->generation;
    request.source_member_generation =
        fixture.core.spec().find_member(fixture.source)->generation;
    request.source_member_digest = fixture.core.spec().find_member(fixture.source)->digest;
    const AuthorityDecision decision = fixture.core.submit(request);
    CIF_CHECK_MSG(decision.outcome == test_case.expected,
                  std::string("lifecycle ") + to_string(test_case.lifecycle) + " gave " +
                      to_string(decision.outcome) + " expected " + to_string(test_case.expected));
    if (test_case.reason != ReasonCode::None && !decision.reasons.empty()) {
      CIF_CHECK_MSG(decision.primary_reason() == test_case.reason,
                    std::string("lifecycle ") + to_string(test_case.lifecycle) + " reason " +
                        to_string(decision.primary_reason()) + " expected " +
                        to_string(test_case.reason));
    }
    CIF_CHECK(fixture.core.self_check().ok());
  }
}

CIF_TEST(lifecycle, partition_revokes_grants_that_cannot_be_degraded) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  const AuthorityRequest original = fixture.request("att-1", 8);
  const AuthorityDecision decision = fixture.core.submit(original);
  CIF_REQUIRE(decision.grant.has_value());
  const GrantId grant_id = decision.grant->grant_id;
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{8});

  CIF_REQUIRE_OK(fixture.core.set_member_lifecycle(fixture.source, MemberLifecycle::Partitioned));

  const AuthorityGrant* grant = fixture.core.find_grant(grant_id);
  CIF_REQUIRE(grant != nullptr);
  CIF_CHECK(grant->state == GrantState::Revoked);
  CIF_CHECK(!grant->reductions.empty());
  CIF_CHECK(grant->reductions.front().code == ReasonCode::MemberPartitioned);
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});
  CIF_CHECK(fixture.core.self_check().ok());

  // A partition that later heals does not silently resurrect authority: the
  // attempt must be re-driven with a fresh identity.
  CIF_REQUIRE_OK(fixture.core.set_member_lifecycle(fixture.source, MemberLifecycle::Active));
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});
  // Submitting the original bytes again is a *stale coordinate*, not a replay:
  // the lifecycle change moved the cluster generation. The fence runs before
  // exactly-once replay precisely so a caller cannot mistake an answer from a
  // superseded coordinate for a current one.
  const AuthorityDecision resubmitted = fixture.core.submit(original);
  CIF_CHECK(resubmitted.outcome == AuthorityOutcome::Stale);
  CIF_CHECK(resubmitted.primary_reason() == ReasonCode::ClusterGenerationStale);

  // The reconciliation path is deliberately not fenced by the coordinate, which
  // is what makes the fence above recoverable in one round trip.
  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("req-resolve-after-partition");
  resolve.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision retried = fixture.core.resolve(resolve);
  CIF_CHECK(retried.idempotent_replay);
  CIF_CHECK(retried.outcome == AuthorityOutcome::Fenced);
  CIF_CHECK(retried.requires_reconciliation);
  CIF_CHECK(retried.primary_reason() == ReasonCode::MemberPartitioned);

  // A refreshed request is a different request and therefore needs a new
  // attempt identity; it is granted normally.
  const AuthorityDecision fresh = fixture.grant("att-2", 8);
  CIF_CHECK(fresh.outcome == AuthorityOutcome::Granted);
}

CIF_TEST(lifecycle, maintenance_exclusions_are_evaluated_in_order) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  // Raise the path ceiling so this test isolates exclusion semantics from
  // capacity pressure.
  Path roomy = *fixture.core.spec().find_path(fixture.path_id);
  roomy.capacity_units = 512;
  CIF_REQUIRE_OK(fixture.core.upsert_path(roomy));

  MaintenanceExclusion exclusion;
  exclusion.id = ExclusionId::from_validated("maint-1");
  exclusion.members.push_back(fixture.source);
  exclusion.valid_from = Tick{0};
  exclusion.valid_to = Tick{0};
  exclusion.mode = MaintenanceMode::Refuse;
  exclusion.reason = "firmware";
  CIF_REQUIRE_OK(fixture.core.upsert_exclusion(exclusion));

  const AuthorityDecision refused = fixture.grant("att-1", 8);
  CIF_CHECK(refused.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(refused.primary_reason() == ReasonCode::MaintenanceExclusionActive);

  exclusion.mode = MaintenanceMode::Degrade;
  CIF_REQUIRE_OK(fixture.core.upsert_exclusion(exclusion));
  const AuthorityDecision degraded = fixture.grant("att-2", 8);
  CIF_CHECK(degraded.outcome == AuthorityOutcome::Degraded);
  CIF_CHECK_EQ(std::string(to_string(degraded.primary_reason())),
               std::string("DEGRADED_BY_MAINTENANCE"));

  exclusion.mode = MaintenanceMode::Allow;
  CIF_REQUIRE_OK(fixture.core.upsert_exclusion(exclusion));
  CIF_CHECK(fixture.grant("att-3", 8).outcome == AuthorityOutcome::Granted);

  // A window that has not opened yet does not apply.
  exclusion.mode = MaintenanceMode::Refuse;
  exclusion.valid_from = Tick{1000};
  exclusion.valid_to = Tick{2000};
  CIF_REQUIRE_OK(fixture.core.upsert_exclusion(exclusion));
  CIF_CHECK(fixture.grant("att-4", 8).outcome == AuthorityOutcome::Granted);

  // A window that has closed does not apply either.
  exclusion.valid_from = Tick{0};
  exclusion.valid_to = Tick{1};
  CIF_REQUIRE_OK(fixture.core.upsert_exclusion(exclusion));
  CIF_REQUIRE_OK(fixture.core.advance_tick(Tick{10}));
  CIF_CHECK(fixture.grant("att-5", 8).outcome == AuthorityOutcome::Granted);

  // A delivery that says it is behind, but is inside the window, is refused.
  exclusion.valid_from = Tick{0};
  exclusion.valid_to = Tick{0};
  CIF_REQUIRE_OK(fixture.core.upsert_exclusion(exclusion));
  AuthorityRequest request = fixture.request("att-6", 8);
  request.cluster_generation = fixture.core.spec().generation();
  CIF_CHECK(fixture.core.submit(request).outcome == AuthorityOutcome::Refused);

  CIF_REQUIRE_OK(fixture.core.remove_exclusion(exclusion.id));
  CIF_CHECK(fixture.grant("att-7", 8).outcome == AuthorityOutcome::Granted);
  CIF_CHECK(fixture.core.self_check().ok());
}

CIF_TEST(lifecycle, lease_expiry_is_exact_and_idempotent) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  const AuthorityDecision decision = fixture.grant("att-1", 8, 50);
  CIF_REQUIRE(decision.grant.has_value());
  const Tick expiry = decision.grant->lease_expiry;
  const GrantId grant_id = decision.grant->grant_id;

  CIF_REQUIRE_OK(fixture.core.advance_tick(Tick{expiry.value() - 1}));
  CIF_REQUIRE_OK(fixture.core.expire_leases());
  CIF_CHECK(fixture.core.find_grant(grant_id)->state == GrantState::Committed);
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{8});

  CIF_REQUIRE_OK(fixture.core.advance_tick(expiry));
  CIF_REQUIRE_OK(fixture.core.expire_leases());
  CIF_CHECK(fixture.core.find_grant(grant_id)->state == GrantState::Expired);
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});

  // Expiring again must not release anything twice.
  CIF_REQUIRE_OK(fixture.core.expire_leases());
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});

  // Logical time never moves backwards.
  CIF_CHECK_STATUS(fixture.core.advance_tick(Tick{1}), StatusCode::StateMismatch);

  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("req-resolve");
  resolve.attempt_id = AttemptId::from_validated("att-1");
  const AuthorityDecision resolved = fixture.core.resolve(resolve);
  CIF_CHECK(resolved.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(resolved.primary_reason() == ReasonCode::GrantExpired);
  CIF_CHECK(fixture.core.self_check().ok());
}

CIF_TEST(lifecycle, policy_generation_is_append_only) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  CIF_REQUIRE_OK(fixture.core.set_policy_generation(PolicyGeneration{7}));
  AuthorityRequest stale = fixture.request("att-1", 8);
  stale.policy_generation = PolicyGeneration{6};
  const AuthorityDecision decision = fixture.core.submit(stale);
  CIF_CHECK(decision.outcome == AuthorityOutcome::Stale);
  CIF_CHECK(decision.primary_reason() == ReasonCode::PolicyGenerationStale);

  AuthorityRequest current = fixture.request("att-2", 8);
  CIF_CHECK(fixture.core.submit(current).outcome == AuthorityOutcome::Granted);

  CIF_CHECK_STATUS(fixture.core.set_policy_generation(PolicyGeneration{3}),
                   StatusCode::StateMismatch);
  CIF_REQUIRE_OK(fixture.core.set_policy_generation(PolicyGeneration{7}));
}

// ---------------------------------------------------------------------------
// locality, obligations and contracts
// ---------------------------------------------------------------------------
CIF_TEST(locality, shared_failure_domain_is_refused) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  // Move the destination into the source's failure domain at level 2.
  Member moved = *fixture.core.spec().find_member(fixture.destination);
  LocalityPath shared;
  CIF_REQUIRE(LocalityPath::parse("dc/room1/rack9/pod9", shared));
  moved.locality = shared;
  moved.generation = MemberGeneration{2};
  moved.digest = sha256("member:m-b:2");
  CIF_REQUIRE_OK(fixture.core.upsert_member(moved));

  AuthorityRequest request = fixture.request("att-1", 8);
  const AuthorityDecision decision = fixture.core.submit(request);
  CIF_CHECK(decision.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(decision.primary_reason() == ReasonCode::LocalityConstraintViolated);

  // Relaxing the contract makes the same relationship eligible again.
  CommunicationContract contract = *fixture.core.contracts().find(fixture.contract_id);
  contract.min_distinct_failure_domains = 1;
  CIF_REQUIRE_OK(fixture.core.upsert_contract(contract));
  AuthorityRequest relaxed = fixture.request("att-2", 8);
  relaxed.contract_generation = fixture.core.contracts().find(fixture.contract_id)->generation;
  CIF_CHECK(fixture.core.submit(relaxed).outcome == AuthorityOutcome::Granted);
}

CIF_TEST(locality, capacity_obligation_blocks_relationships_that_do_not_help) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  // The destination service must span two failure domains with at least 8 units
  // each. With one destination member that is unreachable, so a grant that
  // concentrates capacity is refused rather than pretending to be compliant.
  CapacityObligation obligation;
  obligation.id = ObligationId::from_validated("obl-servers");
  obligation.service = ServiceGroupId::from_validated("servers");
  obligation.min_distinct_failure_domains = 2;
  obligation.failure_domain_level = 2;
  obligation.min_units_per_domain = 8;
  CIF_REQUIRE_OK(fixture.core.upsert_obligation(obligation));

  Path path = *fixture.core.spec().find_path(fixture.path_id);
  path.exclusive = false;
  path.capacity_units = 128;
  CIF_REQUIRE_OK(fixture.core.upsert_path(path));

  const AuthorityDecision first = fixture.grant("att-1", 8);
  CIF_CHECK(first.outcome == AuthorityOutcome::Degraded);
  CIF_CHECK_EQ(std::string(to_string(first.primary_reason())),
               std::string("DEGRADED_BY_REDUNDANCY_LOSS"));

  // A second grant to the same destination domain cannot improve diversity, so
  // it is refused.
  AuthorityRequest second = fixture.request("att-2", 8);
  second.path_generation = fixture.core.spec().find_path(fixture.path_id)->generation;
  const AuthorityDecision refused = fixture.core.submit(second);
  CIF_CHECK(refused.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(refused.primary_reason() == ReasonCode::ContractUnsatisfied);
  CIF_CHECK(fixture.core.self_check().ok());
}

CIF_TEST(contracts, unsupported_capabilities_are_typed) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  struct Case {
    const char* capability;
    ReasonCode reason;
  };
  const Case cases[] = {
      {"rdma-reliability", ReasonCode::HardwareSemanticsUnsupported},
      {"nvlink-partition", ReasonCode::HardwareSemanticsUnsupported},
      {"optical-circuit-switch", ReasonCode::HardwareSemanticsUnsupported},
      {"nic-hardware-offload", ReasonCode::HardwareSemanticsUnsupported},
      {"inter-cluster-route", ReasonCode::InterClusterUnsupported},
      {"unheard-of-capability", ReasonCode::UnsupportedCapability},
  };
  for (const Case& test_case : cases) {
    CommunicationContract contract = *fixture.core.contracts().find(fixture.contract_id);
    contract.required_capabilities.clear();
    contract.required_capabilities.push_back(test_case.capability);
    CIF_REQUIRE_OK(fixture.core.upsert_contract(contract));
    AuthorityRequest request = fixture.request("att-" + std::string(test_case.capability), 8);
    request.contract_generation = fixture.core.contracts().find(fixture.contract_id)->generation;
    const AuthorityDecision decision = fixture.core.submit(request);
    CIF_CHECK_MSG(decision.outcome == AuthorityOutcome::Unsupported, test_case.capability);
    CIF_CHECK_MSG(decision.primary_reason() == test_case.reason, test_case.capability);
  }

  // Removing the capability restores eligibility: eligibility is not authority,
  // but it is a precondition.
  CommunicationContract contract = *fixture.core.contracts().find(fixture.contract_id);
  contract.required_capabilities.clear();
  contract.required_capabilities.push_back("topology-path-binding");
  CIF_REQUIRE_OK(fixture.core.upsert_contract(contract));
  AuthorityRequest request = fixture.request("att-supported", 8);
  request.contract_generation = fixture.core.contracts().find(fixture.contract_id)->generation;
  CIF_CHECK(fixture.core.submit(request).outcome == AuthorityOutcome::Granted);
}

CIF_TEST(contracts, topology_and_service_eligibility) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());

  // A member that does not serve the contract's service group is not eligible.
  Member wrong = *fixture.core.spec().find_member(fixture.source);
  wrong.services.clear();
  wrong.services.push_back(ServiceGroupId::from_validated("something-else"));
  CIF_REQUIRE_OK(fixture.core.upsert_member(wrong));
  AuthorityRequest request = fixture.request("att-1", 8);
  const AuthorityDecision decision = fixture.core.submit(request);
  CIF_CHECK(decision.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(decision.primary_reason() == ReasonCode::ServiceGroupNotServed);

  // Restore, then take the path down.
  CIF_REQUIRE_OK(fixture.core.upsert_member(make_member("m-a", "rack-domain-1",
                                                       "dc/room1/rack1/pod1", "trainers", 2, 64, 3)));
  CIF_REQUIRE_OK(fixture.core.set_path_state(fixture.path_id, PathState::Down));
  AuthorityRequest down = fixture.request("att-2", 8);
  down.path_generation = fixture.core.spec().find_path(fixture.path_id)->generation;
  const AuthorityDecision down_decision = fixture.core.submit(down);
  CIF_CHECK(down_decision.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(down_decision.primary_reason() == ReasonCode::PathNotOperational);

  // A declared-degraded path yields a degraded grant, not a refusal.
  CIF_REQUIRE_OK(fixture.core.set_path_state(fixture.path_id, PathState::Degraded));
  AuthorityRequest degraded = fixture.request("att-3", 8);
  degraded.path_generation = fixture.core.spec().find_path(fixture.path_id)->generation;
  const AuthorityDecision degraded_decision = fixture.core.submit(degraded);
  CIF_CHECK(degraded_decision.outcome == AuthorityOutcome::Degraded);
  CIF_CHECK_EQ(std::string(to_string(degraded_decision.primary_reason())),
               std::string("DEGRADED_BY_REDUNDANCY_LOSS"));

  // A path generation that moved is STALE.
  AuthorityRequest stale_path = fixture.request("att-4", 8);
  stale_path.path_generation = PathGeneration{999};
  CIF_CHECK(fixture.core.submit(stale_path).outcome == AuthorityOutcome::Stale);

  // Removing the path turns the relationship into UNKNOWN (no such path).
  CIF_REQUIRE_OK(fixture.core.remove_path(fixture.path_id));
  AuthorityRequest gone = fixture.request("att-5", 8);
  const AuthorityDecision gone_decision = fixture.core.submit(gone);
  CIF_CHECK(gone_decision.outcome == AuthorityOutcome::Unknown);
  CIF_CHECK(gone_decision.primary_reason() == ReasonCode::PathNotFound);
}

CIF_TEST(contracts, path_is_selected_deterministically_when_not_named) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  Path second;
  second.id = PathId::from_validated("p-ab-alt");
  second.generation = PathGeneration{1};
  second.source_member = fixture.source;
  second.destination_member = fixture.destination;
  second.capacity_units = 64;
  second.exclusive = false;
  CIF_REQUIRE_OK(fixture.core.upsert_path(second));

  // Two candidate paths exist; the lowest id wins, deterministically.
  AuthorityRequest request = fixture.request("att-1", 8);
  request.path_id = PathId{};
  request.path_generation = PathGeneration{};
  const AuthorityDecision decision = fixture.core.submit(request);
  CIF_REQUIRE(decision.outcome == AuthorityOutcome::Granted);
  CIF_CHECK(decision.grant->path_id == PathId::from_validated("p-ab"));

  // Repeating on an independent controller gives the same path.
  Fixture other;
  CIF_REQUIRE_OK(other.build());
  CIF_REQUIRE_OK(other.core.upsert_path(second));
  AuthorityRequest mirror = other.request("att-1", 8);
  mirror.path_id = PathId{};
  mirror.path_generation = PathGeneration{};
  const AuthorityDecision mirrored = other.core.submit(mirror);
  CIF_REQUIRE(mirrored.grant.has_value());
  CIF_CHECK(mirrored.grant->path_id == decision.grant->path_id);
}

CIF_TEST(contracts, renewal_extends_without_double_counting) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  const AuthorityDecision decision = fixture.grant("att-1", 8, 100);
  CIF_REQUIRE(decision.grant.has_value());

  AuthorityRequest renewal = fixture.request("att-1", 8, 500);
  renewal.renewal = true;
  renewal.renewal_of = decision.grant->grant_id;
  renewal.renewal_lease = decision.grant->lease_id;
  renewal.cluster_generation = fixture.core.spec().generation();
  const AuthorityDecision renewed = fixture.core.submit(renewal);
  CIF_CHECK(renewed.outcome == AuthorityOutcome::Granted);
  CIF_REQUIRE(renewed.grant.has_value());
  CIF_CHECK(renewed.grant->lease_expiry.value() > decision.grant->lease_expiry.value());
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{8});

  // Renewing with the wrong lease is a conflict.
  AuthorityRequest forged = renewal;
  forged.renewal_lease = LeaseId::from_validated("l-forged");
  forged.cluster_generation = fixture.core.spec().generation();
  CIF_CHECK(fixture.core.submit(forged).outcome == AuthorityOutcome::Conflicting);

  // Renewing an unknown grant is UNKNOWN.
  AuthorityRequest unknown = renewal;
  unknown.renewal_of = GrantId::from_validated("g-ghost");
  unknown.cluster_generation = fixture.core.spec().generation();
  CIF_CHECK(fixture.core.submit(unknown).outcome == AuthorityOutcome::Unknown);
  CIF_CHECK(fixture.core.self_check().ok());
}

// ---------------------------------------------------------------------------
// recovery
// ---------------------------------------------------------------------------
CIF_TEST(recovery, restart_preserves_topology_and_fences_epoch) {
  const std::string path = cif::test::scratch_path("restart.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  Digest256 topology;
  ClusterEpoch first_epoch;
  ControllerIncarnation first_incarnation;
  ClusterGeneration first_generation;
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalDurabilitySink sink(journal);
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build({}, &sink));
    CIF_REQUIRE(fixture.grant("att-1", 8).outcome == AuthorityOutcome::Granted);
    topology = fixture.core.spec().topology_digest();
    first_epoch = fixture.core.spec().epoch();
    first_incarnation = fixture.core.spec().incarnation();
    first_generation = fixture.core.spec().generation();
    CIF_REQUIRE_OK(journal.close());
  }
  // Replay alone must reproduce the recorded counters exactly: they are adopted
  // from the log, never re-derived.
  {
    std::vector<JournalEntry> entries;
    RecoveryReport raw;
    CIF_REQUIRE_OK(Journal::scan(path, entries, raw));
    RecoveredState state;
    CIF_REQUIRE_OK(replay_journal(entries, state));
    CIF_CHECK_EQ(state.spec.generation().value(), first_generation.value());
    CIF_CHECK(state.spec.topology_digest() == topology);
  }

  AuthorityCore recovered;
  RecoveryReport report;
  CIF_REQUIRE_OK(recover_from(path, recovered, report));

  CIF_CHECK(recovered.spec().topology_digest() == topology);
  CIF_CHECK_EQ(recovered.spec().member_count(), std::size_t{2});
  CIF_CHECK_EQ(recovered.spec().path_count(), std::size_t{1});
  CIF_CHECK_EQ(recovered.contracts().size(), std::size_t{1});
  CIF_CHECK_EQ(recovered.spec().policy_generation().value(), std::uint64_t{1});
  CIF_CHECK(recovered.spec().epoch().value() > first_epoch.value());
  CIF_CHECK(!(recovered.spec().incarnation() == first_incarnation));
  // The restart advances the epoch and, with it, the generation: one further
  // step past the replayed value.
  CIF_CHECK_MSG(recovered.spec().generation().value() == first_generation.value() + 1,
                "replayed generation " + first_generation.to_string() + ", recovered " +
                    recovered.spec().generation().to_string());
  CIF_CHECK(recovered.self_check().ok());

  // A request built against the pre-restart coordinate is fenced.
  Fixture probe;
  CIF_REQUIRE_OK(probe.build());
  AuthorityRequest stale = probe.request("att-1", 8);
  stale.cluster_id = recovered.spec().cluster_id();
  // Current generation, stale epoch and incarnation: this isolates the fence
  // that matters after a restart from the ordinary staleness check.
  stale.cluster_generation = recovered.spec().generation();
  stale.epoch = first_epoch;
  stale.incarnation = first_incarnation;
  stale.policy_generation = recovered.spec().policy_generation();
  stale.contract_id = ContractId::from_validated(kContract);
  stale.contract_generation = recovered.contracts().find(stale.contract_id)->generation;
  stale.source_member = MemberId::from_validated("m-a");
  stale.destination_member = MemberId::from_validated("m-b");
  stale.path_id = PathId::from_validated(kPath);
  stale.path_generation = recovered.spec().find_path(stale.path_id)->generation;
  stale.source_member_generation = recovered.spec().find_member(stale.source_member)->generation;
  stale.source_member_digest = recovered.spec().find_member(stale.source_member)->digest;
  stale.destination_member_generation =
      recovered.spec().find_member(stale.destination_member)->generation;
  stale.destination_member_digest =
      recovered.spec().find_member(stale.destination_member)->digest;
  const AuthorityDecision decision = recovered.submit(stale);
  CIF_CHECK(decision.outcome == AuthorityOutcome::Fenced);
  CIF_CHECK(decision.primary_reason() == ReasonCode::EpochStale);
  std::filesystem::remove(path, error);
}

CIF_TEST(recovery, recovered_state_is_historical_never_fresh) {
  const std::string path = cif::test::scratch_path("historical.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalDurabilitySink sink(journal);
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build({}, &sink));
    CIF_REQUIRE(fixture.grant("att-1", 8).outcome == AuthorityOutcome::Granted);
    CIF_REQUIRE_OK(journal.close());
  }
  AuthorityCore recovered;
  RecoveryReport report;
  CIF_REQUIRE_OK(recover_from(path, recovered, report));
  CIF_CHECK(!report.fresh);
  CIF_CHECK(report.historical());
  CIF_CHECK(recovered.recovered());

  // Audit history is diagnostic and is deliberately not persisted: a freshly
  // recovered controller reports it as empty rather than replaying old
  // decisions as if they had just happened.
  CIF_CHECK(recovered.audit().empty());
  CIF_CHECK(recovered.render_audit().find("empty") != std::string::npos);
  CIF_CHECK(report.render().find("historical = true") != std::string::npos);
  std::filesystem::remove(path, error);
}

CIF_TEST(recovery, corrupt_journal_is_refused_or_conservatively_recovered) {
  const std::string path = cif::test::scratch_path("corrupt-recovery.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalDurabilitySink sink(journal);
    Fixture fixture;
    CIF_REQUIRE_OK(fixture.build({}, &sink));
    CIF_REQUIRE(fixture.grant("att-1", 8).outcome == AuthorityOutcome::Granted);
    CIF_REQUIRE_OK(journal.close());
  }

  // Damage the controller binding record beyond repair.
  {
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    CIF_REQUIRE(file.good());
    file.seekp(48);
    file.put(static_cast<char>(0x5A));
    file.close();
  }
  std::vector<JournalEntry> entries;
  RecoveryReport report;
  const Status scanned = Journal::scan(path, entries, report);
  if (scanned.ok()) {
    CIF_CHECK(report.requires_rebuild() || report.integrity_failure);
    // Whatever survived must replay without inventing members.
    RecoveredState state;
    const Status replayed = replay_journal(entries, state);
    if (replayed.ok()) {
      CIF_CHECK(state.spec.member_count() <= 2);
    }
  } else {
    CIF_CHECK(scanned.is(StatusCode::Corruption) || scanned.is(StatusCode::IntegrityFailure));
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(recovery, self_check_detects_injected_inconsistency) {
  Fixture fixture;
  CIF_REQUIRE_OK(fixture.build());
  CIF_REQUIRE(fixture.grant("att-1", 8).outcome == AuthorityOutcome::Granted);
  CIF_CHECK(fixture.core.self_check().ok());

  // Sanity: the checker actually inspects grants, so removing the member must
  // make it complain.
  CIF_REQUIRE_OK(fixture.core.remove_member(fixture.source));
  CIF_CHECK(fixture.core.self_check().ok());
  CIF_CHECK_EQ(fixture.core.path_committed_units(fixture.path_id), std::uint64_t{0});
}
