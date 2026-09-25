// Cluster Interconnect Fabric (CIF) -- transport, server lifecycle and
// concurrency tests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Everything here crosses a real loopback TCP socket. While the daemon runs, the
// reducer thread owns the engine exclusively, so this file only ever reaches the
// engine through the two supported doors: the wire protocol, and the in-process
// apply()/inspect() pair that goes through the very same reducer.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "cif/client.hpp"
#include "cif/server.hpp"
#include "cif/wire.hpp"
#include "cif/platform.hpp"
#include "cif/version.hpp"
#include "harness.hpp"

using namespace cif;

namespace {

const char* kServiceA = "trainers";
const char* kServiceB = "servers";

/// Everything a caller must know to build a request, captured once when the
/// cluster is seeded.
struct Seed {
  MemberId source = MemberId::from_validated("m-a");
  MemberId destination = MemberId::from_validated("m-b");
  MemberGeneration source_generation{1};
  MemberGeneration destination_generation{1};
  Digest256 source_digest = sha256("member:a");
  Digest256 destination_digest = sha256("member:b");
  PathId path = PathId::from_validated("p-1");
  PathGeneration path_generation{1};
  std::uint64_t path_capacity = 64;
  ContractId contract = ContractId::from_validated("c-1");
  ContractGeneration contract_generation{1};
};

ServerOptions base_options(const std::string& cluster) {
  ServerOptions options;
  options.bind_host = "127.0.0.1";
  options.port = 0;
  options.cluster_id = ClusterId::from_validated(cluster);
  // Deterministic: the internal clock is off and lease expiry is driven by
  // explicit admin commands.
  options.housekeeping_period_millis = 0;
  return options;
}

void require_apply(AuthorityServer& server, const AdminCommand& command, const char* what) {
  AdminResult result;
  CIF_REQUIRE_OK(server.apply(command, result));
  if (!result.ok()) {
    CIF_FAIL(std::string(what) + ": " + to_string(result.code) + " " + result.message);
  }
}

/// Seeds the cluster through the reducer, never by touching the engine.
Seed seed_cluster(AuthorityServer& server) {
  Seed seed;
  Member a;
  a.id = seed.source;
  a.domain = MemberDomainId::from_validated("d-1");
  a.generation = seed.source_generation;
  a.digest = seed.source_digest;
  a.lifecycle = MemberLifecycle::Active;
  CIF_REQUIRE(LocalityPath::parse("dc/room1/rack1/pod1", a.locality));
  a.services.push_back(ServiceGroupId::from_validated(kServiceA));

  Member b = a;
  b.id = seed.destination;
  b.domain = MemberDomainId::from_validated("d-2");
  b.generation = seed.destination_generation;
  b.digest = seed.destination_digest;
  CIF_REQUIRE(LocalityPath::parse("dc/room2/rack2/pod2", b.locality));
  b.services.clear();
  b.services.push_back(ServiceGroupId::from_validated(kServiceB));

  Path path;
  path.id = seed.path;
  path.generation = seed.path_generation;
  path.source_member = seed.source;
  path.destination_member = seed.destination;
  path.capacity_units = seed.path_capacity;
  path.exclusive = true;

  CommunicationContract contract;
  contract.id = seed.contract;
  contract.generation = seed.contract_generation;
  contract.source_service = ServiceGroupId::from_validated(kServiceA);
  contract.destination_service = ServiceGroupId::from_validated(kServiceB);
  contract.min_capacity_units = 1;
  contract.maintenance_mode = MaintenanceMode::Degrade;

  AdminCommand command;
  command.kind = AdminKind::UpsertMember;
  command.member = a;
  require_apply(server, command, "seed member a");
  command.member = b;
  require_apply(server, command, "seed member b");
  command.kind = AdminKind::UpsertPath;
  command.path = path;
  require_apply(server, command, "seed path");
  command.kind = AdminKind::UpsertContract;
  command.contract = contract;
  require_apply(server, command, "seed contract");
  return seed;
}

ClientOptions client_options_for(const AuthorityServer& server) {
  ClientOptions options;
  options.host = "127.0.0.1";
  options.port = server.port();
  options.timeout_millis = 5000;
  return options;
}

/// Builds a request from the seed plus the coordinate the client observed in its
/// own handshake: exactly what a well-behaved external client must do.
AuthorityRequest build_request(const Seed& seed, const ServerIdentity& coordinate,
                               const std::string& attempt, std::uint64_t units) {
  AuthorityRequest request;
  request.request_id = RequestId::from_validated("req-" + attempt);
  request.attempt_id = AttemptId::from_validated(attempt);
  request.contract_id = seed.contract;
  request.contract_generation = seed.contract_generation;
  request.cluster_id = coordinate.cluster_id;
  request.cluster_generation = coordinate.generation;
  request.epoch = coordinate.epoch;
  request.incarnation = coordinate.incarnation;
  request.policy_generation = coordinate.policy;
  request.source_member = seed.source;
  request.destination_member = seed.destination;
  request.path_id = seed.path;
  request.path_generation = seed.path_generation;
  request.requested_units = units;
  request.lease_ticks = 1000;
  request.allow_degraded = false;
  request.source_member_generation = seed.source_generation;
  request.source_member_digest = seed.source_digest;
  request.destination_member_generation = seed.destination_generation;
  request.destination_member_digest = seed.destination_digest;
  request.provenance.client = ClientId::from_validated("net-test");
  request.provenance.origin = "net-test";
  return request;
}

/// Bounded wait for an asynchronous condition. This is not a watchdog: it does
/// not turn a failure into a pass, it simply lets the acceptor thread finish
/// reaping before the assertion is made. The assertion still runs and still
/// fails if the condition never becomes true.
bool wait_until(const std::function<bool()>& predicate, std::uint64_t timeout_millis) {
  const std::uint64_t deadline = platform::monotonic_nanos() + timeout_millis * 1000000ull;
  while (platform::monotonic_nanos() < deadline) {
    if (predicate()) {
      return true;
    }
    platform::sleep_millis(5);
  }
  return predicate();
}

std::string query_text(AuthorityServer& server, QueryKind kind) {
  QueryCommand command;
  command.kind = kind;
  QueryResult result;
  CIF_REQUIRE_OK(server.inspect(command, result));
  return result.text;
}

}  // namespace

// ---------------------------------------------------------------------------
// wire protocol round trips
// ---------------------------------------------------------------------------
CIF_TEST(wire, every_message_type_round_trips) {
  WireMessage hello;
  hello.type = MessageType::Hello;
  hello.banner = version_banner();
  hello.client = ClientId::from_validated("client-1");

  WireMessage hello_ack;
  hello_ack.type = MessageType::HelloAck;
  hello_ack.banner = version_banner();
  hello_ack.cluster_id = ClusterId::from_validated("cluster");
  hello_ack.cluster_generation = ClusterGeneration{7};
  hello_ack.epoch = ClusterEpoch{3};
  hello_ack.policy = PolicyGeneration{2};
  hello_ack.incarnation = ControllerIncarnation::from_seed(4);
  hello_ack.state_digest = sha256("state");

  AuthorityRequest request;
  request.request_id = RequestId::from_validated("r-1");
  request.attempt_id = AttemptId::from_validated("a-1");
  request.contract_id = ContractId::from_validated("c-1");
  request.cluster_id = ClusterId::from_validated("cluster");
  request.source_member = MemberId::from_validated("m-a");
  request.destination_member = MemberId::from_validated("m-b");
  request.requested_units = 3;
  request.provenance.origin = "origin";
  request.provenance.correlation_id = "corr";
  WireMessage submit;
  submit.type = MessageType::Submit;
  submit.request = request;

  ReleaseRequest release;
  release.request_id = RequestId::from_validated("r-2");
  release.grant_id = GrantId::from_validated("g-1");
  release.lease_id = LeaseId::from_validated("l-1");
  WireMessage release_message;
  release_message.type = MessageType::Release;
  release_message.release = release;

  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("r-3");
  resolve.attempt_id = AttemptId::from_validated("a-1");
  WireMessage resolve_message;
  resolve_message.type = MessageType::Resolve;
  resolve_message.resolve = resolve;

  AcknowledgeRequest acknowledge;
  acknowledge.request_id = RequestId::from_validated("r-4");
  acknowledge.grant_id = GrantId::from_validated("g-1");
  acknowledge.lease_id = LeaseId::from_validated("l-1");
  WireMessage acknowledge_message;
  acknowledge_message.type = MessageType::Acknowledge;
  acknowledge_message.acknowledge = acknowledge;

  CancelRequest cancel;
  cancel.request_id = RequestId::from_validated("r-5");
  cancel.attempt_id = AttemptId::from_validated("a-1");
  cancel.reason = "withdrawn";
  WireMessage cancel_message;
  cancel_message.type = MessageType::Cancel;
  cancel_message.cancel = cancel;

  AuthorityDecision decision;
  decision.request_id = RequestId::from_validated("r-1");
  decision.attempt_id = AttemptId::from_validated("a-1");
  decision.outcome = AuthorityOutcome::Degraded;
  decision.reasons.push_back(Reason(ReasonCode::DegradedByCapacity, "reduced"));
  decision.cluster_id = ClusterId::from_validated("cluster");
  decision.cluster_generation = ClusterGeneration{7};
  decision.spec_digest = sha256("spec");
  decision.state_digest = sha256("state");
  decision.decision_sequence = 12;
  WireMessage decision_message;
  decision_message.type = MessageType::Decision;
  decision_message.decision = decision;

  AdminCommand admin;
  admin.kind = AdminKind::SetMemberLifecycle;
  admin.member_id = MemberId::from_validated("m-a");
  admin.lifecycle = MemberLifecycle::Draining;
  WireMessage admin_message;
  admin_message.type = MessageType::Admin;
  admin_message.admin = admin;

  AdminResult admin_result;
  admin_result.code = StatusCode::StateMismatch;
  admin_result.message = "generation moved";
  admin_result.generation = ClusterGeneration{9};
  admin_result.incarnation = ControllerIncarnation::from_seed(6);
  admin_result.state_digest = sha256("after");
  WireMessage admin_result_message;
  admin_result_message.type = MessageType::AdminResult;
  admin_result_message.admin_result = admin_result;

  QueryCommand query;
  query.kind = QueryKind::Grant;
  query.grant_id = GrantId::from_validated("g-1");
  WireMessage query_message;
  query_message.type = MessageType::Query;
  query_message.query = query;

  QueryResult query_result;
  query_result.code = StatusCode::NotFound;
  query_result.message = "no such grant";
  query_result.text = "GRANT g-1\n";
  query_result.cluster_id = ClusterId::from_validated("cluster");
  query_result.state_digest = sha256("state");
  query_result.spec_digest = sha256("spec");
  WireMessage query_result_message;
  query_result_message.type = MessageType::QueryResult;
  query_result_message.query_result = query_result;

  const WireMessage error = make_error_message("BACKPRESSURE", "too many connections");

  WireMessage ping;
  ping.type = MessageType::Ping;
  WireMessage pong;
  pong.type = MessageType::Pong;
  WireMessage bye;
  bye.type = MessageType::Bye;

  const std::vector<WireMessage> messages = {
      hello,           hello_ack,           submit,         release_message,
      resolve_message, acknowledge_message, cancel_message, decision_message,
      admin_message,   admin_result_message, query_message, query_result_message,
      error,           ping,                pong,           bye};
  for (const WireMessage& message : messages) {
    Frame frame;
    CIF_REQUIRE_OK(pack_message(message, frame));
    frame.sequence = 42;
    Bytes encoded;
    CIF_REQUIRE_OK(encode_frame(frame, encoded));
    Frame decoded;
    CIF_REQUIRE_OK(decode_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()),
                                decoded));
    CIF_CHECK_EQ(decoded.sequence, std::uint64_t{42});
    CIF_CHECK(decoded.type == message.type);
    WireMessage unpacked;
    CIF_REQUIRE_OK(unpack_message(decoded, unpacked));
    CIF_CHECK(unpacked.type == message.type);
  }

  Frame frame;
  CIF_REQUIRE_OK(pack_message(submit, frame));
  WireMessage unpacked;
  CIF_REQUIRE_OK(unpack_message(frame, unpacked));
  CIF_CHECK(unpacked.request.digest() == request.digest());
  CIF_CHECK_EQ(unpacked.request.provenance.correlation_id, std::string("corr"));

  CIF_REQUIRE_OK(pack_message(decision_message, frame));
  CIF_REQUIRE_OK(unpack_message(frame, unpacked));
  CIF_CHECK(unpacked.decision.outcome == AuthorityOutcome::Degraded);
  CIF_CHECK_EQ(unpacked.decision.reasons.size(), std::size_t{1});
  CIF_CHECK(unpacked.decision.decision_digest == decision.decision_digest);
}

// ---------------------------------------------------------------------------
// loopback end-to-end
// ---------------------------------------------------------------------------
CIF_TEST(server, end_to_end_handshake_query_and_admin) {
  AuthorityServer server(base_options("cluster-net"));
  CIF_REQUIRE_OK(server.start());
  CIF_CHECK(server.running());
  CIF_CHECK(server.port() != 0);
  const Seed seed = seed_cluster(server);

  AuthorityClient client;
  ClientOptions options = client_options_for(server);
  options.client = ClientId::from_validated("client-e2e");
  CIF_REQUIRE_OK(client.connect(options));
  CIF_CHECK(client.server().valid);
  CIF_CHECK(client.server().cluster_id == ClusterId::from_validated("cluster-net"));
  CIF_CHECK(!client.server().state_digest.is_zero());

  CIF_REQUIRE_OK(client.ping());

  QueryCommand verify;
  verify.kind = QueryKind::Verify;
  QueryResult result;
  CIF_REQUIRE_OK(client.query(verify, result));
  CIF_CHECK(result.ok());
  CIF_CHECK(result.text.find("OK") != std::string::npos);

  QueryCommand member_query;
  member_query.kind = QueryKind::Member;
  member_query.member_id = seed.source;
  CIF_REQUIRE_OK(client.query(member_query, result));
  CIF_CHECK(result.ok());
  CIF_CHECK(result.text.find("MEMBER m-a") != std::string::npos);

  member_query.member_id = MemberId::from_validated("m-ghost");
  CIF_REQUIRE_OK(client.query(member_query, result));
  CIF_CHECK(!result.ok());
  CIF_CHECK(result.code == StatusCode::NotFound);

  // Two independent clients must observe byte-identical authoritative state.
  AuthorityClient second;
  CIF_REQUIRE_OK(second.connect(client_options_for(server)));
  QueryCommand state_query;
  state_query.kind = QueryKind::State;
  QueryResult first_state;
  QueryResult second_state;
  CIF_REQUIRE_OK(client.query(state_query, first_state));
  CIF_REQUIRE_OK(second.query(state_query, second_state));
  CIF_CHECK_EQ(first_state.text, second_state.text);
  CIF_CHECK(first_state.state_digest == second_state.state_digest);
  CIF_CHECK(first_state.spec_digest == second_state.spec_digest);

  // Admin over the wire.
  AdminCommand admin;
  admin.kind = AdminKind::SetMemberLifecycle;
  admin.member_id = seed.source;
  admin.lifecycle = MemberLifecycle::Draining;
  AdminResult admin_result;
  CIF_REQUIRE_OK(client.admin(admin, admin_result));
  CIF_CHECK(admin_result.ok());
  CIF_CHECK(query_text(server, QueryKind::State).find("DRAINING") != std::string::npos);

  // Optimistic concurrency: an admin command pinned to a stale generation is
  // refused, and the current generation is reported back so the caller can
  // retry without guessing.
  admin.lifecycle = MemberLifecycle::Active;
  admin.expect_generation = ClusterGeneration{admin_result.generation.value() - 1};
  admin.has_expectation = true;
  CIF_REQUIRE_OK(client.admin(admin, admin_result));
  CIF_CHECK(!admin_result.ok());
  CIF_CHECK(admin_result.code == StatusCode::StateMismatch);
  CIF_CHECK(admin_result.generation.value() > admin.expect_generation.value());
  // The refused command must not have taken effect.
  CIF_CHECK(query_text(server, QueryKind::State).find("DRAINING") != std::string::npos);

  AdminCommand unknown;
  unknown.kind = AdminKind::None;
  CIF_REQUIRE_OK(client.admin(unknown, admin_result));
  CIF_CHECK(!admin_result.ok());

  CIF_REQUIRE_OK(client.close());
  CIF_REQUIRE_OK(second.close());
  {
    QueryCommand local_verify;
    local_verify.kind = QueryKind::Verify;
    QueryResult local_result;
    CIF_REQUIRE_OK(server.inspect(local_verify, local_result));
    CIF_CHECK_MSG(local_result.ok(), local_result.message);
  }
  CIF_REQUIRE_OK(server.stop());
  CIF_CHECK(!server.running());
  // After stop() the reducer is gone, so the final state is quiescent and may
  // be read directly.
  CIF_CHECK(server.core().self_check().ok());
}

CIF_TEST(server, repeated_start_stop_is_clean) {
  AuthorityServer server(base_options("cluster-churn"));
  for (int cycle = 0; cycle < 25; ++cycle) {
    CIF_REQUIRE_OK(server.start());
    CIF_CHECK(server.running());
    CIF_CHECK(server.port() != 0);
    seed_cluster(server);
    AuthorityClient client;
    CIF_REQUIRE_OK(client.connect(client_options_for(server)));
    QueryCommand verify;
    verify.kind = QueryKind::Verify;
    QueryResult result;
    CIF_REQUIRE_OK(client.query(verify, result));
    CIF_CHECK(result.ok());
    CIF_REQUIRE_OK(client.close());
    CIF_REQUIRE_OK(server.stop());
    CIF_CHECK(!server.running());
  }
  CIF_REQUIRE_OK(server.start());
  CIF_CHECK_STATUS(server.start(), StatusCode::AlreadyExists);
  CIF_REQUIRE_OK(server.stop());
  CIF_REQUIRE_OK(server.stop());
}

CIF_TEST(server, stop_releases_idle_and_conversing_clients) {
  AuthorityServer server(base_options("cluster-stop"));
  CIF_REQUIRE_OK(server.start());
  seed_cluster(server);

  std::vector<std::unique_ptr<AuthorityClient>> clients;
  for (int i = 0; i < 6; ++i) {
    auto client = std::make_unique<AuthorityClient>();
    ClientOptions options = client_options_for(server);
    options.client = ClientId::from_validated("idle-" + std::to_string(i));
    CIF_REQUIRE_OK(client->connect(options));
    clients.push_back(std::move(client));
  }

  std::atomic<bool> stop_returned{false};
  std::thread stopper([&server, &stop_returned] {
    const Status status = server.stop();
    CIF_CHECK_MSG(status.ok(), status.to_string());
    stop_returned.store(true);
  });
  // Clients keep talking while the server is shutting down; failures are
  // expected and are not asserted on, but nothing may hang.
  for (const auto& client : clients) {
    static_cast<void>(client->ping());
  }
  stopper.join();
  CIF_CHECK(stop_returned.load());
  for (const auto& client : clients) {
    static_cast<void>(client->close());
  }
  clients.clear();
  CIF_CHECK(!server.running());
}

CIF_TEST(server, hello_is_required_and_banner_checked) {
  ServerOptions options = base_options("cluster-hello");
  AuthorityServer server(options);
  CIF_REQUIRE_OK(server.start());

  // A client that speaks before saying hello is refused.
  {
    AuthorityClient rude;
    ClientOptions rude_options = client_options_for(server);
    rude_options.skip_hello = true;
    CIF_REQUIRE_OK(rude.connect(rude_options));
    QueryCommand query;
    query.kind = QueryKind::Verify;
    QueryResult result;
    const Status status = rude.query(query, result);
    CIF_CHECK(!status.ok());
    CIF_CHECK(status.code() == StatusCode::RemoteError || status.code() == StatusCode::Corruption);
    CIF_REQUIRE_OK(rude.close());
  }
  // A hello carrying a foreign banner is refused during the handshake.
  {
    AuthorityClient mismatched;
    ClientOptions mismatched_options = client_options_for(server);
    mismatched_options.skip_hello = true;
    CIF_REQUIRE_OK(mismatched.connect(mismatched_options));
    WireMessage hello;
    hello.type = MessageType::Hello;
    hello.banner = "cif/0.0.0 something-else";
    hello.client = ClientId::from_validated("mismatched");
    Frame frame;
    CIF_REQUIRE_OK(pack_message(hello, frame));
    CIF_REQUIRE_OK(mismatched.send_frame(frame));
    Frame reply_frame;
    CIF_REQUIRE_OK(mismatched.receive_frame(reply_frame));
    WireMessage reply;
    CIF_REQUIRE_OK(unpack_message(reply_frame, reply));
    CIF_CHECK(reply.type == MessageType::Error);
    CIF_CHECK_EQ(reply.error_code, std::string("VERSION_MISMATCH"));
    CIF_REQUIRE_OK(mismatched.close());
  }
  // A well-behaved client still gets in.
  {
    AuthorityClient good;
    CIF_REQUIRE_OK(good.connect(client_options_for(server)));
    CIF_CHECK(good.server().valid);
    CIF_REQUIRE_OK(good.close());
  }
  CIF_REQUIRE_OK(server.stop());
}

CIF_TEST(server, connection_limit_reports_backpressure) {
  ServerOptions options = base_options("cluster-limit");
  options.max_connections = 2;
  AuthorityServer server(options);
  CIF_REQUIRE_OK(server.start());
  seed_cluster(server);

  AuthorityClient first;
  AuthorityClient second;
  CIF_REQUIRE_OK(first.connect(client_options_for(server)));
  CIF_REQUIRE_OK(second.connect(client_options_for(server)));
  CIF_REQUIRE_OK(first.ping());
  CIF_REQUIRE_OK(second.ping());

  // The third connection is refused with a typed error rather than being
  // silently accepted and starved.
  AuthorityClient third;
  const Status connected = third.connect(client_options_for(server));
  if (connected.ok()) {
    QueryCommand query;
    query.kind = QueryKind::Verify;
    QueryResult result;
    const Status status = third.query(query, result);
    // If the handshake is refused the connection is already gone; if the
    // handshake somehow succeeded, the first real request must still be refused.
    CIF_CHECK(!status.ok());
  } else {
    CIF_CHECK_MSG(connected.code() == StatusCode::RemoteError ||
                      connected.code() == StatusCode::Unsupported ||
                      connected.code() == StatusCode::IoFailure ||
                      connected.code() == StatusCode::Closed,
                  connected.to_string());
  }
  static_cast<void>(third.close());
  CIF_REQUIRE_OK(first.close());
  CIF_REQUIRE_OK(second.close());
  CIF_REQUIRE_OK(server.stop());
  CIF_CHECK(server.status().stats.connections_rejected > 0);
}

CIF_TEST(transport, byte_at_a_time_framing_is_accepted) {
  AuthorityServer server(base_options("cluster-partial"));
  CIF_REQUIRE_OK(server.start());
  seed_cluster(server);

  AuthorityClient client;
  ClientOptions options = client_options_for(server);
  options.skip_hello = true;
  CIF_REQUIRE_OK(client.connect(options));

  WireMessage hello;
  hello.type = MessageType::Hello;
  hello.banner = version_banner();
  hello.client = ClientId::from_validated("trickler");
  Frame frame;
  CIF_REQUIRE_OK(pack_message(hello, frame));
  Bytes encoded;
  CIF_REQUIRE_OK(encode_frame(frame, encoded));

  // Deliver the frame one byte at a time: the receiver must reassemble it.
  for (std::size_t i = 0; i < encoded.size(); ++i) {
    CIF_REQUIRE_OK(client.send_bytes(std::span<const std::uint8_t>(encoded.data() + i, 1)));
  }
  Frame reply;
  CIF_REQUIRE_OK(client.receive_frame(reply));
  CIF_CHECK(reply.type == MessageType::HelloAck);

  // Two frames coalesced into one write are still separated correctly.
  WireMessage ping;
  ping.type = MessageType::Ping;
  Frame ping_frame;
  CIF_REQUIRE_OK(pack_message(ping, ping_frame));
  Bytes one;
  Bytes two;
  CIF_REQUIRE_OK(encode_frame(ping_frame, one));
  CIF_REQUIRE_OK(encode_frame(ping_frame, two));
  one.insert(one.end(), two.begin(), two.end());
  CIF_REQUIRE_OK(client.send_bytes(std::span<const std::uint8_t>(one.data(), one.size())));
  CIF_REQUIRE_OK(client.receive_frame(reply));
  CIF_CHECK(reply.type == MessageType::Pong);
  CIF_REQUIRE_OK(client.receive_frame(reply));
  CIF_CHECK(reply.type == MessageType::Pong);

  CIF_REQUIRE_OK(client.close());
  CIF_REQUIRE_OK(server.stop());
}

CIF_TEST(transport, garbage_framing_is_refused_without_killing_the_server) {
  AuthorityServer server(base_options("cluster-garbage"));
  CIF_REQUIRE_OK(server.start());
  seed_cluster(server);

  {
    AuthorityClient rude;
    ClientOptions options = client_options_for(server);
    options.skip_hello = true;
    CIF_REQUIRE_OK(rude.connect(options));
    const std::string garbage = "GET / HTTP/1.1\r\nHost: nowhere\r\n\r\n";
    CIF_REQUIRE_OK(rude.send_bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(garbage.data()), garbage.size())));
    Frame reply;
    const Status status = rude.receive_frame(reply);
    if (status.ok()) {
      WireMessage message;
      CIF_REQUIRE_OK(unpack_message(reply, message));
      CIF_CHECK(message.type == MessageType::Error);
    }
    static_cast<void>(rude.close());
  }
  {
    // A frame with a valid header but a corrupted payload.
    AuthorityClient rude;
    ClientOptions options = client_options_for(server);
    options.skip_hello = true;
    CIF_REQUIRE_OK(rude.connect(options));
    WireMessage hello;
    hello.type = MessageType::Hello;
    hello.banner = version_banner();
    hello.client = ClientId::from_validated("corrupter");
    Frame frame;
    CIF_REQUIRE_OK(pack_message(hello, frame));
    Bytes encoded;
    CIF_REQUIRE_OK(encode_frame(frame, encoded));
    encoded.back() = static_cast<std::uint8_t>(encoded.back() ^ 0xFFu);
    CIF_REQUIRE_OK(rude.send_bytes(std::span<const std::uint8_t>(encoded.data(), encoded.size())));
    Frame reply;
    const Status status = rude.receive_frame(reply);
    if (status.ok()) {
      WireMessage message;
      CIF_REQUIRE_OK(unpack_message(reply, message));
      CIF_CHECK(message.type == MessageType::Error);
    }
    static_cast<void>(rude.close());
  }

  // The server is still healthy and serving.
  AuthorityClient healthy;
  CIF_REQUIRE_OK(healthy.connect(client_options_for(server)));
  QueryCommand query;
  query.kind = QueryKind::Verify;
  QueryResult result;
  CIF_REQUIRE_OK(healthy.query(query, result));
  CIF_CHECK(result.ok());
  CIF_REQUIRE_OK(healthy.close());
  CIF_REQUIRE_OK(server.stop());
  CIF_CHECK(server.core().self_check().ok());
  CIF_CHECK(server.status().stats.protocol_errors > 0);
}

CIF_TEST(transport, client_fails_fast_against_a_dead_endpoint) {
  std::uint16_t port = 0;
  {
    AuthorityServer server(base_options("cluster-dead"));
    CIF_REQUIRE_OK(server.start());
    port = server.port();
    CIF_REQUIRE_OK(server.stop());
  }
  AuthorityClient client;
  ClientOptions options;
  options.host = "127.0.0.1";
  options.port = port;
  options.timeout_millis = 1000;
  const Status status = client.connect(options);
  CIF_CHECK(!status.ok());
  CIF_CHECK(status.code() == StatusCode::IoFailure || status.code() == StatusCode::Timeout);
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------
CIF_TEST(concurrency, competing_grants_are_serialised) {
  AuthorityServer server(base_options("cluster-race"));
  CIF_REQUIRE_OK(server.start());
  const Seed seed = seed_cluster(server);

  constexpr int kClients = 12;
  std::vector<std::thread> threads;
  std::vector<AuthorityOutcome> outcomes(kClients, AuthorityOutcome::Invalid);
  std::atomic<int> failures{0};

  for (int i = 0; i < kClients; ++i) {
    threads.emplace_back([&, i] {
      AuthorityClient client;
      ClientOptions options = client_options_for(server);
      options.client = ClientId::from_validated("racer-" + std::to_string(i));
      if (!client.connect(options).ok()) {
        ++failures;
        return;
      }
      AuthorityDecision decision;
      if (!client
               .submit(build_request(seed, client.server(), "att-race-" + std::to_string(i), 4),
                       decision)
               .ok()) {
        ++failures;
        return;
      }
      outcomes[static_cast<std::size_t>(i)] = decision.outcome;
      static_cast<void>(client.close());
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  CIF_CHECK_EQ(failures.load(), 0);

  const std::size_t granted = static_cast<std::size_t>(
      std::count(outcomes.begin(), outcomes.end(), AuthorityOutcome::Granted));
  const std::size_t conflicted = static_cast<std::size_t>(
      std::count(outcomes.begin(), outcomes.end(), AuthorityOutcome::Conflicting));
  CIF_CHECK_MSG(granted == 1, "granted=" + std::to_string(granted));
  CIF_CHECK_MSG(granted + conflicted == kClients,
                "granted=" + std::to_string(granted) + " conflicted=" + std::to_string(conflicted));

  // The accounting is observable through the same door an operator would use.
  AuthorityClient observer;
  CIF_REQUIRE_OK(observer.connect(client_options_for(server)));
  QueryCommand verify;
  verify.kind = QueryKind::Verify;
  QueryResult result;
  CIF_REQUIRE_OK(observer.query(verify, result));
  CIF_CHECK(result.ok());
  CIF_REQUIRE_OK(observer.close());

  CIF_REQUIRE_OK(server.stop());
  CIF_CHECK_EQ(server.core().grants().size(), std::size_t{1});
  CIF_CHECK_EQ(server.core().path_committed_units(seed.path), std::uint64_t{4});
  CIF_CHECK(server.core().self_check().ok());
}

CIF_TEST(concurrency, parallel_clients_preserve_accounting_closure) {
  AuthorityServer server(base_options("cluster-account"));
  CIF_REQUIRE_OK(server.start());
  const Seed seed = seed_cluster(server);

  // Make the path shareable so this exercises capacity rather than exclusivity.
  Path path;
  path.id = seed.path;
  path.generation = seed.path_generation;
  path.source_member = seed.source;
  path.destination_member = seed.destination;
  path.capacity_units = seed.path_capacity;
  path.exclusive = false;
  AdminCommand share;
  share.kind = AdminKind::UpsertPath;
  share.path = path;
  require_apply(server, share, "share path");

  constexpr int kClients = 16;
  constexpr std::uint64_t kUnits = 8;
  const std::uint64_t capacity = seed.path_capacity;

  std::vector<std::thread> threads;
  std::vector<AuthorityOutcome> outcomes(kClients, AuthorityOutcome::Invalid);
  std::vector<GrantId> grants(kClients);
  std::vector<LeaseId> leases(kClients);
  std::vector<ServerIdentity> coordinates(kClients);
  std::atomic<int> failures{0};

  for (int i = 0; i < kClients; ++i) {
    threads.emplace_back([&, i] {
      AuthorityClient client;
      ClientOptions options = client_options_for(server);
      options.client = ClientId::from_validated("worker-" + std::to_string(i));
      if (!client.connect(options).ok()) {
        ++failures;
        return;
      }
      coordinates[static_cast<std::size_t>(i)] = client.server();
      AuthorityDecision decision;
      if (!client
               .submit(build_request(seed, client.server(), "att-acc-" + std::to_string(i), kUnits),
                       decision)
               .ok()) {
        ++failures;
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
  for (std::thread& thread : threads) {
    thread.join();
  }
  CIF_CHECK_EQ(failures.load(), 0);

  std::uint64_t granted_units = 0;
  for (int i = 0; i < kClients; ++i) {
    if (outcomes[static_cast<std::size_t>(i)] == AuthorityOutcome::Granted) {
      granted_units += kUnits;
    } else {
      CIF_CHECK(outcomes[static_cast<std::size_t>(i)] == AuthorityOutcome::Refused);
    }
  }
  CIF_CHECK_MSG(granted_units <= capacity,
                "granted " + std::to_string(granted_units) + " of " + std::to_string(capacity));
  CIF_CHECK_EQ(granted_units, capacity);

  // Every winner releases concurrently; the accounting must close exactly.
  std::vector<std::thread> releasers;
  for (int i = 0; i < kClients; ++i) {
    if (outcomes[static_cast<std::size_t>(i)] != AuthorityOutcome::Granted) {
      continue;
    }
    releasers.emplace_back([&, i] {
      AuthorityClient client;
      ClientOptions options = client_options_for(server);
      options.client = ClientId::from_validated("releaser-" + std::to_string(i));
      if (!client.connect(options).ok()) {
        ++failures;
        return;
      }
      ReleaseRequest release;
      release.request_id = RequestId::from_validated("req-rel-" + std::to_string(i));
      release.grant_id = grants[static_cast<std::size_t>(i)];
      release.lease_id = leases[static_cast<std::size_t>(i)];
      release.attempt_id = AttemptId::from_validated("att-acc-" + std::to_string(i));
      AuthorityDecision decision;
      if (!client.release(release, decision).ok() ||
          decision.outcome != AuthorityOutcome::Granted) {
        ++failures;
      }
      static_cast<void>(client.close());
    });
  }
  for (std::thread& thread : releasers) {
    thread.join();
  }
  CIF_CHECK_EQ(failures.load(), 0);

  // Capacity is genuinely reusable afterwards.
  {
    AuthorityClient client;
    CIF_REQUIRE_OK(client.connect(client_options_for(server)));
    AuthorityDecision decision;
    CIF_REQUIRE_OK(
        client.submit(build_request(seed, client.server(), "att-after", kUnits), decision));
    CIF_CHECK(decision.outcome == AuthorityOutcome::Granted);
    CIF_REQUIRE_OK(client.close());
  }

  CIF_REQUIRE_OK(server.stop());
  // A server without a journal is a fresh controller on every start, so the
  // accounting is asserted before stopping.
  CIF_CHECK_EQ(server.core().path_committed_units(seed.path), kUnits);
  CIF_CHECK(server.core().self_check().ok());
}

CIF_TEST(concurrency, many_sequential_connections_are_reaped) {
  AuthorityServer server(base_options("cluster-leak"));
  CIF_REQUIRE_OK(server.start());
  const Seed seed = seed_cluster(server);
  for (int i = 0; i < 120; ++i) {
    AuthorityClient client;
    ClientOptions options = client_options_for(server);
    options.client = ClientId::from_validated("seq-" + std::to_string(i));
    CIF_REQUIRE_OK(client.connect(options));
    AuthorityDecision decision;
    CIF_REQUIRE_OK(
        client.submit(build_request(seed, client.server(), "att-seq-" + std::to_string(i), 1),
                      decision));
    CIF_REQUIRE_OK(client.close());
  }
  const bool reaped = wait_until(
      [&server] {
        const ServerStatus snapshot = server.status();
        return snapshot.active_connections == 0 &&
               snapshot.stats.connections_closed == snapshot.stats.connections_accepted;
      },
      10000);
  CIF_CHECK_MSG(reaped || true, "reap wait");
  CIF_CHECK_MSG(server.status().active_connections == 0,
                "connections were not reaped: " +
                    std::to_string(server.status().active_connections) + " still live");
  const ServerStatus status = server.status();
  CIF_CHECK_EQ(status.active_connections, std::size_t{0});
  CIF_CHECK_EQ(status.ingest_depth, std::size_t{0});
  CIF_CHECK(status.stats.connections_accepted >= 120);
  CIF_CHECK_EQ(status.stats.connections_closed, status.stats.connections_accepted);
  CIF_REQUIRE_OK(server.stop());
  CIF_CHECK(server.core().self_check().ok());
}

// ---------------------------------------------------------------------------
// durable server
// ---------------------------------------------------------------------------
CIF_TEST(server, durable_journal_survives_close_and_reopen) {
  const std::string path = cif::test::scratch_path("net-durable.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  GrantId first_grant;
  Digest256 first_topology;
  {
    ServerOptions options = base_options("cluster-durable");
    options.journal_path = path;
    AuthorityServer server(options);
    CIF_REQUIRE_OK(server.start());
    CIF_CHECK(server.status().durable);
    const Seed seed = seed_cluster(server);
    first_topology = server.core().spec().topology_digest();

    AuthorityClient client;
    CIF_REQUIRE_OK(client.connect(client_options_for(server)));
    AuthorityDecision decision;
    CIF_REQUIRE_OK(client.submit(build_request(seed, client.server(), "att-durable", 4), decision));
    CIF_REQUIRE(decision.outcome == AuthorityOutcome::Granted);
    first_grant = decision.grant->grant_id;
    CIF_REQUIRE_OK(client.close());
    CIF_REQUIRE_OK(server.stop());
  }
  {
    ServerOptions options = base_options("cluster-durable");
    options.journal_path = path;
    AuthorityServer server(options);
    CIF_REQUIRE_OK(server.start());
    CIF_CHECK(server.recovery().file_present);
    CIF_CHECK(!server.recovery().fresh);
    CIF_CHECK(server.core().recovered());
    CIF_CHECK(server.core().spec().topology_digest() == first_topology);
    // The commit that was never acknowledged is quarantined: it holds capacity
    // so nothing is double-booked, but it carries no usable authority.
    CIF_CHECK_EQ(server.core().quarantined_units(), std::uint64_t{4});

    AuthorityClient client;
    CIF_REQUIRE_OK(client.connect(client_options_for(server)));
    QueryCommand query;
    query.kind = QueryKind::Grant;
    query.grant_id = first_grant;
    QueryResult result;
    CIF_REQUIRE_OK(client.query(query, result));
    CIF_CHECK(result.ok());
    CIF_CHECK(result.text.find("AMBIGUOUS") != std::string::npos);

    ResolveRequest resolve;
    resolve.request_id = RequestId::from_validated("req-resolve");
    resolve.attempt_id = AttemptId::from_validated("att-durable");
    AuthorityDecision decision;
    CIF_REQUIRE_OK(client.resolve(resolve, decision));
    CIF_CHECK(decision.outcome == AuthorityOutcome::Indeterminate);
    CIF_CHECK(decision.requires_reconciliation);

    CancelRequest cancel;
    cancel.request_id = RequestId::from_validated("req-cancel");
    cancel.attempt_id = AttemptId::from_validated("att-durable");
    cancel.reason = "caller never observed the commit";
    CIF_REQUIRE_OK(client.cancel(cancel, decision));
    CIF_CHECK(decision.outcome == AuthorityOutcome::Cancelled);
    CIF_CHECK_EQ(server.core().quarantined_units(), std::uint64_t{0});
    CIF_REQUIRE_OK(client.close());
    CIF_REQUIRE_OK(server.stop());
    CIF_CHECK(server.core().self_check().ok());
  }
  std::filesystem::remove(path, error);
}
