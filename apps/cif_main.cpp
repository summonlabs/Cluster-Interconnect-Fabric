// Cluster Interconnect Fabric (CIF) -- cif, the inspection and control CLI.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// cif <command> [options]
//
// Inspection, administration and journal tooling. The CLI talks the same wire
// protocol as any other client, so everything it can do is something a client
// can do, and nothing it can do bypasses authority.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "cif/client.hpp"
#include "cif/journal.hpp"
#include "cif/render.hpp"
#include "cif/text.hpp"
#include "cif/version.hpp"

namespace {

void print_usage() {
  std::cout <<
      "cif " CIF_VERSION_STRING " -- cluster interconnect fabric tooling\n"
      "\n"
      "usage: cif <command> [options]\n"
      "\n"
      "  cif version\n"
      "  cif --port <n> [--host <addr>] query <controller|state|audit|recovery|verify|version>\n"
      "  cif --port <n> query member <id> | path <id> | grant <id> | attempt <id>\n"
      "  cif --port <n> admin <kind> [--option value ...]\n"
      "  cif --port <n> submit --contract <id> --source <member> --dest <member>\n"
      "        [--source-endpoint <id>] [--dest-endpoint <id>] [--path <id>] [--resource <id>]\n"
      "        [--units <n>] [--lease-ticks <n>] [--attempt <id>] [--renew <grant>]\n"
      "        [--allow-degraded] [--json]\n"
      "  cif --port <n> release --grant <id> [--lease <id>] [--attempt <id>]\n"
      "  cif --port <n> resolve --attempt <id>\n"
      "  cif --port <n> ack --grant <id> --lease <id> [--attempt <id>]\n"
      "  cif --port <n> cancel --attempt <id> [--grant <id>] [--reason <text>]\n"
      "  cif --port <n> load --contract <id> --source <m> --dest <m> --attempts <n> [--units <n>]\n"
      "  cif journal <scan|replay> --path <file>\n"
      "  cif digest --path <file>\n"
      "  cif --help\n"
      "\n"
      "admin kinds: upsert-member remove-member set-member-lifecycle upsert-path remove-path\n"
      "  set-path-state upsert-exclusion remove-exclusion upsert-obligation remove-obligation\n"
      "  upsert-contract remove-contract set-policy advance-tick fence-all expire-leases\n"
      "  revalidate compact self-check\n"
      "\n"
      "exit codes: 0 success, 1 remote refusal, 2 bad arguments, 3 transport failure,\n"
      "            4 authority returned a non-authoritative outcome\n";
}

struct Options {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  bool has_port = false;
  std::uint64_t timeout_millis = 5000;
  bool json = false;
  std::vector<std::string> positional;
  std::map<std::string, std::string> flags;
  std::vector<std::string> repeatable_members;
};

bool take_value(int argc, char** argv, int& index, const std::string& flag, std::string& out) {
  if (index + 1 >= argc) {
    std::cerr << "cif: " << flag << " requires a value\n";
    return false;
  }
  out = argv[++index];
  return true;
}

bool parse_options(int argc, char** argv, Options& out) {
  for (int i = 1; i < argc; ++i) {
    const std::string token = argv[i];
    if (token == "--help" || token == "-h") {
      out.flags["help"] = "1";
      continue;
    }
    if (token == "--json") {
      out.json = true;
      continue;
    }
    if (token == "--allow-degraded") {
      out.flags["allow-degraded"] = "1";
      continue;
    }
    if (token == "--administrative") {
      out.flags["administrative"] = "1";
      continue;
    }
    if (token == "--no-durable") {
      out.flags["no-durable"] = "1";
      continue;
    }
    if (token.size() > 2 && token[0] == '-' && token[1] == '-') {
      std::string value;
      if (!take_value(argc, argv, i, token, value)) {
        return false;
      }
      const std::string key = token.substr(2);
      if (key == "host") {
        out.host = value;
      } else if (key == "port") {
        std::uint64_t port = 0;
        if (!cif::parse_decimal_u64(value, port) || port > 65535) {
          std::cerr << "cif: --port must be 0..65535\n";
          return false;
        }
        out.port = static_cast<std::uint16_t>(port);
        out.has_port = true;
      } else if (key == "timeout-ms") {
        std::uint64_t timeout = 0;
        if (!cif::parse_decimal_u64(value, timeout)) {
          std::cerr << "cif: --timeout-ms must be a non-negative integer\n";
          return false;
        }
        out.timeout_millis = timeout;
      } else {
        out.flags[key] = value;
      }
      continue;
    }
    out.positional.push_back(token);
  }
  return true;
}

const std::string& flag_or(const Options& options, const std::string& key,
                           const std::string& fallback) {
  const auto it = options.flags.find(key);
  return it == options.flags.end() ? fallback : it->second;
}

bool flag_present(const Options& options, const std::string& key) {
  return options.flags.find(key) != options.flags.end();
}

/// Parses "key = value" lines from a rendered response. Rendering is
/// deterministic, which is what makes this safe.
bool parse_rendered(const std::string& text, const std::string& key, std::string& out) {
  std::size_t position = 0;
  while (position < text.size()) {
    const std::size_t end = text.find('\n', position);
    const std::string line = text.substr(position, end == std::string::npos ? std::string::npos
                                                                           : end - position);
    const std::string needle = "  " + key + " = ";
    if (line.compare(0, needle.size(), needle) == 0) {
      out = line.substr(needle.size());
      return true;
    }
    position = end == std::string::npos ? text.size() : end + 1;
  }
  return false;
}

struct Connection {
  cif::AuthorityClient client;
};

bool connect(const Options& options, Connection& out) {
  if (!options.has_port) {
    std::cerr << "cif: --port is required for daemon commands\n";
    return false;
  }
  cif::ClientOptions client_options;
  client_options.host = options.host;
  client_options.port = options.port;
  client_options.timeout_millis = options.timeout_millis;
  client_options.client = cif::ClientId::from_validated("cif-cli");
  const cif::Status status = out.client.connect(client_options);
  if (!status.ok()) {
    std::cerr << "cif: cannot reach " << options.host << ":" << options.port << ": "
              << status.to_string() << "\n";
    return false;
  }
  return true;
}

int report_decision(const Options& options, const cif::AuthorityDecision& decision) {
  if (options.json) {
    std::string out;
    cif::JsonWriter writer(out);
    writer.begin_object();
    writer.key("outcome");
    writer.string_value(cif::to_string(decision.outcome));
    writer.key("request");
    writer.string_value(decision.request_id.to_string());
    writer.key("attempt");
    writer.string_value(decision.attempt_id.to_string());
    writer.key("decision_sequence");
    writer.number_value(decision.decision_sequence);
    writer.key("idempotent_replay");
    writer.bool_value(decision.idempotent_replay);
    writer.key("requires_reconciliation");
    writer.bool_value(decision.requires_reconciliation);
    writer.key("state_digest");
    writer.string_value(decision.state_digest.hex());
    writer.key("decision_digest");
    writer.string_value(decision.decision_digest.hex());
    writer.key("reasons");
    writer.begin_array();
    for (const cif::Reason& reason : decision.reasons) {
      writer.string_value(cif::to_string(reason.code));
    }
    writer.end_array();
    if (decision.grant.has_value()) {
      writer.key("grant");
      writer.string_value(decision.grant->grant_id.to_string());
      writer.key("grant_state");
      writer.string_value(cif::to_string(decision.grant->state));
      writer.key("lease");
      writer.string_value(decision.grant->lease_id.to_string());
      writer.key("capacity_units");
      writer.number_value(decision.grant->capacity_units);
    }
    writer.end_object();
    out += "\n";
    std::cout << out;
  } else {
    std::cout << decision.render();
  }

  if (cif::is_authoritative(decision.outcome)) {
    return 0;
  }
  if (decision.outcome == cif::AuthorityOutcome::Invalid) {
    return 2;
  }
  return 4;
}

int command_version() {
  std::cout << cif::version_banner() << "\n";
  std::cout << "journal_format " << cif::journal_format_version() << "\n";
  std::cout << "wire_protocol " << cif::wire_protocol_version() << "\n";
  std::cout << "test_hooks " << (cif::test_hooks_enabled() ? "on" : "off") << "\n";
  std::cout << "known_capabilities\n";
  for (const std::string_view capability : cif::known_capabilities()) {
    std::cout << "  " << capability << "\n";
  }
  return 0;
}

int command_query(const Options& options, Connection& connection) {
  if (options.positional.size() < 2) {
    std::cerr << "cif: query needs a kind\n";
    return 2;
  }
  cif::QueryCommand command;
  const std::string kind = options.positional[1];
  if (!cif::parse_query_kind(kind, command.kind)) {
    std::cerr << "cif: unknown query kind '" << cif::sanitise_for_display(kind, 32) << "'\n";
    return 2;
  }
  if (command.kind == cif::QueryKind::Member && options.positional.size() >= 3) {
    command.member_id = cif::MemberId::from_validated(options.positional[2]);
  }
  if (command.kind == cif::QueryKind::Path && options.positional.size() >= 3) {
    command.path_id = cif::PathId::from_validated(options.positional[2]);
  }
  if (command.kind == cif::QueryKind::Grant && options.positional.size() >= 3) {
    command.grant_id = cif::GrantId::from_validated(options.positional[2]);
  }
  if (command.kind == cif::QueryKind::Attempt && options.positional.size() >= 3) {
    command.attempt_id = cif::AttemptId::from_validated(options.positional[2]);
  }
  const cif::Status shape = command.validate_shape();
  if (!shape.ok()) {
    std::cerr << "cif: " << shape.to_string() << "\n";
    return 2;
  }
  cif::QueryResult result;
  const cif::Status status = connection.client.query(command, result);
  if (!status.ok()) {
    std::cerr << "cif: " << status.to_string() << "\n";
    return 3;
  }
  if (!result.text.empty()) {
    std::cout << result.text;
  }
  if (!result.ok()) {
    std::cerr << "cif: " << cif::to_string(result.code) << ": "
              << cif::sanitise_for_display(result.message, 192) << "\n";
    return 1;
  }
  return 0;
}

int command_admin(const Options& options, Connection& connection) {
  if (options.positional.size() < 2) {
    std::cerr << "cif: admin needs a kind\n";
    return 2;
  }
  cif::AdminCommand command;
  if (!cif::parse_admin_kind(options.positional[1], command.kind)) {
    std::cerr << "cif: unknown admin kind '" << cif::sanitise_for_display(options.positional[1], 32)
              << "'\n";
    return 2;
  }
  const std::string member = flag_or(options, "member", "");
  const std::string path = flag_or(options, "path", "");
  const std::string contract = flag_or(options, "contract", "");
  const std::string lifecycle = flag_or(options, "lifecycle", "");
  const std::string path_state = flag_or(options, "state", "");
  const std::string generation = flag_or(options, "generation", "");
  const std::string tick = flag_or(options, "tick", "");
  const std::string policy = flag_or(options, "policy", "");

  command.member_id = cif::MemberId::from_validated(member);
  command.path_id = cif::PathId::from_validated(path);
  command.contract_id = cif::ContractId::from_validated(contract);
  command.detail = flag_or(options, "detail", "");

  if (!generation.empty()) {
    std::uint64_t value = 0;
    if (!cif::parse_decimal_u64(generation, value)) {
      std::cerr << "cif: --generation must be a non-negative integer\n";
      return 2;
    }
    command.expect_generation = cif::ClusterGeneration{value};
    command.has_expectation = true;
  }
  if (!tick.empty()) {
    std::uint64_t value = 0;
    if (!cif::parse_decimal_u64(tick, value)) {
      std::cerr << "cif: --tick must be a non-negative integer\n";
      return 2;
    }
    command.tick = cif::Tick{value};
  }
  if (!policy.empty()) {
    std::uint64_t value = 0;
    if (!cif::parse_decimal_u64(policy, value)) {
      std::cerr << "cif: --policy must be a non-negative integer\n";
      return 2;
    }
    command.policy = cif::PolicyGeneration{value};
  }
  if (!lifecycle.empty()) {
    if (lifecycle == "active") command.lifecycle = cif::MemberLifecycle::Active;
    else if (lifecycle == "draining") command.lifecycle = cif::MemberLifecycle::Draining;
    else if (lifecycle == "maintenance") command.lifecycle = cif::MemberLifecycle::Maintenance;
    else if (lifecycle == "faulted") command.lifecycle = cif::MemberLifecycle::Faulted;
    else if (lifecycle == "partitioned") command.lifecycle = cif::MemberLifecycle::Partitioned;
    else if (lifecycle == "removed") command.lifecycle = cif::MemberLifecycle::Removed;
    else if (lifecycle == "enlisted") command.lifecycle = cif::MemberLifecycle::Enlisted;
    else {
      std::cerr << "cif: unknown lifecycle '" << cif::sanitise_for_display(lifecycle, 32) << "'\n";
      return 2;
    }
  }
  if (!path_state.empty()) {
    if (path_state == "operational") command.path_state = cif::PathState::Operational;
    else if (path_state == "degraded") command.path_state = cif::PathState::Degraded;
    else if (path_state == "down") command.path_state = cif::PathState::Down;
    else if (path_state == "maintenance") command.path_state = cif::PathState::Maintenance;
    else if (path_state == "unknown") command.path_state = cif::PathState::Unknown;
    else {
      std::cerr << "cif: unknown path state '" << cif::sanitise_for_display(path_state, 32) << "'\n";
      return 2;
    }
  }

  const cif::Status shape = command.validate_shape();
  if (!shape.ok()) {
    std::cerr << "cif: " << shape.to_string() << "\n";
    return 2;
  }
  cif::AdminResult result;
  const cif::Status status = connection.client.admin(command, result);
  if (!status.ok()) {
    std::cerr << "cif: " << status.to_string() << "\n";
    return 3;
  }
  std::cout << cif::to_string(result.code) << ": " << cif::sanitise_for_display(result.message, 256)
            << "\n";
  std::cout << "  cluster_generation = " << result.generation.to_string() << "\n";
  std::cout << "  epoch = " << result.epoch.to_string() << "\n";
  std::cout << "  state_digest = " << result.state_digest.hex() << "\n";
  return result.ok() ? 0 : 1;
}

/// Fills in the controller coordinate and member evidence a submit needs, the
/// same way any well-behaved client must.
bool prepare_request(const Options& options, Connection& connection, cif::AuthorityRequest& request,
                     std::string& error) {
  const std::string contract = flag_or(options, "contract", "");
  const std::string source = flag_or(options, "source", "");
  const std::string destination = flag_or(options, "dest", "");
  if (contract.empty() || source.empty() || destination.empty()) {
    error = "--contract, --source and --dest are required";
    return false;
  }
  request.contract_id = cif::ContractId::from_validated(contract);
  request.source_member = cif::MemberId::from_validated(source);
  request.destination_member = cif::MemberId::from_validated(destination);
  request.source_endpoint = cif::EndpointId::from_validated(flag_or(options, "source-endpoint", ""));
  request.destination_endpoint = cif::EndpointId::from_validated(flag_or(options, "dest-endpoint", ""));
  request.path_id = cif::PathId::from_validated(flag_or(options, "path", ""));
  request.resource_id = cif::ResourceId::from_validated(flag_or(options, "resource", ""));

  const std::string units = flag_or(options, "units", "0");
  if (!cif::parse_decimal_u64(units, request.requested_units)) {
    error = "--units must be a non-negative integer";
    return false;
  }
  const std::string lease = flag_or(options, "lease-ticks", "0");
  if (!cif::parse_decimal_u64(lease, request.lease_ticks)) {
    error = "--lease-ticks must be a non-negative integer";
    return false;
  }
  request.allow_degraded = flag_present(options, "allow-degraded");

  request.cluster_id = connection.client.server().cluster_id;
  request.cluster_generation = connection.client.server().generation;
  request.epoch = connection.client.server().epoch;
  request.incarnation = connection.client.server().incarnation;
  request.policy_generation = connection.client.server().policy;

  const std::string reservation = flag_or(options, "reservation-generation", "");
  if (!reservation.empty()) {
    std::uint64_t value = 0;
    if (!cif::parse_decimal_u64(reservation, value)) {
      error = "--reservation-generation must be a non-negative integer";
      return false;
    }
    request.reservation_generation = cif::ReservationGeneration{value};
  }

  const auto fetch_member = [&](const cif::MemberId& id, cif::MemberGeneration& generation,
                                cif::Digest256& digest) {
    cif::QueryCommand query;
    query.kind = cif::QueryKind::Member;
    query.member_id = id;
    cif::QueryResult result;
    if (!connection.client.query(query, result).ok() || !result.ok()) {
      return false;
    }
    std::string text;
    if (!parse_rendered(result.text, "generation", text)) {
      return false;
    }
    std::uint64_t value = 0;
    if (!cif::parse_decimal_u64(text, value)) {
      return false;
    }
    generation = cif::MemberGeneration{value};
    if (!parse_rendered(result.text, "digest", text)) {
      return false;
    }
    return cif::Digest256::parse(text, digest);
  };

  if (!fetch_member(request.source_member, request.source_member_generation,
                    request.source_member_digest)) {
    error = "cannot read evidence for source member " + request.source_member.to_string();
    return false;
  }
  if (!fetch_member(request.destination_member, request.destination_member_generation,
                    request.destination_member_digest)) {
    error = "cannot read evidence for destination member " + request.destination_member.to_string();
    return false;
  }

  // The contract generation must be read too: the controller refuses a claim
  // that does not match.
  cif::QueryCommand contract_query;
  contract_query.kind = cif::QueryKind::State;
  cif::QueryResult state;
  if (connection.client.query(contract_query, state).ok() && state.ok()) {
    // render_state prints every contract; find the matching generation.
    std::size_t position = 0;
    while (position < state.text.size()) {
      const std::size_t end = state.text.find('\n', position);
      const std::string line = state.text.substr(
          position, end == std::string::npos ? std::string::npos : end - position);
      if (line.compare(0, 9, "CONTRACT ") == 0 &&
          line.substr(9) == request.contract_id.to_string()) {
        const std::size_t block_end = state.text.find("\nCONTRACT ", position + 1);
        const std::string block =
            state.text.substr(position, block_end == std::string::npos
                                            ? std::string::npos
                                            : block_end - position);
        std::string generation_text;
        if (parse_rendered(block, "generation", generation_text)) {
          std::uint64_t value = 0;
          if (cif::parse_decimal_u64(generation_text, value)) {
            request.contract_generation = cif::ContractGeneration{value};
          }
        }
        break;
      }
      position = end == std::string::npos ? state.text.size() : end + 1;
    }
  }

  const std::string path_generation = flag_or(options, "path-generation", "");
  if (!path_generation.empty()) {
    std::uint64_t value = 0;
    if (!cif::parse_decimal_u64(path_generation, value)) {
      error = "--path-generation must be a non-negative integer";
      return false;
    }
    request.path_generation = cif::PathGeneration{value};
  } else if (!request.path_id.empty()) {
    cif::QueryCommand path_query;
    path_query.kind = cif::QueryKind::Path;
    path_query.path_id = request.path_id;
    cif::QueryResult result;
    if (connection.client.query(path_query, result).ok() && result.ok()) {
      std::string text;
      std::uint64_t value = 0;
      if (parse_rendered(result.text, "generation", text) &&
          cif::parse_decimal_u64(text, value)) {
        request.path_generation = cif::PathGeneration{value};
      }
    }
  }

  const std::string attempt = flag_or(options, "attempt", "");
  request.attempt_id = attempt.empty() ? cif::AttemptId::from_validated("att-" + std::to_string(
                                            connection.client.next_sequence()))
                                       : cif::AttemptId::from_validated(attempt);
  const std::string renew = flag_or(options, "renew", "");
  const std::string renew_lease = flag_or(options, "renew-lease", "");
  if (!renew.empty()) {
    request.renewal = true;
    request.renewal_of = cif::GrantId::from_validated(renew);
    request.renewal_lease = cif::LeaseId::from_validated(renew_lease);
  }
  request.request_id = cif::RequestId::from_validated(
      "req-" + std::to_string(connection.client.next_sequence()));
  request.provenance.client = cif::ClientId::from_validated("cif-cli");
  request.provenance.origin = "cif-cli";
  request.provenance.correlation_id = flag_or(options, "correlation", "cli");
  return true;
}

int command_submit(const Options& options, Connection& connection) {
  cif::AuthorityRequest request;
  std::string error;
  if (!prepare_request(options, connection, request, error)) {
    std::cerr << "cif: " << error << "\n";
    return 2;
  }
  const cif::Status shape = request.validate_shape();
  if (!shape.ok()) {
    std::cerr << "cif: " << shape.to_string() << "\n";
    return 2;
  }
  cif::AuthorityDecision decision;
  const cif::Status status = connection.client.submit(request, decision);
  if (!status.ok()) {
    std::cerr << "cif: " << status.to_string() << "\n";
    return 3;
  }
  return report_decision(options, decision);
}

int command_load(const Options& options, Connection& connection) {
  const std::string attempts = flag_or(options, "attempts", "");
  std::uint64_t count = 0;
  if (!cif::parse_decimal_u64(attempts, count) || count == 0) {
    std::cerr << "cif: --attempts must be a positive integer\n";
    return 2;
  }
  std::map<std::string, std::uint64_t> outcomes;
  std::uint64_t authoritative = 0;
  for (std::uint64_t i = 0; i < count; ++i) {
    cif::AuthorityRequest request;
    std::string error;
    if (!prepare_request(options, connection, request, error)) {
      std::cerr << "cif: " << error << "\n";
      return 2;
    }
    request.attempt_id = cif::AttemptId::from_validated("att-load-" + std::to_string(i));
    request.request_id = cif::RequestId::from_validated("req-load-" + std::to_string(i));
    cif::AuthorityDecision decision;
    const cif::Status status = connection.client.submit(request, decision);
    if (!status.ok()) {
      std::cerr << "cif: " << status.to_string() << "\n";
      return 3;
    }
    outcomes[cif::to_string(decision.outcome)] += 1;
    if (cif::is_authoritative(decision.outcome)) {
      ++authoritative;
    }
  }
  std::cout << "LOAD attempts=" << count << " authoritative=" << authoritative << "\n";
  for (const auto& entry : outcomes) {
    std::cout << "  " << entry.first << " = " << entry.second << "\n";
  }
  return 0;
}

int command_journal(const Options& options) {
  if (options.positional.size() < 2) {
    std::cerr << "cif: journal needs a mode (scan|replay)\n";
    return 2;
  }
  const std::string path = flag_or(options, "path", "");
  if (path.empty()) {
    std::cerr << "cif: journal requires --path\n";
    return 2;
  }
  std::vector<cif::JournalEntry> entries;
  cif::RecoveryReport report;
  const cif::Status scanned = cif::Journal::scan(path, entries, report);
  std::cout << report.render();
  if (!scanned.ok()) {
    std::cerr << "cif: scan failed: " << scanned.to_string() << "\n";
    return 1;
  }
  std::cout << "RECORDS " << entries.size() << "\n";
  if (options.positional[1] == "scan") {
    for (const cif::JournalEntry& entry : entries) {
      std::cout << "  seq=" << entry.sequence << " kind=" << cif::to_string(entry.kind)
                << " tick=" << entry.tick.to_string() << " digest=" << entry.digest().hex() << "\n";
    }
    return 0;
  }
  cif::RecoveredState state;
  const cif::Status replayed = cif::replay_journal(entries, state);
  if (!replayed.ok()) {
    std::cerr << "cif: replay failed: " << replayed.to_string() << "\n";
    return 1;
  }
  std::cout << "REPLAYED cluster=" << state.spec.cluster_id().to_string()
            << " generation=" << state.spec.generation().to_string()
            << " epoch=" << state.spec.epoch().to_string() << "\n";
  std::cout << "  members = " << state.spec.member_count() << "\n";
  std::cout << "  paths = " << state.spec.path_count() << "\n";
  std::cout << "  contracts = " << state.contracts.size() << "\n";
  std::cout << "  grants = " << state.grants.size() << "\n";
  std::cout << "  attempts = " << state.attempts.size() << "\n";
  std::cout << "  topology_digest = " << state.spec.topology_digest().hex() << "\n";
  std::size_t live = 0;
  for (const cif::AuthorityGrant& grant : state.grants) {
    if (cif::holds_capacity(grant.state)) {
      ++live;
    }
  }
  std::cout << "  live_grants = " << live << "\n";
  return 0;
}

int command_digest(const Options& options) {
  const std::string path = flag_or(options, "path", "");
  if (path.empty()) {
    std::cerr << "cif: digest requires --path\n";
    return 2;
  }
  std::vector<cif::JournalEntry> entries;
  cif::RecoveryReport report;
  const cif::Status scanned = cif::Journal::scan(path, entries, report);
  if (!scanned.ok()) {
    std::cerr << "cif: scan failed: " << scanned.to_string() << "\n";
    return 1;
  }
  cif::RecoveredState state;
  const cif::Status replayed = cif::replay_journal(entries, state);
  if (!replayed.ok()) {
    std::cerr << "cif: replay failed: " << replayed.to_string() << "\n";
    return 1;
  }
  std::cout << "topology_digest " << state.spec.topology_digest().hex() << "\n";
  std::cout << "spec_digest " << state.spec.digest().hex() << "\n";
  std::cout << "contract_digest " << state.contracts.digest().hex() << "\n";
  std::cout << "valid_bytes " << report.valid_bytes << "\n";
  std::cout << "records " << entries.size() << "\n";
  return 0;
}

int command_release(const Options& options, Connection& connection) {
  cif::ReleaseRequest request;
  request.request_id = cif::RequestId::from_validated("req-" + std::to_string(
      connection.client.next_sequence()));
  request.grant_id = cif::GrantId::from_validated(flag_or(options, "grant", ""));
  request.attempt_id = cif::AttemptId::from_validated(flag_or(options, "attempt", ""));
  request.lease_id = cif::LeaseId::from_validated(flag_or(options, "lease", ""));
  request.administrative = flag_present(options, "administrative");
  request.provenance.client = cif::ClientId::from_validated("cif-cli");
  request.provenance.origin = "cif-cli";
  const cif::Status shape = request.validate_shape();
  if (!shape.ok()) {
    std::cerr << "cif: " << shape.to_string() << "\n";
    return 2;
  }
  cif::AuthorityDecision decision;
  const cif::Status status = connection.client.release(request, decision);
  if (!status.ok()) {
    std::cerr << "cif: " << status.to_string() << "\n";
    return 3;
  }
  return report_decision(options, decision);
}

int command_resolve(const Options& options, Connection& connection) {
  cif::ResolveRequest request;
  request.request_id = cif::RequestId::from_validated("req-" + std::to_string(
      connection.client.next_sequence()));
  request.attempt_id = cif::AttemptId::from_validated(flag_or(options, "attempt", ""));
  request.provenance.client = cif::ClientId::from_validated("cif-cli");
  request.provenance.origin = "cif-cli";
  const cif::Status shape = request.validate_shape();
  if (!shape.ok()) {
    std::cerr << "cif: " << shape.to_string() << "\n";
    return 2;
  }
  cif::AuthorityDecision decision;
  const cif::Status status = connection.client.resolve(request, decision);
  if (!status.ok()) {
    std::cerr << "cif: " << status.to_string() << "\n";
    return 3;
  }
  return report_decision(options, decision);
}

int command_ack(const Options& options, Connection& connection) {
  cif::AcknowledgeRequest request;
  request.request_id = cif::RequestId::from_validated("req-" + std::to_string(
      connection.client.next_sequence()));
  request.grant_id = cif::GrantId::from_validated(flag_or(options, "grant", ""));
  request.lease_id = cif::LeaseId::from_validated(flag_or(options, "lease", ""));
  request.attempt_id = cif::AttemptId::from_validated(flag_or(options, "attempt", ""));
  request.provenance.client = cif::ClientId::from_validated("cif-cli");
  request.provenance.origin = "cif-cli";
  const cif::Status shape = request.validate_shape();
  if (!shape.ok()) {
    std::cerr << "cif: " << shape.to_string() << "\n";
    return 2;
  }
  cif::AuthorityDecision decision;
  const cif::Status status = connection.client.acknowledge(request, decision);
  if (!status.ok()) {
    std::cerr << "cif: " << status.to_string() << "\n";
    return 3;
  }
  return report_decision(options, decision);
}

int command_cancel(const Options& options, Connection& connection) {
  cif::CancelRequest request;
  request.request_id = cif::RequestId::from_validated("req-" + std::to_string(
      connection.client.next_sequence()));
  request.attempt_id = cif::AttemptId::from_validated(flag_or(options, "attempt", ""));
  request.grant_id = cif::GrantId::from_validated(flag_or(options, "grant", ""));
  request.reason = flag_or(options, "reason", "");
  request.provenance.client = cif::ClientId::from_validated("cif-cli");
  request.provenance.origin = "cif-cli";
  const cif::Status shape = request.validate_shape();
  if (!shape.ok()) {
    std::cerr << "cif: " << shape.to_string() << "\n";
    return 2;
  }
  cif::AuthorityDecision decision;
  const cif::Status status = connection.client.cancel(request, decision);
  if (!status.ok()) {
    std::cerr << "cif: " << status.to_string() << "\n";
    return 3;
  }
  return report_decision(options, decision);
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!parse_options(argc, argv, options)) {
    print_usage();
    return 2;
  }
  if (flag_present(options, "help") || options.positional.empty()) {
    print_usage();
    return options.positional.empty() && !flag_present(options, "help") ? 2 : 0;
  }

  const std::string command = options.positional[0];
  if (command == "version") {
    return command_version();
  }
  if (command == "journal") {
    return command_journal(options);
  }
  if (command == "digest") {
    return command_digest(options);
  }

  Connection connection;
  if (!connect(options, connection)) {
    return 3;
  }

  if (command == "query") {
    return command_query(options, connection);
  }
  if (command == "admin") {
    return command_admin(options, connection);
  }
  if (command == "submit") {
    return command_submit(options, connection);
  }
  if (command == "load") {
    return command_load(options, connection);
  }
  if (command == "release") {
    return command_release(options, connection);
  }
  if (command == "resolve") {
    return command_resolve(options, connection);
  }
  if (command == "ack") {
    return command_ack(options, connection);
  }
  if (command == "cancel") {
    return command_cancel(options, connection);
  }
  std::cerr << "cif: unknown command '" << cif::sanitise_for_display(command, 32) << "'\n";
  print_usage();
  return 2;
}
