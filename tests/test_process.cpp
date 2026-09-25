// Cluster Interconnect Fabric (CIF) -- multiprocess durability and fencing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Threads are not multiprocess proof, so nothing in this file uses threads to
// stand in for processes. Every claim here is demonstrated with independent OS
// processes:
//
//   * cifd is spawned as a real child process, killed with TerminateProcess
//     (SIGKILL on POSIX) -- no destructors, no flush, no cooperation -- and
//     restarted against the same journal.
//   * this test binary re-executes *itself* in a child mode that drives the
//     engine through a durability-sink decorator which hard-kills the process
//     the instant a chosen transition has become durable. That is how the
//     commit-before-acknowledge boundary is hit exactly rather than
//     approximately.
//
// A crash boundary is never inferred from timing: it is the moment a specific
// record has been written and synced.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "cif/authority.hpp"
#include "cif/client.hpp"
#include "cif/journal.hpp"
#include "cif/platform.hpp"
#include "cif/process.hpp"
#include "cif/server.hpp"
#include "cif/version.hpp"
#include "cif/wire.hpp"
#include "harness.hpp"

#if defined(_WIN32)
#include <process.h>
#include <windows.h>
#else
#include <csignal>
#include <unistd.h>
#endif

using namespace cif;

namespace {

// ---------------------------------------------------------------------------
// Hard self-termination. Deliberately not a clean exit: no destructors run, no
// buffers are flushed, no journal close is attempted.
// ---------------------------------------------------------------------------
[[noreturn]] void hard_kill_self(std::uint32_t code) {
#if defined(_WIN32)
  ::TerminateProcess(::GetCurrentProcess(), code);
  // TerminateProcess is asynchronous for the calling thread only in the sense
  // that it never returns; if it somehow did, fall through to abort.
  std::abort();
#else
  ::kill(::getpid(), SIGKILL);
  std::abort();
#endif
}

constexpr std::uint32_t kCrashExitCode = 99;

/// A hard kill looks different on each platform: TerminateProcess reports the
/// code we asked for, SIGKILL reports as a signal death. Both mean "the process
/// was destroyed without running a single destructor".
[[nodiscard]] bool is_hard_kill(std::uint32_t exit_code) {
  return exit_code == kCrashExitCode || exit_code == 137u || exit_code == 128u + 9u;
}

const char* kServiceA = "trainers";
const char* kServiceB = "servers";

struct Seed {
  MemberId source = MemberId::from_validated("m-a");
  MemberId destination = MemberId::from_validated("m-b");
  Digest256 source_digest = sha256("member:a");
  Digest256 destination_digest = sha256("member:b");
  PathId path = PathId::from_validated("p-1");
  ContractId contract = ContractId::from_validated("c-1");
};

void seed_core(AuthorityCore& core, const Seed& seed) {
  Member a;
  a.id = seed.source;
  a.domain = MemberDomainId::from_validated("d-1");
  a.generation = MemberGeneration{1};
  a.digest = seed.source_digest;
  a.lifecycle = MemberLifecycle::Active;
  CIF_REQUIRE(LocalityPath::parse("dc/room1/rack1/pod1", a.locality));
  a.services.push_back(ServiceGroupId::from_validated(kServiceA));

  Member b = a;
  b.id = seed.destination;
  b.domain = MemberDomainId::from_validated("d-2");
  b.digest = seed.destination_digest;
  CIF_REQUIRE(LocalityPath::parse("dc/room2/rack2/pod2", b.locality));
  b.services.clear();
  b.services.push_back(ServiceGroupId::from_validated(kServiceB));

  Path path;
  path.id = seed.path;
  path.generation = PathGeneration{1};
  path.source_member = seed.source;
  path.destination_member = seed.destination;
  path.capacity_units = 64;

  CommunicationContract contract;
  contract.id = seed.contract;
  contract.generation = ContractGeneration{1};
  contract.source_service = ServiceGroupId::from_validated(kServiceA);
  contract.destination_service = ServiceGroupId::from_validated(kServiceB);
  contract.min_capacity_units = 1;

  CIF_REQUIRE_OK(core.upsert_member(a));
  CIF_REQUIRE_OK(core.upsert_member(b));
  CIF_REQUIRE_OK(core.upsert_path(path));
  CIF_REQUIRE_OK(core.upsert_contract(contract));
}

AuthorityRequest build_request(const AuthorityCore& core, const Seed& seed,
                               const std::string& attempt, std::uint64_t units) {
  AuthorityRequest request;
  request.request_id = RequestId::from_validated("req-" + attempt);
  request.attempt_id = AttemptId::from_validated(attempt);
  request.contract_id = seed.contract;
  request.contract_generation = core.contracts().find(seed.contract)->generation;
  request.cluster_id = core.spec().cluster_id();
  request.cluster_generation = core.spec().generation();
  request.epoch = core.spec().epoch();
  request.incarnation = core.spec().incarnation();
  request.policy_generation = core.spec().policy_generation();
  request.source_member = seed.source;
  request.destination_member = seed.destination;
  request.path_id = seed.path;
  request.path_generation = core.spec().find_path(seed.path)->generation;
  request.requested_units = units;
  request.lease_ticks = 4096;
  request.allow_degraded = false;
  request.source_member_generation = core.spec().find_member(seed.source)->generation;
  request.source_member_digest = seed.source_digest;
  request.destination_member_generation = core.spec().find_member(seed.destination)->generation;
  request.destination_member_digest = seed.destination_digest;
  return request;
}

// ---------------------------------------------------------------------------
// Crash-boundary sink.
//
// It wraps the real journal sink and hard-kills the process the moment a
// nominated record kind has been written *and synced*. Nothing is simulated:
// the record really is durable when the process dies.
// ---------------------------------------------------------------------------
class CrashBoundarySink final : public DurabilitySink {
 public:
  CrashBoundarySink(Journal& journal, JournalRecordKind boundary, std::uint64_t ordinal)
      : inner_(journal), boundary_(boundary), ordinal_(ordinal) {}

  [[nodiscard]] Status append(JournalEntry& entry, bool durable) override {
    const JournalRecordKind kind = entry.kind;
    CIF_TRY(inner_.append(entry, durable));
    if (kind == boundary_) {
      ++seen_;
      if (seen_ >= ordinal_) {
        hard_kill_self(kCrashExitCode);
      }
    }
    return Status::success();
  }

  [[nodiscard]] Status compact(const JournalEntry& snapshot) override {
    return inner_.compact(snapshot);
  }
  [[nodiscard]] bool durable() const noexcept override { return true; }
  [[nodiscard]] bool should_compact() const noexcept override { return inner_.should_compact(); }

 private:
  JournalDurabilitySink inner_;
  JournalRecordKind boundary_;
  std::uint64_t ordinal_;
  std::uint64_t seen_ = 0;
};

/// Opens a journal, recovering whatever survives, exactly as cifd does.
Status open_recovered(const std::string& path, Journal& journal, AuthorityCore& core,
                      RecoveryReport& report, DurabilitySink* sink) {
  std::vector<JournalEntry> entries;
  CIF_TRY(Journal::scan(path, entries, report));
  RecoveredState recovered;
  CIF_TRY(replay_journal(entries, recovered));
  CIF_TRY(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                       report.last_sequence));
  core.reset();
  core.attach_sink(sink);
  if (!recovered.has_controller) {
    return core.initialize(ClusterId::from_validated("cluster-mp"),
                           ControllerIncarnation::generate(), PolicyGeneration{1}, Tick{1}, sink);
  }
  const Tick resume{recovered.tick.is_zero() ? 1 : recovered.tick.value() + 1};
  return core.recover(recovered.spec, recovered.contracts, std::move(recovered.grants),
                      std::move(recovered.attempts), recovered.counters, report,
                      ControllerIncarnation::generate(), resume);
}

// ---------------------------------------------------------------------------
// Child modes
// ---------------------------------------------------------------------------
struct ChildArguments {
  std::string mode;
  std::string journal;
  std::string boundary;
  std::string report;
  std::uint64_t ordinal = 1;
  std::uint64_t attempts = 4;
  std::string cluster = "cluster-mp";
};

bool parse_child_arguments(int argc, char** argv, ChildArguments& out) {
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (flag == "--child-crash" || flag == "--child-recover") {
      out.mode = flag;
      continue;
    }
    if (i + 1 >= argc) {
      return false;
    }
    const std::string value = argv[++i];
    if (flag == "--journal") {
      out.journal = value;
    } else if (flag == "--boundary") {
      out.boundary = value;
    } else if (flag == "--report") {
      out.report = value;
    } else if (flag == "--ordinal") {
      if (!parse_decimal_u64(value, out.ordinal)) {
        return false;
      }
    } else if (flag == "--attempts") {
      if (!parse_decimal_u64(value, out.attempts)) {
        return false;
      }
    } else if (flag == "--cluster") {
      out.cluster = value;
    } else {
      return false;
    }
  }
  return !out.mode.empty() && !out.journal.empty();
}

bool boundary_kind(const std::string& name, JournalRecordKind& kind, std::uint64_t& ordinal) {
  if (name == "after-prepare") {
    kind = JournalRecordKind::GrantPrepared;
    return true;
  }
  if (name == "after-commit") {
    kind = JournalRecordKind::GrantCommitted;
    return true;
  }
  if (name == "after-attempt") {
    kind = JournalRecordKind::AttemptTerminal;
    return true;
  }
  if (name == "after-ack") {
    kind = JournalRecordKind::GrantAcknowledged;
    return true;
  }
  if (name == "after-second-commit") {
    kind = JournalRecordKind::GrantCommitted;
    ordinal = 2;
    return true;
  }
  if (name == "after-member") {
    kind = JournalRecordKind::MemberUpsert;
    return true;
  }
  return false;
}

/// Runs a controller against a real journal and dies at the chosen boundary.
int run_crash_child(const ChildArguments& arguments) {
  JournalRecordKind kind = JournalRecordKind::Invalid;
  std::uint64_t ordinal = arguments.ordinal;
  if (!boundary_kind(arguments.boundary, kind, ordinal)) {
    std::fprintf(stderr, "unknown boundary '%s'\n", arguments.boundary.c_str());
    return 2;
  }

  // The journal is *not* removed here: the parent decides whether this is a
  // fresh run or another round against state that already survived a kill.
  Journal journal;
  RecoveryReport report;
  AuthorityCore core;
  CrashBoundarySink sink(journal, kind, ordinal);
  const Status opened = open_recovered(arguments.journal, journal, core, report, &sink);
  if (!opened.ok()) {
    std::fprintf(stderr, "open failed: %s\n", opened.to_string().c_str());
    return 2;
  }
  const Seed seed;
  seed_core(core, seed);

  // Acknowledge the grant so that a later boundary exercises the acknowledged
  // recovery path rather than the quarantined one.
  // Attempt ids carry the epoch: an attempt id is exactly-once *for a specific
  // request*, and the coordinate moves on every restart, so a fresh epoch always
  // needs a fresh identity.
  const std::string epoch_tag = core.spec().epoch().to_string();
  for (std::uint64_t i = 0; i < arguments.attempts; ++i) {
    const std::string attempt = "att-" + epoch_tag + "-" + std::to_string(i);
    const AuthorityDecision decision = core.submit(build_request(core, seed, attempt, 4));
    if (decision.grant.has_value()) {
      AcknowledgeRequest acknowledge;
      acknowledge.request_id = RequestId::from_validated("req-ack-" + std::to_string(i));
      acknowledge.grant_id = decision.grant->grant_id;
      acknowledge.lease_id = decision.grant->lease_id;
      acknowledge.attempt_id = decision.grant->attempt_id;
      static_cast<void>(core.acknowledge(acknowledge));
    }
  }
  // Reaching here means the boundary was never hit.
  static_cast<void>(journal.close());
  std::fprintf(stderr, "boundary '%s' was never reached\n", arguments.boundary.c_str());
  return 3;
}

/// Opens a journal in a fresh process, recovers, reports, and exits.
int run_recover_child(const ChildArguments& arguments) {
  Journal journal;
  RecoveryReport report;
  AuthorityCore core;
  const Status opened = open_recovered(arguments.journal, journal, core, report, nullptr);
  if (!opened.ok()) {
    std::fprintf(stderr, "recover failed: %s\n", opened.to_string().c_str());
    return 2;
  }

  std::ostringstream out;
  out << "recovered " << (core.recovered() ? "true" : "false") << "\n";
  out << "fresh " << (report.fresh ? "true" : "false") << "\n";
  out << "truncated_tail " << (report.truncated_tail ? "true" : "false") << "\n";
  out << "integrity_failure " << (report.integrity_failure ? "true" : "false") << "\n";
  out << "generation " << core.spec().generation().to_string() << "\n";
  out << "epoch " << core.spec().epoch().to_string() << "\n";
  out << "incarnation " << core.spec().incarnation().hex() << "\n";
  out << "members " << core.spec().member_count() << "\n";
  out << "paths " << core.spec().path_count() << "\n";
  out << "contracts " << core.contracts().size() << "\n";
  out << "topology_digest " << core.spec().topology_digest().hex() << "\n";
  out << "state_digest " << core.state_digest().hex() << "\n";
  out << "quarantined_units " << core.quarantined_units() << "\n";
  out << "live_units " << core.path_committed_units(Seed{}.path) << "\n";

  std::size_t live = 0;
  std::size_t quarantined = 0;
  std::size_t released = 0;
  std::size_t revoked = 0;
  for (const AuthorityGrant& grant : core.grants()) {
    switch (grant.state) {
      case GrantState::Committed:
      case GrantState::Acknowledged:
        ++live;
        break;
      case GrantState::Ambiguous:
        ++quarantined;
        break;
      case GrantState::Released:
        ++released;
        break;
      case GrantState::Fenced:
      case GrantState::Revoked:
        ++revoked;
        break;
      default:
        break;
    }
  }
  out << "grants " << core.grants().size() << "\n";
  out << "live_grants " << live << "\n";
  out << "quarantined_grants " << quarantined << "\n";
  out << "released_grants " << released << "\n";
  out << "revoked_grants " << revoked << "\n";
  out << "attempts " << core.attempts().size() << "\n";
  for (const AttemptRecord& attempt : core.attempts()) {
    out << "attempt " << attempt.attempt_id.to_string() << " " << to_string(attempt.outcome) << " "
        << to_string(attempt.primary_reason) << "\n";
  }
  const Status check = core.self_check();
  out << "self_check " << (check.ok() ? "ok" : check.to_string()) << "\n";
  if (!check.ok()) {
    std::fprintf(stderr, "self check failed: %s\n", check.to_string().c_str());
  }

  const Status closed = journal.close();
  out << "close " << (closed.ok() ? "ok" : closed.to_string()) << "\n";

  std::ofstream file(arguments.report, std::ios::trunc);
  if (!file) {
    std::fprintf(stderr, "cannot write report '%s'\n", arguments.report.c_str());
    return 2;
  }
  file << out.str();
  file.flush();
  return 0;
}

std::map<std::string, std::string> read_report(const std::string& path) {
  std::map<std::string, std::string> values;
  std::ifstream file(path);
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::size_t space = line.find(' ');
    if (space == std::string::npos) {
      continue;
    }
    values[line.substr(0, space)] = line.substr(space + 1);
  }
  return values;
}

bool report_flag(const std::map<std::string, std::string>& report, const std::string& key) {
  const auto it = report.find(key);
  return it != report.end() && it->second == "true";
}

std::uint64_t report_number(const std::map<std::string, std::string>& report,
                            const std::string& key) {
  const auto it = report.find(key);
  if (it == report.end()) {
    return 0;
  }
  std::uint64_t value = 0;
  static_cast<void>(parse_decimal_u64(it->second, value));
  return value;
}

int child_mode_handler(int argc, char** argv) {
  ChildArguments arguments;
  bool looks_like_child = false;
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (flag == "--child-crash" || flag == "--child-recover") {
      looks_like_child = true;
      break;
    }
  }
  if (!looks_like_child) {
    return cif::test::kNotHandled;
  }
  if (!parse_child_arguments(argc, argv, arguments)) {
    std::fprintf(stderr, "bad child arguments\n");
    return 2;
  }
  // A child mode must never escape as an uncaught exception: the parent checks
  // the exit code to decide whether the hard kill happened where it intended.
  try {
    if (arguments.mode == "--child-crash") {
      return run_crash_child(arguments);
    }
    return run_recover_child(arguments);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "child mode failed: %s\n", error.what());
    return 4;
  }
}

[[maybe_unused]] const bool g_child_mode_registered = [] {
  cif::test::set_child_mode_handler(&child_mode_handler);
  return true;
}();

// ---------------------------------------------------------------------------
// Parent-side helpers
// ---------------------------------------------------------------------------
ProcessOptions child_options(const ChildArguments& arguments) {
  ProcessOptions options;
  options.executable = current_executable_path();
  options.arguments.push_back(arguments.mode);
  options.arguments.push_back("--journal");
  options.arguments.push_back(arguments.journal);
  if (!arguments.boundary.empty()) {
    options.arguments.push_back("--boundary");
    options.arguments.push_back(arguments.boundary);
  }
  if (!arguments.report.empty()) {
    options.arguments.push_back("--report");
    options.arguments.push_back(arguments.report);
  }
  options.arguments.push_back("--attempts");
  options.arguments.push_back(to_decimal(arguments.attempts));
  return options;
}

std::uint32_t run_child_to_completion(const ChildArguments& arguments) {
  ChildProcess child;
  CIF_REQUIRE_OK(ChildProcess::spawn(child_options(arguments), child));
  std::uint32_t exit_code = 0;
  CIF_REQUIRE_OK(child.wait(exit_code));
  return exit_code;
}

/// Spawns a cifd child, waits for it to listen, and hands back the port.
struct Daemon {
  ChildProcess process;
  std::string ready_file;
  std::string stop_file;
  std::string journal;
  std::uint16_t port = 0;
  std::string incarnation;
  std::string epoch;

  Daemon() = default;
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  /// A failed assertion must not leave a daemon running: an orphan would keep
  /// holding a port and a journal and would poison the next run.
  ~Daemon() {
    if (process.valid() && process.running()) {
      static_cast<void>(process.terminate(kCrashExitCode));
    }
  }
};

std::vector<std::string> daemon_arguments(const Daemon& daemon) {
  return {"--cluster",         "cluster-daemon",
          "--port",            "0",
          "--journal",         daemon.journal,
          "--ready-file",      daemon.ready_file,
          "--stop-file",       daemon.stop_file,
          "--housekeeping-ms", "0"};
}

/// Asks a daemon to stop cleanly and waits for it. Returns its exit code.
std::uint32_t stop_daemon(Daemon& daemon) {
  {
    std::ofstream stop(daemon.stop_file, std::ios::trunc);
    stop << "stop\n";
  }
  std::uint32_t exit_code = 0;
  CIF_REQUIRE_OK(daemon.process.wait(exit_code));
  return exit_code;
}

void start_daemon(Daemon& daemon, const std::string& name) {
  daemon.ready_file = cif::test::scratch_path(name + ".ready");
  daemon.journal = cif::test::scratch_path(name + ".cifjournal");
  std::error_code error;
  std::filesystem::remove(daemon.ready_file, error);

  const std::filesystem::path executable = find_sibling_tool("cifd");
  CIF_REQUIRE_MSG(!executable.empty(), "cifd was not found next to the test binary");

  daemon.stop_file = cif::test::scratch_path(name + ".stop");
  std::filesystem::remove(daemon.stop_file, error);
  ProcessOptions options;
  options.executable = executable;
  options.arguments = daemon_arguments(daemon);
  options.output_file = cif::test::scratch_path(name + ".log");
  CIF_REQUIRE_OK(ChildProcess::spawn(options, daemon.process));
  CIF_REQUIRE_OK(wait_for_file(daemon.ready_file, 30000));

  std::string text;
  CIF_REQUIRE_OK(read_text_file(daemon.ready_file, text));
  std::string port;
  CIF_REQUIRE_MSG(lookup_ready_value(text, "port", port), "ready file has no port");
  std::uint64_t parsed = 0;
  CIF_REQUIRE(parse_decimal_u64(port, parsed) && parsed > 0 && parsed <= 65535);
  daemon.port = static_cast<std::uint16_t>(parsed);
  static_cast<void>(lookup_ready_value(text, "incarnation", daemon.incarnation));
  static_cast<void>(lookup_ready_value(text, "epoch", daemon.epoch));
}

ClientOptions daemon_client_options(const Daemon& daemon, const std::string& client) {
  ClientOptions options;
  options.host = "127.0.0.1";
  options.port = daemon.port;
  options.timeout_millis = 5000;
  options.client = ClientId::from_validated(client);
  return options;
}

/// Re-reads the controller coordinate. Every admin command advances the cluster
/// generation, so a client that has just seeded a cluster must refresh before it
/// can build a request that is not immediately stale.
void refresh_or_fail(AuthorityClient& client) {
  const Status status = client.refresh();
  CIF_REQUIRE_MSG(status.ok(), status.to_string());
}

void require_admin(AuthorityClient& client, const AdminCommand& command, const char* what) {
  AdminResult result;
  CIF_REQUIRE_OK(client.admin(command, result));
  if (!result.ok()) {
    CIF_FAIL(std::string(what) + ": " + to_string(result.code) + " " + result.message);
  }
}

void seed_daemon(AuthorityClient& client) {
  const Seed seed;
  Member a;
  a.id = seed.source;
  a.domain = MemberDomainId::from_validated("d-1");
  a.generation = MemberGeneration{1};
  a.digest = seed.source_digest;
  a.lifecycle = MemberLifecycle::Active;
  CIF_REQUIRE(LocalityPath::parse("dc/room1/rack1/pod1", a.locality));
  a.services.push_back(ServiceGroupId::from_validated(kServiceA));

  Member b = a;
  b.id = seed.destination;
  b.domain = MemberDomainId::from_validated("d-2");
  b.digest = seed.destination_digest;
  CIF_REQUIRE(LocalityPath::parse("dc/room2/rack2/pod2", b.locality));
  b.services.clear();
  b.services.push_back(ServiceGroupId::from_validated(kServiceB));

  Path path;
  path.id = seed.path;
  path.generation = PathGeneration{1};
  path.source_member = seed.source;
  path.destination_member = seed.destination;
  path.capacity_units = 64;

  CommunicationContract contract;
  contract.id = seed.contract;
  contract.generation = ContractGeneration{1};
  contract.source_service = ServiceGroupId::from_validated(kServiceA);
  contract.destination_service = ServiceGroupId::from_validated(kServiceB);
  contract.min_capacity_units = 1;

  AdminCommand command;
  command.kind = AdminKind::UpsertMember;
  command.member = a;
  require_admin(client, command, "seed member a");
  command.member = b;
  require_admin(client, command, "seed member b");
  command.kind = AdminKind::UpsertPath;
  command.path = path;
  require_admin(client, command, "seed path");
  command.kind = AdminKind::UpsertContract;
  command.contract = contract;
  require_admin(client, command, "seed contract");
}

AuthorityRequest daemon_request(const AuthorityClient& client, const std::string& attempt,
                                std::uint64_t units) {
  const Seed seed;
  AuthorityRequest request;
  request.request_id = RequestId::from_validated("req-" + attempt);
  request.attempt_id = AttemptId::from_validated(attempt);
  request.contract_id = seed.contract;
  request.contract_generation = ContractGeneration{1};
  request.cluster_id = client.server().cluster_id;
  request.cluster_generation = client.server().generation;
  request.epoch = client.server().epoch;
  request.incarnation = client.server().incarnation;
  request.policy_generation = client.server().policy;
  request.source_member = seed.source;
  request.destination_member = seed.destination;
  request.path_id = seed.path;
  request.path_generation = PathGeneration{1};
  request.requested_units = units;
  request.lease_ticks = 4096;
  request.allow_degraded = false;
  request.source_member_generation = MemberGeneration{1};
  request.source_member_digest = seed.source_digest;
  request.destination_member_generation = MemberGeneration{1};
  request.destination_member_digest = seed.destination_digest;
  return request;
}

}  // namespace

// ---------------------------------------------------------------------------
// precise lifecycle-boundary kills
// ---------------------------------------------------------------------------
CIF_TEST(multiprocess, commit_before_acknowledge_is_exactly_the_boundary) {
  const std::vector<std::string> boundaries = {"after-prepare", "after-commit", "after-attempt",
                                               "after-ack", "after-member"};
  for (const std::string& boundary : boundaries) {
    const std::string journal = cif::test::scratch_path("mp-" + boundary + ".cifjournal");
    const std::string report_path = cif::test::scratch_path("mp-" + boundary + ".report");
    std::error_code error;
    std::filesystem::remove(journal, error);
    std::filesystem::remove(report_path, error);

    ChildArguments crash;
    crash.mode = "--child-crash";
    crash.journal = journal;
    crash.boundary = boundary;
    crash.attempts = 3;
    const std::uint32_t exit_code = run_child_to_completion(crash);
    // The child really died on the boundary, not by exiting cleanly.
    CIF_CHECK_MSG(is_hard_kill(exit_code),
                  "boundary " + boundary + " exited with " + std::to_string(exit_code));

    ChildArguments recover;
    recover.mode = "--child-recover";
    recover.journal = journal;
    recover.report = report_path;
    CIF_CHECK_EQ(run_child_to_completion(recover), std::uint32_t{0});

    const std::map<std::string, std::string> report = read_report(report_path);
    CIF_REQUIRE_MSG(!report.empty(), "no report for boundary " + boundary);
    CIF_CHECK_EQ(report.at("recovered"), std::string("true"));
    CIF_CHECK_EQ(report.at("self_check"), std::string("ok"));
    CIF_CHECK_EQ(report.at("close"), std::string("ok"));

    const std::uint64_t live_units = report_number(report, "live_units");
    const std::uint64_t quarantined = report_number(report, "quarantined_units");

    if (boundary == "after-prepare") {
      // A prepare without a commit is provably not authority: no capacity is
      // held and no grant is live.
      CIF_CHECK_EQ(live_units, std::uint64_t{0});
      CIF_CHECK_EQ(quarantined, std::uint64_t{0});
      CIF_CHECK_EQ(report_number(report, "live_grants"), std::uint64_t{0});
    } else if (boundary == "after-commit") {
      // A durable commit whose acknowledgement was never recorded is genuinely
      // ambiguous: the capacity is quarantined, never silently handed out and
      // never silently dropped.
      CIF_CHECK_MSG(quarantined == 4, "quarantined=" + std::to_string(quarantined));
      CIF_CHECK_EQ(live_units, std::uint64_t{4});
      CIF_CHECK_EQ(report_number(report, "quarantined_grants"), std::uint64_t{1});
    } else if (boundary == "after-attempt") {
      CIF_CHECK_EQ(quarantined, std::uint64_t{4});
      CIF_CHECK_EQ(live_units, std::uint64_t{4});
    } else if (boundary == "after-ack") {
      // The caller had demonstrably observed the grant, so it is re-validated
      // and re-issued under the new epoch rather than quarantined.
      CIF_CHECK_EQ(quarantined, std::uint64_t{0});
      CIF_CHECK_EQ(live_units, std::uint64_t{4});
      CIF_CHECK_EQ(report_number(report, "live_grants"), std::uint64_t{1});
    } else if (boundary == "after-member") {
      // Killed while the cluster was still being declared: nothing authoritative
      // exists yet, and the recovered controller passes its own invariants.
      CIF_CHECK_EQ(live_units, std::uint64_t{0});
    }
    CIF_CHECK(report_number(report, "members") <= 2);
  }
}

CIF_TEST(multiprocess, repeated_hard_kill_and_restart_is_stable) {
  const std::string journal = cif::test::scratch_path("mp-cycle.cifjournal");
  std::error_code error;
  // Fresh only once: every later cycle must survive the previous kills.
  std::filesystem::remove(journal, error);

  std::string last_incarnation;
  std::uint64_t last_epoch = 0;
  std::string last_topology;
  for (int cycle = 0; cycle < 4; ++cycle) {
    ChildArguments crash;
    crash.mode = "--child-crash";
    crash.journal = journal;
    // Kill at a different lifecycle boundary each round.
    crash.boundary = cycle % 2 == 0 ? "after-commit" : "after-ack";
    crash.attempts = 1;
    const std::uint32_t exit_code = run_child_to_completion(crash);
    CIF_CHECK_MSG(is_hard_kill(exit_code), "cycle " + std::to_string(cycle) + " exit " +
                                               std::to_string(exit_code));

    const std::string report_path =
        cif::test::scratch_path("mp-cycle-" + std::to_string(cycle) + ".report");
    std::filesystem::remove(report_path, error);
    ChildArguments recover;
    recover.mode = "--child-recover";
    recover.journal = journal;
    recover.report = report_path;
    CIF_CHECK_EQ(run_child_to_completion(recover), std::uint32_t{0});

    const std::map<std::string, std::string> report = read_report(report_path);
    CIF_REQUIRE(!report.empty());
    CIF_CHECK_MSG(report.at("self_check") == "ok", report.at("self_check"));
    // The declared topology is identical after every kill: a restart never
    // invents, drops or rewrites a member, path or contract.
    if (cycle > 0) {
      CIF_CHECK_EQ(report.at("topology_digest"), last_topology);
    }
    last_topology = report.at("topology_digest");

    const std::uint64_t epoch = report_number(report, "epoch");
    const std::string incarnation = report.at("incarnation");
    if (cycle > 0) {
      // Every restart is a fresh incarnation and a strictly newer epoch: the
      // fence moves forward and never backwards, even after repeated kills.
      CIF_CHECK_MSG(epoch > last_epoch,
                    "epoch went backwards: " + std::to_string(last_epoch) + " -> " +
                        std::to_string(epoch));
      CIF_CHECK_MSG(incarnation != last_incarnation, "incarnation was reused across a restart");
    }
    last_epoch = epoch;
    last_incarnation = incarnation;

    // Capacity accounting never exceeds the declared total across any number of
    // kills.
    CIF_CHECK(report_number(report, "live_units") <= 64);
  }
}

CIF_TEST(multiprocess, truncated_journal_is_recovered_conservatively) {
  const std::string journal = cif::test::scratch_path("mp-truncate.cifjournal");
  const std::string report_path = cif::test::scratch_path("mp-truncate.report");
  std::error_code error;
  std::filesystem::remove(journal, error);
  std::filesystem::remove(report_path, error);

  // Produce a real journal by running the engine and exiting cleanly. The sink
  // must be attached before the first mutation, so it is created first.
  {
    Journal handle;
    RecoveryReport report;
    AuthorityCore core;
    JournalDurabilitySink sink(handle);
    const Status opened = open_recovered(journal, handle, core, report, &sink);
    CIF_REQUIRE_OK(opened);
    const Seed seed;
    seed_core(core, seed);
    for (int i = 0; i < 3; ++i) {
      static_cast<void>(core.submit(build_request(core, seed, "att-" + std::to_string(i), 4)));
    }
    CIF_REQUIRE_OK(handle.close());
  }

  const std::uint64_t size = platform::file_size_bytes(journal);
  CIF_REQUIRE(size > 64);
  // Torn write: the last record loses its final bytes.
  CIF_REQUIRE_OK(platform::truncate_file(journal, size - 7));

  ChildArguments recover;
  recover.mode = "--child-recover";
  recover.journal = journal;
  recover.report = report_path;
  CIF_CHECK_EQ(run_child_to_completion(recover), std::uint32_t{0});
  const std::map<std::string, std::string> report = read_report(report_path);
  CIF_REQUIRE(!report.empty());
  CIF_CHECK_EQ(report.at("self_check"), std::string("ok"));
  CIF_CHECK(report_flag(report, "truncated_tail") || report_flag(report, "integrity_failure"));
  CIF_CHECK(report_number(report, "live_units") <= 64);
}

// ---------------------------------------------------------------------------
// real cifd: hard kill and restart over the wire
// ---------------------------------------------------------------------------
CIF_TEST(multiprocess, daemon_hard_kill_and_restart_fences_the_old_incarnation) {
  Daemon daemon;
  start_daemon(daemon, "daemon-1");
  CIF_CHECK(daemon.process.running());
  const std::string first_incarnation = daemon.incarnation;
  const std::uint64_t first_epoch = 0;

  GrantId acknowledged_grant;
  LeaseId acknowledged_lease;
  Digest256 topology;
  {
    AuthorityClient client;
    CIF_REQUIRE_OK(client.connect(daemon_client_options(daemon, "daemon-client-1")));
    seed_daemon(client);
    refresh_or_fail(client);
    const Seed seed;

    // One grant is acknowledged; one is left committed-but-unacknowledged.
    AuthorityDecision first;
    CIF_REQUIRE_OK(client.submit(daemon_request(client, "att-acked", 4), first));
    CIF_REQUIRE(first.outcome == AuthorityOutcome::Granted);
    acknowledged_grant = first.grant->grant_id;
    acknowledged_lease = first.grant->lease_id;

    AcknowledgeRequest acknowledge;
    acknowledge.request_id = RequestId::from_validated("req-ack");
    acknowledge.grant_id = acknowledged_grant;
    acknowledge.lease_id = acknowledged_lease;
    acknowledge.attempt_id = AttemptId::from_validated("att-acked");
    AuthorityDecision acked;
    CIF_REQUIRE_OK(client.acknowledge(acknowledge, acked));
    CIF_REQUIRE(acked.outcome == AuthorityOutcome::Granted);

    AuthorityDecision second;
    CIF_REQUIRE_OK(client.submit(daemon_request(client, "att-unacked", 8), second));
    CIF_REQUIRE(second.outcome == AuthorityOutcome::Granted);

    QueryCommand state_query;
    state_query.kind = QueryKind::State;
    QueryResult state;
    CIF_REQUIRE_OK(client.query(state_query, state));
    topology = state.topology_digest;
    CIF_REQUIRE_OK(client.close());
  }
  CIF_CHECK(daemon.process.running());

  // Hard kill: no signal handler, no destructor, no journal close.
  CIF_REQUIRE_OK(daemon.process.terminate(kCrashExitCode));
  CIF_CHECK(!daemon.process.running());

  // Restart against the very same journal.
  Daemon restarted;
  restarted.journal = daemon.journal;
  restarted.ready_file = cif::test::scratch_path("daemon-2.ready");
  std::error_code error;
  std::filesystem::remove(restarted.ready_file, error);
  {
    const std::filesystem::path executable = find_sibling_tool("cifd");
    CIF_REQUIRE(!executable.empty());
    restarted.stop_file = cif::test::scratch_path("daemon-2.stop");
    std::filesystem::remove(restarted.stop_file, error);
    ProcessOptions options;
    options.executable = executable;
    options.arguments = daemon_arguments(restarted);
    options.output_file = cif::test::scratch_path("daemon-2.log");
    CIF_REQUIRE_OK(ChildProcess::spawn(options, restarted.process));
    CIF_REQUIRE_OK(wait_for_file(restarted.ready_file, 30000));
    std::string text;
    CIF_REQUIRE_OK(read_text_file(restarted.ready_file, text));
    std::string port;
    CIF_REQUIRE_MSG(lookup_ready_value(text, "port", port), "ready file has no port");
    std::uint64_t parsed = 0;
    CIF_REQUIRE(parse_decimal_u64(port, parsed));
    restarted.port = static_cast<std::uint16_t>(parsed);
    static_cast<void>(lookup_ready_value(text, "incarnation", restarted.incarnation));
    static_cast<void>(lookup_ready_value(text, "epoch", restarted.epoch));
  }

  CIF_CHECK_MSG(restarted.incarnation != first_incarnation,
                "restarted daemon reused the previous incarnation");

  {
    AuthorityClient client;
    CIF_REQUIRE_OK(client.connect(daemon_client_options(restarted, "daemon-client-2")));
    CIF_CHECK(client.server().valid);

    // The topology survived the kill byte for byte.
    QueryCommand state_query;
    state_query.kind = QueryKind::State;
    QueryResult state;
    CIF_REQUIRE_OK(client.query(state_query, state));
    CIF_CHECK_MSG(state.topology_digest == topology,
                  "the declared cluster changed across a hard restart: " +
                      state.topology_digest.hex() + " != " + topology.hex());
    CIF_CHECK(state.text.find("MEMBER m-a") != std::string::npos);
    CIF_CHECK(state.text.find("MEMBER m-b") != std::string::npos);

    // An acknowledged grant is re-validated and re-issued under the new epoch.
    QueryCommand grant_query;
    grant_query.kind = QueryKind::Grant;
    grant_query.grant_id = acknowledged_grant;
    QueryResult grant_result;
    CIF_REQUIRE_OK(client.query(grant_query, grant_result));
    CIF_CHECK(grant_result.ok());
    CIF_CHECK(grant_result.text.find("AMBIGUOUS") == std::string::npos);

    // The unacknowledged commit is quarantined and reported as indeterminate.
    ResolveRequest resolve;
    resolve.request_id = RequestId::from_validated("req-resolve");
    resolve.attempt_id = AttemptId::from_validated("att-unacked");
    AuthorityDecision resolved;
    CIF_REQUIRE_OK(client.resolve(resolve, resolved));
    CIF_CHECK(resolved.outcome == AuthorityOutcome::Indeterminate);
    CIF_CHECK(resolved.requires_reconciliation);

    // A request built against the pre-kill coordinate is fenced, and the caller
    // is told exactly why.
    const Seed seed;
    AuthorityRequest stale;
    stale.request_id = RequestId::from_validated("req-stale");
    stale.attempt_id = AttemptId::from_validated("att-stale");
    stale.contract_id = seed.contract;
    stale.contract_generation = ContractGeneration{1};
    stale.cluster_id = client.server().cluster_id;
    stale.cluster_generation = client.server().generation;
    stale.epoch = ClusterEpoch{first_epoch == 0 ? 1 : first_epoch};
    stale.incarnation = ControllerIncarnation::from_seed(1);
    stale.policy_generation = client.server().policy;
    stale.source_member = seed.source;
    stale.destination_member = seed.destination;
    stale.path_id = seed.path;
    stale.path_generation = PathGeneration{1};
    stale.requested_units = 4;
    stale.lease_ticks = 4096;
    stale.source_member_generation = MemberGeneration{1};
    stale.source_member_digest = seed.source_digest;
    stale.destination_member_generation = MemberGeneration{1};
    stale.destination_member_digest = seed.destination_digest;
    AuthorityDecision stale_decision;
    CIF_REQUIRE_OK(client.submit(stale, stale_decision));
    CIF_CHECK(stale_decision.outcome == AuthorityOutcome::Fenced);
    CIF_CHECK(stale_decision.primary_reason() == ReasonCode::IncarnationStale ||
              stale_decision.primary_reason() == ReasonCode::EpochStale);

    QueryCommand verify;
    verify.kind = QueryKind::Verify;
    QueryResult verify_result;
    CIF_REQUIRE_OK(client.query(verify, verify_result));
    CIF_CHECK_MSG(verify_result.ok(), verify_result.message);

    // Clean shutdown of the restarted daemon.
    CIF_REQUIRE_OK(client.bye());
    static_cast<void>(client.close());
  }
  CIF_CHECK_EQ(stop_daemon(restarted), std::uint32_t{0});
  // The first daemon was hard-killed, so its exit code is the kill code, not a
  // clean zero. A clean zero here would mean it was never really killed.
  std::uint32_t killed_code = 0;
  CIF_REQUIRE_OK(daemon.process.wait(killed_code));
  CIF_CHECK_MSG(is_hard_kill(killed_code),
                "killed daemon reported exit " + std::to_string(killed_code));
}

CIF_TEST(multiprocess, daemon_survives_kill_under_a_burst_of_work) {
  Daemon daemon;
  start_daemon(daemon, "daemon-burst");
  const std::string first_incarnation = daemon.incarnation;

  {
    AuthorityClient seed_client;
    CIF_REQUIRE_OK(seed_client.connect(daemon_client_options(daemon, "daemon-burst-seed")));
    seed_daemon(seed_client);
    CIF_REQUIRE_OK(seed_client.close());
  }

  // Hammer the daemon from several independent connections while it is killed
  // underneath them.
  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> submitted{0};
  std::vector<std::thread> hammers;
  for (int worker = 0; worker < 4; ++worker) {
    hammers.emplace_back([&, worker] {
      AuthorityClient client;
      if (!client.connect(daemon_client_options(daemon, "hammer-" + std::to_string(worker))).ok()) {
        return;
      }
      refresh_or_fail(client);
      for (int i = 0; i < 200 && !stop.load(); ++i) {
        AuthorityDecision decision;
        const std::string attempt = "att-" + std::to_string(worker) + "-" + std::to_string(i);
        if (!client.submit(daemon_request(client, attempt, 1), decision).ok()) {
          return;
        }
        submitted.fetch_add(1);
      }
      static_cast<void>(client.close());
    });
  }
  while (submitted.load() < 20) {
    platform::sleep_millis(1);
  }
  CIF_REQUIRE_OK(daemon.process.terminate(kCrashExitCode));
  stop.store(true);
  for (std::thread& hammer : hammers) {
    hammer.join();
  }
  CIF_CHECK(!daemon.process.running());

  // Recover in a fresh process and prove the invariants still hold.
  const std::string report_path = cif::test::scratch_path("daemon-burst.report");
  std::error_code error;
  std::filesystem::remove(report_path, error);
  ChildArguments recover;
  recover.mode = "--child-recover";
  recover.journal = daemon.journal;
  recover.report = report_path;
  CIF_CHECK_EQ(run_child_to_completion(recover), std::uint32_t{0});
  const std::map<std::string, std::string> report = read_report(report_path);
  CIF_REQUIRE(!report.empty());
  CIF_CHECK_EQ(report.at("self_check"), std::string("ok"));
  CIF_CHECK(report_number(report, "live_units") <= 64);
  CIF_CHECK(report_number(report, "members") == 2);
  CIF_CHECK(report.at("incarnation") != first_incarnation);
  CIF_CHECK(submitted.load() >= 20);
}
