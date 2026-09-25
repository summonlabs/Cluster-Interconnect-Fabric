// Cluster Interconnect Fabric (CIF) -- cifd, the authority daemon.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// cifd | cluster <id> [options]
//
// Runs one cluster authority: it listens on a loopback TCP port, serves the CIF
// wire protocol, and (when a journal path is given) makes every authority
// transition durable before it takes effect in memory.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "cif/process.hpp"
#include "cif/render.hpp"
#include "cif/server.hpp"
#include "cif/text.hpp"
#include "cif/version.hpp"
#include "cif/platform.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace {

std::atomic<bool> g_stop_requested{false};

#if defined(_WIN32)
BOOL WINAPI console_handler(DWORD signal) {
  if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
    g_stop_requested.store(true);
    return TRUE;
  }
  return FALSE;
}
#else
#include <csignal>
extern "C" void cif_signal_handler(int) { g_stop_requested.store(true); }
#endif

void print_usage() {
  std::cout <<
      "cifd " CIF_VERSION_STRING " -- cluster interconnect fabric authority daemon\n"
      "\n"
      "usage: cifd --cluster <id> [options]\n"
      "\n"
      "required\n"
      "  --cluster <id>              cluster identity this daemon rules\n"
      "\n"
      "options\n"
      "  --host <addr>               bind address (default 127.0.0.1)\n"
      "  --port <n>                  bind port, 0 picks a free port (default 0)\n"
      "  --journal <path>            durable transition log; omit for in-memory state\n"
      "  --ready-file <path>         written once the listener is bound\n"
      "  --stop-file <path>          stop when this file appears\n"
      "  --policy <n>                initial policy generation (default 1)\n"
      "  --housekeeping-ms <n>       logical clock period; 0 disables (default 50)\n"
      "  --max-connections <n>       connection ceiling (default 128)\n"
      "  --ingress <n>               bounded ingress queue depth (default 8192)\n"
      "  --recovery <policy>         revalidate-acknowledged | fence-all\n"
      "  --duration-seconds <n>      stop after n seconds (0 = run until signalled)\n"
      "  --log <path>                append a status line per housekeeping round\n"
      "  --no-durable                accept a journal path but do not fsync (never default)\n"
      "  --help                      this text\n"
      "\n"
      "exit codes: 0 clean stop, 2 bad arguments, 3 start failure, 4 invariant violation\n";
}

struct Arguments {
  cif::ServerOptions server;
  std::uint64_t duration_seconds = 0;
  std::filesystem::path log_path;
  std::filesystem::path stop_file;
  bool help = false;
};

bool parse_u64(const std::string& text, std::uint64_t& out) {
  return cif::parse_decimal_u64(text, out);
}

bool parse_arguments(int argc, char** argv, Arguments& out) {
  // The value of a flag is taken *before* the index advances. Reading argv[i + 1]
  // after incrementing i is how a parser silently consumes the next flag as if
  // it were a value.
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    const auto take = [&](std::string& value) {
      if (i + 1 >= argc) {
        std::cerr << "cifd: " << flag << " requires a value\n";
        return false;
      }
      value = argv[++i];
      return true;
    };

    if (flag == "--help" || flag == "-h") {
      out.help = true;
      return true;
    }
    std::string value;
    if (flag == "--cluster") {
      if (!take(value)) return false;
      if (!cif::ClusterId::parse(value, out.server.cluster_id)) {
        std::cerr << "cifd: --cluster value is not a valid CIF identifier\n";
        return false;
      }
      continue;
    }
    if (flag == "--host") {
      if (!take(value)) return false;
      out.server.bind_host = value;
      continue;
    }
    if (flag == "--port") {
      if (!take(value)) return false;
      std::uint64_t port = 0;
      if (!parse_u64(value, port) || port > 65535) {
        std::cerr << "cifd: --port must be 0..65535\n";
        return false;
      }
      out.server.port = static_cast<std::uint16_t>(port);
      continue;
    }
    if (flag == "--journal") {
      if (!take(value)) return false;
      out.server.journal_path = value;
      continue;
    }
    if (flag == "--ready-file") {
      if (!take(value)) return false;
      out.server.ready_file = value;
      continue;
    }
    if (flag == "--stop-file") {
      if (!take(value)) return false;
      out.stop_file = value;
      continue;
    }
    if (flag == "--policy") {
      if (!take(value)) return false;
      std::uint64_t policy = 0;
      if (!parse_u64(value, policy)) {
        std::cerr << "cifd: --policy must be a non-negative integer\n";
        return false;
      }
      out.server.policy = cif::PolicyGeneration{policy};
      continue;
    }
    if (flag == "--housekeeping-ms") {
      if (!take(value)) return false;
      std::uint64_t period = 0;
      if (!parse_u64(value, period)) {
        std::cerr << "cifd: --housekeeping-ms must be a non-negative integer\n";
        return false;
      }
      out.server.housekeeping_period_millis = period;
      continue;
    }
    if (flag == "--max-connections") {
      if (!take(value)) return false;
      std::uint64_t count = 0;
      if (!parse_u64(value, count)) {
        std::cerr << "cifd: --max-connections must be a non-negative integer\n";
        return false;
      }
      out.server.max_connections = static_cast<std::size_t>(count);
      continue;
    }
    if (flag == "--ingress") {
      if (!take(value)) return false;
      std::uint64_t depth = 0;
      if (!parse_u64(value, depth)) {
        std::cerr << "cifd: --ingress must be a non-negative integer\n";
        return false;
      }
      out.server.ingress_capacity = static_cast<std::size_t>(depth);
      continue;
    }
    if (flag == "--recovery") {
      if (!take(value)) return false;
      if (value == "revalidate-acknowledged") {
        out.server.authority.recovery_policy = cif::RecoveryPolicy::RevalidateAcknowledged;
      } else if (value == "fence-all") {
        out.server.authority.recovery_policy = cif::RecoveryPolicy::FenceAll;
      } else {
        std::cerr << "cifd: --recovery must be revalidate-acknowledged or fence-all\n";
        return false;
      }
      continue;
    }
    if (flag == "--duration-seconds") {
      if (!take(value)) return false;
      if (!parse_u64(value, out.duration_seconds)) {
        std::cerr << "cifd: --duration-seconds must be a non-negative integer\n";
        return false;
      }
      continue;
    }
    if (flag == "--log") {
      if (!take(value)) return false;
      out.log_path = value;
      continue;
    }
    if (flag == "--no-durable") {
      out.server.authority.durable = false;
      continue;
    }
    std::cerr << "cifd: unrecognised argument '" << cif::sanitise_for_display(flag, 64) << "'\n";
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  Arguments arguments;
  if (!parse_arguments(argc, argv, arguments)) {
    print_usage();
    return 2;
  }
  if (arguments.help) {
    print_usage();
    return 0;
  }
  if (arguments.server.cluster_id.empty()) {
    std::cerr << "cifd: --cluster is required\n";
    print_usage();
    return 2;
  }

#if defined(_WIN32)
  static_cast<void>(::SetConsoleCtrlHandler(console_handler, TRUE));
#else
  static_cast<void>(std::signal(SIGINT, cif_signal_handler));
  static_cast<void>(std::signal(SIGTERM, cif_signal_handler));
#endif

  cif::AuthorityServer server(arguments.server);
  const cif::Status started = server.start();
  if (!started.ok()) {
    std::cerr << "cifd: failed to start: " << started.to_string() << "\n";
    return 3;
  }

  std::cout << "cifd " << cif::version_banner() << "\n";
  std::cout << "cluster " << arguments.server.cluster_id.to_string() << "\n";
  std::cout << "listening " << arguments.server.bind_host << ":" << server.port() << "\n";
  std::cout << "durable " << (arguments.server.journal_path.empty() ? "false" : "true") << "\n";
  if (!arguments.server.journal_path.empty()) {
    std::cout << arguments.server.journal_path << "\n";
  }
  std::cout << server.recovery().render();
  std::cout.flush();

  const auto started_at = std::chrono::steady_clock::now();
  std::uint64_t last_logged_round = 0;
  int exit_code = 0;

  while (!g_stop_requested.load()) {
    if (!arguments.stop_file.empty() && cif::platform::file_exists(arguments.stop_file)) {
      break;
    }
    if (arguments.duration_seconds > 0) {
      const auto elapsed = std::chrono::steady_clock::now() - started_at;
      if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >=
          static_cast<long long>(arguments.duration_seconds)) {
        break;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    const cif::ServerStatus status = server.status();
    if (!arguments.log_path.empty() && status.stats.housekeeping_rounds != last_logged_round) {
      last_logged_round = status.stats.housekeeping_rounds;
      std::ofstream log(arguments.log_path, std::ios::app);
      if (log) {
        log << "round=" << last_logged_round << " connections=" << status.active_connections
            << " frames_in=" << status.stats.frames_in << " frames_out=" << status.stats.frames_out
            << " ingest=" << status.ingest_depth << "\n";
      }
    }
  }

  const cif::Status checked = server.core().self_check();
  if (!checked.ok()) {
    std::cerr << "cifd: invariant violation at shutdown: " << checked.to_string() << "\n";
    exit_code = 4;
  }
  const cif::Status stopped = server.stop();
  if (!stopped.ok()) {
    std::cerr << "cifd: stop failed: " << stopped.to_string() << "\n";
    return 3;
  }
  std::cout << "stopped\n";
  std::cout.flush();
  return exit_code;
}
