#include "harness.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "cif/platform.hpp"
#include "cif/text.hpp"

namespace cif::test {
namespace {

thread_local int g_failures_in_test = 0;
thread_local std::string g_current_test;
std::uint64_t g_seed = 0x5EED2026ull;
std::string g_scratch;
ChildModeHandler g_child_mode_handler = nullptr;

struct FailureRecord {
  std::string test;
  std::string message;
};

std::vector<FailureRecord>& failures() {
  static std::vector<FailureRecord> records;
  return records;
}

std::string make_scratch_root() {
  const std::filesystem::path base = std::filesystem::temp_directory_path();
  const std::uint64_t stamp = platform::monotonic_nanos();
  std::filesystem::path candidate =
      base / ("cif-tests-" + std::to_string(platform::current_process_id()) + "-" +
              std::to_string(stamp));
  std::error_code error;
  std::filesystem::create_directories(candidate, error);
  if (error) {
    return (base / "cif-tests").string();
  }
  return candidate.string();
}

void print_usage() {
  std::cout << "usage: <test-binary> [--list] [--filter <substr>] [--seed <n>] [--repeat <n>] "
               "[--verbose]\n";
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

Registrar::Registrar(const char* suite, const char* name, TestBody body) {
  registry().push_back(TestCase{suite, name, body});
}

void fail(const char* file, int line, const std::string& message) {
  ++g_failures_in_test;
  FailureRecord record;
  record.test = g_current_test;
  record.message = std::string(file) + ":" + std::to_string(line) + ": " + message;
  failures().push_back(record);
  std::cout << "    FAIL " << record.message << "\n";
  std::cout.flush();
}

void fail_fatal(const char* file, int line, const std::string& message) {
  fail(file, line, message);
  throw TestAbort(message);
}

void note(const std::string& message) {
  // Diagnostics go to stderr and are flushed immediately: if a test aborts, the
  // markers that led up to it must survive.
  std::cerr << "    note: " << message << std::endl;
}

void set_child_mode_handler(ChildModeHandler handler) noexcept { g_child_mode_handler = handler; }

std::uint64_t current_seed() noexcept { return g_seed; }

const std::string& scratch_directory() { return g_scratch; }

std::string scratch_path(const std::string& leaf) {
  return (std::filesystem::path(g_scratch) / leaf).string();
}

int run_all(int argc, char** argv) {
  if (g_child_mode_handler != nullptr) {
    const int handled = g_child_mode_handler(argc, argv);
    if (handled != kNotHandled) {
      return handled;
    }
  }

  std::string filter;
  std::uint64_t repeat = 1;
  bool verbose = false;

  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--list") {
      for (const TestCase& test : registry()) {
        std::cout << test.suite << "." << test.name << "\n";
      }
      return 0;
    }
    if (argument == "--help" || argument == "-h") {
      print_usage();
      return 0;
    }
    if (argument == "--verbose") {
      verbose = true;
      continue;
    }
    if (argument == "--filter" || argument == "--seed" || argument == "--repeat") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << argument << "\n";
        return 2;
      }
      const std::string value = argv[++i];
      if (argument == "--filter") {
        filter = value;
      } else if (argument == "--seed") {
        if (!cif::parse_decimal_u64(value, g_seed)) {
          std::cerr << "--seed must be a non-negative integer\n";
          return 2;
        }
      } else {
        if (!cif::parse_decimal_u64(value, repeat) || repeat == 0) {
          std::cerr << "--repeat must be a positive integer\n";
          return 2;
        }
      }
      continue;
    }
    std::cerr << "unrecognised argument '" << argument << "'\n";
    print_usage();
    return 2;
  }

  g_scratch = make_scratch_root();

  std::vector<const TestCase*> selected;
  for (const TestCase& test : registry()) {
    const std::string full = test.suite + "." + test.name;
    if (filter.empty() || full.find(filter) != std::string::npos) {
      selected.push_back(&test);
    }
  }
  if (selected.empty()) {
    std::cerr << "no tests matched filter '" << filter << "'\n";
    return 2;
  }

  std::size_t passed = 0;
  std::size_t failed = 0;
  const auto started = std::chrono::steady_clock::now();
  for (std::uint64_t round = 0; round < repeat; ++round) {
    for (const TestCase* test : selected) {
      g_current_test = test->suite + "." + test->name;
      g_failures_in_test = 0;
      failures().clear();
      if (verbose) {
        std::cout << "  running " << g_current_test << "\n";
        std::cout.flush();
      }
      try {
        test->body();
      } catch (const TestAbort&) {
        // The failure was already recorded.
      } catch (const std::exception& error) {
        fail("<harness>", 0, std::string("unexpected exception: ") + error.what());
      } catch (...) {
        fail("<harness>", 0, "unexpected non-standard exception");
      }
      if (g_failures_in_test == 0) {
        ++passed;
        std::cout << "PASS " << g_current_test << "\n";
      } else {
        ++failed;
        std::cout << "FAIL " << g_current_test << " (" << g_failures_in_test << " failures)\n";
      }
      std::cout.flush();
    }
  }
  const auto elapsed = std::chrono::steady_clock::now() - started;
  const auto millis =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

  std::cout << "\nSUMMARY passed=" << passed << " failed=" << failed << " seed=" << g_seed
            << " elapsed_ms=" << millis << "\n";
  std::cout.flush();

  std::error_code error;
  std::filesystem::remove_all(g_scratch, error);
  return failed == 0 ? 0 : 1;
}

}  // namespace cif::test

int main(int argc, char** argv) { return ::cif::test::run_all(argc, argv); }
