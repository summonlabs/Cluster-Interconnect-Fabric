// Cluster Interconnect Fabric (CIF) -- test harness.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A deliberately tiny, dependency-free harness. It has no timeouts, no watchdogs
// and no "skip on hang" behaviour: a hanging test is a defect and the harness
// lets it hang so the defect is visible.
#ifndef CIF_TEST_HARNESS_HPP
#define CIF_TEST_HARNESS_HPP

#include <cstdint>
#include <exception>
#include <functional>
#include <string>
#include <vector>

#include "cif/status.hpp"

namespace cif::test {

using TestBody = void (*)();

struct TestCase {
  std::string suite;
  std::string name;
  TestBody body;
};

/// Raised by CIF_REQUIRE and by CIF_FAIL to abandon the current test.
class TestAbort : public std::exception {
 public:
  explicit TestAbort(std::string what) : what_(std::move(what)) {}
  [[nodiscard]] const char* what() const noexcept override { return what_.c_str(); }

 private:
  std::string what_;
};

[[nodiscard]] std::vector<TestCase>& registry();

struct Registrar {
  Registrar(const char* suite, const char* name, TestBody body);
};

/// Records a failure against the running test.
void fail(const char* file, int line, const std::string& message);

/// Records a failure and aborts the test.
[[noreturn]] void fail_fatal(const char* file, int line, const std::string& message);

void note(const std::string& message);

/// Sentinel returned by a child-mode handler that did not recognise the request.
inline constexpr int kNotHandled = -1000000;

/// Some tests re-execute this very binary as an independent OS process (the
/// only honest way to prove hard-kill/restart behaviour). Such a binary installs
/// a handler that interprets its own argv forms before the test runner sees
/// them.
using ChildModeHandler = int (*)(int argc, char** argv);
void set_child_mode_handler(ChildModeHandler handler) noexcept;

/// Entry point. Supports:
///   --list                 print every registered test as suite.name
///   --filter <substr>      run only tests whose suite.name contains substr
///   --seed <n>             deterministic seed exposed to property tests
///   --repeat <n>           run the selection n times
///   --verbose              print each test name before running it
int run_all(int argc, char** argv);

/// Seed selected for this run. Property tests must derive every random value
/// from it and print it on failure.
[[nodiscard]] std::uint64_t current_seed() noexcept;

/// Temporary directory for this test binary, created on demand and removed by
/// the harness at exit. Never inside the source tree.
[[nodiscard]] const std::string& scratch_directory();

/// Creates a unique path inside the scratch directory.
[[nodiscard]] std::string scratch_path(const std::string& leaf);

}  // namespace cif::test

#define CIF_TEST(suite_name, test_name)                                                  \
  static void cif_test_##suite_name##_##test_name();                                     \
  static const ::cif::test::Registrar cif_registrar_##suite_name##_##test_name(          \
      #suite_name, #test_name, cif_test_##suite_name##_##test_name);                     \
  static void cif_test_##suite_name##_##test_name()

#define CIF_CHECK(condition)                                                       \
  do {                                                                             \
    if (!(condition)) {                                                            \
      ::cif::test::fail(__FILE__, __LINE__, "CHECK failed: " #condition);          \
    }                                                                              \
  } while (false)

#define CIF_REQUIRE(condition)                                                     \
  do {                                                                             \
    if (!(condition)) {                                                            \
      ::cif::test::fail_fatal(__FILE__, __LINE__, "REQUIRE failed: " #condition);  \
    }                                                                              \
  } while (false)

#define CIF_CHECK_MSG(condition, message)                                              \
  do {                                                                                 \
    if (!(condition)) {                                                                \
      ::cif::test::fail(__FILE__, __LINE__,                                            \
                        std::string("CHECK failed: " #condition " -- ") + (message));   \
    }                                                                                  \
  } while (false)

#define CIF_REQUIRE_MSG(condition, message)                                            do {                                                                                   if (!(condition)) {                                                                    ::cif::test::fail_fatal(__FILE__, __LINE__,                                                                  std::string("REQUIRE failed: " #condition " -- ") +                                      (message));                                            }                                                                                  } while (false)

#define CIF_CHECK_OK(expr)                                                              \
  do {                                                                                  \
    const ::cif::Status cif_status_value = (expr);                                       \
    if (!cif_status_value.ok()) {                                                        \
      ::cif::test::fail(__FILE__, __LINE__,                                              \
                        std::string("expected OK from " #expr ", got ") +               \
                            cif_status_value.to_string());                               \
    }                                                                                   \
  } while (false)

#define CIF_REQUIRE_OK(expr)                                                            \
  do {                                                                                  \
    const ::cif::Status cif_status_value = (expr);                                       \
    if (!cif_status_value.ok()) {                                                        \
      ::cif::test::fail_fatal(__FILE__, __LINE__,                                        \
                              std::string("expected OK from " #expr ", got ") +          \
                                  cif_status_value.to_string());                          \
    }                                                                                   \
  } while (false)

#define CIF_CHECK_STATUS(expr, expected)                                                \
  do {                                                                                  \
    const ::cif::Status cif_status_value = (expr);                                       \
    if (!cif_status_value.is(expected)) {                                                \
      ::cif::test::fail(__FILE__, __LINE__,                                              \
                        std::string("expected " #expected " from " #expr ", got ") +     \
                            cif_status_value.to_string());                               \
    }                                                                                   \
  } while (false)

#define CIF_CHECK_EQ(actual, expected)                                                     \
  do {                                                                                     \
    const auto& cif_actual = (actual);                                                      \
    const auto& cif_expected = (expected);                                                  \
    if (!(cif_actual == cif_expected)) {                                                    \
      ::cif::test::fail(__FILE__, __LINE__, std::string("CHECK_EQ failed: " #actual " != "  \
                                                        #expected));                        \
    }                                                                                       \
  } while (false)

#define CIF_FAIL(message) ::cif::test::fail_fatal(__FILE__, __LINE__, (message))

#endif  // CIF_TEST_HARNESS_HPP
