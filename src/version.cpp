#include "cif/version.hpp"

namespace cif {
namespace {

#define CIF_STRINGIFY_IMPL(x) #x
#define CIF_STRINGIFY(x) CIF_STRINGIFY_IMPL(x)

#if defined(_MSC_VER)
#define CIF_TOOLCHAIN_STRING "MSVC " CIF_STRINGIFY(_MSC_VER)
#elif defined(__clang__)
#define CIF_TOOLCHAIN_STRING "clang " __clang_version__
#elif defined(__GNUC__)
#define CIF_TOOLCHAIN_STRING "gcc " __VERSION__
#else
#define CIF_TOOLCHAIN_STRING "unknown"
#endif

#ifdef NDEBUG
constexpr const char* kBuildConfiguration = "Release";
#else
constexpr const char* kBuildConfiguration = "Debug";
#endif

#ifdef CIF_ENABLE_TEST_HOOKS
constexpr bool kTestHooks = true;
#else
constexpr bool kTestHooks = false;
#endif

}  // namespace

const char* version_string() noexcept { return CIF_VERSION_STRING; }

const char* build_toolchain() noexcept { return CIF_TOOLCHAIN_STRING; }

const char* build_configuration() noexcept { return kBuildConfiguration; }

bool test_hooks_enabled() noexcept { return kTestHooks; }

std::uint32_t journal_format_version() noexcept { return CIF_JOURNAL_FORMAT_VERSION; }

std::uint32_t wire_protocol_version() noexcept { return CIF_WIRE_PROTOCOL_VERSION; }

std::string version_banner() {
  std::string out;
  out.reserve(96);
  out += "cif/";
  out += CIF_VERSION_STRING;
  out += " journal=";
  out += std::to_string(CIF_JOURNAL_FORMAT_VERSION);
  out += " wire=";
  out += std::to_string(CIF_WIRE_PROTOCOL_VERSION);
  out += " config=";
  out += kBuildConfiguration;
  out += " toolchain=";
  out += CIF_TOOLCHAIN_STRING;
  out += " testhooks=";
  out += (kTestHooks ? "on" : "off");
  return out;
}

}  // namespace cif
