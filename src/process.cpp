#include "cif/process.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>
#include <utility>

#include "cif/platform.hpp"

#if defined(_WIN32)
#include <process.h>
#include <windows.h>
#else
#include <csignal>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace cif {
namespace {

[[nodiscard]] std::string quote_argument(const std::string& argument) {
  // Windows command line quoting: wrap in double quotes and escape embedded
  // quotes and backslash runs that precede a quote.
  std::string out = "\"";
  std::size_t backslashes = 0;
  for (char c : argument) {
    if (c == '\\') {
      ++backslashes;
      out.push_back(c);
      continue;
    }
    if (c == '"') {
      out.append(backslashes + 1, '\\');
      out.push_back('"');
      backslashes = 0;
      continue;
    }
    backslashes = 0;
    out.push_back(c);
  }
  out.append(backslashes, '\\');
  out.push_back('"');
  return out;
}

}  // namespace

struct ChildProcess::Impl {
#if defined(_WIN32)
  HANDLE process = nullptr;
#else
  pid_t pid = -1;
#endif
  bool reaped = false;
  std::uint32_t exit_code = 0;
  std::filesystem::path output_file;
};

ChildProcess::~ChildProcess() = default;

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : handle_(std::move(other.handle_)), process_id_(other.process_id_) {
  other.process_id_ = 0;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    handle_ = std::move(other.handle_);
    process_id_ = other.process_id_;
    other.process_id_ = 0;
  }
  return *this;
}

Status ChildProcess::spawn(const ProcessOptions& options, ChildProcess& out) {
  if (options.executable.empty()) {
    return Status::error(StatusCode::InvalidArgument, "spawn requires an executable path");
  }
  if (!platform::file_exists(options.executable)) {
    return Status::error(StatusCode::NotFound,
                         "executable not found: " + options.executable.string());
  }

  auto impl = std::make_shared<Impl>();
  impl->output_file = options.output_file;

#if defined(_WIN32)
  std::string command_line;
  command_line += quote_argument(options.executable.string());
  for (const std::string& argument : options.arguments) {
    command_line.push_back(' ');
    command_line += quote_argument(argument);
  }

  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;

  HANDLE output = INVALID_HANDLE_VALUE;
  if (!options.output_file.empty()) {
    static_cast<void>(platform::ensure_parent_directory(options.output_file));
    output = ::CreateFileW(options.output_file.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE) {
      return Status::error(StatusCode::IoFailure,
                           "cannot open child output file " + options.output_file.string());
    }
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  if (output != INVALID_HANDLE_VALUE) {
    startup.dwFlags |= STARTF_USESTDHANDLES;
    startup.hStdOutput = output;
    startup.hStdError = output;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
  }

  PROCESS_INFORMATION info{};
  std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back(L'\0');

  const wchar_t* working_directory =
      options.working_directory.empty() ? nullptr : options.working_directory.c_str();

  const BOOL created = ::CreateProcessW(options.executable.c_str(), mutable_command.data(), nullptr,
                                        nullptr, output != INVALID_HANDLE_VALUE,
                                        CREATE_NO_WINDOW, nullptr, working_directory, &startup, &info);
  if (output != INVALID_HANDLE_VALUE) {
    ::CloseHandle(output);
  }
  if (created == FALSE) {
    return Status::error(StatusCode::IoFailure,
                         "CreateProcess failed (GetLastError=" +
                             std::to_string(::GetLastError()) + ")");
  }
  ::CloseHandle(info.hThread);
  impl->process = info.hProcess;
  out.handle_ = impl;
  out.process_id_ = static_cast<std::uint32_t>(info.dwProcessId);
#else
  std::vector<std::string> storage;
  storage.push_back(options.executable.string());
  for (const std::string& argument : options.arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (std::string& value : storage) {
    argv.push_back(value.data());
  }
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) {
    return Status::error(StatusCode::IoFailure, "fork failed");
  }
  if (pid == 0) {
    static_cast<void>(::setsid());
    if (!options.working_directory.empty()) {
      static_cast<void>(::chdir(options.working_directory.c_str()));
    }
    if (!options.output_file.empty()) {
      static_cast<void>(platform::ensure_parent_directory(options.output_file));
      std::FILE* sink = std::freopen(options.output_file.string().c_str(), "w", stdout);
      static_cast<void>(sink);
      static_cast<void>(std::freopen(options.output_file.string().c_str(), "a", stderr));
    }
    ::execv(argv[0], argv.data());
    ::_exit(127);
  }
  impl->pid = pid;
  out.handle_ = impl;
  out.process_id_ = static_cast<std::uint32_t>(pid);
#endif
  return Status::success();
}

bool ChildProcess::running() {
  if (!handle_ || handle_->reaped) {
    return false;
  }
#if defined(_WIN32)
  const DWORD state = ::WaitForSingleObject(handle_->process, 0);
  return state == WAIT_TIMEOUT;
#else
  int status = 0;
  const pid_t result = ::waitpid(handle_->pid, &status, WNOHANG);
  if (result == handle_->pid) {
    handle_->reaped = true;
    handle_->exit_code = static_cast<std::uint32_t>(WIFEXITED(status) ? WEXITSTATUS(status) : 128);
    return false;
  }
  return result == 0;
#endif
}

Status ChildProcess::wait(std::uint32_t& out_exit_code) {
  if (!handle_) {
    return Status::error(StatusCode::InvalidArgument, "no child process handle");
  }
  if (handle_->reaped) {
    out_exit_code = handle_->exit_code;
    return Status::success();
  }
#if defined(_WIN32)
  const DWORD state = ::WaitForSingleObject(handle_->process, INFINITE);
  if (state != WAIT_OBJECT_0) {
    return Status::error(StatusCode::IoFailure, "WaitForSingleObject failed");
  }
  DWORD code = 0;
  if (::GetExitCodeProcess(handle_->process, &code) == FALSE) {
    return Status::error(StatusCode::IoFailure, "GetExitCodeProcess failed");
  }
  handle_->exit_code = static_cast<std::uint32_t>(code);
#else
  int status = 0;
  for (;;) {
    const pid_t result = ::waitpid(handle_->pid, &status, 0);
    if (result == handle_->pid) {
      break;
    }
    if (result < 0 && errno != EINTR) {
      return Status::error(StatusCode::IoFailure, "waitpid failed");
    }
  }
  handle_->exit_code = static_cast<std::uint32_t>(WIFEXITED(status) ? WEXITSTATUS(status) : 128);
#endif
  handle_->reaped = true;
  out_exit_code = handle_->exit_code;
  return Status::success();
}

Status ChildProcess::terminate(std::uint32_t exit_code) {
  if (!handle_ || handle_->reaped) {
    return Status::error(StatusCode::InvalidArgument, "no live child process to terminate");
  }
#if defined(_WIN32)
  if (::TerminateProcess(handle_->process, exit_code) == FALSE) {
    return Status::error(StatusCode::IoFailure,
                         "TerminateProcess failed (GetLastError=" +
                             std::to_string(::GetLastError()) + ")");
  }
#else
  if (::kill(handle_->pid, SIGKILL) != 0) {
    return Status::error(StatusCode::IoFailure, "kill(SIGKILL) failed");
  }
#endif
  std::uint32_t code = 0;
  return wait(code);
}

std::string ChildProcess::read_output() const {
  if (!handle_ || handle_->output_file.empty()) {
    return {};
  }
  std::ifstream stream(handle_->output_file, std::ios::binary);
  if (!stream) {
    return {};
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

std::filesystem::path current_executable_path() {
#if defined(_WIN32)
  std::vector<wchar_t> buffer(4096);
  const DWORD written = ::GetModuleFileNameW(nullptr, buffer.data(),
                                             static_cast<DWORD>(buffer.size()));
  if (written == 0) {
    return {};
  }
  return std::filesystem::path(std::wstring(buffer.data(), written));
#else
  std::vector<char> buffer(4096);
  const ssize_t written = ::readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
  if (written <= 0) {
    return {};
  }
  return std::filesystem::path(std::string(buffer.data(), static_cast<std::size_t>(written)));
#endif
}

std::filesystem::path current_executable_directory() {
  const std::filesystem::path executable = current_executable_path();
  return executable.empty() ? std::filesystem::path{} : executable.parent_path();
}

std::filesystem::path find_sibling_tool(const std::string& name) {
  const std::filesystem::path directory = current_executable_directory();
  if (directory.empty()) {
    return {};
  }
  const std::filesystem::path direct = directory / name;
  if (platform::file_exists(direct)) {
    return direct;
  }
#if defined(_WIN32)
  const std::filesystem::path with_extension = directory / (name + ".exe");
  if (platform::file_exists(with_extension)) {
    return with_extension;
  }
  const std::filesystem::path parent = directory.parent_path() / "bin" / (name + ".exe");
  if (platform::file_exists(parent)) {
    return parent;
  }
#else
  const std::filesystem::path parent = directory.parent_path() / "bin" / name;
  if (platform::file_exists(parent)) {
    return parent;
  }
#endif
  return {};
}

Status wait_for_file(const std::filesystem::path& path, std::uint64_t timeout_millis) {
  const std::uint64_t deadline = platform::monotonic_nanos() + timeout_millis * 1000000ull;
  for (;;) {
    if (platform::file_exists(path) && platform::file_size_bytes(path) > 0) {
      return Status::success();
    }
    if (platform::monotonic_nanos() >= deadline) {
      return Status::error(StatusCode::Timeout, "timed out waiting for '" + path.string() + "'");
    }
    platform::sleep_millis(5);
  }
}

Status read_text_file(const std::filesystem::path& path, std::string& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return Status::error(StatusCode::IoFailure, "cannot read '" + path.string() + "'");
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  out = buffer.str();
  return Status::success();
}

bool lookup_ready_value(const std::string& text, const std::string& key, std::string& out) {
  std::istringstream stream(text);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::size_t space = line.find(' ');
    if (space == std::string::npos) {
      continue;
    }
    if (line.substr(0, space) == key) {
      out = line.substr(space + 1);
      return true;
    }
  }
  return false;
}

}  // namespace cif
