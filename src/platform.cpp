#include "cif/platform.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <system_error>
#include <thread>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace cif::platform {
namespace {

[[nodiscard]] std::string error_text(const char* what, int code) {
  std::string message = what;
  message += " failed (errno=";
  message += std::to_string(code);
  message += ")";
  return message;
}

}  // namespace

Status sync_file(std::FILE* file) {
  if (file == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "sync_file received a null stream");
  }
  if (std::fflush(file) != 0) {
    return Status::error(StatusCode::IoFailure, error_text("fflush", errno));
  }
#if defined(_WIN32)
  const int descriptor = ::_fileno(file);
  if (descriptor < 0) {
    return Status::error(StatusCode::IoFailure, "invalid file descriptor");
  }
  if (::_commit(descriptor) != 0) {
    return Status::error(StatusCode::IoFailure, error_text("_commit", errno));
  }
#else
  const int descriptor = ::fileno(file);
  if (descriptor < 0) {
    return Status::error(StatusCode::IoFailure, "invalid file descriptor");
  }
  if (::fsync(descriptor) != 0) {
    return Status::error(StatusCode::IoFailure, error_text("fsync", errno));
  }
#endif
  return Status::success();
}

Status atomic_replace(const std::filesystem::path& source, const std::filesystem::path& target) {
#if defined(_WIN32)
  if (::MoveFileExW(source.c_str(), target.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    const DWORD code = ::GetLastError();
    return Status::error(StatusCode::IoFailure,
                         "MoveFileExW failed (GetLastError=" + std::to_string(code) + ")");
  }
  return Status::success();
#else
  std::error_code error;
  std::filesystem::rename(source, target, error);
  if (error) {
    return Status::error(StatusCode::IoFailure, "rename failed: " + error.message());
  }
  return Status::success();
#endif
}

Status remove_file(const std::filesystem::path& path) {
  std::error_code error;
  const bool removed = std::filesystem::remove(path, error);
  if (error) {
    return Status::error(StatusCode::IoFailure, "remove failed: " + error.message());
  }
  if (!removed) {
    return Status::error(StatusCode::NotFound, "file does not exist: " + path.string());
  }
  return Status::success();
}

bool file_exists(const std::filesystem::path& path) noexcept {
  std::error_code error;
  return std::filesystem::exists(path, error) && !error;
}

std::uint64_t file_size_bytes(const std::filesystem::path& path) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    return 0;
  }
  return static_cast<std::uint64_t>(size);
}

Status truncate_file(const std::filesystem::path& path, std::uint64_t size) {
#if defined(_WIN32)
  const int descriptor = ::_wopen(path.c_str(), _O_RDWR | _O_BINARY);
  if (descriptor < 0) {
    return Status::error(StatusCode::IoFailure, error_text("_wopen", errno));
  }
  const int result = ::_chsize_s(descriptor, static_cast<__int64>(size));
  ::_close(descriptor);
  if (result != 0) {
    return Status::error(StatusCode::IoFailure, error_text("_chsize_s", errno));
  }
#else
  if (::truncate(path.c_str(), static_cast<off_t>(size)) != 0) {
    return Status::error(StatusCode::IoFailure, error_text("truncate", errno));
  }
#endif
  return Status::success();
}

Status read_file(const std::filesystem::path& path, std::vector<std::uint8_t>& out,
                 std::uint64_t max_bytes) {
  const std::uint64_t size = file_size_bytes(path);
  if (size > max_bytes) {
    return Status::error(StatusCode::LimitExceeded,
                         "file exceeds the configured read bound of " + std::to_string(max_bytes) +
                             " bytes");
  }
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (file == nullptr) {
    return Status::error(StatusCode::IoFailure,
                         "cannot open '" + path.string() + "' for reading (errno=" +
                             std::to_string(errno) + ")");
  }
  std::vector<std::uint8_t> buffer;
  buffer.resize(static_cast<std::size_t>(size));
  std::size_t read_total = 0;
  while (read_total < buffer.size()) {
    const std::size_t chunk =
        std::fread(buffer.data() + read_total, 1, buffer.size() - read_total, file);
    if (chunk == 0) {
      break;
    }
    read_total += chunk;
  }
  const bool read_error = std::ferror(file) != 0;
  std::fclose(file);
  if (read_error) {
    return Status::error(StatusCode::IoFailure, "read error while reading '" + path.string() + "'");
  }
  if (read_total != buffer.size()) {
    return Status::error(StatusCode::Truncated,
                         "short read: expected " + std::to_string(buffer.size()) + " bytes, got " +
                             std::to_string(read_total));
  }
  out = std::move(buffer);
  return Status::success();
}

Status ensure_parent_directory(const std::filesystem::path& path) {
  const std::filesystem::path parent = path.parent_path();
  if (parent.empty()) {
    return Status::success();
  }
  std::error_code error;
  std::filesystem::create_directories(parent, error);
  if (error) {
    return Status::error(StatusCode::IoFailure,
                         "cannot create directory '" + parent.string() + "': " + error.message());
  }
  return Status::success();
}

std::uint64_t monotonic_nanos() noexcept {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

void sleep_millis(std::uint64_t millis) noexcept {
  std::this_thread::sleep_for(std::chrono::milliseconds(millis));
}

std::uint32_t current_process_id() noexcept {
#if defined(_WIN32)
  return static_cast<std::uint32_t>(::_getpid());
#else
  return static_cast<std::uint32_t>(::getpid());
#endif
}

bool durability_probe(const std::filesystem::path& directory) {
  const std::filesystem::path probe = directory / "cif-durability-probe.tmp";
  std::FILE* file = std::fopen(probe.string().c_str(), "wb");
  if (file == nullptr) {
    return false;
  }
  const std::uint8_t payload[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  const bool wrote = std::fwrite(payload, 1, sizeof(payload), file) == sizeof(payload);
  const bool synced = sync_file(file).ok();
  std::fclose(file);
  std::error_code error;
  std::filesystem::remove(probe, error);
  return wrote && synced;
}

}  // namespace cif::platform
