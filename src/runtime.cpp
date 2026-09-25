#include "cif/net.hpp"

#include <chrono>
#include <cstring>
#include <utility>

#include "cif/platform.hpp"
#include "platform_sockets.hpp"

namespace cif {
namespace {

constexpr std::size_t kInitialBufferBytes = 8192;

}  // namespace

SocketRuntime::SocketRuntime() { platform::ensure_socket_runtime(); }
SocketRuntime::~SocketRuntime() { platform::shutdown_socket_runtime(); }

// ---------------------------------------------------------------------------
// TcpListener
// ---------------------------------------------------------------------------
TcpListener::~TcpListener() { static_cast<void>(close()); }

bool TcpListener::is_open() const noexcept { return socket_ != platform::kInvalidSocket; }

Status TcpListener::bind(const std::string& host, std::uint16_t port, std::size_t backlog) {
  CIF_TRY(close());
  platform::NativeSocket handle = platform::kInvalidSocket;
  std::uint16_t bound_port = 0;
  const int bounded_backlog = static_cast<int>(backlog);
  CIF_TRY(platform::listen_on(host, port, bounded_backlog, handle, bound_port));
  socket_ = handle;
  port_ = bound_port;
  return Status::success();
}

Status TcpListener::accept(TcpStream& out, std::string& peer) {
  if (!is_open()) {
    return Status::error(StatusCode::Closed, "listener is not open");
  }
  platform::NativeSocket accepted = platform::kInvalidSocket;
  CIF_TRY(platform::accept_one(socket_, accepted, peer));
  out.adopt(accepted);
  return Status::success();
}

Status TcpListener::close() {
  if (socket_ == platform::kInvalidSocket) {
    return Status::success();
  }
  platform::close_listener(socket_);
  socket_ = platform::kInvalidSocket;
  return Status::success();
}

// ---------------------------------------------------------------------------
// TcpStream
// ---------------------------------------------------------------------------
TcpStream::~TcpStream() { static_cast<void>(close()); }

TcpStream::TcpStream(TcpStream&& other) noexcept : socket_(other.socket_) {
  other.socket_ = platform::kInvalidSocket;
}

TcpStream& TcpStream::operator=(TcpStream&& other) noexcept {
  if (this != &other) {
    static_cast<void>(close());
    socket_ = other.socket_;
    other.socket_ = platform::kInvalidSocket;
  }
  return *this;
}

Status TcpStream::connect(const std::string& host, std::uint16_t port,
                          std::uint64_t timeout_millis) {
  CIF_TRY(close());
  platform::NativeSocket handle = platform::kInvalidSocket;
  CIF_TRY(platform::connect_to(host, port, timeout_millis, handle));
  socket_ = handle;
  return Status::success();
}

void TcpStream::adopt(std::intptr_t socket) noexcept {
  static_cast<void>(close());
  socket_ = socket;
}

Status TcpStream::close() {
  if (socket_ == platform::kInvalidSocket) {
    return Status::success();
  }
  platform::close_socket(socket_);
  socket_ = platform::kInvalidSocket;
  return Status::success();
}

void TcpStream::abort() noexcept { platform::shutdown_socket(socket_); }

bool TcpStream::is_open() const noexcept { return socket_ != platform::kInvalidSocket; }

Status TcpStream::set_timeouts(std::uint64_t read_millis, std::uint64_t write_millis) {
  if (!is_open()) {
    return Status::error(StatusCode::Closed, "stream is not open");
  }
  return platform::set_socket_timeouts(socket_, read_millis == 0 ? 1 : read_millis,
                                       write_millis == 0 ? 1 : write_millis);
}

Status TcpStream::send_all(std::span<const std::uint8_t> data) {
  if (!is_open()) {
    return Status::error(StatusCode::Closed, "stream is not open");
  }
  return platform::socket_send_all(socket_, data.data(), data.size());
}

Status TcpStream::receive(std::span<std::uint8_t> buffer, std::size_t& out_read) {
  if (!is_open()) {
    return Status::error(StatusCode::Closed, "stream is not open");
  }
  return platform::socket_receive(socket_, buffer.data(), buffer.size(), out_read);
}

// ---------------------------------------------------------------------------
// FrameChannel
// ---------------------------------------------------------------------------
Status FrameChannel::send(const Frame& frame) {
  Bytes encoded;
  CIF_TRY(encode_frame(frame, encoded));
  CIF_TRY(stream_.send_all(std::span<const std::uint8_t>(encoded.data(), encoded.size())));
  return Status::success();
}

Status FrameChannel::receive(Frame& out, std::uint64_t timeout_millis) {
  const std::uint64_t started = platform::monotonic_nanos();
  for (;;) {
    std::size_t size = 0;
    const Status sized = frame_size(std::span<const std::uint8_t>(buffer_.data(), used_), size);
    if (sized.ok()) {
      CIF_TRY(decode_frame(std::span<const std::uint8_t>(buffer_.data(), size), out));
      const std::size_t remaining = used_ - size;
      if (remaining > 0) {
        std::memmove(buffer_.data(), buffer_.data() + size, remaining);
      }
      used_ = remaining;
      return Status::success();
    }
    if (!sized.is(StatusCode::Truncated)) {
      return sized;  // corruption, version mismatch or oversized declaration
    }

    if (used_ == buffer_.size()) {
      if (buffer_.size() >= limits::kMaxFrameBytes) {
        return Status::error(StatusCode::LimitExceeded,
                             "peer sent more than the configured frame bound without completing a "
                             "frame");
      }
      const std::size_t grown = buffer_.empty() ? kInitialBufferBytes : buffer_.size() * 2;
      buffer_.resize(grown > limits::kMaxFrameBytes ? limits::kMaxFrameBytes : grown);
    }

    std::size_t read = 0;
    const Status received =
        stream_.receive(std::span<std::uint8_t>(buffer_.data() + used_, buffer_.size() - used_), read);
    if (!received.ok()) {
      if (received.is(StatusCode::Timeout)) {
        if (timeout_millis == 0) {
          continue;
        }
        const std::uint64_t elapsed = platform::monotonic_nanos() - started;
        if (elapsed >= timeout_millis * 1000000ull) {
          return Status::error(StatusCode::Timeout, "timed out waiting for a frame");
        }
        continue;
      }
      return received;
    }
    if (read == 0) {
      if (used_ == 0) {
        return Status::error(StatusCode::Closed, "peer closed the connection");
      }
      return Status::error(StatusCode::Truncated, "peer closed mid-frame");
    }
    used_ += read;
  }
}

}  // namespace cif
