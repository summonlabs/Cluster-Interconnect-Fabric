#include "platform_sockets.hpp"

#include <atomic>
#include <cstring>

#if defined(_WIN32)
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace cif::platform {
namespace {

std::atomic<int> g_socket_runtime_users{0};

#if defined(_WIN32)
[[nodiscard]] std::string winsock_error_text(int code) {
  return "winsock error " + std::to_string(code);
}
#else
[[nodiscard]] std::string errno_text(int code) {
  return std::string(std::strerror(code)) + " (errno=" + std::to_string(code) + ")";
}
#endif

[[nodiscard]] bool would_block() noexcept {
#if defined(_WIN32)
  const int error = ::WSAGetLastError();
  return error == WSAEWOULDBLOCK || error == WSAETIMEDOUT;
#else
  return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

}  // namespace

void ensure_socket_runtime() noexcept {
  if (g_socket_runtime_users.fetch_add(1) == 0) {
#if defined(_WIN32)
    WSADATA data;
    static_cast<void>(::WSAStartup(MAKEWORD(2, 2), &data));
#endif
  }
}

void shutdown_socket_runtime() noexcept {
  if (g_socket_runtime_users.fetch_sub(1) == 1) {
#if defined(_WIN32)
    ::WSACleanup();
#endif
  }
}

bool socket_runtime_ready() noexcept { return g_socket_runtime_users.load() > 0; }

Status socket_error(const char* what) {
#if defined(_WIN32)
  return Status::error(StatusCode::IoFailure,
                       std::string(what) + ": " + winsock_error_text(::WSAGetLastError()));
#else
  return Status::error(StatusCode::IoFailure, std::string(what) + ": " + errno_text(errno));
#endif
}

Status listen_on(const std::string& host, std::uint16_t port, int backlog, NativeSocket& out_socket,
                 std::uint16_t& out_port) {
  ensure_socket_runtime();

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const int resolved = ::getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints,
                                     &results);
  if (resolved != 0 || results == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "cannot resolve bind address '" + host + "'");
  }

  NativeSocket listener = kInvalidSocket;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    listener = static_cast<NativeSocket>(
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol));
    if (listener == kInvalidSocket) {
      continue;
    }
    int reuse = 1;
    static_cast<void>(::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                                   reinterpret_cast<const char*>(&reuse), sizeof(reuse)));
    if (::bind(listener, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
      break;
    }
    close_socket(listener);
    listener = kInvalidSocket;
  }
  ::freeaddrinfo(results);

  if (listener == kInvalidSocket) {
    return socket_error("bind failed");
  }
  if (::listen(listener, backlog) != 0) {
    const Status failure = socket_error("listen failed");
    close_socket(listener);
    return failure;
  }
  CIF_TRY(socket_local_port(listener, out_port));
  out_socket = listener;
  return Status::success();
}

Status accept_one(NativeSocket listener, NativeSocket& out_socket, std::string& out_peer) {
  sockaddr_storage address{};
#if defined(_WIN32)
  int length = static_cast<int>(sizeof(address));
#else
  socklen_t length = sizeof(address);
#endif
  const NativeSocket accepted =
      static_cast<NativeSocket>(::accept(listener, reinterpret_cast<sockaddr*>(&address), &length));
  if (accepted == kInvalidSocket) {
    return socket_error("accept failed");
  }
  char text[64] = {0};
  if (address.ss_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
    static_cast<void>(::inet_ntop(AF_INET, &ipv4->sin_addr, text, sizeof(text)));
    out_peer = std::string(text) + ":" + std::to_string(ntohs(ipv4->sin_port));
  } else {
    out_peer = "peer";
  }
  out_socket = accepted;
  return Status::success();
}

Status connect_to(const std::string& host, std::uint16_t port, std::uint64_t timeout_millis,
                  NativeSocket& out_socket) {
  ensure_socket_runtime();

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const int resolved = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "cannot resolve '" + host + "'");
  }

  NativeSocket socket_handle = kInvalidSocket;
  Status failure = Status::error(StatusCode::IoFailure, "no address candidates");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    socket_handle = static_cast<NativeSocket>(
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol));
    if (socket_handle == kInvalidSocket) {
      failure = socket_error("socket failed");
      continue;
    }
    CIF_TRY(set_socket_timeouts(socket_handle, timeout_millis == 0 ? 5000 : timeout_millis,
                                timeout_millis == 0 ? 5000 : timeout_millis));
    if (::connect(socket_handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
      ::freeaddrinfo(results);
      out_socket = socket_handle;
      return Status::success();
    }
    failure = socket_error("connect failed");
    close_socket(socket_handle);
    socket_handle = kInvalidSocket;
  }
  ::freeaddrinfo(results);
  return failure;
}

Status socket_local_port(NativeSocket socket_handle, std::uint16_t& out_port) {
  sockaddr_storage address{};
#if defined(_WIN32)
  int length = static_cast<int>(sizeof(address));
#else
  socklen_t length = sizeof(address);
#endif
  if (::getsockname(socket_handle, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return socket_error("getsockname failed");
  }
  if (address.ss_family != AF_INET) {
    return Status::error(StatusCode::Unsupported, "only IPv4 endpoints are supported");
  }
  const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
  out_port = ntohs(ipv4->sin_port);
  return Status::success();
}

Status set_socket_timeouts(NativeSocket socket_handle, std::uint64_t read_millis,
                           std::uint64_t write_millis) {
#if defined(_WIN32)
  DWORD read_timeout = static_cast<DWORD>(read_millis);
  DWORD write_timeout = static_cast<DWORD>(write_millis);
  if (::setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&read_timeout), sizeof(read_timeout)) != 0) {
    return socket_error("setsockopt SO_RCVTIMEO failed");
  }
  if (::setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&write_timeout), sizeof(write_timeout)) != 0) {
    return socket_error("setsockopt SO_SNDTIMEO failed");
  }
#else
  timeval read_timeout{};
  read_timeout.tv_sec = static_cast<time_t>(read_millis / 1000);
  read_timeout.tv_usec = static_cast<suseconds_t>((read_millis % 1000) * 1000);
  timeval write_timeout{};
  write_timeout.tv_sec = static_cast<time_t>(write_millis / 1000);
  write_timeout.tv_usec = static_cast<suseconds_t>((write_millis % 1000) * 1000);
  if (::setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout)) != 0) {
    return socket_error("setsockopt SO_RCVTIMEO failed");
  }
  if (::setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, &write_timeout, sizeof(write_timeout)) != 0) {
    return socket_error("setsockopt SO_SNDTIMEO failed");
  }
#endif
  int nodelay = 1;
  static_cast<void>(::setsockopt(socket_handle, IPPROTO_TCP, TCP_NODELAY,
                                 reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)));
  return Status::success();
}

void close_socket(NativeSocket socket_handle) noexcept {
  if (socket_handle == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  ::closesocket(socket_handle);
#else
  ::close(static_cast<int>(socket_handle));
#endif
}

void shutdown_socket(NativeSocket socket_handle) noexcept {
  if (socket_handle == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  ::shutdown(socket_handle, SD_BOTH);
#else
  ::shutdown(static_cast<int>(socket_handle), SHUT_RDWR);
#endif
}

void close_listener(NativeSocket socket_handle) noexcept {
  if (socket_handle == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  ::closesocket(socket_handle);
#else
  ::shutdown(static_cast<int>(socket_handle), SHUT_RDWR);
  ::close(static_cast<int>(socket_handle));
#endif
}

Status socket_send_all(NativeSocket socket_handle, const std::uint8_t* data, std::size_t length) {
  std::size_t sent = 0;
  while (sent < length) {
    const std::size_t remaining = length - sent;
    const int chunk = static_cast<int>(remaining > 1u << 20 ? 1u << 20 : remaining);
#if defined(_WIN32)
    const int written = ::send(socket_handle, reinterpret_cast<const char*>(data + sent), chunk, 0);
#else
    const ssize_t written = ::send(socket_handle, data + sent, static_cast<std::size_t>(chunk), 0);
#endif
    if (written <= 0) {
      if (written < 0 && would_block()) {
        return Status::error(StatusCode::Timeout, "socket send timed out");
      }
      return socket_error("send failed");
    }
    sent += static_cast<std::size_t>(written);
  }
  return Status::success();
}

Status socket_receive(NativeSocket socket_handle, std::uint8_t* buffer, std::size_t capacity,
                      std::size_t& out_read) {
  if (capacity == 0) {
    out_read = 0;
    return Status::success();
  }
  const int chunk = static_cast<int>(capacity > 1u << 20 ? 1u << 20 : capacity);
#if defined(_WIN32)
  const int received = ::recv(socket_handle, reinterpret_cast<char*>(buffer), chunk, 0);
#else
  const ssize_t received = ::recv(socket_handle, buffer, static_cast<std::size_t>(chunk), 0);
#endif
  if (received == 0) {
    out_read = 0;  // orderly shutdown by the peer
    return Status::success();
  }
  if (received < 0) {
    if (would_block()) {
      return Status::error(StatusCode::Timeout, "socket receive timed out");
    }
    return socket_error("recv failed");
  }
  out_read = static_cast<std::size_t>(received);
  return Status::success();
}

Status socket_wait_readable(NativeSocket socket_handle, std::uint64_t timeout_millis,
                            bool& out_readable) {
  fd_set read_set;
  FD_ZERO(&read_set);
#if defined(_WIN32)
  FD_SET(static_cast<SOCKET>(socket_handle), &read_set);
#else
  FD_SET(static_cast<int>(socket_handle), &read_set);
#endif
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(timeout_millis / 1000);
  timeout.tv_usec = static_cast<long>((timeout_millis % 1000) * 1000);
#if defined(_WIN32)
  const int ready = ::select(0, &read_set, nullptr, nullptr, &timeout);
#else
  const int ready = ::select(static_cast<int>(socket_handle) + 1, &read_set, nullptr, nullptr, &timeout);
#endif
  if (ready < 0) {
    return socket_error("select failed");
  }
  out_readable = ready > 0;
  return Status::success();
}

}  // namespace cif::platform
