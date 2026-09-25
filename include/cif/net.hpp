// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// TCP transport primitives and the length-prefixed frame channel. Everything
// here is loopback-capable and nothing here claims anything about a real
// fabric: the transport is an ordinary TCP stream, which is what makes the
// multiprocess proofs in this repository honest.
#ifndef CIF_NET_HPP
#define CIF_NET_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "cif/bytes.hpp"
#include "cif/status.hpp"
#include "cif/wire.hpp"

namespace cif {

/// RAII wrapper around the process-wide socket runtime.
class SocketRuntime {
 public:
  SocketRuntime();
  ~SocketRuntime();
  SocketRuntime(const SocketRuntime&) = delete;
  SocketRuntime& operator=(const SocketRuntime&) = delete;
};

class TcpStream;

/// Listening TCP socket.
class TcpListener {
 public:
  TcpListener() = default;
  ~TcpListener();
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  [[nodiscard]] Status bind(const std::string& host, std::uint16_t port, std::size_t backlog);
  [[nodiscard]] Status accept(TcpStream& out, std::string& peer);
  [[nodiscard]] Status close();
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] std::intptr_t native() const noexcept { return socket_; }

 private:
  SocketRuntime runtime_{};
  std::intptr_t socket_ = -1;
  std::uint16_t port_ = 0;
};

/// Connected TCP stream. Closing from another thread is supported and is how a
/// blocked reader is released during shutdown.
class TcpStream {
 public:
  TcpStream() = default;
  ~TcpStream();
  TcpStream(const TcpStream&) = delete;
  TcpStream& operator=(const TcpStream&) = delete;
  TcpStream(TcpStream&& other) noexcept;
  TcpStream& operator=(TcpStream&& other) noexcept;

  [[nodiscard]] Status connect(const std::string& host, std::uint16_t port,
                               std::uint64_t timeout_millis);
  void adopt(std::intptr_t socket) noexcept;
  [[nodiscard]] Status close();
  /// Shuts the socket down without destroying the handle. Safe to call from a
  /// thread other than the one blocked in receive(); that is its whole purpose.
  void abort() noexcept;
  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] std::intptr_t native() const noexcept { return socket_; }

  [[nodiscard]] Status set_timeouts(std::uint64_t read_millis, std::uint64_t write_millis);
  [[nodiscard]] Status send_all(std::span<const std::uint8_t> data);
  [[nodiscard]] Status receive(std::span<std::uint8_t> buffer, std::size_t& out_read);

 private:
  SocketRuntime runtime_{};
  std::intptr_t socket_ = -1;
};

/// Frames a byte stream into CIF frames, enforcing the configured bound before
/// allocating. A hostile peer that declares a huge frame is rejected, not
/// obeyed.
class FrameChannel {
 public:
  FrameChannel() = default;
  explicit FrameChannel(TcpStream stream) : stream_(std::move(stream)) {}

  [[nodiscard]] Status send(const Frame& frame);
  [[nodiscard]] Status receive(Frame& out, std::uint64_t timeout_millis);

  void abort() noexcept { stream_.abort(); }
  [[nodiscard]] bool is_open() const noexcept { return stream_.is_open(); }
  [[nodiscard]] TcpStream& stream() noexcept { return stream_; }
  [[nodiscard]] const TcpStream& stream() const noexcept { return stream_; }
  [[nodiscard]] std::size_t buffered() const noexcept { return used_; }

 private:
  TcpStream stream_{};
  Bytes buffer_{};
  std::size_t used_ = 0;
};

}  // namespace cif

#endif  // CIF_NET_HPP
