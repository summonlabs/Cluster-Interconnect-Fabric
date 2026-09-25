// Cluster Interconnect Fabric (CIF) -- internal.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CIF_PLATFORM_SOCKETS_HPP
#define CIF_PLATFORM_SOCKETS_HPP

#include <cstdint>
#include <string>

#include "cif/status.hpp"

namespace cif::platform {

/// Winsock needs process-wide initialisation. One static instance handles it.
void ensure_socket_runtime() noexcept;
void shutdown_socket_runtime() noexcept;
[[nodiscard]] bool socket_runtime_ready() noexcept;

using NativeSocket = std::intptr_t;
inline constexpr NativeSocket kInvalidSocket = static_cast<NativeSocket>(-1);

[[nodiscard]] Status socket_error(const char* what);

/// Creates a listening socket bound to host:port. port 0 asks the operating
/// system for an ephemeral port; query it with socket_local_port().
[[nodiscard]] Status listen_on(const std::string& host, std::uint16_t port, int backlog,
                               NativeSocket& out_socket, std::uint16_t& out_port);

[[nodiscard]] Status accept_one(NativeSocket listener, NativeSocket& out_socket,
                                std::string& out_peer);

[[nodiscard]] Status connect_to(const std::string& host, std::uint16_t port,
                                std::uint64_t timeout_millis, NativeSocket& out_socket);

[[nodiscard]] Status socket_local_port(NativeSocket socket, std::uint16_t& out_port);

[[nodiscard]] Status set_socket_timeouts(NativeSocket socket, std::uint64_t read_millis,
                                         std::uint64_t write_millis);

void close_socket(NativeSocket socket) noexcept;

/// Half-closes both directions so a blocked peer wakes up. Safe to call from a
/// different thread than the one blocked in recv().
void shutdown_socket(NativeSocket socket) noexcept;

/// Closes the listening socket, which makes a blocked accept() return.
void close_listener(NativeSocket socket) noexcept;

[[nodiscard]] Status socket_send_all(NativeSocket socket, const std::uint8_t* data,
                                     std::size_t length);

/// Returns the number of bytes read, 0 on orderly close, or an error.
[[nodiscard]] Status socket_receive(NativeSocket socket, std::uint8_t* buffer, std::size_t capacity,
                                    std::size_t& out_read);

/// Waits until the socket is readable or the deadline expires. Used by the
/// acceptor so it can reap finished connections instead of blocking forever.
[[nodiscard]] Status socket_wait_readable(NativeSocket socket, std::uint64_t timeout_millis,
                                          bool& out_readable);

}  // namespace cif::platform

#endif  // CIF_PLATFORM_SOCKETS_HPP
