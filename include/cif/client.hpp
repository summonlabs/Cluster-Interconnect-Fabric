// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Blocking authority client. One client owns one connection and is not thread
// safe: create one per thread. Every call is a strict request/response round
// trip, so a client can never observe a reply that belongs to a different
// request.
#ifndef CIF_CLIENT_HPP
#define CIF_CLIENT_HPP

#include <cstdint>
#include <string>

#include "cif/net.hpp"
#include "cif/wire.hpp"

namespace cif {

struct ClientOptions {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  std::uint64_t timeout_millis = 5000;
  ClientId client;
  bool skip_hello = false;  ///< Test hook: speak before the protocol handshake.
};

/// What the server said about itself during the handshake.
struct ServerIdentity {
  std::string banner;
  ClusterId cluster_id;
  ClusterGeneration generation{};
  ClusterEpoch epoch{};
  PolicyGeneration policy{};
  ControllerIncarnation incarnation{};
  Digest256 state_digest{};
  bool valid = false;
};

class AuthorityClient {
 public:
  AuthorityClient() = default;
  ~AuthorityClient();

  AuthorityClient(const AuthorityClient&) = delete;
  AuthorityClient& operator=(const AuthorityClient&) = delete;

  [[nodiscard]] Status connect(const ClientOptions& options);
  [[nodiscard]] Status close();
  [[nodiscard]] bool connected() const noexcept { return channel_.is_open(); }
  [[nodiscard]] const ServerIdentity& server() const noexcept { return server_; }
  [[nodiscard]] const ClientOptions& options() const noexcept { return options_; }
  [[nodiscard]] std::uint64_t next_sequence() noexcept { return ++sequence_; }

  [[nodiscard]] Status submit(const AuthorityRequest& request, AuthorityDecision& out);
  [[nodiscard]] Status release(const ReleaseRequest& request, AuthorityDecision& out);
  [[nodiscard]] Status resolve(const ResolveRequest& request, AuthorityDecision& out);
  [[nodiscard]] Status acknowledge(const AcknowledgeRequest& request, AuthorityDecision& out);
  [[nodiscard]] Status cancel(const CancelRequest& request, AuthorityDecision& out);
  [[nodiscard]] Status admin(const AdminCommand& command, AdminResult& out);
  [[nodiscard]] Status query(const QueryCommand& command, QueryResult& out);
  [[nodiscard]] Status ping();
  [[nodiscard]] Status bye();

  /// Repeats the handshake on the existing connection and refreshes the
  /// observed controller coordinate. Authoritative state moves -- every spec
  /// change advances the cluster generation -- so a long-lived client must be
  /// able to re-read the coordinate without dropping its connection.
  [[nodiscard]] Status refresh();

  /// Sends a message and returns whatever comes back, without interpreting it.
  [[nodiscard]] Status exchange(const WireMessage& message, WireMessage& out);

  /// Sends a raw frame. Used by the transport tests to speak malformed framing.
  [[nodiscard]] Status send_frame(const Frame& frame);
  [[nodiscard]] Status send_bytes(std::span<const std::uint8_t> bytes);

  /// Reads one frame, returning whatever it is. Used by transport tests.
  [[nodiscard]] Status receive_frame(Frame& out);

  [[nodiscard]] FrameChannel& channel() noexcept { return channel_; }

 private:
  [[nodiscard]] Status exchange_frame(const Frame& frame, Frame& out);

  ClientOptions options_{};
  FrameChannel channel_{};
  ServerIdentity server_{};
  std::uint64_t sequence_ = 0;
};

}  // namespace cif

#endif  // CIF_CLIENT_HPP
