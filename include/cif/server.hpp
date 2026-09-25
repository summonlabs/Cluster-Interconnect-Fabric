// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The authority daemon.
//
// Threading and ownership contract -- the whole design in one place:
//
//   * Exactly ONE reducer thread owns the AuthorityCore. The core is never
//     touched by any other thread, so it needs no internal locking and its
//     invariants are checkable by reading one file.
//   * The reducer NEVER performs I/O. It turns a decoded request into a decoded
//     reply and deposits the reply in the requesting connection's mailbox. That
//     is what makes socket backpressure unable to stall authority.
//   * One worker thread per connection performs all socket I/O for that
//     connection. It blocks on its own mailbox condition variable while the
//     reducer works, so a slow peer cannot block another peer.
//   * Lock order: the ingress queue mutex and a connection mailbox mutex are
//     both LEAF locks. No thread ever holds two of them at once, so no lock
//     inversion is possible by construction. Worker threads are joined only
//     after every lock has been released.
//   * The ingress queue is bounded. A full queue is reported to the producer as
//     backpressure; producers never block on the reducer, so a stalled reducer
//     cannot deadlock the daemon.
#ifndef CIF_SERVER_HPP
#define CIF_SERVER_HPP

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "cif/authority.hpp"
#include "cif/bounded_queue.hpp"
#include "cif/journal.hpp"
#include "cif/net.hpp"
#include "cif/wire.hpp"

namespace cif {

struct ServerOptions {
  std::string bind_host = "127.0.0.1";
  std::uint16_t port = 0;  ///< 0 asks the operating system for a free port.
  std::size_t max_connections = limits::kMaxConnections;
  std::size_t ingress_capacity = limits::kMaxIngressQueue;
  std::size_t max_batch = limits::kMaxBatchRequests;
  std::uint64_t socket_timeout_millis = 200;
  std::uint64_t housekeeping_period_millis = 0;  ///< 0 disables the internal clock.
  bool require_hello = true;

  std::filesystem::path journal_path;  ///< Empty means non-durable, in-memory.
  std::filesystem::path ready_file;    ///< Optional: written once listening.

  ClusterId cluster_id;
  PolicyGeneration policy{};
  AuthorityOptions authority{};
};

struct ServerStats {
  std::uint64_t connections_accepted = 0;
  std::uint64_t connections_rejected = 0;
  std::uint64_t connections_closed = 0;
  std::uint64_t frames_in = 0;
  std::uint64_t frames_out = 0;
  std::uint64_t protocol_errors = 0;
  std::uint64_t ingress_rejected = 0;
  std::uint64_t housekeeping_rounds = 0;
  std::uint64_t compactions = 0;
};

/// Live view of the daemon. Safe to read from any thread.
struct ServerStatus {
  bool running = false;
  std::string bind_host;
  std::uint16_t port = 0;
  std::string journal_path;
  bool durable = false;
  std::size_t active_connections = 0;
  std::size_t ingest_depth = 0;
  RecoveryReport recovery;
  ServerStats stats;
};

class AuthorityServer {
 public:
  explicit AuthorityServer(ServerOptions options = {});
  ~AuthorityServer();

  AuthorityServer(const AuthorityServer&) = delete;
  AuthorityServer& operator=(const AuthorityServer&) = delete;

  /// Binds the listener, recovers durable state if configured, and starts the
  /// acceptor, reducer and (optionally) housekeeping threads. Idempotent: a
  /// second call on a running server returns AlreadyExists.
  [[nodiscard]] Status start();

  /// Stops accepting, releases every blocked worker, joins every thread and
  /// closes the journal. Safe to call twice and safe to call after a failed
  /// start.
  [[nodiscard]] Status stop();

  [[nodiscard]] bool running() const noexcept { return running_.load(); }
  [[nodiscard]] std::uint16_t port() const noexcept { return listener_.port(); }
  [[nodiscard]] const ServerOptions& options() const noexcept { return options_; }
  [[nodiscard]] ServerStatus status() const;

  /// Applies an administrative command through the *same* single-threaded
  /// reducer path the wire uses. Safe to call from any thread while the daemon
  /// runs: this is the supported way for the process hosting the daemon to
  /// govern its cluster without opening a socket.
  [[nodiscard]] Status apply(const AdminCommand& command, AdminResult& out);

  /// Runs a query through the reducer. Same guarantees as apply().
  [[nodiscard]] Status inspect(const QueryCommand& command, QueryResult& out);

  /// Direct access to the engine.
  ///
  /// CONTRACT: while the daemon is running the reducer thread owns the engine
  /// exclusively, and touching it from any other thread is a data race rather
  /// than a shortcut. Use apply()/inspect() while running. After stop() the
  /// reducer is gone and the final authoritative state is quiescent, so it may
  /// be read directly; it stays valid until the next start() or destruction.
  [[nodiscard]] AuthorityCore& core() noexcept { return *core_; }
  [[nodiscard]] const AuthorityCore& core() const noexcept { return *core_; }
  [[nodiscard]] const RecoveryReport& recovery() const noexcept { return recovery_; }

 private:
  struct Connection {
    std::size_t id = 0;
    std::string peer;
    FrameChannel channel;
    std::thread worker;

    std::mutex mutex;  ///< Leaf lock guarding the reply mailbox.
    std::condition_variable mailbox;
    bool reply_ready = false;
    bool stop_requested = false;
    WireMessage reply;

    ClientId client;
    bool greeted = false;
    std::atomic<bool> finished{false};
  };

  enum class WorkKind : std::uint8_t { Frame, Stop, LocalRequest };

  /// Reply slot for an in-process caller. Its mutex is a leaf lock, exactly like
  /// a connection mailbox.
  struct LocalMailbox {
    std::mutex mutex;
    std::condition_variable ready;
    bool answered = false;
    WireMessage reply;
  };

  struct WorkItem {
    WorkKind kind = WorkKind::Frame;
    std::shared_ptr<Connection> connection;
    Frame frame;
    WireMessage request;
    std::shared_ptr<LocalMailbox> mailbox;
  };

  void accept_loop();
  void reducer_loop();
  void serve(std::shared_ptr<Connection> connection);
  void process(WorkItem& item);
  void housekeeping();
  void deliver(const std::shared_ptr<Connection>& connection, WireMessage message);
  [[nodiscard]] Status round_trip_local(WireMessage request, WireMessage& out);
  void reap_finished();
  void join_connections();
  [[nodiscard]] WireMessage dispatch(const std::shared_ptr<Connection>& connection,
                                     const WireMessage& message);
  [[nodiscard]] Status open_state();

  ServerOptions options_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> running_{false};
  TcpListener listener_;
  BoundedQueue<WorkItem> ingress_;
  std::thread acceptor_;
  std::thread reducer_;
  std::atomic<std::size_t> next_connection_id_{1};

  mutable std::mutex connections_mutex_;
  mutable std::mutex stats_mutex_;
  std::vector<std::shared_ptr<Connection>> connections_;
  ServerStats stats_;

  std::unique_ptr<Journal> journal_;
  std::unique_ptr<JournalDurabilitySink> journal_sink_;
  std::unique_ptr<AuthorityCore> core_;
  RecoveryReport recovery_;
  std::atomic<std::uint64_t> protocol_errors_{0};
};

}  // namespace cif

#endif  // CIF_SERVER_HPP
