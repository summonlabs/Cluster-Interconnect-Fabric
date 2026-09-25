#include "cif/server.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <utility>

#include "cif/bounded_queue.hpp"
#include "cif/render.hpp"
#include "cif/version.hpp"
#include "cif/platform.hpp"
#include "platform_sockets.hpp"

namespace cif {
namespace {

[[nodiscard]] Status apply_admin(AuthorityCore& core, const AdminCommand& command,
                                 std::string& detail) {
  switch (command.kind) {
    case AdminKind::None:
      return Status::error(StatusCode::InvalidArgument, "admin command kind is not set");
    case AdminKind::UpsertMember:
      CIF_TRY(core.upsert_member(command.member));
      detail = "member " + command.member.id.to_string() + " upserted";
      return Status::success();
    case AdminKind::RemoveMember:
      CIF_TRY(core.remove_member(command.member_id));
      detail = "member " + command.member_id.to_string() + " retired";
      return Status::success();
    case AdminKind::SetMemberLifecycle:
      CIF_TRY(core.set_member_lifecycle(command.member_id, command.lifecycle));
      detail = "member " + command.member_id.to_string() + " is now " + to_string(command.lifecycle);
      return Status::success();
    case AdminKind::UpsertPath:
      CIF_TRY(core.upsert_path(command.path));
      detail = "path " + command.path.id.to_string() + " upserted";
      return Status::success();
    case AdminKind::RemovePath:
      CIF_TRY(core.remove_path(command.path_id));
      detail = "path " + command.path_id.to_string() + " removed";
      return Status::success();
    case AdminKind::SetPathState:
      CIF_TRY(core.set_path_state(command.path_id, command.path_state));
      detail = "path " + command.path_id.to_string() + " is now " + to_string(command.path_state);
      return Status::success();
    case AdminKind::UpsertExclusion:
      CIF_TRY(core.upsert_exclusion(command.exclusion));
      detail = "exclusion " + command.exclusion.id.to_string() + " upserted";
      return Status::success();
    case AdminKind::RemoveExclusion:
      CIF_TRY(core.remove_exclusion(command.exclusion_id));
      detail = "exclusion " + command.exclusion_id.to_string() + " removed";
      return Status::success();
    case AdminKind::UpsertObligation:
      CIF_TRY(core.upsert_obligation(command.obligation));
      detail = "obligation " + command.obligation.id.to_string() + " upserted";
      return Status::success();
    case AdminKind::RemoveObligation:
      CIF_TRY(core.remove_obligation(command.obligation_id));
      detail = "obligation " + command.obligation_id.to_string() + " removed";
      return Status::success();
    case AdminKind::UpsertContract:
      CIF_TRY(core.upsert_contract(command.contract));
      detail = "contract " + command.contract.id.to_string() + " upserted";
      return Status::success();
    case AdminKind::RemoveContract:
      CIF_TRY(core.remove_contract(command.contract_id));
      detail = "contract " + command.contract_id.to_string() + " removed";
      return Status::success();
    case AdminKind::SetPolicy:
      CIF_TRY(core.set_policy_generation(command.policy));
      detail = "policy generation is now " + command.policy.to_string();
      return Status::success();
    case AdminKind::AdvanceTick:
      if (command.tick < core.spec().tick()) {
        return Status::error(StatusCode::StateMismatch, "the logical clock must not move backwards");
      }
      CIF_TRY(core.advance_tick(command.tick));
      CIF_TRY(core.expire_leases());
      detail = "logical clock advanced to " + command.tick.to_string();
      return Status::success();
    case AdminKind::FenceAll:
      CIF_TRY(core.fence_all(command.fence_reason, command.detail.empty() ? "administrative fence"
                                                                        : command.detail));
      detail = "every live grant was fenced";
      return Status::success();
    case AdminKind::ExpireLeases:
      CIF_TRY(core.expire_leases());
      detail = "expired leases released";
      return Status::success();
    case AdminKind::Revalidate:
      CIF_TRY(core.revalidate_live_grants());
      detail = "live grants revalidated against current state";
      return Status::success();
    case AdminKind::Compact:
      CIF_TRY(core.maybe_compact());
      detail = "compaction requested";
      return Status::success();
    case AdminKind::SelfCheck:
      CIF_TRY(core.self_check());
      detail = "invariants hold";
      return Status::success();
  }
  return Status::error(StatusCode::InvalidArgument, "unrecognised admin command");
}

}  // namespace

AuthorityServer::AuthorityServer(ServerOptions options)
    : options_(std::move(options)), ingress_(options_.ingress_capacity) {
  if (options_.max_connections == 0) {
    options_.max_connections = 1;
  }
  if (options_.max_connections > limits::kMaxConnections) {
    options_.max_connections = limits::kMaxConnections;
  }
  if (options_.max_batch == 0) {
    options_.max_batch = 1;
  }
  if (options_.max_batch > limits::kMaxBatchRequests) {
    options_.max_batch = limits::kMaxBatchRequests;
  }
  if (options_.socket_timeout_millis == 0) {
    options_.socket_timeout_millis = 200;
  }
}

AuthorityServer::~AuthorityServer() { static_cast<void>(stop()); }

Status AuthorityServer::open_state() {
  recovery_ = RecoveryReport{};
  if (options_.journal_path.empty()) {
    core_ = std::make_unique<AuthorityCore>(options_.authority);
    const ControllerIncarnation incarnation = ControllerIncarnation::generate();
    CIF_TRY(core_->initialize(options_.cluster_id, incarnation, options_.policy, Tick{1}, nullptr));
    recovery_.fresh = true;
    recovery_.detail = "no journal configured: authority is in memory only and is not durable";
    return Status::success();
  }

  std::vector<JournalEntry> entries;
  CIF_TRY(Journal::scan(options_.journal_path, entries, recovery_));

  RecoveredState recovered;
  CIF_TRY(replay_journal(entries, recovered));

  journal_ = std::make_unique<Journal>();
  CIF_TRY(journal_->open(options_.journal_path, recovery_.valid_bytes, recovery_.fresh,
                         recovery_.last_chain, recovery_.last_sequence));
  journal_sink_ = std::make_unique<JournalDurabilitySink>(*journal_);
  core_ = std::make_unique<AuthorityCore>(options_.authority);

  const ControllerIncarnation incarnation = ControllerIncarnation::generate();
  if (!recovered.has_controller) {
    CIF_TRY(core_->initialize(options_.cluster_id, incarnation, options_.policy, Tick{1},
                              journal_sink_.get()));
    recovery_.fresh = true;
    if (recovery_.detail.empty()) {
      recovery_.detail = "journal contained no controller binding; state was initialised fresh";
    }
  } else {
    if (!options_.cluster_id.empty() && !(options_.cluster_id == recovered.spec.cluster_id())) {
      return Status::error(StatusCode::StateMismatch,
                           "journal belongs to cluster " + recovered.spec.cluster_id().to_string() +
                               " but this daemon was told to rule " +
                               options_.cluster_id.to_string());
    }
    const Tick resume_tick{recovered.tick.is_zero() ? 1 : recovered.tick.value() + 1};
    CIF_TRY(core_->recover(recovered.spec, recovered.contracts, std::move(recovered.grants),
                           std::move(recovered.attempts), recovered.counters, recovery_, incarnation,
                           resume_tick));
  }
  return Status::success();
}

Status AuthorityServer::start() {
  if (running_.load()) {
    return Status::error(StatusCode::AlreadyExists, "server is already running");
  }
  stop_.store(false);
  ingress_.reset();

  CIF_TRY(open_state());
  CIF_TRY(listener_.bind(options_.bind_host, options_.port,
                         static_cast<std::size_t>(limits::kMaxListenBacklog)));

  if (!options_.ready_file.empty()) {
    CIF_TRY(platform::ensure_parent_directory(options_.ready_file));
    std::ofstream ready(options_.ready_file, std::ios::trunc);
    if (!ready) {
      return Status::error(StatusCode::IoFailure,
                           "cannot write ready file " + options_.ready_file.string());
    }
    ready << "cifd " << CIF_VERSION_STRING << "\n";
    ready << "host " << options_.bind_host << "\n";
    ready << "port " << listener_.port() << "\n";
    ready << "cluster " << core_->spec().cluster_id().to_string() << "\n";
    ready << "incarnation " << core_->spec().incarnation().hex() << "\n";
    ready << "epoch " << core_->spec().epoch().to_string() << "\n";
    ready << "durable " << (journal_ != nullptr ? "true" : "false") << "\n";
    ready << "pid " << platform::current_process_id() << "\n";
    ready.flush();
  }

  running_.store(true);
  reducer_ = std::thread([this] { reducer_loop(); });
  acceptor_ = std::thread([this] { accept_loop(); });
  return Status::success();
}

Status AuthorityServer::stop() {
  const bool was_running = running_.exchange(false);
  if (!was_running && !acceptor_.joinable() && !reducer_.joinable()) {
    // Nothing was ever started (or stop() already ran): release the listener and
    // make sure the log is closed, but keep the recovered engine readable.
    static_cast<void>(listener_.close());
    if (journal_ != nullptr) {
      static_cast<void>(journal_->close());
    }
    return Status::success();
  }
  stop_.store(true);

  // 1. Release the acceptor, which is either blocked in accept() or in a short
  //    poll. The ingress queue stays open: the reducer still has to be told to
  //    stop through it.
  static_cast<void>(listener_.close());
  if (acceptor_.joinable()) {
    acceptor_.join();
  }

  // 2. Release every blocked worker. Nothing here holds a lock while joining.
  join_connections();

  // 3. Release the reducer. The queue is still open so the stop item is
  //    accepted; it is closed afterwards as a safety net for any producer that
  //    outlives this call.
  if (reducer_.joinable()) {
    WorkItem stop_item;
    stop_item.kind = WorkKind::Stop;
    static_cast<void>(ingress_.push(std::move(stop_item)));
    reducer_.join();
  }
  ingress_.close();

  // 4. Close the log. The engine and the log are deliberately *kept* rather
  //    than destroyed: after stop() the reducer is gone, so the final
  //    authoritative state is quiescent and an embedding process may still
  //    inspect it. They are released by the next start() or by destruction.
  if (journal_ != nullptr) {
    static_cast<void>(journal_->close());
  }

  std::vector<std::shared_ptr<Connection>> drained;
  {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    drained.swap(connections_);
  }
  drained.clear();
  return Status::success();
}

void AuthorityServer::join_connections() {
  std::vector<std::shared_ptr<Connection>> local;
  {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    local = connections_;
  }
  for (const std::shared_ptr<Connection>& connection : local) {
    connection->channel.abort();
    {
      std::lock_guard<std::mutex> lock(connection->mutex);
      connection->stop_requested = true;
    }
    connection->mailbox.notify_all();
  }
  for (const std::shared_ptr<Connection>& connection : local) {
    if (connection->worker.joinable()) {
      connection->worker.join();
    }
  }
  std::lock_guard<std::mutex> lock(connections_mutex_);
  connections_.clear();
}

void AuthorityServer::reap_finished() {
  // Connections are *moved out* one by one, never compacted with remove_if.
  //
  // This is a lifetime rule, not a style preference: a Connection owns its
  // worker std::thread, and destroying a Connection whose thread is still
  // joinable calls std::terminate. remove_if overwrites the removed elements
  // with the kept ones, which destroys the removed shared_ptrs before anybody
  // has joined their threads. Moving each finished connection into its own
  // vector keeps every one of them alive until it has been joined.
  std::vector<std::shared_ptr<Connection>> finished;
  {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    std::vector<std::shared_ptr<Connection>> live;
    live.reserve(connections_.size());
    for (std::shared_ptr<Connection>& connection : connections_) {
      if (connection->finished.load()) {
        finished.push_back(std::move(connection));
      } else {
        live.push_back(std::move(connection));
      }
    }
    connections_.swap(live);
  }
  for (const std::shared_ptr<Connection>& connection : finished) {
    if (connection->worker.joinable()) {
      connection->worker.join();
    }
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.connections_closed += 1;
  }
}

void AuthorityServer::accept_loop() {
  for (;;) {
    if (stop_.load()) {
      break;
    }
    reap_finished();
    bool readable = false;
    const Status waited = platform::socket_wait_readable(listener_.native(), 100, readable);
    if (!waited.ok()) {
      if (stop_.load()) {
        break;
      }
      continue;
    }
    if (!readable) {
      continue;
    }

    std::size_t live = 0;
    {
      std::lock_guard<std::mutex> lock(connections_mutex_);
      live = connections_.size();
    }
    TcpStream stream;
    std::string peer;
    const Status accepted = listener_.accept(stream, peer);
    if (!accepted.ok()) {
      if (stop_.load()) {
        break;
      }
      continue;
    }

    auto connection = std::make_shared<Connection>();
    connection->id = next_connection_id_.fetch_add(1);
    connection->peer = peer;
    connection->channel = FrameChannel(std::move(stream));
    static_cast<void>(connection->channel.stream().set_timeouts(options_.socket_timeout_millis,
                                                                options_.socket_timeout_millis));

    {
      std::lock_guard<std::mutex> stats_lock(stats_mutex_);
      stats_.connections_accepted += 1;
    }

    if (live >= options_.max_connections) {
      Frame refusal;
      static_cast<void>(pack_message(
          make_error_message("BACKPRESSURE", "connection limit reached; retry later"), refusal));
      static_cast<void>(connection->channel.send(refusal));
      {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.connections_rejected += 1;
      }
      static_cast<void>(connection->channel.stream().close());
      continue;
    }

    std::shared_ptr<Connection> captured = connection;
    captured->worker = std::thread([this, captured] { serve(captured); });
    {
      std::lock_guard<std::mutex> lock(connections_mutex_);
      connections_.push_back(std::move(connection));
    }
  }
}

void AuthorityServer::serve(std::shared_ptr<Connection> connection) {
  while (!stop_.load()) {
    Frame frame;
    const Status received = connection->channel.receive(frame, options_.socket_timeout_millis);
    if (!received.ok()) {
      if (received.is(StatusCode::Timeout) && !stop_.load()) {
        continue;
      }
      if (!stop_.load() && !received.is(StatusCode::Closed)) {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.protocol_errors += 1;
      }
      break;
    }
    {
      std::lock_guard<std::mutex> stats_lock(stats_mutex_);
      stats_.frames_in += 1;
    }

    WorkItem item;
    item.kind = WorkKind::Frame;
    item.connection = connection;
    item.frame = std::move(frame);
    if (!ingress_.push(std::move(item))) {
      {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.ingress_rejected += 1;
      }
      Frame refusal;
      static_cast<void>(pack_message(
          make_error_message("BACKPRESSURE", "ingress queue is full; retry later"), refusal));
      static_cast<void>(connection->channel.send(refusal));
      continue;
    }

    WireMessage reply;
    {
      std::unique_lock<std::mutex> lock(connection->mutex);
      connection->mailbox.wait(lock, [&connection] {
        return connection->reply_ready || connection->stop_requested;
      });
      if (!connection->reply_ready) {
        break;  // shutdown requested
      }
      reply = std::move(connection->reply);
      connection->reply_ready = false;
    }

    Frame out;
    const Status packed = pack_message(reply, out);
    if (!packed.ok()) {
      Frame fallback;
      static_cast<void>(pack_message(
          make_error_message("INTERNAL", "reply could not be encoded: " + packed.to_string()),
          fallback));
      static_cast<void>(connection->channel.send(fallback));
      break;
    }
    const Status sent = connection->channel.send(out);
    if (!sent.ok()) {
      break;
    }
    {
      std::lock_guard<std::mutex> stats_lock(stats_mutex_);
      stats_.frames_out += 1;
    }
    if (reply.type == MessageType::Bye) {
      break;
    }
  }
  connection->finished.store(true);
}

void AuthorityServer::deliver(const std::shared_ptr<Connection>& connection, WireMessage message) {
  {
    std::lock_guard<std::mutex> lock(connection->mutex);
    connection->reply = std::move(message);
    connection->reply_ready = true;
  }
  connection->mailbox.notify_all();
}

Status AuthorityServer::round_trip_local(WireMessage request, WireMessage& out) {
  if (!running_.load() || core_ == nullptr) {
    return Status::error(StatusCode::Closed, "the authority is not running");
  }
  auto mailbox = std::make_shared<LocalMailbox>();
  WorkItem item;
  item.kind = WorkKind::LocalRequest;
  item.request = std::move(request);
  item.mailbox = mailbox;
  if (!ingress_.push(std::move(item))) {
    return Status::error(StatusCode::Backpressure, "the ingress queue is full");
  }
  std::unique_lock<std::mutex> lock(mailbox->mutex);
  mailbox->ready.wait(lock, [&mailbox] { return mailbox->answered; });
  out = std::move(mailbox->reply);
  return Status::success();
}

Status AuthorityServer::apply(const AdminCommand& command, AdminResult& out) {
  WireMessage request;
  request.type = MessageType::Admin;
  request.admin = command;
  WireMessage reply;
  CIF_TRY(round_trip_local(std::move(request), reply));
  if (reply.type == MessageType::Error) {
    return Status::error(StatusCode::RemoteError,
                         reply.error_code + ": " + sanitise_for_display(reply.error_message, 192));
  }
  if (reply.type != MessageType::AdminResult) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected ADMIN_RESULT, received ") + to_string(reply.type));
  }
  out = reply.admin_result;
  return Status::success();
}

Status AuthorityServer::inspect(const QueryCommand& command, QueryResult& out) {
  WireMessage request;
  request.type = MessageType::Query;
  request.query = command;
  WireMessage reply;
  CIF_TRY(round_trip_local(std::move(request), reply));
  if (reply.type == MessageType::Error) {
    return Status::error(StatusCode::RemoteError,
                         reply.error_code + ": " + sanitise_for_display(reply.error_message, 192));
  }
  if (reply.type != MessageType::QueryResult) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected QUERY_RESULT, received ") + to_string(reply.type));
  }
  out = reply.query_result;
  return Status::success();
}

void AuthorityServer::reducer_loop() {
  bool stopping = false;
  while (!stopping) {
    WorkItem item;
    bool have = false;
    if (options_.housekeeping_period_millis > 0) {
      have = ingress_.pop_wait_for(item,
                                   std::chrono::milliseconds(options_.housekeeping_period_millis));
      if (!have) {
        if (ingress_.closed()) {
          break;
        }
        housekeeping();
        continue;
      }
    } else {
      have = ingress_.pop_wait(item);
      if (!have) {
        break;  // queue closed and drained
      }
    }
    for (std::size_t processed = 0;; ++processed) {
      if (item.kind == WorkKind::Stop) {
        stopping = true;
        break;
      }
      if (item.kind == WorkKind::LocalRequest) {
        // An in-process request is answered directly on the caller's mailbox.
        // The reducer still performs no I/O and still holds no lock while it
        // works, so its contract is unchanged.
        std::shared_ptr<LocalMailbox> mailbox = item.mailbox;
        WireMessage reply = dispatch(nullptr, item.request);
        {
          std::lock_guard<std::mutex> lock(mailbox->mutex);
          mailbox->reply = std::move(reply);
          mailbox->answered = true;
        }
        mailbox->ready.notify_all();
      } else {
        process(item);
      }
      if (processed + 1 >= options_.max_batch) {
        break;
      }
      if (!ingress_.try_pop(item)) {
        break;
      }
    }
  }
}

void AuthorityServer::housekeeping() {
  if (core_ == nullptr) {
    return;
  }
  if (!core_->spec().tick().can_advance()) {
    return;  // logical time is saturated; nothing left to expire
  }
  const Tick now{core_->spec().tick().value() + 1};
  static_cast<void>(core_->advance_tick(now));
  static_cast<void>(core_->expire_leases());
  if (core_->options().durable) {
    static_cast<void>(core_->maybe_compact());
  }
  std::lock_guard<std::mutex> lock(stats_mutex_);
  stats_.housekeeping_rounds += 1;
}

WireMessage AuthorityServer::dispatch(const std::shared_ptr<Connection>& connection,
                                      const WireMessage& message) {
  WireMessage reply;
  switch (message.type) {
    case MessageType::Hello: {
      if (connection == nullptr) {
        return make_error_message("PROTOCOL", "an in-process request cannot perform a handshake");
      }
      if (message.banner != version_banner()) {
        reply = make_error_message("VERSION_MISMATCH",
                                   "peer banner '" + sanitise_for_display(message.banner, 96) +
                                       "' does not match '" + version_banner() + "'");
        return reply;
      }
      connection->client = message.client;
      connection->greeted = true;
      reply.type = MessageType::HelloAck;
      reply.banner = version_banner();
      reply.cluster_id = core_->spec().cluster_id();
      reply.cluster_generation = core_->spec().generation();
      reply.epoch = core_->spec().epoch();
      reply.policy = core_->spec().policy_generation();
      reply.incarnation = core_->spec().incarnation();
      reply.state_digest = core_->state_digest();
      return reply;
    }
    case MessageType::Ping:
      reply.type = MessageType::Pong;
      return reply;
    case MessageType::Bye:
      reply.type = MessageType::Bye;
      return reply;
    default:
      break;
  }

  if (connection != nullptr && options_.require_hello && !connection->greeted) {
    return make_error_message("PROTOCOL", "the first message on a connection must be HELLO");
  }

  switch (message.type) {
    case MessageType::Submit:
      reply.type = MessageType::Decision;
      reply.decision = core_->submit(message.request);
      break;
    case MessageType::Release:
      reply.type = MessageType::Decision;
      reply.decision = core_->release(message.release);
      break;
    case MessageType::Resolve:
      reply.type = MessageType::Decision;
      reply.decision = core_->resolve(message.resolve);
      break;
    case MessageType::Acknowledge:
      reply.type = MessageType::Decision;
      reply.decision = core_->acknowledge(message.acknowledge);
      break;
    case MessageType::Cancel:
      reply.type = MessageType::Decision;
      reply.decision = core_->cancel(message.cancel);
      break;
    case MessageType::Admin: {
      reply.type = MessageType::AdminResult;
      const AdminCommand& command = message.admin;
      const Status shape = command.validate_shape();
      if (!shape.ok()) {
        reply.admin_result.code = shape.code();
        reply.admin_result.message = shape.message();
        break;
      }
      if (command.has_expectation && !(command.expect_generation == core_->spec().generation())) {
        reply.admin_result.code = StatusCode::StateMismatch;
        reply.admin_result.message =
            "expected cluster generation " + command.expect_generation.to_string() +
            " but the controller is at " + core_->spec().generation().to_string();
        break;
      }
      std::string detail;
      const Status applied = apply_admin(*core_, command, detail);
      reply.admin_result.code = applied.code();
      reply.admin_result.message = applied.ok() ? detail : applied.to_string();
      break;
    }
    case MessageType::Query: {
      reply.type = MessageType::QueryResult;
      const QueryCommand& command = message.query;
      const Status shape = command.validate_shape();
      if (!shape.ok()) {
        reply.query_result.code = shape.code();
        reply.query_result.message = shape.message();
        break;
      }
      QueryResult& result = reply.query_result;
      result.cluster_id = core_->spec().cluster_id();
      result.generation = core_->spec().generation();
      result.epoch = core_->spec().epoch();
      result.policy = core_->spec().policy_generation();
      result.incarnation = core_->spec().incarnation();
      result.state_digest = core_->state_digest();
      result.spec_digest = core_->spec().digest();
      result.topology_digest = core_->spec().topology_digest();
      switch (command.kind) {
        case QueryKind::Version:
          result.text = version_banner();
          break;
        case QueryKind::Controller:
          result.text = render_controller(core_->controller_identity());
          break;
        case QueryKind::State:
          result.text = core_->render_state();
          break;
        case QueryKind::Audit:
          result.text = core_->render_audit();
          break;
        case QueryKind::Recovery:
          result.text = recovery_.render();
          break;
        case QueryKind::Verify: {
          const Status checked = core_->self_check();
          result.text = checked.ok() ? "OK invariants hold\n" : "VIOLATION " + checked.to_string() + "\n";
          if (!checked.ok()) {
            result.code = checked.code();
            result.message = checked.message();
          }
          break;
        }
        case QueryKind::Member: {
          const Member* member = core_->spec().find_member(command.member_id);
          if (member == nullptr) {
            result.code = StatusCode::NotFound;
            result.message = "member " + command.member_id.to_string() + " is not declared";
          } else {
            result.text = render_member(*member);
          }
          break;
        }
        case QueryKind::Path: {
          const Path* path = core_->spec().find_path(command.path_id);
          if (path == nullptr) {
            result.code = StatusCode::NotFound;
            result.message = "path " + command.path_id.to_string() + " is not declared";
          } else {
            result.text = render_path(*path);
          }
          break;
        }
        case QueryKind::Grant: {
          const AuthorityGrant* grant = core_->find_grant(command.grant_id);
          if (grant == nullptr) {
            result.code = StatusCode::NotFound;
            result.message = "grant " + command.grant_id.to_string() + " is not present";
          } else {
            result.text = render_grant(*grant);
          }
          break;
        }
        case QueryKind::Attempt: {
          const AttemptRecord* attempt = core_->find_attempt(command.attempt_id);
          if (attempt == nullptr) {
            result.code = StatusCode::NotFound;
            result.message = "attempt " + command.attempt_id.to_string() + " is not present";
          } else {
            result.text = render_attempt(*attempt);
          }
          break;
        }
        case QueryKind::None:
          result.code = StatusCode::InvalidArgument;
          result.message = "query kind is not set";
          break;
      }
      break;
    }
    case MessageType::Invalid:
    case MessageType::HelloAck:
    case MessageType::Decision:
    case MessageType::AdminResult:
    case MessageType::QueryResult:
    case MessageType::Error:
    case MessageType::Pong:
    case MessageType::Ping:
    case MessageType::Bye:
    case MessageType::Hello:
      reply = make_error_message("PROTOCOL",
                                 std::string("clients must not send ") + to_string(message.type));
      break;
  }

  if (reply.type == MessageType::AdminResult) {
    reply.admin_result.generation = core_->spec().generation();
    reply.admin_result.epoch = core_->spec().epoch();
    reply.admin_result.incarnation = core_->spec().incarnation();
    reply.admin_result.state_digest = core_->state_digest();
  }
  return reply;
}

void AuthorityServer::process(WorkItem& item) {
  const std::shared_ptr<Connection>& connection = item.connection;
  WireMessage message;
  const Status unpacked = unpack_message(item.frame, message);
  if (!unpacked.ok()) {
    protocol_errors_.fetch_add(1);
    // The statistics lock is released before the reply is delivered: no thread
    // in this daemon ever holds two locks at once.
    {
      std::lock_guard<std::mutex> lock(stats_mutex_);
      stats_.protocol_errors += 1;
    }
    deliver(connection, make_error_message("MALFORMED_FRAME", unpacked.to_string()));
    return;
  }
  WireMessage reply = dispatch(connection, message);
  reply.sequence = item.frame.sequence;
  deliver(connection, std::move(reply));
}

ServerStatus AuthorityServer::status() const {
  ServerStatus snapshot;
  snapshot.running = running_.load();
  snapshot.bind_host = options_.bind_host;
  snapshot.port = listener_.port();
  snapshot.journal_path = options_.journal_path.string();
  snapshot.durable = journal_ != nullptr;
  snapshot.ingest_depth = ingress_.size();
  snapshot.recovery = recovery_;
  {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    snapshot.active_connections = connections_.size();
  }
  {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    snapshot.stats = stats_;
  }
  return snapshot;
}

}  // namespace cif
