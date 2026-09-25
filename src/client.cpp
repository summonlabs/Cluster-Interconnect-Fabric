#include "cif/client.hpp"

#include <utility>

#include "cif/version.hpp"

namespace cif {

AuthorityClient::~AuthorityClient() { static_cast<void>(close()); }

Status AuthorityClient::connect(const ClientOptions& options) {
  options_ = options;
  if (options_.client.empty()) {
    options_.client = ClientId::from_validated("cif-client-" + std::to_string(++sequence_));
  }
  CIF_TRY(channel_.stream().connect(options_.host, options_.port, options_.timeout_millis));
  CIF_TRY(channel_.stream().set_timeouts(options_.timeout_millis, options_.timeout_millis));
  server_ = ServerIdentity{};

  if (options_.skip_hello) {
    return Status::success();
  }

  WireMessage hello;
  hello.type = MessageType::Hello;
  hello.banner = version_banner();
  hello.client = options_.client;

  WireMessage reply;
  CIF_TRY(exchange(hello, reply));
  if (reply.type == MessageType::Error) {
    return Status::error(StatusCode::Unsupported,
                         reply.error_code + ": " + sanitise_for_display(reply.error_message, 192));
  }
  if (reply.type != MessageType::HelloAck) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected HELLO_ACK, received ") + to_string(reply.type));
  }
  server_.banner = reply.banner;
  server_.cluster_id = reply.cluster_id;
  server_.generation = reply.cluster_generation;
  server_.epoch = reply.epoch;
  server_.policy = reply.policy;
  server_.incarnation = reply.incarnation;
  server_.state_digest = reply.state_digest;
  server_.valid = true;
  return Status::success();
}

Status AuthorityClient::refresh() {
  if (!channel_.is_open()) {
    return Status::error(StatusCode::Closed, "client is not connected");
  }
  WireMessage hello;
  hello.type = MessageType::Hello;
  hello.banner = version_banner();
  hello.client = options_.client;
  WireMessage reply;
  CIF_TRY(exchange(hello, reply));
  if (reply.type == MessageType::Error) {
    return Status::error(StatusCode::RemoteError,
                         reply.error_code + ": " + sanitise_for_display(reply.error_message, 192));
  }
  if (reply.type != MessageType::HelloAck) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected HELLO_ACK, received ") + to_string(reply.type));
  }
  server_.banner = reply.banner;
  server_.cluster_id = reply.cluster_id;
  server_.generation = reply.cluster_generation;
  server_.epoch = reply.epoch;
  server_.policy = reply.policy;
  server_.incarnation = reply.incarnation;
  server_.state_digest = reply.state_digest;
  server_.valid = true;
  return Status::success();
}

Status AuthorityClient::close() {
  if (!channel_.is_open()) {
    return Status::success();
  }
  channel_.abort();
  CIF_TRY(channel_.stream().close());
  server_ = ServerIdentity{};
  return Status::success();
}

Status AuthorityClient::exchange_frame(const Frame& frame, Frame& out) {
  CIF_TRY(channel_.send(frame));
  return channel_.receive(out, options_.timeout_millis);
}

Status AuthorityClient::exchange(const WireMessage& message, WireMessage& out) {
  Frame frame;
  CIF_TRY(pack_message(message, frame));
  frame.sequence = ++sequence_;
  Frame reply_frame;
  CIF_TRY(exchange_frame(frame, reply_frame));
  return unpack_message(reply_frame, out);
}

Status AuthorityClient::send_frame(const Frame& frame) { return channel_.send(frame); }

Status AuthorityClient::send_bytes(std::span<const std::uint8_t> bytes) {
  return channel_.stream().send_all(bytes);
}

Status AuthorityClient::receive_frame(Frame& out) {
  return channel_.receive(out, options_.timeout_millis);
}

namespace {

[[nodiscard]] Status expect_decision(const WireMessage& reply, AuthorityDecision& out) {
  if (reply.type == MessageType::Error) {
    return Status::error(StatusCode::RemoteError, reply.error_code + ": " +
                                                      sanitise_for_display(reply.error_message, 192));
  }
  if (reply.type != MessageType::Decision) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected DECISION, received ") + to_string(reply.type));
  }
  out = reply.decision;
  return Status::success();
}

}  // namespace

Status AuthorityClient::submit(const AuthorityRequest& request, AuthorityDecision& out) {
  WireMessage message;
  message.type = MessageType::Submit;
  message.request = request;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  return expect_decision(reply, out);
}

Status AuthorityClient::release(const ReleaseRequest& request, AuthorityDecision& out) {
  WireMessage message;
  message.type = MessageType::Release;
  message.release = request;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  return expect_decision(reply, out);
}

Status AuthorityClient::resolve(const ResolveRequest& request, AuthorityDecision& out) {
  WireMessage message;
  message.type = MessageType::Resolve;
  message.resolve = request;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  return expect_decision(reply, out);
}

Status AuthorityClient::acknowledge(const AcknowledgeRequest& request, AuthorityDecision& out) {
  WireMessage message;
  message.type = MessageType::Acknowledge;
  message.acknowledge = request;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  return expect_decision(reply, out);
}

Status AuthorityClient::cancel(const CancelRequest& request, AuthorityDecision& out) {
  WireMessage message;
  message.type = MessageType::Cancel;
  message.cancel = request;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  return expect_decision(reply, out);
}

Status AuthorityClient::admin(const AdminCommand& command, AdminResult& out) {
  WireMessage message;
  message.type = MessageType::Admin;
  message.admin = command;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  if (reply.type == MessageType::Error) {
    return Status::error(StatusCode::RemoteError, reply.error_code + ": " +
                                                      sanitise_for_display(reply.error_message, 192));
  }
  if (reply.type != MessageType::AdminResult) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected ADMIN_RESULT, received ") + to_string(reply.type));
  }
  out = reply.admin_result;
  return Status::success();
}

Status AuthorityClient::query(const QueryCommand& command, QueryResult& out) {
  WireMessage message;
  message.type = MessageType::Query;
  message.query = command;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  if (reply.type == MessageType::Error) {
    return Status::error(StatusCode::RemoteError, reply.error_code + ": " +
                                                      sanitise_for_display(reply.error_message, 192));
  }
  if (reply.type != MessageType::QueryResult) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected QUERY_RESULT, received ") + to_string(reply.type));
  }
  out = reply.query_result;
  return Status::success();
}

Status AuthorityClient::ping() {
  WireMessage message;
  message.type = MessageType::Ping;
  WireMessage reply;
  CIF_TRY(exchange(message, reply));
  if (reply.type != MessageType::Pong) {
    return Status::error(StatusCode::Corruption,
                         std::string("expected PONG, received ") + to_string(reply.type));
  }
  return Status::success();
}

Status AuthorityClient::bye() {
  WireMessage message;
  message.type = MessageType::Bye;
  WireMessage reply;
  const Status exchanged = exchange(message, reply);
  static_cast<void>(channel_.stream().close());
  return exchanged;
}

}  // namespace cif
