#include "cif/wire.hpp"

#include <utility>

#include "cif/version.hpp"

namespace cif {
namespace {

constexpr std::size_t kHeaderSize = Frame::kHeaderSize;
constexpr std::size_t kTrailerSize = 4;

[[nodiscard]] ReasonCode parse_fence_reason(std::uint16_t raw) noexcept {
  if (raw > static_cast<std::uint16_t>(ReasonCode::DegradedByRedundancyLoss)) {
    return ReasonCode::ControllerRestarted;
  }
  return static_cast<ReasonCode>(raw);
}

void encode_status(ByteWriter& writer, const Status& status) {
  writer.u8(static_cast<std::uint8_t>(status.code()));
  writer.text(status.message());
}

[[nodiscard]] bool decode_status(ByteReader& reader, Status& out) {
  std::uint8_t code = 0;
  if (!reader.u8(code)) return false;
  if (code > static_cast<std::uint8_t>(StatusCode::Internal)) {
    reader.fail(StatusCode::Corruption, "status code byte out of range");
    return false;
  }
  std::string message;
  if (!reader.text(message, limits::kMaxNoteBytes)) return false;
  if (!is_valid_utf8(message)) {
    reader.fail(StatusCode::Corruption, "status message is not valid UTF-8");
    return false;
  }
  out = Status::error(static_cast<StatusCode>(code), std::move(message));
  return true;
}

}  // namespace

const char* to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::Invalid: return "INVALID";
    case MessageType::Hello: return "HELLO";
    case MessageType::HelloAck: return "HELLO_ACK";
    case MessageType::Submit: return "SUBMIT";
    case MessageType::Release: return "RELEASE";
    case MessageType::Resolve: return "RESOLVE";
    case MessageType::Acknowledge: return "ACKNOWLEDGE";
    case MessageType::Cancel: return "CANCEL";
    case MessageType::Decision: return "DECISION";
    case MessageType::Admin: return "ADMIN";
    case MessageType::AdminResult: return "ADMIN_RESULT";
    case MessageType::Query: return "QUERY";
    case MessageType::QueryResult: return "QUERY_RESULT";
    case MessageType::Error: return "ERROR";
    case MessageType::Ping: return "PING";
    case MessageType::Pong: return "PONG";
    case MessageType::Bye: return "BYE";
  }
  return "UNRECOGNISED_MESSAGE";
}

const char* to_string(AdminKind kind) noexcept {
  switch (kind) {
    case AdminKind::None: return "NONE";
    case AdminKind::UpsertMember: return "UPSERT_MEMBER";
    case AdminKind::RemoveMember: return "REMOVE_MEMBER";
    case AdminKind::SetMemberLifecycle: return "SET_MEMBER_LIFECYCLE";
    case AdminKind::UpsertPath: return "UPSERT_PATH";
    case AdminKind::RemovePath: return "REMOVE_PATH";
    case AdminKind::SetPathState: return "SET_PATH_STATE";
    case AdminKind::UpsertExclusion: return "UPSERT_EXCLUSION";
    case AdminKind::RemoveExclusion: return "REMOVE_EXCLUSION";
    case AdminKind::UpsertObligation: return "UPSERT_OBLIGATION";
    case AdminKind::RemoveObligation: return "REMOVE_OBLIGATION";
    case AdminKind::UpsertContract: return "UPSERT_CONTRACT";
    case AdminKind::RemoveContract: return "REMOVE_CONTRACT";
    case AdminKind::SetPolicy: return "SET_POLICY";
    case AdminKind::AdvanceTick: return "ADVANCE_TICK";
    case AdminKind::FenceAll: return "FENCE_ALL";
    case AdminKind::ExpireLeases: return "EXPIRE_LEASES";
    case AdminKind::Revalidate: return "REVALIDATE";
    case AdminKind::Compact: return "COMPACT";
    case AdminKind::SelfCheck: return "SELF_CHECK";
  }
  return "UNRECOGNISED_ADMIN_KIND";
}

bool parse_admin_kind(std::string_view text, AdminKind& out) noexcept {
  struct Binding {
    const char* name;
    AdminKind kind;
  };
  static const Binding kBindings[] = {
      {"upsert-member", AdminKind::UpsertMember},
      {"remove-member", AdminKind::RemoveMember},
      {"set-member-lifecycle", AdminKind::SetMemberLifecycle},
      {"upsert-path", AdminKind::UpsertPath},
      {"remove-path", AdminKind::RemovePath},
      {"set-path-state", AdminKind::SetPathState},
      {"upsert-exclusion", AdminKind::UpsertExclusion},
      {"remove-exclusion", AdminKind::RemoveExclusion},
      {"upsert-obligation", AdminKind::UpsertObligation},
      {"remove-obligation", AdminKind::RemoveObligation},
      {"upsert-contract", AdminKind::UpsertContract},
      {"remove-contract", AdminKind::RemoveContract},
      {"set-policy", AdminKind::SetPolicy},
      {"advance-tick", AdminKind::AdvanceTick},
      {"fence-all", AdminKind::FenceAll},
      {"expire-leases", AdminKind::ExpireLeases},
      {"revalidate", AdminKind::Revalidate},
      {"compact", AdminKind::Compact},
      {"self-check", AdminKind::SelfCheck},
  };
  for (const Binding& binding : kBindings) {
    if (text == binding.name) {
      out = binding.kind;
      return true;
    }
  }
  return false;
}

const char* to_string(QueryKind kind) noexcept {
  switch (kind) {
    case QueryKind::None: return "NONE";
    case QueryKind::Controller: return "CONTROLLER";
    case QueryKind::State: return "STATE";
    case QueryKind::Audit: return "AUDIT";
    case QueryKind::Member: return "MEMBER";
    case QueryKind::Path: return "PATH";
    case QueryKind::Grant: return "GRANT";
    case QueryKind::Attempt: return "ATTEMPT";
    case QueryKind::Recovery: return "RECOVERY";
    case QueryKind::Verify: return "VERIFY";
    case QueryKind::Version: return "VERSION";
  }
  return "UNRECOGNISED_QUERY_KIND";
}

bool parse_query_kind(std::string_view text, QueryKind& out) noexcept {
  struct Binding {
    const char* name;
    QueryKind kind;
  };
  static const Binding kBindings[] = {
      {"controller", QueryKind::Controller}, {"state", QueryKind::State},
      {"audit", QueryKind::Audit},           {"member", QueryKind::Member},
      {"path", QueryKind::Path},             {"grant", QueryKind::Grant},
      {"attempt", QueryKind::Attempt},       {"recovery", QueryKind::Recovery},
      {"verify", QueryKind::Verify},         {"version", QueryKind::Version},
  };
  for (const Binding& binding : kBindings) {
    if (text == binding.name) {
      out = binding.kind;
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// AdminCommand
// ---------------------------------------------------------------------------
Status AdminCommand::validate_shape() const {
  if (kind == AdminKind::None) {
    return Status::error(StatusCode::InvalidArgument, "admin command kind must be set");
  }
  switch (kind) {
    case AdminKind::UpsertMember:
      if (member.id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "member to upsert has no id");
      }
      break;
    case AdminKind::RemoveMember:
      if (member_id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "member to remove has no id");
      }
      break;
    case AdminKind::SetMemberLifecycle:
      if (member_id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "member lifecycle change has no id");
      }
      break;
    case AdminKind::UpsertPath:
      if (path.id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "path to upsert has no id");
      }
      break;
    case AdminKind::RemovePath:
      if (path_id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "path to remove has no id");
      }
      break;
    case AdminKind::SetPathState:
      if (path_id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "path state change has no id");
      }
      break;
    case AdminKind::UpsertExclusion:
      if (exclusion.id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "exclusion to upsert has no id");
      }
      break;
    case AdminKind::RemoveExclusion:
      if (exclusion_id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "exclusion to remove has no id");
      }
      break;
    case AdminKind::UpsertObligation:
      if (obligation.id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "obligation to upsert has no id");
      }
      break;
    case AdminKind::RemoveObligation:
      if (obligation_id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "obligation to remove has no id");
      }
      break;
    case AdminKind::UpsertContract:
      if (contract.id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "contract to upsert has no id");
      }
      break;
    case AdminKind::RemoveContract:
      if (contract_id.empty()) {
        return Status::error(StatusCode::InvalidArgument, "contract to remove has no id");
      }
      break;
    case AdminKind::SetPolicy:
    case AdminKind::AdvanceTick:
    case AdminKind::FenceAll:
    case AdminKind::ExpireLeases:
    case AdminKind::Revalidate:
    case AdminKind::Compact:
    case AdminKind::SelfCheck:
    case AdminKind::None:
      break;
  }
  return Status::success();
}

void AdminCommand::encode(ByteWriter& writer) const {
  writer.u16(static_cast<std::uint16_t>(kind));
  writer.text(detail);
  writer.boolean(has_expectation);
  encode_counter(writer, expect_generation);
  encode_member(writer, member);
  encode_id(writer, member_id);
  writer.u8(static_cast<std::uint8_t>(lifecycle));
  encode_path(writer, path);
  encode_id(writer, path_id);
  writer.u8(static_cast<std::uint8_t>(path_state));
  encode_exclusion(writer, exclusion);
  encode_id(writer, exclusion_id);
  encode_obligation(writer, obligation);
  encode_id(writer, obligation_id);
  contract.encode(writer);
  encode_id(writer, contract_id);
  encode_counter(writer, policy);
  encode_counter(writer, tick);
  writer.u16(static_cast<std::uint16_t>(fence_reason));
}

bool AdminCommand::decode(ByteReader& reader, AdminCommand& out) {
  AdminCommand command;
  std::uint16_t kind = 0;
  if (!reader.u16(kind)) return false;
  if (kind > static_cast<std::uint16_t>(AdminKind::SelfCheck)) {
    reader.fail(StatusCode::Corruption, "admin kind out of range");
    return false;
  }
  command.kind = static_cast<AdminKind>(kind);
  if (!reader.text(command.detail, limits::kMaxNoteBytes)) return false;
  if (!is_valid_utf8(command.detail)) {
    reader.fail(StatusCode::Corruption, "admin detail is not valid UTF-8");
    return false;
  }
  if (!reader.boolean(command.has_expectation)) return false;
  if (!decode_counter(reader, command.expect_generation)) return false;
  if (!decode_member(reader, command.member)) return false;
  if (!decode_id(reader, command.member_id)) return false;
  std::uint8_t lifecycle = 0;
  if (!reader.u8(lifecycle)) return false;
  if (lifecycle > static_cast<std::uint8_t>(MemberLifecycle::Removed)) {
    reader.fail(StatusCode::Corruption, "admin lifecycle byte out of range");
    return false;
  }
  command.lifecycle = static_cast<MemberLifecycle>(lifecycle);
  if (!decode_path(reader, command.path)) return false;
  if (!decode_id(reader, command.path_id)) return false;
  std::uint8_t path_state = 0;
  if (!reader.u8(path_state)) return false;
  if (path_state > static_cast<std::uint8_t>(PathState::Unknown)) {
    reader.fail(StatusCode::Corruption, "admin path state byte out of range");
    return false;
  }
  command.path_state = static_cast<PathState>(path_state);
  if (!decode_exclusion(reader, command.exclusion)) return false;
  if (!decode_id(reader, command.exclusion_id)) return false;
  if (!decode_obligation(reader, command.obligation)) return false;
  if (!decode_id(reader, command.obligation_id)) return false;
  if (!CommunicationContract::decode(reader, command.contract)) return false;
  if (!decode_id(reader, command.contract_id)) return false;
  if (!decode_counter(reader, command.policy)) return false;
  if (!decode_counter(reader, command.tick)) return false;
  std::uint16_t fence_reason = 0;
  if (!reader.u16(fence_reason)) return false;
  command.fence_reason = parse_fence_reason(fence_reason);
  out = std::move(command);
  return true;
}

// ---------------------------------------------------------------------------
// AdminResult
// ---------------------------------------------------------------------------
void AdminResult::encode(ByteWriter& writer) const {
  encode_status(writer, Status::error(code, message));
  encode_counter(writer, generation);
  encode_counter(writer, epoch);
  encode_incarnation(writer, incarnation);
  writer.digest(state_digest);
}

bool AdminResult::decode(ByteReader& reader, AdminResult& out) {
  AdminResult result;
  Status status;
  if (!decode_status(reader, status)) return false;
  result.code = status.code();
  result.message = status.message();
  if (!decode_counter(reader, result.generation)) return false;
  if (!decode_counter(reader, result.epoch)) return false;
  if (!decode_incarnation(reader, result.incarnation)) return false;
  if (!reader.digest(result.state_digest)) return false;
  out = std::move(result);
  return true;
}

// ---------------------------------------------------------------------------
// QueryCommand / QueryResult
// ---------------------------------------------------------------------------
Status QueryCommand::validate_shape() const {
  if (kind == QueryKind::None) {
    return Status::error(StatusCode::InvalidArgument, "query kind must be set");
  }
  if (kind == QueryKind::Member && member_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "member query needs a member id");
  }
  if (kind == QueryKind::Path && path_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "path query needs a path id");
  }
  if (kind == QueryKind::Grant && grant_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "grant query needs a grant id");
  }
  if (kind == QueryKind::Attempt && attempt_id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "attempt query needs an attempt id");
  }
  return Status::success();
}

void QueryCommand::encode(ByteWriter& writer) const {
  writer.u16(static_cast<std::uint16_t>(kind));
  encode_id(writer, member_id);
  encode_id(writer, path_id);
  encode_id(writer, grant_id);
  encode_id(writer, attempt_id);
  writer.boolean(include_terminal);
}

bool QueryCommand::decode(ByteReader& reader, QueryCommand& out) {
  QueryCommand command;
  std::uint16_t kind = 0;
  if (!reader.u16(kind)) return false;
  if (kind > static_cast<std::uint16_t>(QueryKind::Version)) {
    reader.fail(StatusCode::Corruption, "query kind out of range");
    return false;
  }
  command.kind = static_cast<QueryKind>(kind);
  if (!decode_id(reader, command.member_id)) return false;
  if (!decode_id(reader, command.path_id)) return false;
  if (!decode_id(reader, command.grant_id)) return false;
  if (!decode_id(reader, command.attempt_id)) return false;
  if (!reader.boolean(command.include_terminal)) return false;
  out = std::move(command);
  return true;
}

void QueryResult::encode(ByteWriter& writer) const {
  encode_status(writer, Status::error(code, message));
  writer.text(text);
  encode_id(writer, cluster_id);
  encode_counter(writer, generation);
  encode_counter(writer, epoch);
  encode_counter(writer, policy);
  encode_incarnation(writer, incarnation);
  writer.digest(state_digest);
  writer.digest(spec_digest);
  writer.digest(topology_digest);
}

bool QueryResult::decode(ByteReader& reader, QueryResult& out) {
  QueryResult result;
  Status status;
  if (!decode_status(reader, status)) return false;
  result.code = status.code();
  result.message = status.message();
  if (!reader.text(result.text, limits::kMaxFramePayloadBytes)) return false;
  if (!is_valid_utf8(result.text)) {
    reader.fail(StatusCode::Corruption, "query text is not valid UTF-8");
    return false;
  }
  if (!decode_id(reader, result.cluster_id)) return false;
  if (!decode_counter(reader, result.generation)) return false;
  if (!decode_counter(reader, result.epoch)) return false;
  if (!decode_counter(reader, result.policy)) return false;
  if (!decode_incarnation(reader, result.incarnation)) return false;
  if (!reader.digest(result.state_digest)) return false;
  if (!reader.digest(result.spec_digest)) return false;
  if (!reader.digest(result.topology_digest)) return false;
  out = std::move(result);
  return true;
}

// ---------------------------------------------------------------------------
// WireMessage
// ---------------------------------------------------------------------------
void WireMessage::encode(ByteWriter& writer) const {
  switch (type) {
    case MessageType::Invalid:
      break;
    case MessageType::Hello:
      writer.text(banner);
      encode_id(writer, client);
      break;
    case MessageType::HelloAck:
      writer.text(banner);
      encode_id(writer, cluster_id);
      encode_counter(writer, cluster_generation);
      encode_counter(writer, epoch);
      encode_counter(writer, policy);
      encode_incarnation(writer, incarnation);
      writer.digest(state_digest);
      break;
    case MessageType::Submit:
      request.encode(writer);
      break;
    case MessageType::Release:
      release.encode(writer);
      break;
    case MessageType::Resolve:
      resolve.encode(writer);
      break;
    case MessageType::Acknowledge:
      acknowledge.encode(writer);
      break;
    case MessageType::Cancel:
      cancel.encode(writer);
      break;
    case MessageType::Decision:
      decision.encode(writer);
      break;
    case MessageType::Admin:
      admin.encode(writer);
      break;
    case MessageType::AdminResult:
      admin_result.encode(writer);
      break;
    case MessageType::Query:
      query.encode(writer);
      break;
    case MessageType::QueryResult:
      query_result.encode(writer);
      break;
    case MessageType::Error:
      writer.text(error_code);
      writer.text(error_message);
      break;
    case MessageType::Ping:
    case MessageType::Pong:
    case MessageType::Bye:
      break;
  }
}

bool WireMessage::decode(ByteReader& reader, WireMessage& out) {
  WireMessage message;
  switch (out.type) {
    case MessageType::Invalid:
      reader.fail(StatusCode::Corruption, "message type INVALID cannot be decoded");
      return false;
    case MessageType::Hello:
      if (!reader.text(message.banner, limits::kMaxIdentifierBytes)) return false;
      if (!decode_id(reader, message.client)) return false;
      break;
    case MessageType::HelloAck:
      if (!reader.text(message.banner, limits::kMaxIdentifierBytes)) return false;
      if (!decode_id(reader, message.cluster_id)) return false;
      if (!decode_counter(reader, message.cluster_generation)) return false;
      if (!decode_counter(reader, message.epoch)) return false;
      if (!decode_counter(reader, message.policy)) return false;
      if (!decode_incarnation(reader, message.incarnation)) return false;
      if (!reader.digest(message.state_digest)) return false;
      break;
    case MessageType::Submit:
      if (!AuthorityRequest::decode(reader, message.request)) return false;
      break;
    case MessageType::Release:
      if (!ReleaseRequest::decode(reader, message.release)) return false;
      break;
    case MessageType::Resolve:
      if (!ResolveRequest::decode(reader, message.resolve)) return false;
      break;
    case MessageType::Acknowledge:
      if (!AcknowledgeRequest::decode(reader, message.acknowledge)) return false;
      break;
    case MessageType::Cancel:
      if (!CancelRequest::decode(reader, message.cancel)) return false;
      break;
    case MessageType::Decision:
      if (!AuthorityDecision::decode(reader, message.decision)) return false;
      break;
    case MessageType::Admin:
      if (!AdminCommand::decode(reader, message.admin)) return false;
      break;
    case MessageType::AdminResult:
      if (!AdminResult::decode(reader, message.admin_result)) return false;
      break;
    case MessageType::Query:
      if (!QueryCommand::decode(reader, message.query)) return false;
      break;
    case MessageType::QueryResult:
      if (!QueryResult::decode(reader, message.query_result)) return false;
      break;
    case MessageType::Error:
      if (!reader.text(message.error_code, limits::kMaxIdentifierBytes)) return false;
      if (!reader.text(message.error_message, limits::kMaxNoteBytes)) return false;
      break;
    case MessageType::Ping:
    case MessageType::Pong:
    case MessageType::Bye:
      break;
  }
  message.type = out.type;
  message.flags = out.flags;
  message.sequence = out.sequence;
  out = std::move(message);
  return true;
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------
Status encode_frame(const Frame& frame, Bytes& out) {
  const Bytes& payload = frame.payload;
  if (payload.size() > limits::kMaxFramePayloadBytes) {
    return Status::error(StatusCode::LimitExceeded,
                         "frame payload of " + std::to_string(payload.size()) +
                             " bytes exceeds the configured bound");
  }

  Bytes header;
  ByteWriter header_writer(header);
  header_writer.u32(Frame::kMagic);
  header_writer.u16(static_cast<std::uint16_t>(CIF_WIRE_PROTOCOL_VERSION));
  header_writer.u16(static_cast<std::uint16_t>(frame.type));
  header_writer.u32(frame.flags);
  header_writer.u64(frame.sequence);
  header_writer.u32(static_cast<std::uint32_t>(payload.size()));
  header_writer.u32(0);  // reserved; covered by the header CRC so it is not a
                         // free channel for smuggling bytes past the checks
  const std::uint32_t header_crc =
      crc32c(std::span<const std::uint8_t>(header.data(), header.size()));
  header_writer.u32(header_crc);
  if (header.size() != kHeaderSize) {
    return Status::error(StatusCode::Internal, "frame header size mismatch");
  }

  Bytes trailer;
  ByteWriter trailer_writer(trailer);
  trailer_writer.u32(crc32c(payload));

  out.clear();
  out.reserve(kHeaderSize + payload.size() + kTrailerSize);
  out.insert(out.end(), header.begin(), header.end());
  out.insert(out.end(), payload.begin(), payload.end());
  out.insert(out.end(), trailer.begin(), trailer.end());
  return Status::success();
}

Status frame_size(std::span<const std::uint8_t> buffer, std::size_t& out_size) {
  out_size = 0;
  if (buffer.size() < kHeaderSize) {
    return Status::error(StatusCode::Truncated, "frame header is incomplete");
  }
  ByteReader reader(buffer);
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t type = 0;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;
  std::uint32_t payload_length = 0;
  std::uint32_t reserved = 0;
  std::uint32_t header_crc = 0;
  static_cast<void>(reader.u32(magic));
  static_cast<void>(reader.u16(version));
  static_cast<void>(reader.u16(type));
  static_cast<void>(reader.u32(flags));
  static_cast<void>(reader.u64(sequence));
  static_cast<void>(reader.u32(payload_length));
  static_cast<void>(reader.u32(reserved));
  static_cast<void>(reader.u32(header_crc));

  if (magic != Frame::kMagic) {
    return Status::error(StatusCode::Corruption, "frame magic does not match");
  }
  if (header_crc != crc32c(buffer.subspan(0, 28))) {
    return Status::error(StatusCode::IntegrityFailure, "frame header failed its integrity check");
  }
  if (payload_length > limits::kMaxFramePayloadBytes) {
    return Status::error(StatusCode::LimitExceeded,
                         "peer declared a frame payload of " + std::to_string(payload_length) +
                             " bytes, above the configured bound");
  }
  const std::size_t total = kHeaderSize + static_cast<std::size_t>(payload_length) + kTrailerSize;
  if (buffer.size() < total) {
    return Status::error(StatusCode::Truncated, "frame payload is incomplete");
  }
  out_size = total;
  return Status::success();
}

Status decode_frame(std::span<const std::uint8_t> buffer, Frame& out) {
  std::size_t total = 0;
  CIF_TRY(frame_size(buffer, total));
  ByteReader reader(buffer);
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t type = 0;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;
  std::uint32_t payload_length = 0;
  std::uint32_t reserved = 0;
  std::uint32_t header_crc = 0;
  static_cast<void>(reader.u32(magic));
  static_cast<void>(reader.u16(version));
  static_cast<void>(reader.u16(type));
  static_cast<void>(reader.u32(flags));
  static_cast<void>(reader.u64(sequence));
  static_cast<void>(reader.u32(payload_length));
  static_cast<void>(reader.u32(reserved));
  static_cast<void>(reader.u32(header_crc));

  if (version != CIF_WIRE_PROTOCOL_VERSION) {
    return Status::error(StatusCode::VersionMismatch,
                         "peer speaks wire protocol version " + std::to_string(version) +
                             "; this build speaks " +
                             std::to_string(CIF_WIRE_PROTOCOL_VERSION));
  }
  if (type > static_cast<std::uint16_t>(MessageType::Bye)) {
    return Status::error(StatusCode::Corruption,
                         "message type " + std::to_string(type) + " is not a known type");
  }
  std::span<const std::uint8_t> payload;
  if (!reader.raw(payload_length, payload)) {
    return Status::error(StatusCode::Truncated, "frame payload is short");
  }
  std::uint32_t payload_crc = 0;
  if (!reader.u32(payload_crc)) {
    return Status::error(StatusCode::Truncated, "frame trailer is short");
  }
  if (payload_crc != crc32c(payload)) {
    return Status::error(StatusCode::IntegrityFailure, "frame payload failed its integrity check");
  }
  if (!reader.at_end()) {
    return Status::error(StatusCode::Corruption, "frame has trailing bytes past its declared size");
  }
  out.type = static_cast<MessageType>(type);
  out.flags = flags;
  out.sequence = sequence;
  out.payload.assign(payload.begin(), payload.end());
  return Status::success();
}

Status pack_message(const WireMessage& message, Frame& out) {
  Frame frame;
  frame.type = message.type;
  frame.flags = message.flags;
  frame.sequence = message.sequence;
  ByteWriter writer(frame.payload);
  message.encode(writer);
  if (frame.payload.size() > limits::kMaxFramePayloadBytes) {
    return Status::error(StatusCode::LimitExceeded,
                         "message of " + std::to_string(frame.payload.size()) +
                             " bytes exceeds the configured frame bound");
  }
  out = std::move(frame);
  return Status::success();
}

Status unpack_message(const Frame& frame, WireMessage& out) {
  WireMessage message;
  message.type = frame.type;
  message.flags = frame.flags;
  message.sequence = frame.sequence;
  ByteReader reader(std::span<const std::uint8_t>(frame.payload.data(), frame.payload.size()));
  if (!WireMessage::decode(reader, message)) {
    // Preserve the *typed* failure: a decode that ran out of bytes is
    // TRUNCATED, one that declared too much is CAPACITY_EXHAUSTED, and only a
    // structurally impossible payload is CORRUPTION. Collapsing them would
    // destroy exactly the information an operator needs.
    const Status& failure = reader.failure();
    return Status::error(failure.ok() ? StatusCode::Corruption : failure.code(),
                         std::string("cannot decode ") + to_string(frame.type) +
                             " message: " + failure.to_string());
  }
  if (!reader.at_end()) {
    return Status::error(StatusCode::Corruption,
                         std::string(to_string(frame.type)) + " message has " +
                             std::to_string(reader.remaining()) + " trailing bytes");
  }
  out = std::move(message);
  return Status::success();
}

WireMessage make_error_message(std::string code, std::string text) {
  WireMessage message;
  message.type = MessageType::Error;
  message.error_code = std::move(code);
  message.error_message = std::move(text);
  return message;
}

}  // namespace cif
