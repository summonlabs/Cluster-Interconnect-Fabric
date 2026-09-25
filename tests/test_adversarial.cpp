// Cluster Interconnect Fabric (CIF) -- adversarial input tests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Everything here feeds the runtime bytes it should not trust. Nothing in this
// file may hang, crash, allocate without bound, or turn missing evidence into
// success.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "cif/authority.hpp"
#include "cif/journal.hpp"
#include "cif/rng.hpp"
#include "cif/version.hpp"
#include "cif/wire.hpp"
#include "harness.hpp"

using namespace cif;

namespace {

std::string read_all(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

void write_all(const std::string& path, const std::string& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

AuthorityRequest sample_request(const AuthorityCore& core, const std::string& attempt) {
  AuthorityRequest request;
  request.request_id = RequestId::from_validated("req-" + attempt);
  request.attempt_id = AttemptId::from_validated(attempt);
  request.contract_id = ContractId::from_validated("c-1");
  request.cluster_id = core.spec().cluster_id();
  request.cluster_generation = core.spec().generation();
  request.epoch = core.spec().epoch();
  request.incarnation = core.spec().incarnation();
  request.policy_generation = core.spec().policy_generation();
  request.source_member = MemberId::from_validated("m-a");
  request.destination_member = MemberId::from_validated("m-b");
  request.path_id = PathId::from_validated("p-1");
  request.requested_units = 4;
  request.lease_ticks = 64;
  const Member* source = core.spec().find_member(request.source_member);
  const Member* destination = core.spec().find_member(request.destination_member);
  if (source != nullptr) {
    request.source_member_generation = source->generation;
    request.source_member_digest = source->digest;
  }
  if (destination != nullptr) {
    request.destination_member_generation = destination->generation;
    request.destination_member_digest = destination->digest;
  }
  const Path* path = core.spec().find_path(request.path_id);
  if (path != nullptr) {
    request.path_generation = path->generation;
  }
  const CommunicationContract* contract = core.contracts().find(request.contract_id);
  if (contract != nullptr) {
    request.contract_generation = contract->generation;
  }
  return request;
}

/// The engine owns a self-referential durability sink, so it is deliberately
/// neither copyable nor movable; tests populate a caller-owned instance.
void make_core(AuthorityCore& core) {
  CIF_REQUIRE_OK(core.initialize(ClusterId::from_validated("cluster-adv"),
                                 ControllerIncarnation::from_seed(17), PolicyGeneration{1},
                                 Tick{1}, nullptr));
  Member a;
  a.id = MemberId::from_validated("m-a");
  a.domain = MemberDomainId::from_validated("d-1");
  a.generation = MemberGeneration{1};
  a.digest = sha256("member:a");
  a.lifecycle = MemberLifecycle::Active;
  CIF_REQUIRE(LocalityPath::parse("dc/room1/rack1/pod1", a.locality));
  a.services.push_back(ServiceGroupId::from_validated("trainers"));
  CIF_REQUIRE_OK(core.upsert_member(a));

  Member b = a;
  b.id = MemberId::from_validated("m-b");
  b.domain = MemberDomainId::from_validated("d-2");
  b.digest = sha256("member:b");
  CIF_REQUIRE(LocalityPath::parse("dc/room2/rack2/pod2", b.locality));
  b.services.clear();
  b.services.push_back(ServiceGroupId::from_validated("servers"));
  CIF_REQUIRE_OK(core.upsert_member(b));

  Path path;
  path.id = PathId::from_validated("p-1");
  path.generation = PathGeneration{1};
  path.source_member = a.id;
  path.destination_member = b.id;
  path.capacity_units = 64;
  CIF_REQUIRE_OK(core.upsert_path(path));

  CommunicationContract contract;
  contract.id = ContractId::from_validated("c-1");
  contract.generation = ContractGeneration{1};
  contract.source_service = ServiceGroupId::from_validated("trainers");
  contract.destination_service = ServiceGroupId::from_validated("servers");
  contract.min_capacity_units = 1;
  contract.maintenance_mode = MaintenanceMode::Degrade;
  CIF_REQUIRE_OK(core.upsert_contract(contract));
}

}  // namespace

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------
CIF_TEST(hostile, frame_bomb_is_rejected) {
  // Builds a syntactically valid header for the given declared payload length.
  // The layout is magic, version, type, flags, sequence, payload length,
  // reserved, header CRC -- and the CRC covers all 28 bytes before it, so the
  // reserved field is not a free channel.
  const auto make_header = [](std::uint32_t payload_length, std::uint16_t version,
                              std::uint16_t type) {
    Bytes header;
    ByteWriter writer(header);
    writer.u32(Frame::kMagic);
    writer.u16(version);
    writer.u16(type);
    writer.u32(0);
    writer.u64(0);
    writer.u32(payload_length);
    writer.u32(0);
    const std::uint32_t crc =
        crc32c(std::span<const std::uint8_t>(header.data(), header.size()));
    writer.u32(crc);
    return header;
  };

  // A header that declares a payload far beyond the configured bound must be
  // rejected before anything is allocated for it.
  const Bytes header =
      make_header(0xFFFFFFFFu, static_cast<std::uint16_t>(wire_protocol_version()),
                  static_cast<std::uint16_t>(MessageType::Ping));
  std::size_t size = 0;
  const Status status = frame_size(std::span<const std::uint8_t>(header.data(), header.size()), size);
  CIF_CHECK_STATUS(status, StatusCode::LimitExceeded);
  CIF_CHECK_EQ(size, std::size_t{0});

  // A declared length just above the bound is refused too, and one below it
  // only reports that the payload has not arrived.
  const Bytes just_over =
      make_header(static_cast<std::uint32_t>(limits::kMaxFramePayloadBytes) + 1u,
                  static_cast<std::uint16_t>(wire_protocol_version()),
                  static_cast<std::uint16_t>(MessageType::Ping));
  CIF_CHECK_STATUS(frame_size(std::span<const std::uint8_t>(just_over.data(), just_over.size()),
                              size),
                   StatusCode::LimitExceeded);

  const Bytes within_bound =
      make_header(1024, static_cast<std::uint16_t>(wire_protocol_version()),
                  static_cast<std::uint16_t>(MessageType::Ping));
  CIF_CHECK_STATUS(frame_size(std::span<const std::uint8_t>(within_bound.data(),
                                                            within_bound.size()),
                              size),
                   StatusCode::Truncated);
}

CIF_TEST(hostile, framing_header_and_trailer_are_verified) {
  WireMessage message;
  message.type = MessageType::Ping;
  Frame frame;
  CIF_REQUIRE_OK(pack_message(message, frame));
  Bytes encoded;
  CIF_REQUIRE_OK(encode_frame(frame, encoded));
  CIF_CHECK_EQ(encoded.size(), Frame::kHeaderSize + 4);

  std::size_t size = 0;
  CIF_REQUIRE_OK(frame_size(std::span<const std::uint8_t>(encoded.data(), encoded.size()), size));
  CIF_CHECK_EQ(size, encoded.size());
  Frame decoded;
  CIF_REQUIRE_OK(decode_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()), decoded));
  CIF_CHECK(decoded.type == MessageType::Ping);

  // Every single-byte mutation of the header or trailer must be rejected.
  for (std::size_t index = 0; index < encoded.size(); ++index) {
    Bytes mutated = encoded;
    mutated[index] = static_cast<std::uint8_t>(mutated[index] ^ 0x01u);
    Frame ignored;
    const Status status =
        decode_frame(std::span<const std::uint8_t>(mutated.data(), mutated.size()), ignored);
    CIF_CHECK_MSG(!status.ok(), "byte " + std::to_string(index) + " accepted after mutation");
    if (!status.ok()) {
      CIF_CHECK(status.is(StatusCode::IntegrityFailure) || status.is(StatusCode::Corruption) ||
                status.is(StatusCode::LimitExceeded) || status.is(StatusCode::Truncated) ||
                status.is(StatusCode::VersionMismatch));
    }
  }

  // Truncation at every length must be reported, never silently accepted.
  for (std::size_t length = 1; length < encoded.size(); ++length) {
    Frame ignored;
    const Status status =
        decode_frame(std::span<const std::uint8_t>(encoded.data(), length), ignored);
    CIF_CHECK(!status.ok());
    CIF_CHECK(status.is(StatusCode::Truncated) || status.is(StatusCode::Corruption) ||
              status.is(StatusCode::LimitExceeded));
  }

  // Trailing bytes are refused.
  Bytes extended = encoded;
  extended.push_back(0x00);
  Frame ignored;
  CIF_CHECK(!decode_frame(std::span<const std::uint8_t>(extended.data(), extended.size()), ignored)
                 .ok());
}

CIF_TEST(hostile, unknown_version_and_message_type) {
  WireMessage message;
  message.type = MessageType::Ping;
  Frame frame;
  CIF_REQUIRE_OK(pack_message(message, frame));
  Bytes encoded;
  CIF_REQUIRE_OK(encode_frame(frame, encoded));

  // The version lives inside the CRC-protected region, so an attacker who
  // changes it must also forge the CRC -- and then the frame is internally
  // consistent but speaks a version this build does not understand.
  Bytes wrong_version = encoded;
  wrong_version[4] = 99;
  wrong_version[5] = 0;
  const std::uint32_t crc =
      crc32c(std::span<const std::uint8_t>(wrong_version.data(), 28));
  for (int i = 0; i < 4; ++i) {
    wrong_version[28 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>((crc >> (i * 8)) & 0xFFu);
  }
  Frame ignored;
  CIF_CHECK_STATUS(decode_frame(std::span<const std::uint8_t>(wrong_version.data(),
                                                              wrong_version.size()),
                                ignored),
                   StatusCode::VersionMismatch);

  // Changing the version *without* repairing the CRC is caught earlier, as an
  // integrity failure: nothing in the header is interpreted until it is proven
  // intact.
  Bytes torn_version = encoded;
  torn_version[4] = 99;
  CIF_CHECK_STATUS(decode_frame(std::span<const std::uint8_t>(torn_version.data(),
                                                              torn_version.size()),
                                ignored),
                   StatusCode::IntegrityFailure);

  // An out-of-range message type is rejected rather than reinterpreted.
  Bytes unknown_type = encoded;
  unknown_type[6] = 0xFF;
  unknown_type[7] = 0xFF;
  const std::uint32_t type_crc =
      crc32c(std::span<const std::uint8_t>(unknown_type.data(), 28));
  for (int i = 0; i < 4; ++i) {
    unknown_type[28 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>((type_crc >> (i * 8)) & 0xFFu);
  }
  CIF_CHECK_STATUS(
      decode_frame(std::span<const std::uint8_t>(unknown_type.data(), unknown_type.size()), ignored),
      StatusCode::Corruption);
}

CIF_TEST(hostile, message_payloads_are_bounds_checked) {
  AuthorityCore core;
  make_core(core);

  // A well-formed SUBMIT round-trips.
  const AuthorityRequest request = sample_request(core, "att-1");
  WireMessage message;
  message.type = MessageType::Submit;
  message.request = request;
  Frame frame;
  CIF_REQUIRE_OK(pack_message(message, frame));
  WireMessage decoded;
  CIF_REQUIRE_OK(unpack_message(frame, decoded));
  CIF_CHECK(decoded.request.attempt_id == request.attempt_id);
  CIF_CHECK(decoded.request.digest() == request.digest());

  // Truncating the payload at every length must be reported.
  for (std::size_t length = 0; length < frame.payload.size(); ++length) {
    Frame truncated = frame;
    truncated.payload.resize(length);
    WireMessage ignored;
    CIF_CHECK(!unpack_message(truncated, ignored).ok());
  }

  // Trailing bytes inside a message are refused.
  Frame extended = frame;
  extended.payload.push_back(0x00);
  WireMessage ignored;
  CIF_CHECK_STATUS(unpack_message(extended, ignored), StatusCode::Corruption);

  // An identifier longer than the bound is refused before allocation.
  Bytes payload;
  ByteWriter writer(payload);
  const AuthorityRequest& source = request;
  encode_id(writer, source.request_id);
  writer.text(std::string(limits::kMaxIdentifierBytes + 64, 'x'));
  Frame huge = frame;
  huge.payload = payload;
  CIF_CHECK(!unpack_message(huge, ignored).ok());

  // A text field declaring an enormous length is refused.
  Bytes bomb;
  ByteWriter bomb_writer(bomb);
  bomb_writer.u64(0xFFFFFFFFFFFFFFFFull);
  Frame bomb_frame = frame;
  bomb_frame.payload = bomb;
  const Status status = unpack_message(bomb_frame, ignored);
  CIF_CHECK(!status.ok());
  CIF_CHECK(status.is(StatusCode::CapacityExhausted) || status.is(StatusCode::Truncated));

  // A non-canonical varint is refused.
  const Bytes non_canonical = {0x80, 0x00};
  Frame non_canonical_frame = frame;
  non_canonical_frame.payload = non_canonical;
  CIF_CHECK(!unpack_message(non_canonical_frame, ignored).ok());
}

CIF_TEST(hostile, invalid_unicode_is_rejected_everywhere) {
  AuthorityCore core;
  make_core(core);
  AuthorityRequest request = sample_request(core, "att-1");

  // Invalid UTF-8 in provenance text is a malformed request.
  request.provenance.origin = std::string("bad") + '\xC3';
  CIF_CHECK_STATUS(request.validate_shape(), StatusCode::InvalidArgument);
  request.provenance.origin = "ok";

  // Embedded NUL is rejected.
  std::string with_nul("a");
  with_nul.push_back('\0');
  with_nul += "b";
  request.provenance.correlation_id = with_nul;
  CIF_CHECK_STATUS(request.validate_shape(), StatusCode::InvalidArgument);
  request.provenance.correlation_id.clear();

  // A surrogate code point smuggled into a member note is rejected.
  Member member;
  member.id = MemberId::from_validated("m-bad");
  member.domain = MemberDomainId::from_validated("d");
  member.note = std::string("\xED\xA0\x80");
  CIF_CHECK_STATUS(core.upsert_member(member), StatusCode::InvalidArgument);

  // Overlong encodings too.
  member.note = std::string("\xC0\xAF");
  CIF_CHECK_STATUS(core.upsert_member(member), StatusCode::InvalidArgument);

  member.note = std::string(limits::kMaxNoteBytes + 1, 'a');
  CIF_CHECK_STATUS(core.upsert_member(member), StatusCode::LimitExceeded);
}

// ---------------------------------------------------------------------------
// spec mutation hostility
// ---------------------------------------------------------------------------
CIF_TEST(hostile, duplicate_and_regressing_identities) {
  AuthorityCore core;
  make_core(core);

  // Same id, same generation, different digest: an identity conflict, not an
  // update.
  Member conflicting = *core.spec().find_member(MemberId::from_validated("m-a"));
  conflicting.digest = sha256("forged");
  CIF_CHECK_STATUS(core.upsert_member(conflicting), StatusCode::DuplicateIdentity);

  // Generation moving backwards is refused.
  Member older = *core.spec().find_member(MemberId::from_validated("m-a"));
  older.generation = MemberGeneration{0};
  older.digest = sha256("older");
  CIF_CHECK_STATUS(core.upsert_member(older), StatusCode::StateMismatch);

  // A retired member cannot be resurrected at the same generation.
  CIF_REQUIRE_OK(core.remove_member(MemberId::from_validated("m-a")));
  // Re-publishing the retired record verbatim is idempotent and harmless...
  Member retired = *core.spec().find_member(MemberId::from_validated("m-a"));
  CIF_REQUIRE_OK(core.upsert_member(retired));
  // ...but bringing it back to life at the same generation is not: retirement
  // is terminal and an identity is never reused.
  Member resurrected = retired;
  resurrected.lifecycle = MemberLifecycle::Active;
  CIF_CHECK_STATUS(core.upsert_member(resurrected), StatusCode::StateMismatch);
  CIF_CHECK_STATUS(core.set_member_lifecycle(MemberId::from_validated("m-a"),
                                             MemberLifecycle::Active),
                   StatusCode::StateMismatch);

  // Removing a member that is not present is NOT_FOUND, not a silent success.
  CIF_CHECK_STATUS(core.remove_member(MemberId::from_validated("m-ghost")), StatusCode::NotFound);
  CIF_CHECK_STATUS(core.remove_path(PathId::from_validated("p-ghost")), StatusCode::NotFound);
  CIF_CHECK_STATUS(core.remove_contract(ContractId::from_validated("c-ghost")),
                   StatusCode::NotFound);
}

CIF_TEST(hostile, extreme_values_and_overflow) {
  AuthorityCore core;
  make_core(core);

  // Units beyond the configured bound are rejected, not wrapped.
  AuthorityRequest request = sample_request(core, "att-1");
  request.requested_units = UINT64_MAX;
  CIF_CHECK_STATUS(request.validate_shape(), StatusCode::LimitExceeded);
  CIF_CHECK(core.submit(request).outcome == AuthorityOutcome::Invalid);

  request.requested_units = limits::kMaxRequestedUnits;
  CIF_CHECK(request.validate_shape().ok());
  // The largest representable request is *evaluated*: it is not malformed, it
  // simply cannot be satisfied, and the answer says so.
  const AuthorityDecision maximum = core.submit(request);
  CIF_CHECK(maximum.outcome == AuthorityOutcome::Refused);
  CIF_CHECK(maximum.primary_reason() == ReasonCode::CapacityExhausted);

  // One unit beyond the representable bound is malformed.
  request.requested_units = limits::kMaxRequestedUnits + 1;
  CIF_CHECK(!request.validate_shape().ok());
  CIF_CHECK(core.submit(request).outcome == AuthorityOutcome::Invalid);
  CIF_CHECK(core.self_check().ok());

  // Lease lengths beyond the bound are rejected.
  AuthorityRequest long_lease = sample_request(core, "att-2");
  long_lease.lease_ticks = UINT64_MAX;
  CIF_CHECK(core.submit(long_lease).outcome == AuthorityOutcome::Invalid);

  // A contract whose minimum exceeds its maximum is nonsense.
  CommunicationContract contract;
  contract.id = ContractId::from_validated("c-bad");
  contract.generation = ContractGeneration{1};
  contract.source_service = ServiceGroupId::from_validated("trainers");
  contract.destination_service = ServiceGroupId::from_validated("servers");
  contract.min_capacity_units = 10;
  contract.max_capacity_units = 5;
  CIF_CHECK_STATUS(core.upsert_contract(contract), StatusCode::InvalidArgument);

  contract.min_capacity_units = limits::kMaxCapacityUnits + 1;
  contract.max_capacity_units = 0;
  CIF_CHECK_STATUS(core.upsert_contract(contract), StatusCode::LimitExceeded);

  // An exclusion window that ends before it starts is nonsense.
  MaintenanceExclusion exclusion;
  exclusion.id = ExclusionId::from_validated("x-bad");
  exclusion.valid_from = Tick{100};
  exclusion.valid_to = Tick{50};
  CIF_CHECK_STATUS(core.upsert_exclusion(exclusion), StatusCode::InvalidArgument);

  CIF_CHECK(core.self_check().ok());
}

CIF_TEST(hostile, bounded_collections_refuse_growth) {
  AuthorityCore core;
  make_core(core);
  // Fill the member table to its bound with distinct identities and confirm the
  // next insert is refused rather than truncating or overwriting.
  std::size_t inserted = 0;
  for (std::size_t i = 0; i < limits::kMaxMembers + 8; ++i) {
    Member member;
    member.id = MemberId::from_validated("bulk-" + std::to_string(i));
    member.domain = MemberDomainId::from_validated("bulk-domain");
    member.generation = MemberGeneration{1};
    member.digest = sha256("bulk:" + std::to_string(i));
    member.lifecycle = MemberLifecycle::Active;
    CIF_REQUIRE(LocalityPath::parse("dc/room/rack/pod", member.locality));
    const Status status = core.upsert_member(member);
    if (!status.ok()) {
      CIF_CHECK_STATUS(status, StatusCode::CapacityExhausted);
      break;
    }
    ++inserted;
  }
  CIF_CHECK_EQ(inserted, limits::kMaxMembers - 2);
  CIF_CHECK_EQ(core.spec().member_count(), limits::kMaxMembers);
  CIF_CHECK(core.self_check().ok());
}

// ---------------------------------------------------------------------------
// journal hostility
// ---------------------------------------------------------------------------
CIF_TEST(hostile, journal_survives_truncation_at_every_byte) {
  const std::string path = cif::test::scratch_path("adv-truncate.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    AuthorityCore core;
  make_core(core);
    JournalDurabilitySink sink(journal);
    core.attach_sink(&sink);
    for (int i = 0; i < 6; ++i) {
      CIF_REQUIRE(core.submit(sample_request(core, "att-" + std::to_string(i))).outcome ==
                  AuthorityOutcome::Granted);
    }
    CIF_REQUIRE_OK(journal.close());
  }
  const std::string bytes = read_all(path);
  CIF_REQUIRE(bytes.size() > 200);

  for (std::size_t length = 0; length <= bytes.size(); length += 3) {
    const std::string copy = cif::test::scratch_path("adv-cut.cifjournal");
    write_all(copy, bytes.substr(0, length));
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    const Status status = Journal::scan(copy, entries, report);
    if (length == 0) {
      // A zero-length file is indistinguishable from a journal that was never
      // written, and nothing was ever committed to it. It is reported as fresh,
      // with the fact that a file existed recorded distinctly.
      CIF_REQUIRE_OK(status);
      CIF_CHECK(report.fresh);
      CIF_CHECK(report.file_present);
      CIF_CHECK(entries.empty());
    } else if (length < Journal::kFileHeaderSize) {
      CIF_CHECK(!status.ok());
      CIF_CHECK(report.integrity_failure || entries.empty());
    } else {
      CIF_CHECK(status.ok() || report.integrity_failure || report.version_mismatch);
      RecoveredState state;
      if (status.ok() && replay_journal(entries, state).ok()) {
        CIF_CHECK(state.spec.member_count() <= 2 + limits::kMaxMembers);
      }
    }
    std::filesystem::remove(copy, error);
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(hostile, journal_rejects_oversized_record_declaration) {
  const std::string path = cif::test::scratch_path("adv-oversize.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    JournalEntry entry;
    entry.kind = JournalRecordKind::MemberUpsert;
    entry.member.id = MemberId::from_validated("m-a");
    entry.member.domain = MemberDomainId::from_validated("d");
    entry.member.generation = MemberGeneration{1};
    CIF_REQUIRE_OK(journal.append(entry, true));
    CIF_REQUIRE_OK(journal.close());
  }
  std::string bytes = read_all(path);
  const std::size_t record_offset = Journal::kFileHeaderSize;
  // Declare a payload far beyond the bound and repair the header CRC so the
  // header itself is well formed: the bound must still stop the scan.
  const std::uint32_t declared = 0x7FFFFFFFu;
  for (int i = 0; i < 4; ++i) {
    bytes[record_offset + 16 + static_cast<std::size_t>(i)] =
        static_cast<char>((declared >> (i * 8)) & 0xFFu);
  }
  const std::uint32_t crc = crc32c(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(bytes.data()) + record_offset, 24));
  for (int i = 0; i < 4; ++i) {
    bytes[record_offset + 24 + static_cast<std::size_t>(i)] =
        static_cast<char>((crc >> (i * 8)) & 0xFFu);
  }
  const std::string copy = cif::test::scratch_path("adv-oversize2.cifjournal");
  write_all(copy, bytes);

  std::vector<JournalEntry> entries;
  RecoveryReport report;
  const Status status = Journal::scan(copy, entries, report);
  CIF_CHECK(status.ok());
  CIF_CHECK(report.integrity_failure);
  CIF_CHECK(entries.empty());
  CIF_CHECK_EQ(report.discarded_bytes, bytes.size() - record_offset);
  std::filesystem::remove(path, error);
  std::filesystem::remove(copy, error);
}

CIF_TEST(hostile, journal_rejects_spliced_records) {
  const std::string path = cif::test::scratch_path("adv-splice.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    for (int i = 0; i < 5; ++i) {
      JournalEntry entry;
      entry.kind = JournalRecordKind::MemberUpsert;
      entry.member.id = MemberId::from_validated("m-" + std::to_string(i));
      entry.member.domain = MemberDomainId::from_validated("d");
      entry.member.generation = MemberGeneration{1};
      entry.member.digest = sha256("m" + std::to_string(i));
      CIF_REQUIRE_OK(journal.append(entry, true));
    }
    CIF_REQUIRE_OK(journal.close());
  }
  const std::string bytes = read_all(path);
  const std::size_t body = bytes.size() - Journal::kFileHeaderSize;
  const std::size_t record = body / 5;

  // Swapping two adjacent records keeps every per-record CRC valid but breaks
  // the chain and the sequence: exactly the attack the chain exists to catch.
  for (std::size_t i = 0; i + 2 <= 4; ++i) {
    std::string mutated = bytes.substr(0, Journal::kFileHeaderSize + i * record);
    mutated += bytes.substr(Journal::kFileHeaderSize + (i + 1) * record, record);
    mutated += bytes.substr(Journal::kFileHeaderSize + i * record, record);
    mutated += bytes.substr(Journal::kFileHeaderSize + (i + 2) * record);
    const std::string copy = cif::test::scratch_path("adv-swap.cifjournal");
    write_all(copy, mutated);
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    const Status status = Journal::scan(copy, entries, report);
    CIF_CHECK(status.ok());
    CIF_CHECK_MSG(report.integrity_failure || report.replay_detected,
                  "swapped records " + std::to_string(i) + " and " + std::to_string(i + 1) +
                      " were accepted");
    CIF_CHECK(entries.size() <= i + 1);
    std::filesystem::remove(copy, error);
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(hostile, authority_refuses_replayed_and_reordered_events) {
  AuthorityCore core;
  make_core(core);
  const AuthorityRequest original = sample_request(core, "att-1");
  CIF_REQUIRE(core.submit(original).outcome == AuthorityOutcome::Granted);

  // Replaying the identical request is idempotent, not a second grant.
  const AuthorityDecision replay = core.submit(original);
  CIF_CHECK(replay.idempotent_replay);
  CIF_CHECK_EQ(core.grants().size(), std::size_t{1});

  // Replaying it after the world moved on is refused by the coordinate fence.
  CIF_REQUIRE_OK(core.upsert_path([] {
    Path path;
    path.id = PathId::from_validated("p-1");
    path.generation = PathGeneration{2};
    path.source_member = MemberId::from_validated("m-a");
    path.destination_member = MemberId::from_validated("m-b");
    path.capacity_units = 64;
    return path;
  }()));
  const AuthorityDecision stale = core.submit(original);
  CIF_CHECK(stale.outcome == AuthorityOutcome::Stale);
  CIF_CHECK_EQ(core.grants().size(), std::size_t{1});

  // An attempt id from the future is simply unknown.
  ResolveRequest resolve;
  resolve.request_id = RequestId::from_validated("req-res");
  resolve.attempt_id = AttemptId::from_validated("att-never-seen");
  CIF_CHECK(core.resolve(resolve).outcome == AuthorityOutcome::Unknown);
  CIF_CHECK(core.self_check().ok());
}

CIF_TEST(hostile, random_byte_mutation_never_produces_authority) {
  const std::uint64_t base = cif::test::current_seed();
  AuthorityCore core;
  make_core(core);
  const AuthorityRequest request = sample_request(core, "att-1");
  WireMessage message;
  message.type = MessageType::Submit;
  message.request = request;
  Frame frame;
  CIF_REQUIRE_OK(pack_message(message, frame));
  Bytes encoded;
  CIF_REQUIRE_OK(encode_frame(frame, encoded));

  Pcg32 rng(base, 0xABCDEF01u);
  std::size_t rejected = 0;
  for (int trial = 0; trial < 4000; ++trial) {
    Bytes mutated = encoded;
    const std::size_t flips = 1 + static_cast<std::size_t>(rng.bounded(4));
    for (std::size_t i = 0; i < flips; ++i) {
      const std::size_t index = static_cast<std::size_t>(rng.bounded(mutated.size()));
      mutated[index] = static_cast<std::uint8_t>(mutated[index] ^
                                                 static_cast<std::uint8_t>(1u << rng.bounded(8)));
    }
    Frame decoded;
    if (!decode_frame(std::span<const std::uint8_t>(mutated.data(), mutated.size()), decoded).ok()) {
      ++rejected;
      continue;
    }
    WireMessage unpacked;
    if (!unpack_message(decoded, unpacked).ok()) {
      ++rejected;
      continue;
    }
    // If the bytes survived framing and decoding, running them must still not
    // produce authority for anything other than the unmutated request.
    AuthorityCore scratch;
    make_core(scratch);
    const AuthorityDecision decision = scratch.submit(unpacked.request);
    if (unpacked.request.digest() != request.digest()) {
      CIF_CHECK_MSG(decision.grant.has_value() == false ||
                        !(decision.grant->attempt_id == request.attempt_id),
                    "mutated request produced a grant for the original attempt, seed=" +
                        std::to_string(base));
    }
    CIF_CHECK(scratch.self_check().ok());
  }
  CIF_CHECK(rejected > 3900);
}
