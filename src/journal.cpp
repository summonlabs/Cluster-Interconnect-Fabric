#include "cif/journal.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "cif/version.hpp"
#include "cif/platform.hpp"

namespace cif {
namespace {

constexpr char kFileMagic[8] = {'C', 'I', 'F', 'J', 'N', 'L', '0', '1'};
constexpr std::uint32_t kRecordMagic = 0x52464943u;  // 'C','I','F','R' little-endian
constexpr std::uint16_t kRecordFormatVersion = 1;

/// A journal larger than this is not scanned: the runtime reports it rather
/// than allocating for it.
constexpr std::uint64_t kMaxScanBytes =
    limits::kMaxJournalBytes + limits::kMaxJournalRecordBytes + 4096u;

[[nodiscard]] bool is_known_kind(std::uint16_t raw) noexcept {
  return raw >= static_cast<std::uint16_t>(JournalRecordKind::Snapshot) &&
         raw <= static_cast<std::uint16_t>(JournalRecordKind::CountersSync);
}

[[nodiscard]] Status write_exact(std::FILE* file, const std::uint8_t* data, std::size_t length) {
  if (length == 0) {
    return Status::success();
  }
  if (std::fwrite(data, 1, length, file) != length) {
    return Status::error(StatusCode::IoFailure, "short write to journal");
  }
  return Status::success();
}

[[nodiscard]] Status read_prefix(const std::filesystem::path& path, std::uint64_t max_bytes,
                                 Bytes& out, std::uint64_t& actual_size) {
  actual_size = platform::file_size_bytes(path);
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (file == nullptr) {
    return Status::error(StatusCode::IoFailure,
                         "cannot open journal '" + path.string() + "' (errno=" +
                             std::to_string(errno) + ")");
  }
  const std::uint64_t want = actual_size < max_bytes ? actual_size : max_bytes;
  Bytes buffer;
  buffer.resize(static_cast<std::size_t>(want));
  std::size_t total = 0;
  while (total < buffer.size()) {
    const std::size_t chunk = std::fread(buffer.data() + total, 1, buffer.size() - total, file);
    if (chunk == 0) {
      break;
    }
    total += chunk;
  }
  const bool failed = std::ferror(file) != 0;
  std::fclose(file);
  if (failed) {
    return Status::error(StatusCode::IoFailure, "read error while scanning the journal");
  }
  buffer.resize(total);
  out = std::move(buffer);
  return Status::success();
}

void encode_grant_vector(ByteWriter& writer, const std::vector<AuthorityGrant>& grants) {
  writer.count(grants.size());
  for (const AuthorityGrant& grant : grants) {
    grant.encode(writer);
  }
}

[[nodiscard]] bool decode_grant_vector(ByteReader& reader, std::vector<AuthorityGrant>& out) {
  std::size_t count = 0;
  if (!reader.count(limits::kMaxGrants, count)) {
    return false;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    AuthorityGrant grant;
    if (!AuthorityGrant::decode(reader, grant)) {
      return false;
    }
    out.push_back(std::move(grant));
  }
  return true;
}

void encode_attempt_vector(ByteWriter& writer, const std::vector<AttemptRecord>& attempts) {
  writer.count(attempts.size());
  for (const AttemptRecord& attempt : attempts) {
    attempt.encode(writer);
  }
}

[[nodiscard]] bool decode_attempt_vector(ByteReader& reader, std::vector<AttemptRecord>& out) {
  std::size_t count = 0;
  if (!reader.count(limits::kMaxAttempts, count)) {
    return false;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    AttemptRecord attempt;
    if (!AttemptRecord::decode(reader, attempt)) {
      return false;
    }
    out.push_back(std::move(attempt));
  }
  return true;
}

}  // namespace

const char* to_string(JournalRecordKind kind) noexcept {
  switch (kind) {
    case JournalRecordKind::Invalid: return "INVALID";
    case JournalRecordKind::Snapshot: return "SNAPSHOT";
    case JournalRecordKind::SetController: return "SET_CONTROLLER";
    case JournalRecordKind::MemberUpsert: return "MEMBER_UPSERT";
    case JournalRecordKind::MemberRemove: return "MEMBER_REMOVE";
    case JournalRecordKind::MemberLifecycle: return "MEMBER_LIFECYCLE";
    case JournalRecordKind::PathUpsert: return "PATH_UPSERT";
    case JournalRecordKind::PathRemove: return "PATH_REMOVE";
    case JournalRecordKind::PathState: return "PATH_STATE";
    case JournalRecordKind::ExclusionUpsert: return "EXCLUSION_UPSERT";
    case JournalRecordKind::ExclusionRemove: return "EXCLUSION_REMOVE";
    case JournalRecordKind::ObligationUpsert: return "OBLIGATION_UPSERT";
    case JournalRecordKind::ObligationRemove: return "OBLIGATION_REMOVE";
    case JournalRecordKind::ContractUpsert: return "CONTRACT_UPSERT";
    case JournalRecordKind::ContractRemove: return "CONTRACT_REMOVE";
    case JournalRecordKind::EpochBegin: return "EPOCH_BEGIN";
    case JournalRecordKind::PolicySet: return "POLICY_SET";
    case JournalRecordKind::TickMark: return "TICK_MARK";
    case JournalRecordKind::GrantPrepared: return "GRANT_PREPARED";
    case JournalRecordKind::GrantCommitted: return "GRANT_COMMITTED";
    case JournalRecordKind::GrantAcknowledged: return "GRANT_ACKNOWLEDGED";
    case JournalRecordKind::GrantReleased: return "GRANT_RELEASED";
    case JournalRecordKind::GrantTerminal: return "GRANT_TERMINAL";
    case JournalRecordKind::AttemptTerminal: return "ATTEMPT_TERMINAL";
    case JournalRecordKind::AttemptCancelled: return "ATTEMPT_CANCELLED";
    case JournalRecordKind::CountersSync: return "COUNTERS_SYNC";
  }
  return "UNRECOGNISED_RECORD_KIND";
}

// ---------------------------------------------------------------------------
// JournalEntry codec
// ---------------------------------------------------------------------------
void JournalEntry::encode(ByteWriter& writer) const {
  encode_counter(writer, tick);
  switch (kind) {
    case JournalRecordKind::Invalid:
      break;
    case JournalRecordKind::Snapshot:
      writer.u32(CIF_SNAPSHOT_FORMAT_VERSION);
      snapshot_spec.encode(writer);
      snapshot_contracts.encode(writer);
      encode_grant_vector(writer, snapshot_grants);
      encode_attempt_vector(writer, snapshot_attempts);
      snapshot_counters.encode(writer);
      break;
    case JournalRecordKind::SetController:
    case JournalRecordKind::EpochBegin:
      encode_id(writer, cluster_id);
      encode_counter(writer, cluster_generation);
      encode_counter(writer, epoch);
      encode_counter(writer, policy_generation);
      encode_incarnation(writer, incarnation);
      break;
    case JournalRecordKind::PolicySet:
      encode_counter(writer, policy_generation);
      break;
    case JournalRecordKind::MemberUpsert:
      encode_member(writer, member);
      break;
    case JournalRecordKind::MemberRemove:
      encode_id(writer, member_id);
      break;
    case JournalRecordKind::MemberLifecycle:
      encode_id(writer, member_id);
      writer.u8(static_cast<std::uint8_t>(lifecycle));
      break;
    case JournalRecordKind::PathUpsert:
      encode_path(writer, path);
      break;
    case JournalRecordKind::PathRemove:
      encode_id(writer, path_id);
      break;
    case JournalRecordKind::PathState:
      encode_id(writer, path_id);
      writer.u8(static_cast<std::uint8_t>(path_state));
      break;
    case JournalRecordKind::ExclusionUpsert:
      encode_exclusion(writer, exclusion);
      break;
    case JournalRecordKind::ExclusionRemove:
      encode_id(writer, exclusion_id);
      break;
    case JournalRecordKind::ObligationUpsert:
      encode_obligation(writer, obligation);
      break;
    case JournalRecordKind::ObligationRemove:
      encode_id(writer, obligation_id);
      break;
    case JournalRecordKind::ContractUpsert:
      contract.encode(writer);
      break;
    case JournalRecordKind::ContractRemove:
      encode_id(writer, contract_id);
      break;
    case JournalRecordKind::TickMark:
      break;
    case JournalRecordKind::GrantPrepared:
    case JournalRecordKind::GrantCommitted:
    case JournalRecordKind::GrantAcknowledged:
    case JournalRecordKind::GrantReleased:
    case JournalRecordKind::GrantTerminal:
      grant.encode(writer);
      writer.u8(static_cast<std::uint8_t>(grant_state));
      writer.u64(referenced_sequence);
      break;
    case JournalRecordKind::AttemptTerminal:
      attempt.encode(writer);
      break;
    case JournalRecordKind::AttemptCancelled:
      encode_id(writer, attempt_id);
      writer.text(note);
      break;
    case JournalRecordKind::CountersSync:
      snapshot_counters.encode(writer);
      break;
  }
}

bool JournalEntry::decode(ByteReader& reader, JournalEntry& out) {
  JournalEntry entry;
  // The record kind and sequence live in the record header, not the payload;
  // the caller must supply them before decoding.
  entry.kind = out.kind;
  entry.sequence = out.sequence;
  if (entry.kind == JournalRecordKind::Invalid) {
    reader.fail(StatusCode::Corruption, "record kind INVALID cannot be decoded");
    return false;
  }
  if (!decode_counter(reader, entry.tick)) {
    return false;
  }
  switch (entry.kind) {
    case JournalRecordKind::Invalid:
      reader.fail(StatusCode::Corruption, "record kind INVALID cannot appear in a journal");
      return false;
    case JournalRecordKind::Snapshot: {
      std::uint32_t snapshot_version = 0;
      if (!reader.u32(snapshot_version)) return false;
      if (snapshot_version != CIF_SNAPSHOT_FORMAT_VERSION) {
        reader.fail(StatusCode::VersionMismatch, "snapshot format version not understood");
        return false;
      }
      if (!ClusterSpec::decode(reader, entry.snapshot_spec)) return false;
      if (!ContractSet::decode(reader, entry.snapshot_contracts)) return false;
      if (!decode_grant_vector(reader, entry.snapshot_grants)) return false;
      if (!decode_attempt_vector(reader, entry.snapshot_attempts)) return false;
      if (!AuthorityCounters::decode(reader, entry.snapshot_counters)) return false;
      break;
    }
    case JournalRecordKind::SetController:
    case JournalRecordKind::EpochBegin:
      if (!decode_id(reader, entry.cluster_id)) return false;
      if (!decode_counter(reader, entry.cluster_generation)) return false;
      if (!decode_counter(reader, entry.epoch)) return false;
      if (!decode_counter(reader, entry.policy_generation)) return false;
      if (!decode_incarnation(reader, entry.incarnation)) return false;
      break;
    case JournalRecordKind::PolicySet:
      if (!decode_counter(reader, entry.policy_generation)) return false;
      break;
    case JournalRecordKind::MemberUpsert:
      if (!decode_member(reader, entry.member)) return false;
      break;
    case JournalRecordKind::MemberRemove:
      if (!decode_id(reader, entry.member_id)) return false;
      break;
    case JournalRecordKind::MemberLifecycle: {
      if (!decode_id(reader, entry.member_id)) return false;
      std::uint8_t lifecycle = 0;
      if (!reader.u8(lifecycle)) return false;
      if (lifecycle > static_cast<std::uint8_t>(MemberLifecycle::Removed)) {
        reader.fail(StatusCode::Corruption, "member lifecycle byte out of range");
        return false;
      }
      entry.lifecycle = static_cast<MemberLifecycle>(lifecycle);
      break;
    }
    case JournalRecordKind::PathUpsert:
      if (!decode_path(reader, entry.path)) return false;
      break;
    case JournalRecordKind::PathRemove:
      if (!decode_id(reader, entry.path_id)) return false;
      break;
    case JournalRecordKind::PathState: {
      if (!decode_id(reader, entry.path_id)) return false;
      std::uint8_t state = 0;
      if (!reader.u8(state)) return false;
      if (state > static_cast<std::uint8_t>(PathState::Unknown)) {
        reader.fail(StatusCode::Corruption, "path state byte out of range");
        return false;
      }
      entry.path_state = static_cast<PathState>(state);
      break;
    }
    case JournalRecordKind::ExclusionUpsert:
      if (!decode_exclusion(reader, entry.exclusion)) return false;
      break;
    case JournalRecordKind::ExclusionRemove:
      if (!decode_id(reader, entry.exclusion_id)) return false;
      break;
    case JournalRecordKind::ObligationUpsert:
      if (!decode_obligation(reader, entry.obligation)) return false;
      break;
    case JournalRecordKind::ObligationRemove:
      if (!decode_id(reader, entry.obligation_id)) return false;
      break;
    case JournalRecordKind::ContractUpsert:
      if (!CommunicationContract::decode(reader, entry.contract)) return false;
      break;
    case JournalRecordKind::ContractRemove:
      if (!decode_id(reader, entry.contract_id)) return false;
      break;
    case JournalRecordKind::TickMark:
      break;
    case JournalRecordKind::GrantPrepared:
    case JournalRecordKind::GrantCommitted:
    case JournalRecordKind::GrantAcknowledged:
    case JournalRecordKind::GrantReleased:
    case JournalRecordKind::GrantTerminal: {
      if (!AuthorityGrant::decode(reader, entry.grant)) return false;
      std::uint8_t state = 0;
      if (!reader.u8(state)) return false;
      if (state > static_cast<std::uint8_t>(GrantState::Superseded)) {
        reader.fail(StatusCode::Corruption, "grant state byte out of range");
        return false;
      }
      entry.grant_state = static_cast<GrantState>(state);
      if (!reader.u64(entry.referenced_sequence)) return false;
      break;
    }
    case JournalRecordKind::AttemptTerminal:
      if (!AttemptRecord::decode(reader, entry.attempt)) return false;
      break;
    case JournalRecordKind::AttemptCancelled:
      if (!decode_id(reader, entry.attempt_id)) return false;
      if (!reader.text(entry.note, limits::kMaxNoteBytes)) return false;
      if (!is_valid_utf8(entry.note)) {
        reader.fail(StatusCode::Corruption, "cancel note is not valid UTF-8");
        return false;
      }
      break;
    case JournalRecordKind::CountersSync:
      if (!AuthorityCounters::decode(reader, entry.snapshot_counters)) return false;
      break;
  }
  out = std::move(entry);
  return true;
}

Digest256 JournalEntry::digest() const {
  Bytes buffer;
  ByteWriter writer(buffer);
  encode(writer);
  return canonical_digest("cif.journal.record.v1", buffer);
}

// ---------------------------------------------------------------------------
// RecoveryReport
// ---------------------------------------------------------------------------
std::string RecoveryReport::render() const {
  std::string out;
  out += "RECOVERY\n";
  out += "  file_present = ";
  out += file_present ? "true\n" : "false\n";
  out += "  fresh = ";
  out += fresh ? "true\n" : "false\n";
  out += "  truncated_tail = ";
  out += truncated_tail ? "true\n" : "false\n";
  out += "  integrity_failure = ";
  out += integrity_failure ? "true\n" : "false\n";
  out += "  version_mismatch = ";
  out += version_mismatch ? "true\n" : "false\n";
  out += "  replay_detected = ";
  out += replay_detected ? "true\n" : "false\n";
  out += "  discarded_bytes = " + to_decimal(discarded_bytes) + "\n";
  out += "  records_read = " + to_decimal(records_read) + "\n";
  out += "  records_applied = " + to_decimal(records_applied) + "\n";
  out += "  records_rejected = " + to_decimal(records_rejected) + "\n";
  out += "  last_sequence = " + to_decimal(last_sequence) + "\n";
  out += "  valid_bytes = " + to_decimal(valid_bytes) + "\n";
  out += "  historical = ";
  out += historical() ? "true\n" : "false\n";
  if (!detail.empty()) {
    out += "  detail = ";
    out += sanitise_for_display(detail, limits::kMaxNoteBytes);
    out += "\n";
  }
  return out;
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------
Journal::~Journal() { static_cast<void>(close()); }

Status Journal::scan(const std::filesystem::path& path, std::vector<JournalEntry>& entries,
                     RecoveryReport& report) {
  entries.clear();
  report = RecoveryReport{};

  if (!platform::file_exists(path)) {
    report.fresh = true;
    report.detail = "no journal file present; starting with empty state";
    return Status::success();
  }
  report.file_present = true;

  const std::uint64_t size = platform::file_size_bytes(path);
  if (size == 0) {
    report.fresh = true;
    report.detail = "journal file is empty; starting with empty state";
    return Status::success();
  }
  if (size > kMaxScanBytes) {
    report.integrity_failure = true;
    report.detail = "journal exceeds the configured scan bound of " +
                    std::to_string(kMaxScanBytes) + " bytes";
    return Status::error(StatusCode::LimitExceeded, report.detail);
  }

  Bytes bytes;
  std::uint64_t actual = 0;
  CIF_TRY(read_prefix(path, kMaxScanBytes, bytes, actual));

  if (bytes.size() < kFileHeaderSize) {
    report.integrity_failure = true;
    report.discarded_bytes = bytes.size();
    report.detail = "file is smaller than the journal header";
    return Status::error(StatusCode::Corruption, report.detail);
  }
  if (std::memcmp(bytes.data(), kFileMagic, sizeof(kFileMagic)) != 0) {
    report.integrity_failure = true;
    report.discarded_bytes = bytes.size();
    report.detail = "journal magic does not match";
    return Status::error(StatusCode::Corruption, report.detail);
  }

  ByteReader header_reader(std::span<const std::uint8_t>(bytes.data(), kFileHeaderSize));
  std::span<const std::uint8_t> magic_view;
  static_cast<void>(header_reader.raw(8, magic_view));
  std::uint32_t format_version = 0;
  std::uint32_t flags = 0;
  std::uint64_t created = 0;
  std::uint32_t header_crc = 0;
  static_cast<void>(header_reader.u32(format_version));
  static_cast<void>(header_reader.u32(flags));
  static_cast<void>(header_reader.u64(created));
  static_cast<void>(header_reader.u32(header_crc));
  if (header_crc != crc32c(std::span<const std::uint8_t>(bytes.data(), 24))) {
    report.integrity_failure = true;
    report.discarded_bytes = bytes.size();
    report.detail = "journal file header failed its integrity check";
    return Status::error(StatusCode::IntegrityFailure, report.detail);
  }
  if (format_version != CIF_JOURNAL_FORMAT_VERSION) {
    report.version_mismatch = true;
    report.detail = "journal format version " + std::to_string(format_version) +
                    " is not understood by this build (expected " +
                    std::to_string(CIF_JOURNAL_FORMAT_VERSION) + ")";
    return Status::error(StatusCode::VersionMismatch, report.detail);
  }

  std::size_t offset = kFileHeaderSize;
  std::uint32_t chain = 0;
  std::uint64_t expected_sequence = 0;
  bool accept_records = true;
  while (accept_records && offset < bytes.size()) {
    if (bytes.size() - offset < kRecordHeaderSize) {
      report.truncated_tail = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "trailing bytes are shorter than a record header";
      break;
    }
    ByteReader reader(std::span<const std::uint8_t>(bytes.data() + offset, bytes.size() - offset));
    std::uint32_t record_magic = 0;
    std::uint16_t record_version = 0;
    std::uint16_t kind_raw = 0;
    std::uint64_t sequence = 0;
    std::uint32_t payload_length = 0;
    std::uint32_t record_chain = 0;
    std::uint32_t record_header_crc = 0;
    static_cast<void>(reader.u32(record_magic));
    static_cast<void>(reader.u16(record_version));
    static_cast<void>(reader.u16(kind_raw));
    static_cast<void>(reader.u64(sequence));
    static_cast<void>(reader.u32(payload_length));
    static_cast<void>(reader.u32(record_chain));
    static_cast<void>(reader.u32(record_header_crc));

    const std::uint32_t computed_header_crc =
        crc32c(std::span<const std::uint8_t>(bytes.data() + offset, 24));
    if (record_magic != kRecordMagic || record_header_crc != computed_header_crc) {
      report.integrity_failure = true;
      report.truncated_tail = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record header failed its integrity check at offset " + std::to_string(offset);
      break;
    }
    if (record_version != kRecordFormatVersion) {
      report.version_mismatch = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record format version " + std::to_string(record_version) +
                      " is not understood by this build";
      break;
    }
    if (!is_known_kind(kind_raw)) {
      report.integrity_failure = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record kind " + std::to_string(kind_raw) + " is not a known kind";
      break;
    }
    if (payload_length > limits::kMaxJournalRecordBytes) {
      report.integrity_failure = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record declares " + std::to_string(payload_length) +
                      " payload bytes, above the configured bound";
      break;
    }
    const std::uint64_t record_total =
        static_cast<std::uint64_t>(kRecordHeaderSize) + payload_length + 4u;
    if (static_cast<std::uint64_t>(bytes.size() - offset) < record_total) {
      report.truncated_tail = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record at offset " + std::to_string(offset) + " is incomplete";
      break;
    }

    const std::uint8_t* payload = bytes.data() + offset + kRecordHeaderSize;
    std::uint32_t stored_payload_crc = 0;
    {
      ByteReader tail(std::span<const std::uint8_t>(payload + payload_length, 4));
      static_cast<void>(tail.u32(stored_payload_crc));
    }
    const std::uint32_t computed_payload_crc =
        crc32c(std::span<const std::uint8_t>(payload, payload_length));
    if (computed_payload_crc != stored_payload_crc) {
      report.integrity_failure = true;
      report.truncated_tail = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record payload failed its integrity check at offset " + std::to_string(offset);
      break;
    }

    Bytes chain_input;
    chain_input.reserve(4 + payload_length);
    chain_input.push_back(static_cast<std::uint8_t>(chain & 0xFFu));
    chain_input.push_back(static_cast<std::uint8_t>((chain >> 8) & 0xFFu));
    chain_input.push_back(static_cast<std::uint8_t>((chain >> 16) & 0xFFu));
    chain_input.push_back(static_cast<std::uint8_t>((chain >> 24) & 0xFFu));
    chain_input.insert(chain_input.end(), payload, payload + payload_length);
    const std::uint32_t computed_chain = crc32c(chain_input);
    if (computed_chain != record_chain) {
      report.integrity_failure = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record chain check failed at offset " + std::to_string(offset) +
                      ": a record was removed, reordered or spliced";
      break;
    }

    if (sequence != expected_sequence) {
      report.replay_detected = true;
      report.integrity_failure = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record sequence " + std::to_string(sequence) +
                      " breaks continuity (expected " + std::to_string(expected_sequence) + ")";
      break;
    }

    JournalEntry entry;
    entry.kind = static_cast<JournalRecordKind>(kind_raw);
    entry.sequence = sequence;
    ByteReader payload_reader(std::span<const std::uint8_t>(payload, payload_length));
    if (!JournalEntry::decode(payload_reader, entry)) {
      report.integrity_failure = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record payload could not be decoded: " + payload_reader.failure().to_string();
      break;
    }
    if (!payload_reader.at_end()) {
      report.integrity_failure = true;
      report.discarded_bytes = bytes.size() - offset;
      report.detail = "record payload has " + std::to_string(payload_reader.remaining()) +
                      " trailing bytes";
      break;
    }

    entries.push_back(std::move(entry));
    chain = computed_chain;
    expected_sequence = sequence + 1u;
    offset += static_cast<std::size_t>(record_total);
  }

  report.records_read = entries.size();
  report.last_sequence = expected_sequence;
  report.last_chain = chain;
  report.valid_bytes = offset;
  if (report.detail.empty() && !report.fresh) {
    report.detail = "journal scanned cleanly";
  }
  return Status::success();
}

Status Journal::open_raw(const std::filesystem::path& path, bool reset) {
  CIF_TRY(platform::ensure_parent_directory(path));
  const char* mode = reset ? "wb+" : "rb+";
  std::FILE* file = std::fopen(path.string().c_str(), mode);
  if (file == nullptr && !reset) {
    // The file may not exist yet: create it.
    file = std::fopen(path.string().c_str(), "wb+");
  }
  if (file == nullptr) {
    return Status::error(StatusCode::IoFailure,
                         "cannot open journal '" + path.string() + "' for writing (errno=" +
                             std::to_string(errno) + ")");
  }
  file_ = file;
  path_ = path;
  return Status::success();
}

Status Journal::open(const std::filesystem::path& path, std::uint64_t truncate_to, bool reset,
                     std::uint32_t initial_chain, std::uint64_t last_sequence) {
  CIF_TRY(close());
  const bool need_header = reset || !platform::file_exists(path) || platform::file_size_bytes(path) == 0;
  CIF_TRY(open_raw(path, need_header));

  if (need_header) {
    // Fresh log: write the file header.
    Bytes header;
    ByteWriter writer(header);
    writer.raw(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(kFileMagic),
                                             sizeof(kFileMagic)));
    writer.u32(CIF_JOURNAL_FORMAT_VERSION);
    writer.u32(0);
    writer.u64(0);
    const std::uint32_t crc = crc32c(std::span<const std::uint8_t>(header.data(), header.size()));
    writer.u32(crc);
    writer.u32(0);
    CIF_TRY(write_exact(file_, header.data(), header.size()));
    CIF_TRY(platform::sync_file(file_));
    byte_count_ = header.size();
    record_count_ = 0;
    last_sequence_ = 0;
    chain_ = 0;
    return Status::success();
  }

  // Continue an existing log: physically remove the discarded tail first.
  if (std::fflush(file_) != 0) {
    return Status::error(StatusCode::IoFailure, "fflush failed while opening the journal");
  }
  std::fclose(file_);
  file_ = nullptr;
  if (truncate_to > 0) {
    CIF_TRY(platform::truncate_file(path, truncate_to));
  }
  CIF_TRY(open_raw(path, false));
  if (std::fseek(file_, 0, SEEK_END) != 0) {
    return Status::error(StatusCode::IoFailure, "cannot seek to the end of the journal");
  }
  byte_count_ = platform::file_size_bytes(path);
  record_count_ = 0;
  last_sequence_ = last_sequence;
  chain_ = initial_chain;
  return Status::success();
}

Status Journal::write_record(const JournalEntry& entry, bool durable) {
  if (file_ == nullptr) {
    return Status::error(StatusCode::Closed, "journal is not open");
  }
  if (entry.kind == JournalRecordKind::Invalid) {
    return Status::error(StatusCode::InvalidArgument, "cannot append an INVALID record");
  }

  Bytes payload;
  ByteWriter payload_writer(payload);
  entry.encode(payload_writer);

  if (payload.size() > limits::kMaxJournalRecordBytes) {
    return Status::error(StatusCode::LimitExceeded,
                         "record payload of " + std::to_string(payload.size()) +
                             " bytes exceeds the configured bound");
  }

  Bytes chain_input;
  chain_input.reserve(4 + payload.size());
  chain_input.push_back(static_cast<std::uint8_t>(chain_ & 0xFFu));
  chain_input.push_back(static_cast<std::uint8_t>((chain_ >> 8) & 0xFFu));
  chain_input.push_back(static_cast<std::uint8_t>((chain_ >> 16) & 0xFFu));
  chain_input.push_back(static_cast<std::uint8_t>((chain_ >> 24) & 0xFFu));
  chain_input.insert(chain_input.end(), payload.begin(), payload.end());
  const std::uint32_t record_chain = crc32c(chain_input);

  Bytes header;
  ByteWriter header_writer(header);
  header_writer.u32(kRecordMagic);
  header_writer.u16(kRecordFormatVersion);
  header_writer.u16(static_cast<std::uint16_t>(entry.kind));
  header_writer.u64(entry.sequence);
  header_writer.u32(static_cast<std::uint32_t>(payload.size()));
  header_writer.u32(record_chain);
  const std::uint32_t header_crc =
      crc32c(std::span<const std::uint8_t>(header.data(), header.size()));
  header_writer.u32(header_crc);

  Bytes trailer;
  ByteWriter trailer_writer(trailer);
  trailer_writer.u32(crc32c(payload));

  CIF_TRY(write_exact(file_, header.data(), header.size()));
  CIF_TRY(write_exact(file_, payload.data(), payload.size()));
  CIF_TRY(write_exact(file_, trailer.data(), trailer.size()));
  if (durable) {
    CIF_TRY(platform::sync_file(file_));
  }

  byte_count_ += header.size() + payload.size() + trailer.size();
  ++record_count_;
  last_sequence_ = entry.sequence + 1u;
  chain_ = record_chain;
  return Status::success();
}

Status Journal::write_fresh_record(const JournalEntry& entry) {
  JournalEntry stamped = entry;
  stamped.sequence = 0;
  return write_record(stamped, true);
}

Status Journal::append(JournalEntry& entry, bool durable) {
  if (should_compact()) {
    return Status::error(StatusCode::CapacityExhausted,
                         "journal has reached its configured bound; compaction is required");
  }
  entry.sequence = last_sequence_;
  return write_record(entry, durable);
}

Status Journal::compact(const JournalEntry& snapshot) {
  if (snapshot.kind != JournalRecordKind::Snapshot) {
    return Status::error(StatusCode::InvalidArgument, "compaction requires a SNAPSHOT record");
  }
  const std::filesystem::path temporary = path_.string().empty()
                                              ? std::filesystem::path("cif-journal.tmp")
                                              : std::filesystem::path(path_.string() + ".compact");
  CIF_TRY(close());

  Journal fresh;
  CIF_TRY(fresh.open(temporary, 0, true, 0, 0));
  // Sequence numbers restart at zero for the replacement log: the log identity
  // changes with compaction, and the caller records that in the audit trail.
  CIF_TRY(fresh.write_fresh_record(snapshot));
  const std::uint64_t bytes = fresh.byte_count();
  const std::uint64_t records = fresh.record_count();
  const std::uint64_t last_sequence = fresh.last_sequence();
  const std::uint32_t chain = fresh.chain_;
  CIF_TRY(fresh.close());

  CIF_TRY(platform::atomic_replace(temporary, path_));

  CIF_TRY(open_raw(path_, false));
  if (std::fseek(file_, 0, SEEK_END) != 0) {
    return Status::error(StatusCode::IoFailure, "cannot seek to the end after compaction");
  }
  byte_count_ = bytes;
  record_count_ = records;
  last_sequence_ = last_sequence;
  chain_ = chain;
  return Status::success();
}

Status Journal::sync() {
  if (file_ == nullptr) {
    return Status::error(StatusCode::Closed, "journal is not open");
  }
  return platform::sync_file(file_);
}

Status Journal::close() {
  if (file_ == nullptr) {
    return Status::success();
  }
  std::FILE* file = file_;
  file_ = nullptr;
  const Status synced = platform::sync_file(file);
  const int closed = std::fclose(file);
  if (!synced.ok()) {
    return synced;
  }
  if (closed != 0) {
    return Status::error(StatusCode::IoFailure, "fclose failed while closing the journal");
  }
  return Status::success();
}


// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------
Status replay_journal(const std::vector<JournalEntry>& entries, RecoveredState& out) {
  RecoveredState state;
  std::uint64_t last_sequence = 0;
  bool seen_sequence = false;

  for (const JournalEntry& entry : entries) {
    if (seen_sequence && entry.sequence != last_sequence + 1u) {
      return Status::error(StatusCode::Corruption,
                           "journal replay saw a sequence gap at " + std::to_string(entry.sequence));
    }
    seen_sequence = true;
    last_sequence = entry.sequence;
    if (entry.tick > state.tick) {
      state.tick = entry.tick;
    }

    const auto upsert_grant = [&state](const AuthorityGrant& grant) -> Status {
      const auto slot =
          std::lower_bound(state.grants.begin(), state.grants.end(), grant.grant_id,
                           [](const AuthorityGrant& existing, const GrantId& key) {
                             return existing.grant_id < key;
                           });
      if (slot != state.grants.end() && slot->grant_id == grant.grant_id) {
        *slot = grant;
      } else {
        if (state.grants.size() >= limits::kMaxGrants) {
          return Status::error(StatusCode::CapacityExhausted, "replayed grant table is full");
        }
        state.grants.insert(slot, grant);
      }
      return Status::success();
    };
    const auto upsert_attempt = [&state](const AttemptRecord& attempt) -> Status {
      const auto slot =
          std::lower_bound(state.attempts.begin(), state.attempts.end(), attempt.attempt_id,
                           [](const AttemptRecord& existing, const AttemptId& key) {
                             return existing.attempt_id < key;
                           });
      if (slot != state.attempts.end() && slot->attempt_id == attempt.attempt_id) {
        *slot = attempt;
      } else {
        if (state.attempts.size() >= limits::kMaxAttempts) {
          return Status::error(StatusCode::CapacityExhausted, "replayed attempt table is full");
        }
        state.attempts.insert(slot, attempt);
      }
      return Status::success();
    };

    switch (entry.kind) {
      case JournalRecordKind::Invalid:
        return Status::error(StatusCode::Corruption, "journal contains an INVALID record");
      case JournalRecordKind::Snapshot:
        state.spec = entry.snapshot_spec;
        state.contracts = entry.snapshot_contracts;
        state.grants = entry.snapshot_grants;
        state.attempts = entry.snapshot_attempts;
        state.counters = entry.snapshot_counters;
        state.has_controller = !state.spec.cluster_id().empty();
        std::sort(state.grants.begin(), state.grants.end(),
                  [](const AuthorityGrant& a, const AuthorityGrant& b) { return a.grant_id < b.grant_id; });
        std::sort(state.attempts.begin(), state.attempts.end(),
                  [](const AttemptRecord& a, const AttemptRecord& b) {
                    return a.attempt_id < b.attempt_id;
                  });
        break;
      case JournalRecordKind::SetController:
        CIF_TRY(state.spec.set_cluster_id(entry.cluster_id));
        state.spec.set_incarnation(entry.incarnation);
        state.spec.set_policy_generation(entry.policy_generation);
        state.spec.restore_counters(entry.cluster_generation, entry.epoch);
        state.spec.set_tick(state.tick);
        state.has_controller = true;
        break;
      case JournalRecordKind::EpochBegin:
        CIF_TRY(state.spec.begin_epoch(entry.incarnation, entry.policy_generation));
        break;
      case JournalRecordKind::PolicySet:
        state.spec.set_policy_generation(entry.policy_generation);
        break;
      case JournalRecordKind::TickMark:
        state.spec.set_tick(entry.tick);
        break;
      case JournalRecordKind::MemberUpsert:
        CIF_TRY(state.spec.upsert_member(entry.member));
        break;
      case JournalRecordKind::MemberRemove:
        CIF_TRY(state.spec.remove_member(entry.member_id));
        break;
      case JournalRecordKind::MemberLifecycle:
        CIF_TRY(state.spec.set_member_lifecycle(entry.member_id, entry.lifecycle, entry.tick));
        break;
      case JournalRecordKind::PathUpsert:
        CIF_TRY(state.spec.upsert_path(entry.path));
        break;
      case JournalRecordKind::PathRemove:
        CIF_TRY(state.spec.remove_path(entry.path_id));
        break;
      case JournalRecordKind::PathState:
        CIF_TRY(state.spec.set_path_state(entry.path_id, entry.path_state));
        break;
      case JournalRecordKind::ExclusionUpsert:
        CIF_TRY(state.spec.upsert_exclusion(entry.exclusion));
        break;
      case JournalRecordKind::ExclusionRemove:
        CIF_TRY(state.spec.remove_exclusion(entry.exclusion_id));
        break;
      case JournalRecordKind::ObligationUpsert:
        CIF_TRY(state.spec.upsert_obligation(entry.obligation));
        break;
      case JournalRecordKind::ObligationRemove:
        CIF_TRY(state.spec.remove_obligation(entry.obligation_id));
        break;
      case JournalRecordKind::ContractUpsert:
        CIF_TRY(state.contracts.upsert(entry.contract));
        break;
      case JournalRecordKind::ContractRemove:
        CIF_TRY(state.contracts.remove(entry.contract_id));
        break;
      case JournalRecordKind::GrantPrepared:
      case JournalRecordKind::GrantCommitted:
      case JournalRecordKind::GrantAcknowledged:
      case JournalRecordKind::GrantReleased:
      case JournalRecordKind::GrantTerminal: {
        AuthorityGrant grant = entry.grant;
        // The recorded state is the truth and is adopted verbatim. Capacity
        // accounting is *derived* from the state, never trusted as an
        // independent field, so a log can never claim capacity it does not hold.
        grant.state = entry.grant_state;
        grant.capacity_reserved = holds_capacity(grant.state);
        CIF_TRY(upsert_grant(grant));
        break;
      }
      case JournalRecordKind::AttemptTerminal:
        CIF_TRY(upsert_attempt(entry.attempt));
        break;
      case JournalRecordKind::AttemptCancelled: {
        AttemptRecord attempt;
        attempt.attempt_id = entry.attempt_id;
        attempt.cancelled = true;
        attempt.terminal_tick = entry.tick;
        attempt.primary_reason = ReasonCode::AttemptCancelled;
        const AttemptRecord* existing = nullptr;
        for (const AttemptRecord& candidate : state.attempts) {
          if (candidate.attempt_id == entry.attempt_id) {
            existing = &candidate;
            break;
          }
        }
        if (existing != nullptr) {
          attempt = *existing;
          attempt.cancelled = true;
          attempt.terminal_tick = entry.tick;
          attempt.primary_reason = ReasonCode::AttemptCancelled;
        }
        CIF_TRY(upsert_attempt(attempt));
        break;
      }
      case JournalRecordKind::CountersSync:
        state.counters = entry.snapshot_counters;
        break;
    }
  }

  if (state.tick > state.spec.tick()) {
    state.spec.set_tick(state.tick);
  } else {
    state.tick = state.spec.tick();
  }
  out = std::move(state);
  return Status::success();
}

}  // namespace cif
