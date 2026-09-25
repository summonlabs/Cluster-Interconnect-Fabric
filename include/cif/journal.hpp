// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Durable, versioned, integrity-checked, bounded transition log.
//
// Design rules that the implementation is held to:
//   * Every record carries a format version, a length, a payload CRC-32C and a
//     chain CRC that binds it to its predecessor. Reordering, deletion and
//     splicing are therefore detectable, not merely unlikely.
//   * A record is never partially believed. A torn record ends the scan; the
//     surviving prefix is adopted and the discarded byte count is reported.
//   * The log is bounded by byte count and record count. Reaching either bound
//     is a normal, reported condition that triggers compaction -- never a
//     silent overwrite.
//   * Recovery is conservative: state that survives a restart is *historical*.
//     Nothing recovered is presented as freshly observed.
#ifndef CIF_JOURNAL_HPP
#define CIF_JOURNAL_HPP

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "cif/bytes.hpp"
#include "cif/contract.hpp"
#include "cif/grant.hpp"
#include "cif/identity.hpp"
#include "cif/model.hpp"
#include "cif/status.hpp"

namespace cif {

/// Every durable transition the authority can make.
enum class JournalRecordKind : std::uint16_t {
  Invalid = 0,
  Snapshot = 1,           ///< Complete state image; resets the log.
  SetController = 2,      ///< Bind cluster id, generation, epoch, policy, incarnation.
  MemberUpsert = 3,
  MemberRemove = 4,
  MemberLifecycle = 5,
  PathUpsert = 6,
  PathRemove = 7,
  PathState = 8,
  ExclusionUpsert = 9,
  ExclusionRemove = 10,
  ObligationUpsert = 11,
  ObligationRemove = 12,
  ContractUpsert = 13,
  ContractRemove = 14,
  EpochBegin = 15,
  PolicySet = 16,
  TickMark = 17,
  GrantPrepared = 18,
  GrantCommitted = 19,
  GrantAcknowledged = 20,
  GrantReleased = 21,
  GrantTerminal = 22,     ///< Expired / fenced / revoked / superseded.
  AttemptTerminal = 23,
  AttemptCancelled = 24,
  CountersSync = 25,
};

[[nodiscard]] const char* to_string(JournalRecordKind kind) noexcept;

/// One log record. Deliberately a single flat struct: the record kinds are few
/// and mutually exclusive, and a flat struct keeps encode/decode auditable.
struct JournalEntry {
  JournalRecordKind kind = JournalRecordKind::Invalid;
  std::uint64_t sequence = 0;
  Tick tick{};

  ClusterId cluster_id;
  ClusterGeneration cluster_generation{};
  ClusterEpoch epoch{};
  PolicyGeneration policy_generation{};
  ControllerIncarnation incarnation{};

  Member member;
  MemberId member_id;
  MemberLifecycle lifecycle = MemberLifecycle::Enlisted;

  Path path;
  PathId path_id;
  PathState path_state = PathState::Operational;

  MaintenanceExclusion exclusion;
  ExclusionId exclusion_id;

  CapacityObligation obligation;
  ObligationId obligation_id;

  CommunicationContract contract;
  ContractId contract_id;

  AuthorityGrant grant;
  GrantId grant_id;
  AttemptId attempt_id;
  LeaseId lease_id;
  GrantState grant_state = GrantState::Prepared;
  std::uint64_t referenced_sequence = 0;

  AttemptRecord attempt;

  ClusterSpec snapshot_spec;
  ContractSet snapshot_contracts;
  std::vector<AuthorityGrant> snapshot_grants;
  std::vector<AttemptRecord> snapshot_attempts;
  AuthorityCounters snapshot_counters;

  std::string note;

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, JournalEntry& out);
  [[nodiscard]] Digest256 digest() const;
};

/// What the scan found. Reported verbatim by the CLI and recorded in the
/// controller's recovery evidence.
struct RecoveryReport {
  bool file_present = false;
  bool fresh = false;             ///< No usable log existed.
  bool truncated_tail = false;    ///< Trailing bytes were discarded.
  bool integrity_failure = false; ///< A record failed its checks.
  bool version_mismatch = false;  ///< Format version not understood.
  bool replay_detected = false;   ///< Non-contiguous sequence numbers seen.
  std::uint64_t discarded_bytes = 0;
  std::uint64_t records_read = 0;
  std::uint64_t records_applied = 0;
  std::uint64_t records_rejected = 0;
  std::uint64_t last_sequence = 0;
  std::uint64_t valid_bytes = 0;
  std::uint32_t last_chain = 0;
  std::string detail;

  [[nodiscard]] bool requires_rebuild() const noexcept {
    return truncated_tail || integrity_failure || version_mismatch || replay_detected;
  }
  /// True when the recovered state must not be presented as freshly observed.
  [[nodiscard]] bool historical() const noexcept { return !fresh; }
  [[nodiscard]] std::string render() const;
};

/// State reconstructed from a journal prefix. Every field here is *historical*:
/// it is what the controller knew when it last wrote, not what is true now.
struct RecoveredState {
  ClusterSpec spec;
  ContractSet contracts;
  std::vector<AuthorityGrant> grants;
  std::vector<AttemptRecord> attempts;
  AuthorityCounters counters;
  bool has_controller = false;
  Tick tick{};
};

/// Replays a journal prefix into a RecoveredState. Replay is total and
/// deterministic: the same prefix always yields byte-identical state, which is
/// what makes 'cif verify' and cross-process digest comparison meaningful.
[[nodiscard]] Status replay_journal(const std::vector<JournalEntry>& entries, RecoveredState& out);

/// Append-only log file. One writer at a time; the class is not thread safe and
/// says so rather than pretending otherwise.
class Journal {
 public:
  Journal() = default;
  ~Journal();

  Journal(const Journal&) = delete;
  Journal& operator=(const Journal&) = delete;
  Journal(Journal&&) = delete;
  Journal& operator=(Journal&&) = delete;

  /// Reads every record in the file, validating version, CRCs, chain and
  /// sequence continuity. Never throws. On a torn or corrupt tail the scan stops
  /// at the last sound record and reports exactly how many bytes were discarded.
  [[nodiscard]] static Status scan(const std::filesystem::path& path,
                                   std::vector<JournalEntry>& entries,
                                   RecoveryReport& report);

  /// Opens for append. 'truncate_to' must be the value reported by scan() as
  /// valid_bytes (zero for a fresh log). Pass reset = true to start a new log.
  [[nodiscard]] Status open(const std::filesystem::path& path,
                            std::uint64_t truncate_to,
                            bool reset,
                            std::uint32_t initial_chain,
                            std::uint64_t last_sequence);

  /// Appends one record, stamping it with the sequence number it was assigned.
  /// 'durable' requests an fsync before returning; pass false only for records
  /// that may be lost without changing authority.
  [[nodiscard]] Status append(JournalEntry& entry, bool durable);

  /// Replaces the whole log with a single snapshot record. Atomic: the new log
  /// is written to a sibling file, synced, and moved into place.
  [[nodiscard]] Status compact(const JournalEntry& snapshot);

  [[nodiscard]] Status close();
  [[nodiscard]] Status sync();

  [[nodiscard]] bool is_open() const noexcept { return file_ != nullptr; }
  [[nodiscard]] std::uint64_t byte_count() const noexcept { return byte_count_; }
  [[nodiscard]] std::uint64_t record_count() const noexcept { return record_count_; }
  [[nodiscard]] std::uint64_t last_sequence() const noexcept { return last_sequence_; }
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  /// True when the log has reached either configured bound.
  [[nodiscard]] bool should_compact() const noexcept {
    return byte_count_ >= limits::kMaxJournalBytes || record_count_ >= limits::kMaxJournalRecords;
  }

  /// Header size in bytes, exposed so tests can construct deliberately torn
  /// files without duplicating format knowledge.
  static constexpr std::size_t kFileHeaderSize = 32;
  static constexpr std::size_t kRecordHeaderSize = 28;

 private:
  [[nodiscard]] Status write_record(const JournalEntry& entry, bool durable);
  [[nodiscard]] Status write_fresh_record(const JournalEntry& entry);
  [[nodiscard]] Status open_raw(const std::filesystem::path& path, bool reset);

  std::FILE* file_ = nullptr;
  std::filesystem::path path_;
  std::uint64_t byte_count_ = 0;
  std::uint64_t record_count_ = 0;
  std::uint64_t last_sequence_ = 0;
  std::uint32_t chain_ = 0;
};

}  // namespace cif

#endif  // CIF_JOURNAL_HPP
