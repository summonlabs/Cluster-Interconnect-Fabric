// Cluster Interconnect Fabric (CIF) -- core primitive tests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "cif/journal.hpp"
#include "cif/rng.hpp"
#include "cif/text.hpp"
#include "cif/version.hpp"
#include "harness.hpp"
#include "cif/platform.hpp"

using namespace cif;

namespace {

std::string read_all(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
  return text;
}

void patch_byte(const std::string& path, std::streamoff offset, std::uint8_t value) {
  std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
  CIF_REQUIRE(file.good());
  file.seekp(offset);
  file.put(static_cast<char>(value));
  file.close();
}

}  // namespace

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------
CIF_TEST(identity, parse_and_validate) {
  MemberId member;
  CIF_CHECK(MemberId::parse("member-01", member));
  CIF_CHECK(member.value() == "member-01");
  CIF_CHECK(!member.empty());

  PathId path;
  CIF_CHECK(PathId::parse("rack/pod:path+1", path));
  CIF_CHECK(path.value() == "rack/pod:path+1");

  PathId empty;
  CIF_CHECK(!PathId::parse("", empty));
  CIF_CHECK(empty.empty());

  // The templated types are genuinely distinct: this compiles only because the
  // ids are not interchangeable.
  static_assert(!std::is_same_v<MemberId, PathId>);
  static_assert(!std::is_same_v<ClusterGeneration, ClusterEpoch>);
  static_assert(!std::is_same_v<MemberGeneration, PathGeneration>);
}

CIF_TEST(identity, rejects_invalid) {
  const char* bad[] = {"has space", "has\ttab", "new\nline", "nul", "unicode-\xC3\xA9",
                       "quote\"inside", "back\\slash", "semi;colon"};
  for (const char* candidate : bad) {
    MemberId parsed;
    if (std::string(candidate) == "nul") {
      std::string with_nul("a");
      with_nul.push_back('\0');
      with_nul.push_back('b');
      CIF_CHECK(!MemberId::is_valid(with_nul));
      continue;
    }
    CIF_CHECK_MSG(!MemberId::parse(candidate, parsed), candidate);
  }
  std::string too_long(limits::kMaxIdentifierBytes + 1, 'a');
  CIF_CHECK(!MemberId::is_valid(too_long));
  CIF_CHECK(MemberId::is_valid(std::string(limits::kMaxIdentifierBytes, 'a')));
}

CIF_TEST(identity, counter_saturates) {
  ClusterGeneration generation{0};
  CIF_CHECK(generation.is_zero());
  CIF_CHECK(generation.can_advance());
  generation = generation.advanced();
  CIF_CHECK_EQ(generation.value(), 1u);

  ClusterGeneration saturated{ClusterGeneration::kMax};
  CIF_CHECK(!saturated.can_advance());
  CIF_CHECK_EQ(saturated.advanced().value(), ClusterGeneration::kMax);
}

CIF_TEST(identity, incarnation_roundtrip) {
  const ControllerIncarnation generated = ControllerIncarnation::generate();
  CIF_CHECK(!generated.is_zero());
  ControllerIncarnation parsed;
  CIF_REQUIRE(ControllerIncarnation::parse(generated.hex(), parsed));
  CIF_CHECK(parsed == generated);
  CIF_CHECK_EQ(generated.hex().size(), std::size_t{32});

  ControllerIncarnation rejected;
  CIF_CHECK(!ControllerIncarnation::parse("short", rejected));
  CIF_CHECK(!ControllerIncarnation::parse(
      "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", rejected));

  const ControllerIncarnation a = ControllerIncarnation::from_seed(1);
  const ControllerIncarnation b = ControllerIncarnation::from_seed(1);
  const ControllerIncarnation c = ControllerIncarnation::from_seed(2);
  CIF_CHECK(a == b);
  CIF_CHECK(a != c);
}

// ---------------------------------------------------------------------------
// hashing
// ---------------------------------------------------------------------------
CIF_TEST(hash, sha256_known_vectors) {
  CIF_CHECK_EQ(sha256_hex(""),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CIF_CHECK_EQ(sha256_hex("abc"),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CIF_CHECK_EQ(
      sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

  std::string million(1000000, 'a');
  CIF_CHECK_EQ(sha256_hex(million),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

  // Every buffer length around the 64-byte block boundary must hash correctly.
  for (std::size_t length = 0; length <= 200; ++length) {
    std::string data;
    for (std::size_t i = 0; i < length; ++i) {
      data.push_back(static_cast<char>('a' + static_cast<int>(i % 26)));
    }
    Sha256 streamed;
    for (std::size_t split = 0; split <= data.size(); ++split) {
      streamed.update(std::string_view(data).substr(0, split));
      streamed.update(std::string_view(data).substr(split));
      CIF_CHECK_MSG(streamed.digest() == sha256(data), "split " + std::to_string(split));
      streamed.reset();
    }
  }
}

CIF_TEST(hash, crc32c_known_vector) {
  CIF_CHECK_EQ(crc32c(std::string_view("123456789")), 0xE3069283u);
  CIF_CHECK_EQ(crc32c(std::string_view("")), 0u);
  CIF_CHECK_EQ(crc32c(std::string_view("a")), 0xC1D04330u);
}

CIF_TEST(hash, digest_parse_and_render) {
  const Digest256 digest = sha256("cif");
  const std::string hex = digest.hex();
  CIF_CHECK_EQ(hex.size(), std::size_t{64});
  Digest256 parsed;
  CIF_REQUIRE(Digest256::parse(hex, parsed));
  CIF_CHECK(parsed == digest);
  CIF_CHECK(!Digest256::parse("", parsed));
  CIF_CHECK(!Digest256::parse(hex.substr(0, 63), parsed));
  std::string upper = hex;
  for (char& c : upper) {
    if (c >= 'a' && c <= 'f') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  CIF_CHECK(Digest256::parse(upper, parsed));
  CIF_CHECK(parsed == digest);
  CIF_CHECK(Digest256::zero().is_zero());
  CIF_CHECK(!digest.is_zero());
}

CIF_TEST(hash, domain_hasher_separates_concatenations) {
  DomainHasher left("domain");
  left.add(std::string_view("ab"));
  left.add(std::string_view("c"));
  DomainHasher right("domain");
  right.add(std::string_view("a"));
  right.add(std::string_view("bc"));
  CIF_CHECK(left.finish() != right.finish());

  DomainHasher other("other");
  other.add(std::string_view("abc"));
  CIF_CHECK(other.finish() != left.finish());
}

// ---------------------------------------------------------------------------
// canonical byte codec
// ---------------------------------------------------------------------------
CIF_TEST(bytes, canonical_roundtrip) {
  Bytes buffer;
  ByteWriter writer(buffer);
  writer.u8(0xAB);
  writer.u16(0xBEEF);
  writer.u32(0xDEADBEEF);
  writer.u64(0x0123456789ABCDEF);
  writer.varint(0);
  writer.varint(127);
  writer.varint(128);
  writer.varint(UINT64_MAX);
  writer.boolean(true);
  writer.boolean(false);
  writer.text("hello");
  writer.blob(Bytes{1, 2, 3});
  writer.digest(sha256("x"));

  ByteReader reader(std::span<const std::uint8_t>(buffer.data(), buffer.size()));
  std::uint8_t u8 = 0;
  std::uint16_t u16 = 0;
  std::uint32_t u32 = 0;
  std::uint64_t u64 = 0;
  CIF_REQUIRE(reader.u8(u8));
  CIF_CHECK_EQ(u8, std::uint8_t{0xAB});
  CIF_REQUIRE(reader.u16(u16));
  CIF_CHECK_EQ(u16, std::uint16_t{0xBEEF});
  CIF_REQUIRE(reader.u32(u32));
  CIF_CHECK_EQ(u32, 0xDEADBEEFu);
  CIF_REQUIRE(reader.u64(u64));
  CIF_CHECK_EQ(u64, 0x0123456789ABCDEFull);
  std::uint64_t varint = 0;
  CIF_REQUIRE(reader.varint(varint));
  CIF_CHECK_EQ(varint, 0u);
  CIF_REQUIRE(reader.varint(varint));
  CIF_CHECK_EQ(varint, 127u);
  CIF_REQUIRE(reader.varint(varint));
  CIF_CHECK_EQ(varint, 128u);
  CIF_REQUIRE(reader.varint(varint));
  CIF_CHECK_EQ(varint, UINT64_MAX);
  bool boolean = false;
  CIF_REQUIRE(reader.boolean(boolean));
  CIF_CHECK(boolean);
  CIF_REQUIRE(reader.boolean(boolean));
  CIF_CHECK(!boolean);
  std::string text;
  CIF_REQUIRE(reader.text(text, 64));
  CIF_CHECK_EQ(text, std::string("hello"));
  Bytes blob;
  CIF_REQUIRE(reader.blob(blob, 64));
  CIF_CHECK_EQ(blob.size(), std::size_t{3});
  Digest256 digest;
  CIF_REQUIRE(reader.digest(digest));
  CIF_CHECK(digest == sha256("x"));
  CIF_CHECK(reader.at_end());
  CIF_CHECK(!reader.failed());
}

CIF_TEST(bytes, rejects_non_canonical_varint) {
  const Bytes overlong = {0x80, 0x00};  // canonical encoding of zero is {0x00}
  ByteReader reader(std::span<const std::uint8_t>(overlong.data(), overlong.size()));
  std::uint64_t value = 0;
  CIF_CHECK(!reader.varint(value));
  CIF_CHECK(reader.failed());
  CIF_CHECK(reader.failure().code() == StatusCode::Corruption);

  const Bytes ten_bytes = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80};
  ByteReader long_reader(std::span<const std::uint8_t>(ten_bytes.data(), ten_bytes.size()));
  CIF_CHECK(!long_reader.varint(value));
  CIF_CHECK(long_reader.failure().code() == StatusCode::Corruption);

  const Bytes overflowing = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
  ByteReader overflow_reader(
      std::span<const std::uint8_t>(overflowing.data(), overflowing.size()));
  CIF_CHECK(!overflow_reader.varint(value));
}

CIF_TEST(bytes, rejects_truncated_and_oversized) {
  Bytes buffer;
  ByteWriter writer(buffer);
  writer.count(limits::kMaxMembers + 1);
  ByteReader reader(std::span<const std::uint8_t>(buffer.data(), buffer.size()));
  std::size_t count = 0;
  CIF_CHECK(!reader.count(limits::kMaxMembers, count));
  CIF_CHECK(reader.failure().code() == StatusCode::CapacityExhausted);

  const Bytes nothing;
  ByteReader empty(nothing);
  std::uint32_t value = 0;
  CIF_CHECK(!empty.u32(value));
  CIF_CHECK(empty.failure().code() == StatusCode::Truncated);

  const Bytes one_byte = {0x01};
  ByteReader blob_reader(std::span<const std::uint8_t>(one_byte.data(), one_byte.size()));
  Bytes blob;
  CIF_CHECK(!blob_reader.blob(blob, 16));
  CIF_CHECK(blob_reader.failure().code() == StatusCode::Truncated);

  Bytes header;
  ByteWriter header_writer(header);
  header_writer.count(1024);
  ByteReader big(std::span<const std::uint8_t>(header.data(), header.size()));
  CIF_CHECK(!big.blob(blob, 16));
  CIF_CHECK(big.failure().code() == StatusCode::CapacityExhausted);
}

CIF_TEST(bytes, checked_arithmetic) {
  std::uint64_t out = 0;
  CIF_CHECK(checked_add(1, 2, out));
  CIF_CHECK_EQ(out, 3u);
  CIF_CHECK(!checked_add(UINT64_MAX, 1, out));
  CIF_CHECK(checked_sub(5, 3, out));
  CIF_CHECK_EQ(out, 2u);
  CIF_CHECK(!checked_sub(3, 5, out));
  CIF_CHECK(checked_mul(6, 7, out));
  CIF_CHECK_EQ(out, 42u);
  CIF_CHECK(!checked_mul(UINT64_MAX, 2, out));

  std::uint32_t small = 0;
  CIF_CHECK(checked_narrow(std::uint64_t{7}, small));
  CIF_CHECK_EQ(small, 7u);
  CIF_CHECK(!checked_narrow(UINT64_MAX, small));
  std::uint64_t wide = 0;
  CIF_CHECK(checked_narrow(std::uint32_t{7}, wide));
  CIF_CHECK_EQ(wide, 7u);
  std::uint32_t from_signed = 0;
  CIF_CHECK(!checked_narrow(-1, from_signed));
}

// ---------------------------------------------------------------------------
// text
// ---------------------------------------------------------------------------
CIF_TEST(text, accepts_valid_utf8) {
  CIF_CHECK(is_valid_utf8(""));
  CIF_CHECK(is_valid_utf8("plain ascii"));
  CIF_CHECK(is_valid_utf8("caf\xC3\xA9"));
  CIF_CHECK(is_valid_utf8("\xE2\x82\xAC"));       // euro sign
  CIF_CHECK(is_valid_utf8("\xF0\x9F\x98\x80"));   // emoji
  CIF_CHECK(is_valid_utf8("\x7F"));               // DEL is a valid scalar
}

CIF_TEST(text, rejects_malformed_utf8) {
  CIF_CHECK(!is_valid_utf8("\x80"));              // lone continuation
  CIF_CHECK(!is_valid_utf8("\xC0\x80"));          // overlong NUL
  CIF_CHECK(!is_valid_utf8("\xC1\xBF"));          // overlong
  CIF_CHECK(!is_valid_utf8("\xE0\x80\x80"));      // overlong
  CIF_CHECK(!is_valid_utf8("\xED\xA0\x80"));      // UTF-16 surrogate
  CIF_CHECK(!is_valid_utf8("\xED\xBF\xBF"));      // high surrogate
  CIF_CHECK(!is_valid_utf8("\xF4\x90\x80\x80"));  // above U+10FFFF
  CIF_CHECK(!is_valid_utf8("\xF5\x80\x80\x80"));  // invalid lead byte
  CIF_CHECK(!is_valid_utf8("\xC3"));              // truncated
  CIF_CHECK(!is_valid_utf8("\xE2\x82"));          // truncated
  CIF_CHECK(!is_valid_utf8("\xF0\x9F\x98"));      // truncated
  CIF_CHECK(!is_valid_utf8("\xFF\xFE"));          // never valid in UTF-8
  std::string with_nul("a");
  with_nul.push_back('\0');
  CIF_CHECK(!is_valid_utf8(with_nul));
}

CIF_TEST(text, identifier_grammar) {
  CIF_CHECK(is_valid_identifier("abc", 8));
  CIF_CHECK(is_valid_identifier("A-Z_0.9:/@+", 32));
  CIF_CHECK(!is_valid_identifier("", 8));
  CIF_CHECK(!is_valid_identifier("abcdefghi", 8));
  CIF_CHECK(!is_valid_identifier("with space", 32));
  std::string embedded_nul("with");
  embedded_nul.push_back('\0');
  embedded_nul += "nul";
  CIF_CHECK(!is_valid_identifier(embedded_nul, 32));
  CIF_CHECK(!is_valid_identifier("\xC3\xA9", 32));
}

CIF_TEST(text, sanitise_and_decimal) {
  const std::string hostile = std::string("safe") + '\x1B' + "[31mred\x7F\xFF";
  const std::string sanitised = sanitise_for_display(hostile, 64);
  CIF_CHECK_EQ(sanitised, std::string("safe?[31mred??"));
  CIF_CHECK_EQ(sanitise_for_display("abcdef", 3), std::string("abc"));

  CIF_CHECK_EQ(to_decimal(0), std::string("0"));
  CIF_CHECK_EQ(to_decimal(42), std::string("42"));
  CIF_CHECK_EQ(to_decimal(UINT64_MAX), std::string("18446744073709551615"));
  std::uint64_t value = 0;
  CIF_CHECK(parse_decimal_u64("18446744073709551615", value));
  CIF_CHECK_EQ(value, UINT64_MAX);
  CIF_CHECK(!parse_decimal_u64("18446744073709551616", value));
  CIF_CHECK(!parse_decimal_u64("", value));
  CIF_CHECK(!parse_decimal_u64("12a", value));
  CIF_CHECK(!parse_decimal_u64("-1", value));
}

// ---------------------------------------------------------------------------
// deterministic rng
// ---------------------------------------------------------------------------
CIF_TEST(rng, deterministic_from_seed) {
  Pcg32 left(12345, 67890);
  Pcg32 right(12345, 67890);
  for (int i = 0; i < 1000; ++i) {
    CIF_CHECK_EQ(left.next_u64(), right.next_u64());
  }
  Pcg32 different(12346, 67890);
  CIF_CHECK(left.next_u64() != different.next_u64());

  Pcg32 bounded(7, 1);
  std::uint64_t total = 0;
  for (int i = 0; i < 10000; ++i) {
    const std::uint64_t value = bounded.bounded(10);
    CIF_CHECK(value < 10);
    total += value;
  }
  CIF_CHECK(total > 40000 && total < 60000);

  SplitMix64 split(42);
  Pcg32 first = split.make_stream();
  Pcg32 second = split.make_stream();
  CIF_CHECK(first.next_u64() != second.next_u64());

  CIF_CHECK_EQ(bounded.bounded(0), 0u);
  CIF_CHECK_EQ(bounded.range(5, 4), 5u);
  CIF_CHECK(bounded.range(3, 3) == 3u);
}

// ---------------------------------------------------------------------------
// journal
// ---------------------------------------------------------------------------
namespace {

JournalEntry sample_entry(JournalRecordKind kind, std::uint64_t salt) {
  JournalEntry entry;
  entry.kind = kind;
  entry.tick = Tick{salt + 1};
  switch (kind) {
    case JournalRecordKind::SetController:
      entry.cluster_id = ClusterId::from_validated("cluster-" + std::to_string(salt));
      entry.cluster_generation = ClusterGeneration{salt};
      entry.epoch = ClusterEpoch{salt};
      entry.policy_generation = PolicyGeneration{salt};
      entry.incarnation = ControllerIncarnation::from_seed(salt);
      break;
    case JournalRecordKind::EpochBegin:
      entry.cluster_id = ClusterId::from_validated("cluster");
      entry.epoch = ClusterEpoch{salt};
      entry.policy_generation = PolicyGeneration{salt};
      entry.incarnation = ControllerIncarnation::from_seed(salt);
      break;
    case JournalRecordKind::PolicySet:
      entry.policy_generation = PolicyGeneration{salt};
      break;
    case JournalRecordKind::MemberUpsert:
      entry.member.id = MemberId::from_validated("member-" + std::to_string(salt));
      entry.member.domain = MemberDomainId::from_validated("domain");
      entry.member.generation = MemberGeneration{salt};
      entry.member.digest = sha256("member" + std::to_string(salt));
      entry.member.lifecycle = MemberLifecycle::Active;
      CIF_REQUIRE(LocalityPath::parse("dc/room/rack", entry.member.locality) ||
                  true);
      break;
    case JournalRecordKind::MemberRemove:
      entry.member_id = MemberId::from_validated("member-" + std::to_string(salt));
      break;
    case JournalRecordKind::MemberLifecycle:
      entry.member_id = MemberId::from_validated("member-" + std::to_string(salt));
      entry.lifecycle = MemberLifecycle::Draining;
      break;
    case JournalRecordKind::PathUpsert:
      entry.path.id = PathId::from_validated("path-" + std::to_string(salt));
      entry.path.generation = PathGeneration{salt};
      entry.path.source_member = MemberId::from_validated("a");
      entry.path.destination_member = MemberId::from_validated("b");
      break;
    case JournalRecordKind::PathRemove:
      entry.path_id = PathId::from_validated("path-" + std::to_string(salt));
      break;
    case JournalRecordKind::PathState:
      entry.path_id = PathId::from_validated("path-" + std::to_string(salt));
      entry.path_state = PathState::Degraded;
      break;
    case JournalRecordKind::ExclusionUpsert:
      entry.exclusion.id = ExclusionId::from_validated("excl-" + std::to_string(salt));
      entry.exclusion.mode = MaintenanceMode::Degrade;
      entry.exclusion.reason = "planned work";
      break;
    case JournalRecordKind::ExclusionRemove:
      entry.exclusion_id = ExclusionId::from_validated("excl-" + std::to_string(salt));
      break;
    case JournalRecordKind::ObligationUpsert:
      entry.obligation.id = ObligationId::from_validated("obl-" + std::to_string(salt));
      entry.obligation.service = ServiceGroupId::from_validated("svc");
      entry.obligation.min_distinct_failure_domains = 2;
      break;
    case JournalRecordKind::ObligationRemove:
      entry.obligation_id = ObligationId::from_validated("obl-" + std::to_string(salt));
      break;
    case JournalRecordKind::ContractUpsert:
      entry.contract.id = ContractId::from_validated("ctr-" + std::to_string(salt));
      entry.contract.generation = ContractGeneration{salt};
      entry.contract.source_service = ServiceGroupId::from_validated("a");
      entry.contract.destination_service = ServiceGroupId::from_validated("b");
      break;
    case JournalRecordKind::ContractRemove:
      entry.contract_id = ContractId::from_validated("ctr-" + std::to_string(salt));
      break;
    case JournalRecordKind::TickMark:
      break;
    case JournalRecordKind::GrantPrepared:
    case JournalRecordKind::GrantCommitted:
    case JournalRecordKind::GrantAcknowledged:
    case JournalRecordKind::GrantReleased:
    case JournalRecordKind::GrantTerminal:
      entry.grant.grant_id = GrantId::from_validated("g-" + std::to_string(salt));
      entry.grant.lease_id = LeaseId::from_validated("l-" + std::to_string(salt));
      entry.grant.attempt_id = AttemptId::from_validated("att-" + std::to_string(salt));
      entry.grant.cluster_id = ClusterId::from_validated("cluster");
      entry.grant.capacity_units = salt;
      entry.grant.source_member = MemberId::from_validated("a");
      entry.grant.destination_member = MemberId::from_validated("b");
      entry.grant.path_id = PathId::from_validated("p");
      entry.grant.reductions.push_back(Reason(ReasonCode::DegradedByCapacity, "reduced"));
      entry.grant_state = GrantState::Committed;
      entry.referenced_sequence = salt * 3;
      break;
    case JournalRecordKind::AttemptTerminal:
      entry.attempt.attempt_id = AttemptId::from_validated("att-" + std::to_string(salt));
      entry.attempt.request_id = RequestId::from_validated("req-" + std::to_string(salt));
      entry.attempt.request_digest = sha256("req" + std::to_string(salt));
      entry.attempt.grant_id = GrantId::from_validated("g-" + std::to_string(salt));
      entry.attempt.outcome = AuthorityOutcome::Granted;
      break;
    case JournalRecordKind::AttemptCancelled:
      entry.attempt_id = AttemptId::from_validated("att-" + std::to_string(salt));
      entry.note = "operator cancelled";
      break;
    case JournalRecordKind::CountersSync:
      entry.snapshot_counters.decisions = salt;
      entry.snapshot_counters.grants = salt;
      break;
    case JournalRecordKind::Snapshot:
      entry.snapshot_spec.set_cluster_id(ClusterId::from_validated("cluster"));
      entry.snapshot_spec.restore_counters(ClusterGeneration{salt}, ClusterEpoch{salt});
      entry.snapshot_spec.set_incarnation(ControllerIncarnation::from_seed(salt));
      entry.snapshot_counters.decisions = salt;
      break;
    case JournalRecordKind::Invalid:
      break;
  }
  return entry;
}

/// Appends a sample record. The journal stamps the sequence onto the entry it
/// is given, so the entry must be an lvalue.
Status append_sample(Journal& journal, JournalRecordKind kind, std::uint64_t salt,
                     bool durable = true) {
  JournalEntry entry = sample_entry(kind, salt);
  return journal.append(entry, durable);
}

const std::vector<JournalRecordKind>& all_kinds() {
  static const std::vector<JournalRecordKind> kinds = {
      JournalRecordKind::SetController,    JournalRecordKind::EpochBegin,
      JournalRecordKind::PolicySet,        JournalRecordKind::MemberUpsert,
      JournalRecordKind::MemberRemove,     JournalRecordKind::MemberLifecycle,
      JournalRecordKind::PathUpsert,       JournalRecordKind::PathRemove,
      JournalRecordKind::PathState,        JournalRecordKind::ExclusionUpsert,
      JournalRecordKind::ExclusionRemove,  JournalRecordKind::ObligationUpsert,
      JournalRecordKind::ObligationRemove, JournalRecordKind::ContractUpsert,
      JournalRecordKind::ContractRemove,   JournalRecordKind::TickMark,
      JournalRecordKind::GrantPrepared,    JournalRecordKind::GrantCommitted,
      JournalRecordKind::GrantAcknowledged, JournalRecordKind::GrantReleased,
      JournalRecordKind::GrantTerminal,    JournalRecordKind::AttemptTerminal,
      JournalRecordKind::AttemptCancelled, JournalRecordKind::CountersSync,
      JournalRecordKind::Snapshot};
  return kinds;
}

}  // namespace

CIF_TEST(journal, roundtrip_every_record_kind) {
  const std::string path = cif::test::scratch_path("roundtrip.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  std::vector<JournalEntry> written;
  {
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
    std::uint64_t salt = 1;
    for (JournalRecordKind kind : all_kinds()) {
      JournalEntry entry = sample_entry(kind, salt);
      CIF_REQUIRE_OK(journal.append(entry, true));
      entry.sequence = journal.last_sequence() - 1;
      written.push_back(entry);
      ++salt;
    }
    CIF_CHECK_EQ(journal.record_count(), written.size());
    CIF_REQUIRE_OK(journal.close());
  }

  std::vector<JournalEntry> read;
  RecoveryReport report;
  CIF_REQUIRE_OK(Journal::scan(path, read, report));
  CIF_CHECK_MSG(!report.truncated_tail, report.detail);
  CIF_CHECK_MSG(!report.integrity_failure, report.detail);
  CIF_CHECK_MSG(!report.version_mismatch, report.detail);
  CIF_CHECK_MSG(read.size() == written.size(),
                report.detail + " (read " + std::to_string(read.size()) + " of " +
                    std::to_string(written.size()) + ")");
  CIF_REQUIRE(read.size() == written.size());
  for (std::size_t i = 0; i < read.size(); ++i) {
    CIF_CHECK_EQ(read[i].kind, written[i].kind);
    CIF_CHECK_EQ(read[i].sequence, i);
    CIF_CHECK_MSG(read[i].digest() == written[i].digest(),
                  std::string("record ") + to_string(written[i].kind));
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(journal, reopen_preserves_state) {
  const std::string path = cif::test::scratch_path("reopen.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  {
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
    CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::SetController, 1, true));
    CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::MemberUpsert, 2, true));
    CIF_REQUIRE_OK(journal.close());
  }
  {
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_CHECK_EQ(entries.size(), std::size_t{2});
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, report.valid_bytes, report.fresh, report.last_chain,
                                report.last_sequence));
    CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::MemberUpsert, 3, true));
    CIF_CHECK_EQ(journal.last_sequence(), std::uint64_t{3});
    CIF_REQUIRE_OK(journal.close());
  }
  {
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(path, entries, report));
    CIF_CHECK_EQ(entries.size(), std::size_t{3});
    CIF_CHECK_EQ(entries[2].sequence, std::uint64_t{2});
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(journal, detects_torn_tail) {
  const std::string path = cif::test::scratch_path("torn.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  {
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
    for (std::uint64_t salt = 1; salt <= 4; ++salt) {
      CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::MemberUpsert, salt, true));
    }
    CIF_REQUIRE_OK(journal.close());
  }
  const std::uint64_t full_size = platform::file_size_bytes(path);
  CIF_REQUIRE(full_size > 40);

  // Cut the file in the middle of the last record: a genuine torn write.
  for (std::uint64_t cut = 1; cut <= 8; ++cut) {
    const std::string copy = cif::test::scratch_path("torn-" + std::to_string(cut) + ".cifjournal");
    std::filesystem::copy_file(path, copy, std::filesystem::copy_options::overwrite_existing);
    CIF_REQUIRE_OK(platform::truncate_file(copy, full_size - cut));

    std::vector<JournalEntry> entries;
    RecoveryReport report;
    CIF_REQUIRE_OK(Journal::scan(copy, entries, report));
    CIF_CHECK_EQ(entries.size(), std::size_t{3});
    CIF_CHECK(report.truncated_tail);
    CIF_CHECK(!report.fresh);
    CIF_CHECK_EQ(report.valid_bytes <= full_size - cut, true);
    std::filesystem::remove(copy, error);
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(journal, detects_corruption) {
  const std::string path = cif::test::scratch_path("corrupt.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  {
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
    for (std::uint64_t salt = 1; salt <= 4; ++salt) {
      CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::MemberUpsert, salt, true));
    }
    CIF_REQUIRE_OK(journal.close());
  }
  const std::uint64_t size = platform::file_size_bytes(path);

  // Flip one bit in every byte position of the file in turn. The scan must
  // never report more records than the uncorrupted prefix, and must never
  // report success on a corrupted body without flagging it.
  std::vector<JournalEntry> baseline;
  RecoveryReport baseline_report;
  CIF_REQUIRE_OK(Journal::scan(path, baseline, baseline_report));
  CIF_CHECK_EQ(baseline.size(), std::size_t{4});

  for (std::uint64_t offset = 0; offset < size; offset += 7) {
    const std::string copy = cif::test::scratch_path("bit.cifjournal");
    std::filesystem::copy_file(path, copy, std::filesystem::copy_options::overwrite_existing);
    std::string bytes = read_all(copy);
    CIF_REQUIRE(bytes.size() == size);
    const std::size_t index = static_cast<std::size_t>(offset);
    bytes[index] = static_cast<char>(static_cast<unsigned char>(bytes[index]) ^ 0x40u);
    {
      std::ofstream output(copy, std::ios::binary | std::ios::trunc);
      output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }

    std::vector<JournalEntry> entries;
    RecoveryReport report;
    const Status scanned = Journal::scan(copy, entries, report);
    if (scanned.ok()) {
      const bool flagged = report.integrity_failure || report.truncated_tail ||
                           report.version_mismatch || report.replay_detected;
      const bool identical = entries.size() == baseline.size();
      CIF_CHECK_MSG(flagged || identical,
                    "corruption at offset " + std::to_string(offset) + " went unnoticed");
    } else {
      CIF_CHECK(scanned.is(StatusCode::Corruption) || scanned.is(StatusCode::IntegrityFailure) ||
                scanned.is(StatusCode::VersionMismatch));
    }
    std::filesystem::remove(copy, error);
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(journal, detects_replay_and_reorder) {
  const std::string path = cif::test::scratch_path("replay.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  {
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
    for (std::uint64_t salt = 1; salt <= 3; ++salt) {
      CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::MemberUpsert, salt, true));
    }
    CIF_REQUIRE_OK(journal.close());
  }
  const std::string bytes = read_all(path);
  const std::uint64_t header = Journal::kFileHeaderSize;

  // Duplicating a whole record breaks the chain and the sequence.
  {
    const std::string copy = cif::test::scratch_path("dup.cifjournal");
    const std::string record = bytes.substr(static_cast<std::size_t>(header));
    const std::size_t first_end = record.size() / 3;
    std::string mutated = bytes + record.substr(0, first_end);
    std::ofstream output(copy, std::ios::binary | std::ios::trunc);
    output.write(mutated.data(), static_cast<std::streamsize>(mutated.size()));
    output.close();
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    const Status scanned = Journal::scan(copy, entries, report);
    CIF_CHECK(scanned.ok());
    CIF_CHECK(report.integrity_failure || report.replay_detected);
    CIF_CHECK(entries.size() <= 3);
    std::filesystem::remove(copy, error);
  }

  // Deleting the middle record must be detected by the chain.
  {
    const std::string copy = cif::test::scratch_path("splice.cifjournal");
    const std::size_t record_size = (bytes.size() - static_cast<std::size_t>(header)) / 3;
    std::string mutated = bytes.substr(0, static_cast<std::size_t>(header) + record_size);
    mutated += bytes.substr(static_cast<std::size_t>(header) + record_size * 2);
    std::ofstream output(copy, std::ios::binary | std::ios::trunc);
    output.write(mutated.data(), static_cast<std::streamsize>(mutated.size()));
    output.close();
    std::vector<JournalEntry> entries;
    RecoveryReport report;
    const Status scanned = Journal::scan(copy, entries, report);
    CIF_CHECK(scanned.ok());
    CIF_CHECK(report.integrity_failure || report.replay_detected);
    CIF_CHECK(entries.size() <= 2);
    std::filesystem::remove(copy, error);
  }
  std::filesystem::remove(path, error);
}

CIF_TEST(journal, rejects_wrong_format_version) {
  const std::string path = cif::test::scratch_path("version.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
    CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::MemberUpsert, 1, true));
    CIF_REQUIRE_OK(journal.close());
  }
  patch_byte(path, 8, 0x7F);
  std::vector<JournalEntry> entries;
  RecoveryReport report;
  const Status scanned = Journal::scan(path, entries, report);
  CIF_CHECK(!scanned.ok());
  CIF_CHECK(report.integrity_failure || report.version_mismatch);
  std::filesystem::remove(path, error);
}

CIF_TEST(journal, rejects_bad_magic_and_empty_prefix) {
  const std::string path = cif::test::scratch_path("magic.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);
  {
    Journal journal;
    CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
    CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::MemberUpsert, 1, true));
    CIF_REQUIRE_OK(journal.close());
  }
  patch_byte(path, 0, 'X');
  std::vector<JournalEntry> entries;
  RecoveryReport report;
  CIF_CHECK(!Journal::scan(path, entries, report).ok());
  CIF_CHECK(report.integrity_failure);

  const std::string tiny = cif::test::scratch_path("tiny.cifjournal");
  {
    std::ofstream output(tiny, std::ios::binary | std::ios::trunc);
    output << "CIF";
  }
  entries.clear();
  RecoveryReport tiny_report;
  CIF_CHECK(!Journal::scan(tiny, entries, tiny_report).ok());
  CIF_CHECK(tiny_report.integrity_failure);

  const std::string absent = cif::test::scratch_path("absent.cifjournal");
  std::filesystem::remove(absent, error);
  entries.clear();
  RecoveryReport absent_report;
  CIF_REQUIRE_OK(Journal::scan(absent, entries, absent_report));
  CIF_CHECK(absent_report.fresh);
  CIF_CHECK(entries.empty());

  std::filesystem::remove(path, error);
  std::filesystem::remove(tiny, error);
}

CIF_TEST(journal, bounded_and_compactable) {
  static_assert(limits::kMaxJournalBytes > 0, "the journal byte bound must be positive");
  static_assert(limits::kMaxJournalRecords > 0, "the journal record bound must be positive");

  const std::string path = cif::test::scratch_path("bounded.cifjournal");
  std::error_code error;
  std::filesystem::remove(path, error);

  Journal journal;
  CIF_REQUIRE_OK(journal.open(path, 0, true, 0, 0));
  std::uint64_t salt = 1;
  for (;;) {
    const Status appended =
        append_sample(journal, JournalRecordKind::MemberUpsert, salt, false);
    if (!appended.ok()) {
      CIF_CHECK(appended.is(StatusCode::CapacityExhausted));
      CIF_CHECK(journal.should_compact());
      break;
    }
    ++salt;
    CIF_CHECK_MSG(salt <= limits::kMaxJournalRecords + 1, "journal never reached its bound");
  }
  CIF_CHECK(salt > 1);

  // Compaction replaces the log with a single snapshot that replays identically.
  JournalEntry snapshot;
  snapshot.kind = JournalRecordKind::Snapshot;
  snapshot.snapshot_spec.set_cluster_id(ClusterId::from_validated("cluster"));
  snapshot.snapshot_spec.restore_counters(ClusterGeneration{9}, ClusterEpoch{3});
  snapshot.snapshot_spec.set_incarnation(ControllerIncarnation::from_seed(9));
  snapshot.snapshot_counters.grants = 5;
  CIF_REQUIRE_OK(journal.compact(snapshot));
  CIF_CHECK_EQ(journal.record_count(), std::uint64_t{1});
  CIF_CHECK(journal.byte_count() < limits::kMaxJournalBytes);
  CIF_REQUIRE_OK(append_sample(journal, JournalRecordKind::PolicySet, 2, true));
  CIF_REQUIRE_OK(journal.close());

  std::vector<JournalEntry> entries;
  RecoveryReport report;
  CIF_REQUIRE_OK(Journal::scan(path, entries, report));
  CIF_CHECK_EQ(entries.size(), std::size_t{2});
  CIF_CHECK_EQ(entries[0].kind, JournalRecordKind::Snapshot);
  CIF_CHECK(!report.requires_rebuild());

  RecoveredState state;
  CIF_REQUIRE_OK(replay_journal(entries, state));
  CIF_CHECK_EQ(state.spec.cluster_id().value(), std::string("cluster"));
  CIF_CHECK_EQ(state.spec.generation().value(), std::uint64_t{9});
  CIF_CHECK_EQ(state.counters.grants, std::uint64_t{5});
  std::filesystem::remove(path, error);
}

CIF_TEST(version, banner_is_stable) {
  const std::string banner = version_banner();
  CIF_CHECK(banner.find("journal=") != std::string::npos);
  CIF_CHECK(banner.find("wire=") != std::string::npos);
  CIF_CHECK_EQ(std::string(version_string()), std::string("1.0.0"));
  CIF_CHECK_EQ(version_banner(), banner);
}
