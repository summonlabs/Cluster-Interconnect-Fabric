// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The cluster domain model: member domains, endpoints, service groups,
// resources, topology paths, maintenance exclusions and capacity obligations.
//
// Boundaries: CIF does not discover members, it is told about them. A member is
// a *governed participant* published by a rack/pod domain authority; the digest
// and generation below are that authority's statement, echoed verbatim. CIF
// never invents a member, never probes hardware and never claims a physical
// property that was not declared to it.
#ifndef CIF_MODEL_HPP
#define CIF_MODEL_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "cif/bytes.hpp"
#include "cif/hash.hpp"
#include "cif/identity.hpp"
#include "cif/limits.hpp"
#include "cif/status.hpp"

namespace cif {

/// Lifecycle of a governed member as published by its domain authority.
enum class MemberLifecycle : std::uint8_t {
  Enlisted = 0,     ///< Known, not yet carrying traffic.
  Active,           ///< Fully operational.
  Draining,         ///< Still serving, no new relationships should be created.
  Maintenance,      ///< Administratively out.
  Faulted,          ///< Declared failed by its domain authority.
  Partitioned,      ///< Unreachable / split from the ruling controller.
  Removed,          ///< Retired; identity must never be reused.
};

[[nodiscard]] const char* to_string(MemberLifecycle value) noexcept;
[[nodiscard]] bool is_operational(MemberLifecycle value) noexcept;
[[nodiscard]] bool is_present(MemberLifecycle value) noexcept;
[[nodiscard]] bool is_terminal(MemberLifecycle value) noexcept;

/// Operational state of a declared topology path.
enum class PathState : std::uint8_t {
  Operational = 0,
  Degraded,
  Down,
  Maintenance,
  Unknown,
};

[[nodiscard]] const char* to_string(PathState value) noexcept;

/// What to do when a maintenance exclusion covers a participant.
enum class MaintenanceMode : std::uint8_t {
  Refuse = 0,  ///< No new authority while the exclusion is active.
  Degrade,     ///< Authority granted, explicitly reduced and recorded.
  Allow,       ///< Exclusion is informational only.
};

[[nodiscard]] const char* to_string(MaintenanceMode value) noexcept;

// ---------------------------------------------------------------------------
// Locality / failure domain
// ---------------------------------------------------------------------------
/// An ordered locality path from the broadest domain to the narrowest, e.g.
/// {dc-a, room-1, rack-07, pod-3}. Failure domains are prefixes of this path.
class LocalityPath {
 public:
  static constexpr std::size_t kMaxDepth = limits::kMaxLocalityDepth;

  LocalityPath() = default;

  /// Parses "dc-a/room-1/rack-07". Rejects empty labels, >kMaxDepth labels,
  /// invalid identifier bytes, leading/trailing/doubled separators.
  [[nodiscard]] static bool parse(std::string_view text, LocalityPath& out) noexcept;

  [[nodiscard]] bool push(std::string_view label);
  void clear() noexcept { labels_.clear(); }

  [[nodiscard]] const std::vector<std::string>& labels() const noexcept { return labels_; }
  [[nodiscard]] std::size_t depth() const noexcept { return labels_.size(); }
  [[nodiscard]] bool empty() const noexcept { return labels_.empty(); }
  [[nodiscard]] std::string_view label(std::size_t index) const noexcept { return labels_[index]; }

  [[nodiscard]] std::string to_string() const;

  /// Key of the failure domain at the given level (labels[0..level) joined).
  [[nodiscard]] std::string domain_key(std::size_t level) const;

  /// True when this path is a prefix of (or equal to) 'other'.
  [[nodiscard]] bool is_prefix_of(const LocalityPath& other) const noexcept;

  /// Number of leading labels shared with 'other'.
  [[nodiscard]] static std::size_t common_prefix(const LocalityPath& a, const LocalityPath& b) noexcept;

  /// Number of distinct failure-domain keys at 'level' among 'paths'.
  [[nodiscard]] static std::size_t distinct_domains(const std::vector<const LocalityPath*>& paths,
                                                    std::size_t level);

  friend bool operator==(const LocalityPath& a, const LocalityPath& b) noexcept {
    return a.labels_ == b.labels_;
  }
  friend bool operator!=(const LocalityPath& a, const LocalityPath& b) noexcept { return !(a == b); }
  friend bool operator<(const LocalityPath& a, const LocalityPath& b) noexcept {
    return a.labels_ < b.labels_;
  }

 private:
  std::vector<std::string> labels_;
};

// ---------------------------------------------------------------------------
// Member domain entities
// ---------------------------------------------------------------------------
struct Endpoint {
  EndpointId id;
  LocalityPath locality;                   ///< Narrower locality than the member, when declared.
  std::vector<ServiceGroupId> service_groups;
  std::uint64_t capacity_class = 0;        ///< Caller declared class; opaque to CIF.
};

struct Resource {
  ResourceId id;
  std::string kind;                        ///< Opaque label (e.g. "credit-pool").
  std::uint64_t total_units = 0;
  ReservationGeneration reservation_generation{};
  bool reservable = true;
};

struct Member {
  MemberId id;
  MemberDomainId domain;                   ///< Governing rack/pod domain authority.
  MemberGeneration generation{};
  Digest256 digest{};                      ///< Domain authority's statement about this member.
  MemberLifecycle lifecycle = MemberLifecycle::Enlisted;
  LocalityPath locality;
  std::vector<Endpoint> endpoints;
  std::vector<ServiceGroupId> services;    ///< Service groups offered by this member.
  std::vector<Resource> resources;
  Tick last_observed{};
  std::string note;

  [[nodiscard]] const Endpoint* find_endpoint(const EndpointId& endpoint_id) const noexcept;
  [[nodiscard]] const Resource* find_resource(const ResourceId& resource_id) const noexcept;
  [[nodiscard]] bool serves(const ServiceGroupId& service) const noexcept;
  [[nodiscard]] LocalityPath effective_locality(const EndpointId& endpoint) const;
};

struct Path {
  PathId id;
  PathGeneration generation{};
  MemberId source_member;
  EndpointId source_endpoint;
  MemberId destination_member;
  EndpointId destination_endpoint;
  std::vector<ResourceId> resources;
  std::uint64_t capacity_units = 0;        ///< Declared units this path can carry.
  bool exclusive = false;                  ///< At most one live grant may bind it.
  PathState state = PathState::Operational;
  std::uint32_t declared_hops = 0;         ///< Caller metadata; never authoritative.
};

struct MaintenanceExclusion {
  ExclusionId id;
  LocalityPath domain_prefix;              ///< Empty means "matches any locality".
  std::vector<MemberId> members;           ///< Empty means "matches any member".
  std::vector<PathId> paths;               ///< Empty means "matches any path".
  Tick valid_from{};
  Tick valid_to{};                         ///< Zero means open ended.
  MaintenanceMode mode = MaintenanceMode::Refuse;
  bool enabled = true;
  std::string reason;

  [[nodiscard]] bool active_at(Tick now) const noexcept;
  [[nodiscard]] bool covers_member(const Member& member, Tick now) const noexcept;
  [[nodiscard]] bool covers_path(const Path& path, Tick now) const noexcept;
};

struct CapacityObligation {
  ObligationId id;
  ServiceGroupId service;
  std::uint32_t min_distinct_failure_domains = 1;
  std::uint8_t failure_domain_level = 0;
  std::uint64_t min_units_per_domain = 0;
  bool enabled = true;
};

// ---------------------------------------------------------------------------
// Cluster specification
// ---------------------------------------------------------------------------
/// The authoritative statement of what the cluster is right now. Members, paths
/// and exclusions are held in id-sorted order so that the canonical encoding --
/// and therefore every digest taken over it -- is order independent.
class ClusterSpec {
 public:
  ClusterSpec() = default;

  // -- identity ------------------------------------------------------------
  [[nodiscard]] const ClusterId& cluster_id() const noexcept { return cluster_id_; }
  [[nodiscard]] ClusterGeneration generation() const noexcept { return generation_; }
  [[nodiscard]] ClusterEpoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] PolicyGeneration policy_generation() const noexcept { return policy_generation_; }
  [[nodiscard]] const ControllerIncarnation& incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] Tick tick() const noexcept { return tick_; }
  [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }

  Status set_cluster_id(const ClusterId& id);
  // Every mutator advances the revision. The digest cache below is keyed on it,
  // so a mutator that forgot to do so would hand out a stale digest.
  void set_incarnation(ControllerIncarnation incarnation) noexcept {
    incarnation_ = incarnation;
    ++revision_;
  }
  void set_policy_generation(PolicyGeneration value) noexcept {
    policy_generation_ = value;
    ++revision_;
  }
  void set_tick(Tick value) noexcept {
    tick_ = value;
    ++revision_;
  }

  /// Advances the cluster generation. Callers must have already made the
  /// change; the generation is the statement that "the spec changed".
  Status bump_generation();
  /// Advances the epoch for a new controller incarnation.
  Status begin_epoch(ControllerIncarnation incarnation, PolicyGeneration policy);
  /// Marks a spec revision bump without changing generations (used by recovery).
  void note_revision() noexcept { ++revision_; }

  /// Restores generation and epoch verbatim. Used only by journal replay, where
  /// the recorded counters are the historical truth and must be adopted, never
  /// re-derived.
  void restore_counters(ClusterGeneration generation, ClusterEpoch epoch) noexcept {
    generation_ = generation;
    epoch_ = epoch;
    ++revision_;
  }


  // -- members -------------------------------------------------------------
  [[nodiscard]] const std::vector<Member>& members() const noexcept { return members_; }
  [[nodiscard]] const Member* find_member(const MemberId& id) const noexcept;
  [[nodiscard]] std::size_t member_count() const noexcept { return members_.size(); }

  Status upsert_member(Member member);
  Status remove_member(const MemberId& id);
  Status set_member_lifecycle(const MemberId& id, MemberLifecycle lifecycle, Tick at);

  // -- paths ---------------------------------------------------------------
  [[nodiscard]] const std::vector<Path>& paths() const noexcept { return paths_; }
  [[nodiscard]] const Path* find_path(const PathId& id) const noexcept;
  [[nodiscard]] std::size_t path_count() const noexcept { return paths_.size(); }

  Status upsert_path(Path path);
  Status remove_path(const PathId& id);
  Status set_path_state(const PathId& id, PathState state);

  // -- exclusions ----------------------------------------------------------
  [[nodiscard]] const std::vector<MaintenanceExclusion>& exclusions() const noexcept {
    return exclusions_;
  }
  [[nodiscard]] const MaintenanceExclusion* find_exclusion(const ExclusionId& id) const noexcept;
  Status upsert_exclusion(MaintenanceExclusion exclusion);
  Status remove_exclusion(const ExclusionId& id);

  /// First active exclusion covering this member, in id order. Deterministic.
  [[nodiscard]] const MaintenanceExclusion* exclusion_for_member(const Member& member) const noexcept;
  [[nodiscard]] const MaintenanceExclusion* exclusion_for_path(const Path& path) const noexcept;

  // -- obligations ---------------------------------------------------------
  [[nodiscard]] const std::vector<CapacityObligation>& obligations() const noexcept {
    return obligations_;
  }
  [[nodiscard]] const CapacityObligation* find_obligation(const ObligationId& id) const noexcept;
  Status upsert_obligation(CapacityObligation obligation);
  Status remove_obligation(const ObligationId& id);

  // -- integrity -----------------------------------------------------------
  /// Full structural validation. Returns the first violation found.
  [[nodiscard]] Status validate() const;

  /// Canonical encoding of everything that affects authority.
  void encode(ByteWriter& writer) const;

  /// Inverse of encode(). Does not bump generations: a decoded specification is
  /// a historical statement and must be adopted verbatim, never re-stamped.
  [[nodiscard]] static bool decode(ByteReader& reader, ClusterSpec& out);

  /// Digest of the canonical encoding of the full specification.
  [[nodiscard]] Digest256 digest() const;

  /// Digest of everything except the controller incarnation and epoch, i.e. the
  /// "what" without the "who is ruling". Used to prove that a restart preserved
  /// the member/path set exactly.
  [[nodiscard]] Digest256 topology_digest() const;

 private:
  ClusterId cluster_id_{};
  ClusterGeneration generation_{};
  ClusterEpoch epoch_{};
  PolicyGeneration policy_generation_{};
  ControllerIncarnation incarnation_{};
  Tick tick_{};
  std::uint64_t revision_ = 0;

  std::vector<Member> members_;            ///< Sorted by id.
  std::vector<Path> paths_;                ///< Sorted by id.
  std::vector<MaintenanceExclusion> exclusions_;  ///< Sorted by id.
  std::vector<CapacityObligation> obligations_;   ///< Sorted by id.

  // Each digest carries its own revision key. Sharing one key would let
  // computing either digest mark the other as valid, and the other would then
  // be served as an all-zero digest -- a silent, catastrophic lie about
  // authoritative state.
  mutable std::uint64_t cached_spec_revision_ = std::numeric_limits<std::uint64_t>::max();
  mutable std::uint64_t cached_topology_revision_ = std::numeric_limits<std::uint64_t>::max();
  mutable Digest256 cached_spec_digest_{};
  mutable Digest256 cached_topology_digest_{};
};

/// Fixed, documented capability vocabulary. Any capability requested by a
/// contract that is not in this list is refused as UNSUPPORTED: CIF models
/// governance, not hardware.
[[nodiscard]] bool is_known_capability(std::string_view capability) noexcept;

/// Every known capability name, in canonical order. Used by tooling and by tests
/// that assert the vocabulary has not silently grown.
[[nodiscard]] const std::vector<std::string_view>& known_capabilities();

// ---------------------------------------------------------------------------
// Canonical codecs (used by the journal and by digest computation)
// ---------------------------------------------------------------------------
void encode_locality(ByteWriter& writer, const LocalityPath& locality);
[[nodiscard]] bool decode_locality(ByteReader& reader, LocalityPath& out);

void encode_member(ByteWriter& writer, const Member& member);
[[nodiscard]] bool decode_member(ByteReader& reader, Member& out);

void encode_path(ByteWriter& writer, const Path& path);
[[nodiscard]] bool decode_path(ByteReader& reader, Path& out);

void encode_exclusion(ByteWriter& writer, const MaintenanceExclusion& exclusion);
[[nodiscard]] bool decode_exclusion(ByteReader& reader, MaintenanceExclusion& out);

void encode_obligation(ByteWriter& writer, const CapacityObligation& obligation);
[[nodiscard]] bool decode_obligation(ByteReader& reader, CapacityObligation& out);

/// Digest of a member as the controller would re-publish it. Distinct from
/// Member::digest, which is the *domain authority's* statement.
[[nodiscard]] Digest256 member_state_digest(const Member& member);

}  // namespace cif

#endif  // CIF_MODEL_HPP
