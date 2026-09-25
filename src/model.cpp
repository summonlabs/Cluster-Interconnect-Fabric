#include "cif/model.hpp"

#include <algorithm>
#include <utility>

namespace cif {
namespace {

constexpr const char* kCapabilities[] = {
    // Governance-level capabilities CIF genuinely evaluates. Hardware and
    // transport capabilities are deliberately absent: see is_known_capability.
    "topology-path-binding",
    "exclusive-path-binding",
    "failure-domain-diversity",
    "maintenance-exclusion",
    "capacity-reservation",
};

template <typename Container, typename Key>
[[nodiscard]] auto find_sorted(const Container& container, const Key& key) {
  return std::lower_bound(container.begin(), container.end(), key,
                          [](const auto& element, const auto& value) { return element.id < value; });
}

template <typename Container, typename Value>
[[nodiscard]] std::size_t lower_bound_index(const Container& container, const Value& value) {
  return static_cast<std::size_t>(
      std::lower_bound(container.begin(), container.end(), value,
                       [](const auto& element, const auto& v) { return element.id < v; }) -
      container.begin());
}

}  // namespace

// ---------------------------------------------------------------------------
// Enum rendering
// ---------------------------------------------------------------------------
const char* to_string(MemberLifecycle value) noexcept {
  switch (value) {
    case MemberLifecycle::Enlisted: return "ENLISTED";
    case MemberLifecycle::Active: return "ACTIVE";
    case MemberLifecycle::Draining: return "DRAINING";
    case MemberLifecycle::Maintenance: return "MAINTENANCE";
    case MemberLifecycle::Faulted: return "FAULTED";
    case MemberLifecycle::Partitioned: return "PARTITIONED";
    case MemberLifecycle::Removed: return "REMOVED";
  }
  return "UNRECOGNISED_LIFECYCLE";
}

bool is_operational(MemberLifecycle value) noexcept { return value == MemberLifecycle::Active; }

bool is_present(MemberLifecycle value) noexcept { return value != MemberLifecycle::Removed; }

bool is_terminal(MemberLifecycle value) noexcept { return value == MemberLifecycle::Removed; }

const char* to_string(PathState value) noexcept {
  switch (value) {
    case PathState::Operational: return "OPERATIONAL";
    case PathState::Degraded: return "DEGRADED";
    case PathState::Down: return "DOWN";
    case PathState::Maintenance: return "MAINTENANCE";
    case PathState::Unknown: return "UNKNOWN";
  }
  return "UNRECOGNISED_PATH_STATE";
}

const char* to_string(MaintenanceMode value) noexcept {
  switch (value) {
    case MaintenanceMode::Refuse: return "REFUSE";
    case MaintenanceMode::Degrade: return "DEGRADE";
    case MaintenanceMode::Allow: return "ALLOW";
  }
  return "UNRECOGNISED_MAINTENANCE_MODE";
}

// ---------------------------------------------------------------------------
// LocalityPath
// ---------------------------------------------------------------------------
bool LocalityPath::parse(std::string_view text, LocalityPath& out) noexcept {
  if (text.empty() || text.size() > limits::kMaxLocalityDepth * (limits::kMaxIdentifierBytes + 1)) {
    return false;
  }
  LocalityPath parsed;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t slash = text.find('/', start);
    const std::size_t end = slash == std::string_view::npos ? text.size() : slash;
    const std::string_view label = text.substr(start, end - start);
    if (!is_valid_identifier(label, limits::kMaxIdentifierBytes)) {
      return false;
    }
    if (parsed.labels_.size() >= kMaxDepth) {
      return false;
    }
    parsed.labels_.emplace_back(label);
    if (slash == std::string_view::npos) {
      break;
    }
    start = slash + 1;
    if (start > text.size()) {
      return false;  // trailing separator
    }
  }
  if (parsed.labels_.empty()) {
    return false;
  }
  out = std::move(parsed);
  return true;
}

bool LocalityPath::push(std::string_view label) {
  if (labels_.size() >= kMaxDepth || !is_valid_identifier(label, limits::kMaxIdentifierBytes)) {
    return false;
  }
  labels_.emplace_back(label);
  return true;
}

std::string LocalityPath::to_string() const {
  std::string out;
  for (std::size_t i = 0; i < labels_.size(); ++i) {
    if (i != 0) {
      out.push_back('/');
    }
    out += labels_[i];
  }
  return out;
}

std::string LocalityPath::domain_key(std::size_t level) const {
  const std::size_t bounded = level < labels_.size() ? level : labels_.size();
  std::string out;
  for (std::size_t i = 0; i < bounded; ++i) {
    if (i != 0) {
      out.push_back('/');
    }
    out += labels_[i];
  }
  return out;
}

bool LocalityPath::is_prefix_of(const LocalityPath& other) const noexcept {
  if (labels_.size() > other.labels_.size()) {
    return false;
  }
  for (std::size_t i = 0; i < labels_.size(); ++i) {
    if (labels_[i] != other.labels_[i]) {
      return false;
    }
  }
  return true;
}

std::size_t LocalityPath::common_prefix(const LocalityPath& a, const LocalityPath& b) noexcept {
  const std::size_t limit = std::min(a.labels_.size(), b.labels_.size());
  std::size_t count = 0;
  while (count < limit && a.labels_[count] == b.labels_[count]) {
    ++count;
  }
  return count;
}

std::size_t LocalityPath::distinct_domains(const std::vector<const LocalityPath*>& paths,
                                           std::size_t level) {
  if (paths.empty()) {
    return 0;
  }
  std::vector<std::string> keys;
  keys.reserve(paths.size());
  for (const LocalityPath* path : paths) {
    if (path != nullptr) {
      keys.push_back(path->domain_key(level));
    }
  }
  std::sort(keys.begin(), keys.end());
  keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
  return keys.size();
}

// ---------------------------------------------------------------------------
// Member / Path / Exclusion / Obligation helpers
// ---------------------------------------------------------------------------
const Endpoint* Member::find_endpoint(const EndpointId& endpoint_id) const noexcept {
  const auto it = std::find_if(endpoints.begin(), endpoints.end(), [&endpoint_id](const Endpoint& endpoint) {
    return endpoint.id == endpoint_id;
  });
  return it == endpoints.end() ? nullptr : &*it;
}

const Resource* Member::find_resource(const ResourceId& resource_id) const noexcept {
  const auto it = std::find_if(resources.begin(), resources.end(), [&resource_id](const Resource& resource) {
    return resource.id == resource_id;
  });
  return it == resources.end() ? nullptr : &*it;
}

bool Member::serves(const ServiceGroupId& service) const noexcept {
  return std::find(services.begin(), services.end(), service) != services.end();
}

LocalityPath Member::effective_locality(const EndpointId& endpoint) const {
  const Endpoint* found = find_endpoint(endpoint);
  if (found != nullptr && !found->locality.empty()) {
    return found->locality;
  }
  return locality;
}

bool MaintenanceExclusion::active_at(Tick now) const noexcept {
  if (!enabled) {
    return false;
  }
  if (now < valid_from) {
    return false;
  }
  if (!valid_to.is_zero() && now > valid_to) {
    return false;
  }
  return true;
}

bool MaintenanceExclusion::covers_member(const Member& member, Tick now) const noexcept {
  if (!active_at(now)) {
    return false;
  }
  if (!members.empty() &&
      std::find(members.begin(), members.end(), member.id) == members.end()) {
    return false;
  }
  if (!domain_prefix.empty() && !domain_prefix.is_prefix_of(member.locality)) {
    return false;
  }
  return true;
}

bool MaintenanceExclusion::covers_path(const Path& path, Tick now) const noexcept {
  if (!active_at(now)) {
    return false;
  }
  if (!paths.empty() && std::find(paths.begin(), paths.end(), path.id) == paths.end()) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// ClusterSpec
// ---------------------------------------------------------------------------
Status ClusterSpec::set_cluster_id(const ClusterId& id) {
  if (id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "cluster id must not be empty");
  }
  if (!cluster_id_.empty() && cluster_id_ != id) {
    return Status::error(StatusCode::StateMismatch,
                         "cluster id is immutable for the lifetime of a controller state file");
  }
  cluster_id_ = id;
  return Status::success();
}

Status ClusterSpec::bump_generation() {
  if (!generation_.can_advance()) {
    return Status::error(StatusCode::CapacityExhausted,
                         "cluster generation is saturated at UINT64_MAX");
  }
  generation_ = generation_.advanced();
  ++revision_;
  return Status::success();
}

Status ClusterSpec::begin_epoch(ControllerIncarnation incarnation, PolicyGeneration policy) {
  if (!epoch_.can_advance()) {
    return Status::error(StatusCode::CapacityExhausted, "cluster epoch is saturated at UINT64_MAX");
  }
  if (!generation_.can_advance()) {
    return Status::error(StatusCode::CapacityExhausted,
                         "cluster generation is saturated at UINT64_MAX");
  }
  epoch_ = epoch_.advanced();
  // A new epoch changes who rules, and therefore changes what any caller may
  // rely on. The cluster generation moves with it so that a caller pinning the
  // previous coordinate is told it is stale rather than being served an answer
  // it cannot distinguish from a fresh one.
  generation_ = generation_.advanced();
  incarnation_ = incarnation;
  if (policy >= policy_generation_) {
    policy_generation_ = policy;
  }
  ++revision_;
  return Status::success();
}

const Member* ClusterSpec::find_member(const MemberId& id) const noexcept {
  const auto it = find_sorted(members_, id);
  if (it == members_.end() || it->id != id) {
    return nullptr;
  }
  return &*it;
}

Status ClusterSpec::upsert_member(Member member) {
  if (member.id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "member id must not be empty");
  }
  if (member.endpoints.size() > limits::kMaxEndpointsPerMember) {
    return Status::error(StatusCode::LimitExceeded, "member declares too many endpoints");
  }
  if (member.services.size() > limits::kMaxServicesPerMember) {
    return Status::error(StatusCode::LimitExceeded, "member declares too many service groups");
  }
  if (member.resources.size() > limits::kMaxResourcesPerMember) {
    return Status::error(StatusCode::LimitExceeded, "member declares too many resources");
  }
  if (!is_valid_utf8(member.note)) {
    return Status::error(StatusCode::InvalidArgument, "member note is not valid UTF-8");
  }
  if (member.note.size() > limits::kMaxNoteBytes) {
    return Status::error(StatusCode::LimitExceeded, "member note exceeds the configured bound");
  }
  for (const Endpoint& endpoint : member.endpoints) {
    if (endpoint.id.empty()) {
      return Status::error(StatusCode::InvalidArgument, "endpoint id must not be empty");
    }
  }
  if (!member.digest.is_zero() && member.digest.bytes().size() != Digest256::kSize) {
    return Status::error(StatusCode::Internal, "unreachable digest size");
  }

  const std::size_t index = lower_bound_index(members_, member.id);
  if (index < members_.size() && members_[index].id == member.id) {
    const Member& existing = members_[index];
    if (member.generation < existing.generation) {
      return Status::error(StatusCode::StateMismatch,
                           "member update would move generation backwards for " + member.id.to_string());
    }
    if (member.generation == existing.generation && member.digest != existing.digest &&
        !existing.digest.is_zero()) {
      return Status::error(StatusCode::DuplicateIdentity,
                           "member " + member.id.to_string() +
                               " re-published at the same generation with a different digest");
    }
    // Same identity, same generation, same digest: idempotent replacement is
    // allowed but must not silently resurrect a removed member.
    if (is_terminal(existing.lifecycle) && !is_terminal(member.lifecycle)) {
      return Status::error(StatusCode::StateMismatch,
                           "member " + member.id.to_string() +
                               " was removed and cannot be brought back at the same generation");
    }
    members_[index] = std::move(member);
  } else {
    if (members_.size() >= limits::kMaxMembers) {
      return Status::error(StatusCode::CapacityExhausted, "cluster member table is full");
    }
    members_.insert(members_.begin() + static_cast<std::ptrdiff_t>(index), std::move(member));
  }
  ++revision_;
  return bump_generation();
}

Status ClusterSpec::remove_member(const MemberId& id) {
  const std::size_t index = lower_bound_index(members_, id);
  if (index >= members_.size() || members_[index].id != id) {
    return Status::error(StatusCode::NotFound, "member " + id.to_string() + " is not present");
  }
  // Retirement is a lifecycle transition, not erasure: identity must never be
  // reused, so the record is kept with lifecycle REMOVED.
  members_[index].lifecycle = MemberLifecycle::Removed;
  members_[index].endpoints.clear();
  members_[index].resources.clear();
  members_[index].services.clear();
  ++revision_;
  return bump_generation();
}

Status ClusterSpec::set_member_lifecycle(const MemberId& id, MemberLifecycle lifecycle, Tick at) {
  const std::size_t index = lower_bound_index(members_, id);
  if (index >= members_.size() || members_[index].id != id) {
    return Status::error(StatusCode::NotFound, "member " + id.to_string() + " is not present");
  }
  Member& member = members_[index];
  if (is_terminal(member.lifecycle) && !is_terminal(lifecycle)) {
    return Status::error(StatusCode::StateMismatch,
                         "member " + id.to_string() + " is retired and cannot be reactivated");
  }
  member.lifecycle = lifecycle;
  member.last_observed = at;
  ++revision_;
  return bump_generation();
}

const Path* ClusterSpec::find_path(const PathId& id) const noexcept {
  const auto it = find_sorted(paths_, id);
  if (it == paths_.end() || it->id != id) {
    return nullptr;
  }
  return &*it;
}

Status ClusterSpec::upsert_path(Path path) {
  if (path.id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "path id must not be empty");
  }
  if (path.source_member.empty() || path.destination_member.empty()) {
    return Status::error(StatusCode::InvalidArgument, "path must name both endpoints' members");
  }
  if (path.resources.size() > limits::kMaxResourcesPerPath) {
    return Status::error(StatusCode::LimitExceeded, "path references too many resources");
  }
  const std::size_t index = lower_bound_index(paths_, path.id);
  if (index < paths_.size() && paths_[index].id == path.id) {
    if (path.generation < paths_[index].generation) {
      return Status::error(StatusCode::StateMismatch,
                           "path update would move generation backwards for " + path.id.to_string());
    }
    paths_[index] = std::move(path);
  } else {
    if (paths_.size() >= limits::kMaxPaths) {
      return Status::error(StatusCode::CapacityExhausted, "cluster path table is full");
    }
    paths_.insert(paths_.begin() + static_cast<std::ptrdiff_t>(index), std::move(path));
  }
  ++revision_;
  return bump_generation();
}

Status ClusterSpec::remove_path(const PathId& id) {
  const std::size_t index = lower_bound_index(paths_, id);
  if (index >= paths_.size() || paths_[index].id != id) {
    return Status::error(StatusCode::NotFound, "path " + id.to_string() + " is not present");
  }
  paths_.erase(paths_.begin() + static_cast<std::ptrdiff_t>(index));
  ++revision_;
  return bump_generation();
}

Status ClusterSpec::set_path_state(const PathId& id, PathState state) {
  const std::size_t index = lower_bound_index(paths_, id);
  if (index >= paths_.size() || paths_[index].id != id) {
    return Status::error(StatusCode::NotFound, "path " + id.to_string() + " is not present");
  }
  paths_[index].state = state;
  ++revision_;
  return bump_generation();
}

const MaintenanceExclusion* ClusterSpec::find_exclusion(const ExclusionId& id) const noexcept {
  const auto it = find_sorted(exclusions_, id);
  if (it == exclusions_.end() || it->id != id) {
    return nullptr;
  }
  return &*it;
}

Status ClusterSpec::upsert_exclusion(MaintenanceExclusion exclusion) {
  if (exclusion.id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "exclusion id must not be empty");
  }
  if (exclusion.members.size() > limits::kMaxExclusionMembers) {
    return Status::error(StatusCode::LimitExceeded, "exclusion names too many members");
  }
  if (!is_valid_utf8(exclusion.reason) || exclusion.reason.size() > limits::kMaxNoteBytes) {
    return Status::error(StatusCode::InvalidArgument, "exclusion reason is not acceptable text");
  }
  if (!exclusion.valid_to.is_zero() && exclusion.valid_to < exclusion.valid_from) {
    return Status::error(StatusCode::InvalidArgument, "exclusion window ends before it starts");
  }
  const std::size_t index = lower_bound_index(exclusions_, exclusion.id);
  if (index < exclusions_.size() && exclusions_[index].id == exclusion.id) {
    exclusions_[index] = std::move(exclusion);
  } else {
    if (exclusions_.size() >= limits::kMaxExclusions) {
      return Status::error(StatusCode::CapacityExhausted, "exclusion table is full");
    }
    exclusions_.insert(exclusions_.begin() + static_cast<std::ptrdiff_t>(index), std::move(exclusion));
  }
  ++revision_;
  return bump_generation();
}

Status ClusterSpec::remove_exclusion(const ExclusionId& id) {
  const std::size_t index = lower_bound_index(exclusions_, id);
  if (index >= exclusions_.size() || exclusions_[index].id != id) {
    return Status::error(StatusCode::NotFound, "exclusion " + id.to_string() + " is not present");
  }
  exclusions_.erase(exclusions_.begin() + static_cast<std::ptrdiff_t>(index));
  ++revision_;
  return bump_generation();
}

const MaintenanceExclusion* ClusterSpec::exclusion_for_member(const Member& member) const noexcept {
  for (const MaintenanceExclusion& exclusion : exclusions_) {
    if (exclusion.covers_member(member, tick_)) {
      return &exclusion;
    }
  }
  return nullptr;
}

const MaintenanceExclusion* ClusterSpec::exclusion_for_path(const Path& path) const noexcept {
  for (const MaintenanceExclusion& exclusion : exclusions_) {
    if (exclusion.covers_path(path, tick_)) {
      return &exclusion;
    }
  }
  return nullptr;
}

const CapacityObligation* ClusterSpec::find_obligation(const ObligationId& id) const noexcept {
  const auto it = find_sorted(obligations_, id);
  if (it == obligations_.end() || it->id != id) {
    return nullptr;
  }
  return &*it;
}

Status ClusterSpec::upsert_obligation(CapacityObligation obligation) {
  if (obligation.id.empty() || obligation.service.empty()) {
    return Status::error(StatusCode::InvalidArgument, "obligation must name an id and a service group");
  }
  if (obligation.failure_domain_level > static_cast<std::uint8_t>(LocalityPath::kMaxDepth)) {
    return Status::error(StatusCode::InvalidArgument, "obligation failure-domain level is out of range");
  }
  const std::size_t index = lower_bound_index(obligations_, obligation.id);
  if (index < obligations_.size() && obligations_[index].id == obligation.id) {
    obligations_[index] = std::move(obligation);
  } else {
    if (obligations_.size() >= limits::kMaxObligations) {
      return Status::error(StatusCode::CapacityExhausted, "obligation table is full");
    }
    obligations_.insert(obligations_.begin() + static_cast<std::ptrdiff_t>(index), std::move(obligation));
  }
  ++revision_;
  return bump_generation();
}

Status ClusterSpec::remove_obligation(const ObligationId& id) {
  const std::size_t index = lower_bound_index(obligations_, id);
  if (index >= obligations_.size() || obligations_[index].id != id) {
    return Status::error(StatusCode::NotFound, "obligation " + id.to_string() + " is not present");
  }
  obligations_.erase(obligations_.begin() + static_cast<std::ptrdiff_t>(index));
  ++revision_;
  return bump_generation();
}

Status ClusterSpec::validate() const {
  if (cluster_id_.empty()) {
    return Status::error(StatusCode::InvalidArgument, "cluster id is not set");
  }
  for (std::size_t i = 1; i < members_.size(); ++i) {
    if (members_[i].id == members_[i - 1].id) {
      return Status::error(StatusCode::DuplicateIdentity,
                           "duplicate member id " + members_[i].id.to_string());
    }
    if (members_[i].id < members_[i - 1].id) {
      return Status::error(StatusCode::Internal, "member table is not sorted");
    }
  }
  for (std::size_t i = 1; i < paths_.size(); ++i) {
    if (paths_[i].id == paths_[i - 1].id) {
      return Status::error(StatusCode::DuplicateIdentity, "duplicate path id " + paths_[i].id.to_string());
    }
  }
  for (const Path& path : paths_) {
    if (find_member(path.source_member) == nullptr) {
      return Status::error(StatusCode::NotFound,
                           "path " + path.id.to_string() + " references unknown source member");
    }
    if (find_member(path.destination_member) == nullptr) {
      return Status::error(StatusCode::NotFound,
                           "path " + path.id.to_string() + " references unknown destination member");
    }
  }
  for (const MaintenanceExclusion& exclusion : exclusions_) {
    for (const MemberId& member : exclusion.members) {
      if (find_member(member) == nullptr) {
        return Status::error(StatusCode::NotFound,
                             "exclusion " + exclusion.id.to_string() + " references unknown member");
      }
    }
    for (const PathId& path : exclusion.paths) {
      if (find_path(path) == nullptr) {
        return Status::error(StatusCode::NotFound,
                             "exclusion " + exclusion.id.to_string() + " references unknown path");
      }
    }
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------
void encode_locality(ByteWriter& writer, const LocalityPath& locality) {
  writer.count(locality.depth());
  for (const std::string& label : locality.labels()) {
    writer.text(label);
  }
}

bool decode_locality(ByteReader& reader, LocalityPath& out) {
  std::size_t depth = 0;
  if (!reader.count(LocalityPath::kMaxDepth, depth)) {
    return false;
  }
  LocalityPath parsed;
  for (std::size_t i = 0; i < depth; ++i) {
    std::string label;
    if (!reader.text(label, limits::kMaxIdentifierBytes)) {
      return false;
    }
    if (!parsed.push(label)) {
      reader.fail(StatusCode::Corruption, "locality label rejected by the identifier grammar");
      return false;
    }
  }
  out = std::move(parsed);
  return true;
}

void encode_member(ByteWriter& writer, const Member& member) {
  encode_id(writer, member.id);
  encode_id(writer, member.domain);
  encode_counter(writer, member.generation);
  writer.digest(member.digest);
  writer.u8(static_cast<std::uint8_t>(member.lifecycle));
  encode_locality(writer, member.locality);
  writer.count(member.endpoints.size());
  for (const Endpoint& endpoint : member.endpoints) {
    encode_id(writer, endpoint.id);
    encode_locality(writer, endpoint.locality);
    writer.count(endpoint.service_groups.size());
    for (const ServiceGroupId& service : endpoint.service_groups) {
      encode_id(writer, service);
    }
    writer.u64(endpoint.capacity_class);
  }
  writer.count(member.services.size());
  for (const ServiceGroupId& service : member.services) {
    encode_id(writer, service);
  }
  writer.count(member.resources.size());
  for (const Resource& resource : member.resources) {
    encode_id(writer, resource.id);
    writer.text(resource.kind);
    writer.u64(resource.total_units);
    encode_counter(writer, resource.reservation_generation);
    writer.boolean(resource.reservable);
  }
  encode_counter(writer, member.last_observed);
  writer.text(member.note);
}

bool decode_member(ByteReader& reader, Member& out) {
  Member member;
  if (!decode_id(reader, member.id)) return false;
  if (!decode_id(reader, member.domain)) return false;
  if (!decode_counter(reader, member.generation)) return false;
  if (!reader.digest(member.digest)) return false;

  std::uint8_t lifecycle = 0;
  if (!reader.u8(lifecycle)) return false;
  if (lifecycle > static_cast<std::uint8_t>(MemberLifecycle::Removed)) {
    reader.fail(StatusCode::Corruption, "member lifecycle byte out of range");
    return false;
  }
  member.lifecycle = static_cast<MemberLifecycle>(lifecycle);

  if (!decode_locality(reader, member.locality)) return false;

  std::size_t endpoint_count = 0;
  if (!reader.count(limits::kMaxEndpointsPerMember, endpoint_count)) return false;
  member.endpoints.reserve(endpoint_count);
  for (std::size_t i = 0; i < endpoint_count; ++i) {
    Endpoint endpoint;
    if (!decode_id(reader, endpoint.id)) return false;
    if (!decode_locality(reader, endpoint.locality)) return false;
    std::size_t service_count = 0;
    if (!reader.count(limits::kMaxServicesPerMember, service_count)) return false;
    endpoint.service_groups.reserve(service_count);
    for (std::size_t s = 0; s < service_count; ++s) {
      ServiceGroupId service;
      if (!decode_id(reader, service)) return false;
      endpoint.service_groups.push_back(std::move(service));
    }
    if (!reader.u64(endpoint.capacity_class)) return false;
    member.endpoints.push_back(std::move(endpoint));
  }

  std::size_t service_count = 0;
  if (!reader.count(limits::kMaxServicesPerMember, service_count)) return false;
  member.services.reserve(service_count);
  for (std::size_t i = 0; i < service_count; ++i) {
    ServiceGroupId service;
    if (!decode_id(reader, service)) return false;
    member.services.push_back(std::move(service));
  }

  std::size_t resource_count = 0;
  if (!reader.count(limits::kMaxResourcesPerMember, resource_count)) return false;
  member.resources.reserve(resource_count);
  for (std::size_t i = 0; i < resource_count; ++i) {
    Resource resource;
    if (!decode_id(reader, resource.id)) return false;
    if (!reader.text(resource.kind, limits::kMaxIdentifierBytes)) return false;
    if (!reader.u64(resource.total_units)) return false;
    if (!decode_counter(reader, resource.reservation_generation)) return false;
    if (!reader.boolean(resource.reservable)) return false;
    member.resources.push_back(std::move(resource));
  }

  if (!decode_counter(reader, member.last_observed)) return false;
  if (!reader.text(member.note, limits::kMaxNoteBytes)) return false;
  if (!is_valid_utf8(member.note)) {
    reader.fail(StatusCode::Corruption, "member note is not valid UTF-8");
    return false;
  }
  out = std::move(member);
  return true;
}

void encode_path(ByteWriter& writer, const Path& path) {
  encode_id(writer, path.id);
  encode_counter(writer, path.generation);
  encode_id(writer, path.source_member);
  encode_id(writer, path.source_endpoint);
  encode_id(writer, path.destination_member);
  encode_id(writer, path.destination_endpoint);
  writer.count(path.resources.size());
  for (const ResourceId& resource : path.resources) {
    encode_id(writer, resource);
  }
  writer.u64(path.capacity_units);
  writer.boolean(path.exclusive);
  writer.u8(static_cast<std::uint8_t>(path.state));
  writer.u32(path.declared_hops);
}

bool decode_path(ByteReader& reader, Path& out) {
  Path path;
  if (!decode_id(reader, path.id)) return false;
  if (!decode_counter(reader, path.generation)) return false;
  if (!decode_id(reader, path.source_member)) return false;
  if (!decode_id(reader, path.source_endpoint)) return false;
  if (!decode_id(reader, path.destination_member)) return false;
  if (!decode_id(reader, path.destination_endpoint)) return false;
  std::size_t resource_count = 0;
  if (!reader.count(limits::kMaxResourcesPerPath, resource_count)) return false;
  path.resources.reserve(resource_count);
  for (std::size_t i = 0; i < resource_count; ++i) {
    ResourceId resource;
    if (!decode_id(reader, resource)) return false;
    path.resources.push_back(std::move(resource));
  }
  if (!reader.u64(path.capacity_units)) return false;
  if (!reader.boolean(path.exclusive)) return false;
  std::uint8_t state = 0;
  if (!reader.u8(state)) return false;
  if (state > static_cast<std::uint8_t>(PathState::Unknown)) {
    reader.fail(StatusCode::Corruption, "path state byte out of range");
    return false;
  }
  path.state = static_cast<PathState>(state);
  if (!reader.u32(path.declared_hops)) return false;
  out = std::move(path);
  return true;
}

void encode_exclusion(ByteWriter& writer, const MaintenanceExclusion& exclusion) {
  encode_id(writer, exclusion.id);
  encode_locality(writer, exclusion.domain_prefix);
  writer.count(exclusion.members.size());
  for (const MemberId& member : exclusion.members) {
    encode_id(writer, member);
  }
  writer.count(exclusion.paths.size());
  for (const PathId& path : exclusion.paths) {
    encode_id(writer, path);
  }
  encode_counter(writer, exclusion.valid_from);
  encode_counter(writer, exclusion.valid_to);
  writer.u8(static_cast<std::uint8_t>(exclusion.mode));
  writer.boolean(exclusion.enabled);
  writer.text(exclusion.reason);
}

bool decode_exclusion(ByteReader& reader, MaintenanceExclusion& out) {
  MaintenanceExclusion exclusion;
  if (!decode_id(reader, exclusion.id)) return false;
  // An empty domain prefix is legitimate ("any locality"); decode_locality
  // therefore accepts depth 0 here.
  if (!decode_locality(reader, exclusion.domain_prefix)) return false;
  std::size_t member_count = 0;
  if (!reader.count(limits::kMaxExclusionMembers, member_count)) return false;
  exclusion.members.reserve(member_count);
  for (std::size_t i = 0; i < member_count; ++i) {
    MemberId member;
    if (!decode_id(reader, member)) return false;
    exclusion.members.push_back(std::move(member));
  }
  std::size_t path_count = 0;
  if (!reader.count(limits::kMaxPaths, path_count)) return false;
  exclusion.paths.reserve(path_count);
  for (std::size_t i = 0; i < path_count; ++i) {
    PathId path;
    if (!decode_id(reader, path)) return false;
    exclusion.paths.push_back(std::move(path));
  }
  if (!decode_counter(reader, exclusion.valid_from)) return false;
  if (!decode_counter(reader, exclusion.valid_to)) return false;
  std::uint8_t mode = 0;
  if (!reader.u8(mode)) return false;
  if (mode > static_cast<std::uint8_t>(MaintenanceMode::Allow)) {
    reader.fail(StatusCode::Corruption, "maintenance mode byte out of range");
    return false;
  }
  exclusion.mode = static_cast<MaintenanceMode>(mode);
  if (!reader.boolean(exclusion.enabled)) return false;
  if (!reader.text(exclusion.reason, limits::kMaxNoteBytes)) return false;
  if (!is_valid_utf8(exclusion.reason)) {
    reader.fail(StatusCode::Corruption, "exclusion reason is not valid UTF-8");
    return false;
  }
  out = std::move(exclusion);
  return true;
}

void encode_obligation(ByteWriter& writer, const CapacityObligation& obligation) {
  encode_id(writer, obligation.id);
  encode_id(writer, obligation.service);
  writer.u32(obligation.min_distinct_failure_domains);
  writer.u8(obligation.failure_domain_level);
  writer.u64(obligation.min_units_per_domain);
  writer.boolean(obligation.enabled);
}

bool decode_obligation(ByteReader& reader, CapacityObligation& out) {
  CapacityObligation obligation;
  if (!decode_id(reader, obligation.id)) return false;
  if (!decode_id(reader, obligation.service)) return false;
  if (!reader.u32(obligation.min_distinct_failure_domains)) return false;
  if (!reader.u8(obligation.failure_domain_level)) return false;
  if (!reader.u64(obligation.min_units_per_domain)) return false;
  if (!reader.boolean(obligation.enabled)) return false;
  out = std::move(obligation);
  return true;
}

void ClusterSpec::encode(ByteWriter& writer) const {
  encode_id(writer, cluster_id_);
  encode_counter(writer, generation_);
  encode_counter(writer, epoch_);
  encode_counter(writer, policy_generation_);
  encode_incarnation(writer, incarnation_);
  encode_counter(writer, tick_);
  writer.count(members_.size());
  for (const Member& member : members_) {
    encode_member(writer, member);
  }
  writer.count(paths_.size());
  for (const Path& path : paths_) {
    encode_path(writer, path);
  }
  writer.count(exclusions_.size());
  for (const MaintenanceExclusion& exclusion : exclusions_) {
    encode_exclusion(writer, exclusion);
  }
  writer.count(obligations_.size());
  for (const CapacityObligation& obligation : obligations_) {
    encode_obligation(writer, obligation);
  }
}

bool ClusterSpec::decode(ByteReader& reader, ClusterSpec& out) {
  ClusterSpec spec;
  if (!decode_id(reader, spec.cluster_id_)) return false;
  if (!decode_counter(reader, spec.generation_)) return false;
  if (!decode_counter(reader, spec.epoch_)) return false;
  if (!decode_counter(reader, spec.policy_generation_)) return false;
  if (!decode_incarnation(reader, spec.incarnation_)) return false;
  if (!decode_counter(reader, spec.tick_)) return false;

  std::size_t member_count = 0;
  if (!reader.count(limits::kMaxMembers, member_count)) return false;
  spec.members_.reserve(member_count);
  for (std::size_t i = 0; i < member_count; ++i) {
    Member member;
    if (!decode_member(reader, member)) return false;
    if (!spec.members_.empty() && !(spec.members_.back().id < member.id)) {
      reader.fail(StatusCode::Corruption, "member table is not strictly sorted by id");
      return false;
    }
    spec.members_.push_back(std::move(member));
  }

  std::size_t path_count = 0;
  if (!reader.count(limits::kMaxPaths, path_count)) return false;
  spec.paths_.reserve(path_count);
  for (std::size_t i = 0; i < path_count; ++i) {
    Path path;
    if (!decode_path(reader, path)) return false;
    if (!spec.paths_.empty() && !(spec.paths_.back().id < path.id)) {
      reader.fail(StatusCode::Corruption, "path table is not strictly sorted by id");
      return false;
    }
    spec.paths_.push_back(std::move(path));
  }

  std::size_t exclusion_count = 0;
  if (!reader.count(limits::kMaxExclusions, exclusion_count)) return false;
  spec.exclusions_.reserve(exclusion_count);
  for (std::size_t i = 0; i < exclusion_count; ++i) {
    MaintenanceExclusion exclusion;
    if (!decode_exclusion(reader, exclusion)) return false;
    if (!spec.exclusions_.empty() && !(spec.exclusions_.back().id < exclusion.id)) {
      reader.fail(StatusCode::Corruption, "exclusion table is not strictly sorted by id");
      return false;
    }
    spec.exclusions_.push_back(std::move(exclusion));
  }

  std::size_t obligation_count = 0;
  if (!reader.count(limits::kMaxObligations, obligation_count)) return false;
  spec.obligations_.reserve(obligation_count);
  for (std::size_t i = 0; i < obligation_count; ++i) {
    CapacityObligation obligation;
    if (!decode_obligation(reader, obligation)) return false;
    if (!spec.obligations_.empty() && !(spec.obligations_.back().id < obligation.id)) {
      reader.fail(StatusCode::Corruption, "obligation table is not strictly sorted by id");
      return false;
    }
    spec.obligations_.push_back(std::move(obligation));
  }

  out = std::move(spec);
  return true;
}

Digest256 ClusterSpec::digest() const {
  if (cached_spec_revision_ == revision_) {
    return cached_spec_digest_;
  }
  Bytes buffer;
  ByteWriter writer(buffer);
  encode(writer);
  cached_spec_digest_ = canonical_digest("cif.cluster.spec.v1", buffer);
  cached_spec_revision_ = revision_;
  return cached_spec_digest_;
}

Digest256 ClusterSpec::topology_digest() const {
  if (cached_topology_revision_ == revision_) {
    return cached_topology_digest_;
  }
  Bytes buffer;
  ByteWriter writer(buffer);
  encode_id(writer, cluster_id_);
  writer.count(members_.size());
  for (const Member& member : members_) {
    encode_member(writer, member);
  }
  writer.count(paths_.size());
  for (const Path& path : paths_) {
    encode_path(writer, path);
  }
  writer.count(exclusions_.size());
  for (const MaintenanceExclusion& exclusion : exclusions_) {
    encode_exclusion(writer, exclusion);
  }
  writer.count(obligations_.size());
  for (const CapacityObligation& obligation : obligations_) {
    encode_obligation(writer, obligation);
  }
  cached_topology_digest_ = canonical_digest("cif.cluster.topology.v1", buffer);
  cached_topology_revision_ = revision_;
  return cached_topology_digest_;
}

Digest256 member_state_digest(const Member& member) {
  Bytes buffer;
  ByteWriter writer(buffer);
  encode_member(writer, member);
  return canonical_digest("cif.member.state.v1", buffer);
}

bool is_known_capability(std::string_view capability) noexcept {
  for (const char* known : kCapabilities) {
    if (capability == known) {
      return true;
    }
  }
  return false;
}

const std::vector<std::string_view>& known_capabilities() {
  static const std::vector<std::string_view> capabilities(std::begin(kCapabilities),
                                                           std::end(kCapabilities));
  return capabilities;
}

}  // namespace cif
