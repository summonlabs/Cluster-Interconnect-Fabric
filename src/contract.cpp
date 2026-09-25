#include "cif/contract.hpp"

#include <algorithm>
#include <utility>

namespace cif {
namespace {

template <typename Container, typename Key>
[[nodiscard]] std::size_t lower_bound_index(const Container& container, const Key& key) {
  return static_cast<std::size_t>(
      std::lower_bound(container.begin(), container.end(), key,
                       [](const auto& element, const auto& value) { return element.id < value; }) -
      container.begin());
}

}  // namespace

Status CommunicationContract::validate() const {
  if (id.empty()) {
    return Status::error(StatusCode::InvalidArgument, "contract id must not be empty");
  }
  if (source_service.empty() || destination_service.empty()) {
    return Status::error(StatusCode::InvalidArgument,
                         "contract must name both a source and a destination service group");
  }
  if (max_capacity_units != 0 && min_capacity_units > max_capacity_units) {
    return Status::error(StatusCode::InvalidArgument,
                         "contract minimum capacity exceeds its maximum capacity");
  }
  if (min_capacity_units > limits::kMaxCapacityUnits) {
    return Status::error(StatusCode::LimitExceeded, "contract minimum capacity is out of range");
  }
  if (max_capacity_units > limits::kMaxCapacityUnits) {
    return Status::error(StatusCode::LimitExceeded, "contract maximum capacity is out of range");
  }
  if (failure_domain_level > static_cast<std::uint8_t>(LocalityPath::kMaxDepth)) {
    return Status::error(StatusCode::InvalidArgument, "failure domain level is out of range");
  }
  if (min_distinct_failure_domains > limits::kMaxMembers) {
    return Status::error(StatusCode::LimitExceeded,
                         "contract demands more failure domains than the member bound allows");
  }
  if (required_capabilities.size() > limits::kMaxRequiredCapabilities) {
    return Status::error(StatusCode::LimitExceeded, "contract requires too many capabilities");
  }
  for (const std::string& capability : required_capabilities) {
    if (!is_valid_identifier(capability, limits::kMaxIdentifierBytes)) {
      return Status::error(StatusCode::InvalidArgument, "capability name is not a valid identifier");
    }
  }
  if (!enabled) {
    return Status::error(StatusCode::StateMismatch, "contract is disabled");
  }
  return Status::success();
}

std::vector<std::string> CommunicationContract::unsupported_capabilities() const {
  std::vector<std::string> unsupported;
  for (const std::string& capability : required_capabilities) {
    if (!is_known_capability(capability)) {
      unsupported.push_back(capability);
    }
  }
  return unsupported;
}

void CommunicationContract::encode(ByteWriter& writer) const {
  encode_id(writer, id);
  encode_counter(writer, generation);
  encode_id(writer, source_service);
  encode_id(writer, destination_service);
  writer.u64(min_capacity_units);
  writer.u64(max_capacity_units);
  writer.u32(min_distinct_failure_domains);
  writer.u8(failure_domain_level);
  writer.boolean(require_exclusive_path);
  writer.u8(static_cast<std::uint8_t>(maintenance_mode));
  writer.boolean(allow_draining);
  writer.boolean(allow_faulted);
  writer.boolean(allow_partitioned);
  writer.boolean(allow_degraded);
  writer.count(required_capabilities.size());
  for (const std::string& capability : required_capabilities) {
    writer.text(capability);
  }
  writer.boolean(enabled);
}

bool CommunicationContract::decode(ByteReader& reader, CommunicationContract& out) {
  CommunicationContract contract;
  if (!decode_id(reader, contract.id)) return false;
  if (!decode_counter(reader, contract.generation)) return false;
  if (!decode_id(reader, contract.source_service)) return false;
  if (!decode_id(reader, contract.destination_service)) return false;
  if (!reader.u64(contract.min_capacity_units)) return false;
  if (!reader.u64(contract.max_capacity_units)) return false;
  if (!reader.u32(contract.min_distinct_failure_domains)) return false;
  if (!reader.u8(contract.failure_domain_level)) return false;
  if (!reader.boolean(contract.require_exclusive_path)) return false;
  std::uint8_t mode = 0;
  if (!reader.u8(mode)) return false;
  if (mode > static_cast<std::uint8_t>(MaintenanceMode::Allow)) {
    reader.fail(StatusCode::Corruption, "contract maintenance mode byte out of range");
    return false;
  }
  contract.maintenance_mode = static_cast<MaintenanceMode>(mode);
  if (!reader.boolean(contract.allow_draining)) return false;
  if (!reader.boolean(contract.allow_faulted)) return false;
  if (!reader.boolean(contract.allow_partitioned)) return false;
  if (!reader.boolean(contract.allow_degraded)) return false;
  std::size_t capability_count = 0;
  if (!reader.count(limits::kMaxRequiredCapabilities, capability_count)) return false;
  contract.required_capabilities.reserve(capability_count);
  for (std::size_t i = 0; i < capability_count; ++i) {
    std::string capability;
    if (!reader.text(capability, limits::kMaxIdentifierBytes)) return false;
    if (!is_valid_identifier(capability, limits::kMaxIdentifierBytes)) {
      reader.fail(StatusCode::Corruption, "capability name is not a valid identifier");
      return false;
    }
    contract.required_capabilities.push_back(std::move(capability));
  }
  if (!reader.boolean(contract.enabled)) return false;
  out = std::move(contract);
  return true;
}

Digest256 CommunicationContract::digest() const {
  Bytes buffer;
  ByteWriter writer(buffer);
  encode(writer);
  return canonical_digest("cif.contract.v1", buffer);
}

Status ContractSet::upsert(CommunicationContract contract) {
  CIF_TRY(contract.validate());
  const std::size_t index = lower_bound_index(contracts_, contract.id);
  if (index < contracts_.size() && contracts_[index].id == contract.id) {
    if (contract.generation < contracts_[index].generation) {
      return Status::error(StatusCode::StateMismatch,
                           "contract update would move generation backwards for " + contract.id.to_string());
    }
    contracts_[index] = std::move(contract);
  } else {
    if (contracts_.size() >= limits::kMaxContracts) {
      return Status::error(StatusCode::CapacityExhausted, "contract table is full");
    }
    contracts_.insert(contracts_.begin() + static_cast<std::ptrdiff_t>(index), std::move(contract));
  }
  ++revision_;
  return Status::success();
}

Status ContractSet::remove(const ContractId& id) {
  const std::size_t index = lower_bound_index(contracts_, id);
  if (index >= contracts_.size() || contracts_[index].id != id) {
    return Status::error(StatusCode::NotFound, "contract " + id.to_string() + " is not present");
  }
  contracts_.erase(contracts_.begin() + static_cast<std::ptrdiff_t>(index));
  ++revision_;
  return Status::success();
}

const CommunicationContract* ContractSet::find(const ContractId& id) const noexcept {
  const std::size_t index = lower_bound_index(contracts_, id);
  if (index >= contracts_.size() || contracts_[index].id != id) {
    return nullptr;
  }
  return &contracts_[index];
}

Status ContractSet::validate() const {
  for (std::size_t i = 1; i < contracts_.size(); ++i) {
    if (contracts_[i].id == contracts_[i - 1].id) {
      return Status::error(StatusCode::DuplicateIdentity,
                           "duplicate contract id " + contracts_[i].id.to_string());
    }
  }
  for (const CommunicationContract& contract : contracts_) {
    CIF_TRY(contract.validate());
  }
  return Status::success();
}

void ContractSet::encode(ByteWriter& writer) const {
  writer.count(contracts_.size());
  for (const CommunicationContract& contract : contracts_) {
    contract.encode(writer);
  }
}

bool ContractSet::decode(ByteReader& reader, ContractSet& out) {
  std::size_t count = 0;
  if (!reader.count(limits::kMaxContracts, count)) {
    return false;
  }
  ContractSet set;
  for (std::size_t i = 0; i < count; ++i) {
    CommunicationContract contract;
    if (!CommunicationContract::decode(reader, contract)) {
      return false;
    }
    const Status status = set.upsert(std::move(contract));
    if (!status.ok()) {
      reader.fail(status.code(), status.message());
      return false;
    }
  }
  out = std::move(set);
  return true;
}

Digest256 ContractSet::digest() const {
  if (cached_valid_ && cached_revision_ == revision_) {
    return cached_digest_;
  }
  Bytes buffer;
  ByteWriter writer(buffer);
  encode(writer);
  cached_digest_ = canonical_digest("cif.contractset.v1", buffer);
  cached_revision_ = revision_;
  cached_valid_ = true;
  return cached_digest_;
}

}  // namespace cif
