// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A communication contract is the *operator's* statement of what a
// cluster-wide communication relationship must satisfy. It is a requirement,
// never an authority: satisfying a contract makes a request eligible, it does
// not make it authoritative.
#ifndef CIF_CONTRACT_HPP
#define CIF_CONTRACT_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "cif/bytes.hpp"
#include "cif/identity.hpp"
#include "cif/model.hpp"
#include "cif/status.hpp"

namespace cif {

struct CommunicationContract {
  ContractId id;
  ContractGeneration generation{};

  ServiceGroupId source_service;       ///< Service group the relationship starts from.
  ServiceGroupId destination_service;  ///< Service group the relationship reaches.

  std::uint64_t min_capacity_units = 0;
  std::uint64_t max_capacity_units = 0;  ///< Zero means "no contract-level ceiling".

  std::uint32_t min_distinct_failure_domains = 1;
  std::uint8_t failure_domain_level = 0;

  bool require_exclusive_path = false;

  MaintenanceMode maintenance_mode = MaintenanceMode::Refuse;
  bool allow_draining = false;
  bool allow_faulted = false;
  bool allow_partitioned = false;

  /// Whether the engine may answer DEGRADED (reduced scope) instead of REFUSED.
  bool allow_degraded = true;

  /// Capability names the contract requires. Any name outside the documented
  /// vocabulary makes every decision against this contract UNSUPPORTED.
  std::vector<std::string> required_capabilities;

  bool enabled = true;

  [[nodiscard]] Status validate() const;

  /// Names from required_capabilities that this build does not implement.
  [[nodiscard]] std::vector<std::string> unsupported_capabilities() const;

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, CommunicationContract& out);
  [[nodiscard]] Digest256 digest() const;
};

/// Bounded, id-sorted store of contracts.
class ContractSet {
 public:
  ContractSet() = default;

  [[nodiscard]] Status upsert(CommunicationContract contract);
  [[nodiscard]] Status remove(const ContractId& id);
  [[nodiscard]] const CommunicationContract* find(const ContractId& id) const noexcept;
  [[nodiscard]] const std::vector<CommunicationContract>& all() const noexcept { return contracts_; }
  [[nodiscard]] std::size_t size() const noexcept { return contracts_.size(); }
  void clear() noexcept {
    contracts_.clear();
    ++revision_;
  }

  /// Removes a contract. Returns NotFound when absent; this is deliberate so
  /// that an operator deleting a contract twice learns about it.
  [[nodiscard]] Status validate() const;

  void encode(ByteWriter& writer) const;
  [[nodiscard]] static bool decode(ByteReader& reader, ContractSet& out);

  /// Digest of the canonical contract encoding. Cached against the store's
  /// revision so that a hot path that needs it once per decision does not
  /// re-encode every contract every time.
  [[nodiscard]] Digest256 digest() const;

  /// Bumped by every mutation. Exposed so callers can key their own caches.
  [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }

 private:
  std::vector<CommunicationContract> contracts_;  ///< Sorted by id.
  std::uint64_t revision_ = 0;
  mutable Digest256 cached_digest_{};
  mutable std::uint64_t cached_revision_ = 0;
  mutable bool cached_valid_ = false;
};

}  // namespace cif

#endif  // CIF_CONTRACT_HPP
