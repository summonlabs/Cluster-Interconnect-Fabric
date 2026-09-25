// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every bounded quantity in the runtime lives here so that adversarial inputs
// meet a single, auditable set of limits. Sizes are validated *before*
// allocation; counts decoded from untrusted bytes are compared against these
// constants before any container resize.
#ifndef CIF_LIMITS_HPP
#define CIF_LIMITS_HPP

#include <cstddef>
#include <cstdint>

namespace cif::limits {

// -- identifiers and text ---------------------------------------------------
inline constexpr std::size_t kMaxIdentifierBytes = 128;
inline constexpr std::size_t kMaxNoteBytes = 512;
inline constexpr std::size_t kMaxLocalityDepth = 16;
inline constexpr std::size_t kMaxReasonDetailBytes = 256;
inline constexpr std::size_t kMaxReasons = 24;
inline constexpr std::size_t kMaxExplanationBytes = 8192;

// -- cluster spec -----------------------------------------------------------
inline constexpr std::size_t kMaxMembers = 4096;
inline constexpr std::size_t kMaxEndpointsPerMember = 256;
inline constexpr std::size_t kMaxServicesPerMember = 256;
inline constexpr std::size_t kMaxResourcesPerMember = 256;
inline constexpr std::size_t kMaxPaths = 16384;
inline constexpr std::size_t kMaxResourcesPerPath = 16;
inline constexpr std::size_t kMaxExclusions = 1024;
inline constexpr std::size_t kMaxExclusionMembers = 512;
inline constexpr std::size_t kMaxObligations = 1024;
inline constexpr std::size_t kMaxContracts = 4096;
inline constexpr std::size_t kMaxRequiredCapabilities = 8;

// -- grants / attempts ------------------------------------------------------
inline constexpr std::size_t kMaxGrants = 65536;
inline constexpr std::size_t kMaxAttempts = 65536;
inline constexpr std::size_t kMaxLiveGrantsPerPath = 64;
inline constexpr std::size_t kMaxHistoryEntries = 8192;

// -- capacity ---------------------------------------------------------------
inline constexpr std::uint64_t kMaxCapacityUnits = 1ull << 40;
inline constexpr std::uint64_t kMaxLeaseTicks = 1ull << 32;
inline constexpr std::uint64_t kMaxRequestedUnits = kMaxCapacityUnits;

// -- journal ----------------------------------------------------------------
inline constexpr std::size_t kMaxJournalRecordBytes = 1u << 20;
inline constexpr std::uint64_t kMaxJournalBytes = 64ull << 20;
inline constexpr std::uint64_t kMaxJournalRecords = 1ull << 20;

// -- transport --------------------------------------------------------------
inline constexpr std::size_t kMaxFrameBytes = 1u << 20;
inline constexpr std::size_t kMaxFramePayloadBytes = kMaxFrameBytes - 64;
inline constexpr std::size_t kMaxConnections = 128;
inline constexpr std::size_t kMaxIngressQueue = 8192;
inline constexpr std::size_t kMaxWorkers = 32;
inline constexpr std::size_t kMaxPendingEffects = 4096;
inline constexpr std::size_t kMaxBatchRequests = 256;
inline constexpr std::size_t kMaxListenBacklog = 64;

}  // namespace cif::limits

#endif  // CIF_LIMITS_HPP
