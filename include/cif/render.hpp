// Cluster Interconnect Fabric (CIF) -- public API.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic rendering. Every renderer here is a pure function of its
// argument: no clocks, no addresses, no locale, no pointer values. Two
// processes that hold the same state render byte-identical text, which is what
// makes the CLI usable as an inspection and differential-testing tool.
#ifndef CIF_RENDER_HPP
#define CIF_RENDER_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "cif/identity.hpp"
#include "cif/status.hpp"

namespace cif {

struct AuthorityGrant;
struct AuthorityDecision;
struct AttemptRecord;
struct Member;
struct Path;
struct MaintenanceExclusion;
struct CapacityObligation;
struct CommunicationContract;

[[nodiscard]] std::string render_reasons(const std::vector<Reason>& reasons);
[[nodiscard]] std::string render_grant(const AuthorityGrant& grant);
[[nodiscard]] std::string render_attempt(const AttemptRecord& attempt);
[[nodiscard]] std::string render_decision(const AuthorityDecision& decision);

[[nodiscard]] std::string render_member(const Member& member);
[[nodiscard]] std::string render_path(const Path& path);
[[nodiscard]] std::string render_exclusion(const MaintenanceExclusion& exclusion);
[[nodiscard]] std::string render_obligation(const CapacityObligation& obligation);
[[nodiscard]] std::string render_contract(const CommunicationContract& contract);
[[nodiscard]] std::string render_controller(const ControllerIdentity& identity);

/// Minimal JSON string escaping for the machine-readable output modes. Rejects
/// nothing; invalid UTF-8 bytes are replaced with '?' so that output is always
/// well-formed JSON.
[[nodiscard]] std::string json_escape(std::string_view text);

/// Appends "  key": "value" style fields; kept deliberately tiny so that the
/// CLI has no third-party dependency.
class JsonWriter {
 public:
  explicit JsonWriter(std::string& sink) : sink_(&sink) {}

  void begin_object();
  void end_object();
  void begin_array();
  void end_array();
  void key(std::string_view name);
  void string_value(std::string_view value);
  void number_value(std::uint64_t value);
  void bool_value(bool value);
  void raw_value(std::string_view value);

 private:
  void separate();
  std::string* sink_;
  bool first_ = true;
  bool after_key_ = false;
};

}  // namespace cif

#endif  // CIF_RENDER_HPP
