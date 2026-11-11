#pragma once
// PS4 NID (name identifier) support. Orbis ELFs import and export symbols by
// NID: SHA-1(name || fixed 16-byte suffix), first 8 bytes read as a
// little-endian u64, written big-endian and base64-encoded (alphabet
// A-Z a-z 0-9 + -, no padding) into 11 characters. Import strings carry the
// library and module ids after the NID: "<nid>#<lib>#<mod>", each id in the
// same 64-character alphabet.
//
// The name database is the ps4libdoc known-name list compiled in
// (src/hyperion/data/ps4_nid_names.inc), plus an optional user file
// %LOCALAPPDATA%\reverse-slop\nids.txt whose entries override the built-in
// names: one entry per line, either `name` (the NID is computed) or
// `<11-char nid> name`; blank lines and lines starting with '#' are skipped.
#include "core/types.h"
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace hype::nid {

// 11-character NID of a symbol name
std::string encode(std::string_view name);

// Raw 64-bit NID value (the integer form ps4libdoc calls "id")
u64 hash(std::string_view name);

// Parses an 11-character NID into its 64-bit value; false on bad input
bool decode(std::string_view nid, u64& out);

// Decodes a "#<lib>#<mod>" id field (base64 digits, most significant first)
bool decode_id(std::string_view field, u64& out);

// Name for a NID ("<nid>" or "<nid>#<lib>#<mod>"), user overrides first
std::optional<std::string> lookup(std::string_view nid_or_symbol);

// Loads an override file (format above). Returns the number of entries
// added. The default %LOCALAPPDATA% file is loaded on first lookup; tests
// and callers can add more files explicitly
size_t load_overrides(const std::filesystem::path& file);

// Adds or replaces one override entry
void add_override(std::string_view nid, std::string name);

// Drops every override (the built-in list stays)
void clear_overrides();

// Number of names in the built-in database
size_t builtin_count();

// Default override file path ("" when %LOCALAPPDATA% is unset)
std::filesystem::path default_override_path();

}
