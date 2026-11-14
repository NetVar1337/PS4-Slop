#pragma once

// src/core/infra/paths.hpp
// where all the app data lives

#include <string>
#include <string_view>

namespace slop::core::infra::paths {

void init();

// everything exists after init
const std::string& app_data();       // %LOCALAPPDATA%\reverse-slop
const std::string& settings_file();  // .../settings.json
const std::string& sessions_dir();   // .../sessions
const std::string& crashes_dir();    // .../crashes

// tests only: point every path below at dir (call init() to restore); the
// folder is created, nothing else is touched
void set_app_data_for_testing(std::string dir);

// writes <path>.tmp, flushes it, then MoveFileExW(REPLACE_EXISTING) over the
// destination; the destination is never deleted first so a failed replace leaves
// the old file intact. creates the parent folder. false on any failure
bool write_file_atomic(const std::string& path, std::string_view data);

} // namespace slop::core::infra::paths
