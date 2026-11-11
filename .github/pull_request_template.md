## Summary

<!-- What changes and why. Link issues with "Fixes #123". -->

## Testing

<!-- Commands you ran and their result, e.g.
     powershell -File tools\build.ps1 -NoFrontend -Test
     npm run typecheck && npm test (app/) -->

## Checklist

- [ ] Regression test added or updated for behavior changes
- [ ] No new MSVC /W4 warnings; `pwsh tools/clang_tidy.ps1` clean for touched files
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Dependency added/bumped: hash pinned in `cmake/deps.cmake` and `THIRD_PARTY_NOTICES.md` regenerated
- [ ] Version bump only via `VERSION` + `tools/sync_version.ps1`
