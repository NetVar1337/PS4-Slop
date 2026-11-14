# Roadmap, changelog and audit

These live at the repository root so they stay next to the code they describe:

| File | What it is |
| --- | --- |
| [`ROADMAP.md`](https://github.com/NetVar1337/SlopStation/blob/main/ROADMAP.md) | prioritized work list derived from the audit (P0 → P3) |
| [`CHANGELOG.md`](https://github.com/NetVar1337/SlopStation/blob/main/CHANGELOG.md) | release notes, one section per version; the release workflow publishes the matching section |
| [`docs/AUDIT.md`](../AUDIT.md) | the full audit: 115 numbered items with severity and status |
| [`docs/MERGE.md`](../MERGE.md) | what landed from the sibling projects and what stayed external |
| [`SECURITY.md`](https://github.com/NetVar1337/SlopStation/blob/main/SECURITY.md) | reporting, supported versions, scope |
| [`CONTRIBUTING.md`](https://github.com/NetVar1337/SlopStation/blob/main/CONTRIBUTING.md) | build/test/style rules for changes |
| [`THIRD_PARTY_NOTICES.md`](https://github.com/NetVar1337/SlopStation/blob/main/THIRD_PARTY_NOTICES.md) | third-party components and licenses |

## Release process

1. Bump `VERSION`; `tools/sync_version.ps1` propagates it.
2. Add the `## [x.y.z]` section to `CHANGELOG.md`.
3. Push the tag. The release workflow checks the tag against `VERSION`, reuses the main
   build's engine, compiles the frontend with the release profile, signs, and publishes the
   installer, the portable zip, `SHA256SUMS`, `latest.json` and an SBOM.
4. The `packages` workflow runs on the published release and regenerates the winget, Scoop
   and Chocolatey manifests from `SHA256SUMS`.
