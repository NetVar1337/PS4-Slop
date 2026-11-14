# Package manager manifests

Templates for the three package managers, filled from a release's `SHA256SUMS` by
`tools/gen_packages.ps1`. The `packages` workflow runs that script on every published
release and uploads the result as the `package-manifests` artifact.

```powershell
# from a checkout, against the latest published release
gh release download v0.2.3 -R NetVar1337/SlopStation -p SHA256SUMS
powershell -File tools/gen_packages.ps1 -Version 0.2.3 -Sums SHA256SUMS -OutDir _packages

# or let the script fetch the sums itself
powershell -File tools/gen_packages.ps1 -Version 0.2.3 -OutDir _packages
```

| Directory | Manager | Installer | Scope |
| --- | --- | --- | --- |
| `winget/` | Windows Package Manager | `SlopStation_<version>_x64-setup.exe` (nullsoft) | user |
| `scoop/` | Scoop | `SlopStation-portable-<tag>.zip` | user |
| `choco/` | Chocolatey | `SlopStation_<version>_x64-setup.exe` | per-user NSIS |

## Placeholders

`gen_packages.ps1` substitutes these; a manifest that still contains `__` after generation
is a bug and the script fails.

| Placeholder | Value |
| --- | --- |
| `__VERSION__` | `0.2.3` (from `VERSION` or `-Version`) |
| `__TAG__` | `v0.2.3` |
| `__RELEASE_DATE__` | `yyyy-MM-dd` of the release |
| `__SETUP_URL__` | release download URL of the NSIS installer |
| `__SETUP_SHA256__` | its SHA-256 from `SHA256SUMS` |
| `__ZIP_URL__` | release download URL of the portable zip |
| `__ZIP_SHA256__` | its SHA-256 from `SHA256SUMS` |

## Submitting

- **winget**: the `packages` workflow opens the PR automatically when a `WINGET_TOKEN`
  secret exists (classic PAT with `public_repo`, plus a fork of
  `microsoft/winget-pkgs`). Without the secret, run
  `wingetcreate submit --token <pat> _packages/winget` by hand.
- **Scoop**: copy `slopstation.json` into a bucket (or submit it to
  `ScoopInstaller/Extras`). `checkver`/`autoupdate` keep it current from GitHub releases.
- **Chocolatey**: `choco pack _packages/choco` then `choco push`. The NSIS installer is
  per-user, so the package installs for the account running `choco` — document that in the
  package description rather than trying to force a machine-wide install.
