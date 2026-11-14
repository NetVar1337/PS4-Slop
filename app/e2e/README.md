# E2E driver

Drives the **real** stack end to end: spawns `reverse-slop-engine.exe` and the
`SlopTarget.exe` fixture, then either talks to the engine API directly
(`smoke`) or launches the Vite dev UI in headless Chrome/Edge and captures the
screenshots used in the top-level README (`screenshots`).

## Setup

```powershell
# engine + fixture must be built first
powershell -File tools/build.ps1 -NoFrontend
cd app
npm install            # vite for the screenshots mode
cd e2e
npm install            # playwright-core (drives your installed Chrome/Edge)
```

## Run

```powershell
npm run smoke          # API battery: health, attach, read, watchlist, script, detach
npm run screenshots    # regenerate docs/screenshots/*.png from the live UI
```

Useful overrides (env): `SLOP_E2E_PORT` (default 8791), `SLOP_E2E_TOKEN`,
`SLOP_E2E_ENGINE`, `SLOP_E2E_FIXTURE`, `SLOP_E2E_OUT`.

If another live engine is already advertised the engine coalesces onto it (by
product design); the driver then uses that endpoint and **leaves it running**
instead of shutting it down.

CI: the nightly `tests` lane of `.github/workflows/build.yml` runs `smoke` against the engine it just built. Screenshots
mode is not in CI (image-compare flakiness); run it by hand when the UI changes.
