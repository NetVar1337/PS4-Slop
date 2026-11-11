/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Browser dev mode only: engine port (default 8765). */
  readonly VITE_SLOP_PORT?: string;
  /** Browser dev mode only: engine bearer token (the engine's mcp_token). */
  readonly VITE_SLOP_TOKEN?: string;
}
