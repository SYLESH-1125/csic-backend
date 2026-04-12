/**
 * NEXT_PUBLIC_* values exposed to the browser. Loaded via next.config (see loadEnvConfig + env map).
 * Trims whitespace and strips matching quotes from .env lines.
 */
function cleanEnv(val: string | undefined): string {
  if (val == null) return ""
  let t = val.trim()
  if (
    (t.startsWith('"') && t.endsWith('"')) ||
    (t.startsWith("'") && t.endsWith("'"))
  ) {
    t = t.slice(1, -1).trim()
  }
  return t
}

const apiUrlRaw = cleanEnv(process.env.NEXT_PUBLIC_API_URL) || "http://127.0.0.1:8000"
const wsUrlRaw = cleanEnv(process.env.NEXT_PUBLIC_WS_URL)
/** Standalone Operation Room Next app (`app/phase_5_CISC/operation-room/frontend`). Default port 3001. */
const operationRoomAppRaw =
  cleanEnv(process.env.NEXT_PUBLIC_OPERATION_ROOM_APP_URL) ||
  cleanEnv(process.env.NEXT_PUBLIC_OPERATION_ROOM_UI_ORIGIN) ||
  "http://127.0.0.1:3001"

export const publicEnv = {
  apiUrl: apiUrlRaw,
  wsUrl: wsUrlRaw,
  operationRoomAppUrl: operationRoomAppRaw.replace(/\/+$/, ""),
  googleClientId: cleanEnv(process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID),
  googleApiKey: cleanEnv(process.env.NEXT_PUBLIC_GOOGLE_API_KEY),
  demoMode:
    cleanEnv(process.env.NEXT_PUBLIC_CSIC_DEMO_MODE) === "1" ||
    cleanEnv(process.env.NEXT_PUBLIC_CSIC_DEMO_MODE).toLowerCase() === "true",
} as const

/** REST API origin (no trailing slash). */
export function getApiBaseUrl(): string {
  return publicEnv.apiUrl.replace("://0.0.0.0", "://127.0.0.1").replace(/\/+$/, "")
}

/** WebSocket origin (no trailing slash). */
export function getWsBaseUrl(): string {
  const fromExplicit = publicEnv.wsUrl
  const derived =
    fromExplicit ||
    publicEnv.apiUrl.replace(/^http:\/\//, "ws://").replace(/^https:\/\//, "wss://")
  return derived.replace("://0.0.0.0", "://127.0.0.1").replace(/\/+$/, "")
}

/** Origin of the embedded Operation Room Next app (no trailing slash). */
export function getOperationRoomAppUrl(): string {
  return publicEnv.operationRoomAppUrl.replace("://0.0.0.0", "://127.0.0.1")
}
