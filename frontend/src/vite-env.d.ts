/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Full URL of the deployed backend, e.g. https://sigintx-api.onrender.com */
  readonly VITE_API_URL?: string
  /** Set to "true" to bypass the login screen on public/demo deployments */
  readonly VITE_AUTH_DISABLED?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
