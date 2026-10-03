export interface ClientOptions {
  apiKey: string
  baseUrl?: string
  timeoutMs?: number
  fetch?: typeof fetch
}

export interface ApiErrorBody {
  detail?: string | unknown[]
  error?: { code?: string; message?: string; request_id?: string; retryable?: boolean }
}

export interface WebhookHeaders {
  id: string
  timestamp: string
  signature: string
}

export interface ApiResponse<T> {
  data: T
  operationId?: string | undefined
  operationLocation?: string | undefined
}

export async function verifyWebhook(
  secret: string,
  body: string | Uint8Array,
  headers: WebhookHeaders,
  options: { toleranceSeconds?: number; nowSeconds?: number } = {},
): Promise<Record<string, unknown>> {
  if (!secret.startsWith("whsec_") || !headers.id) throw new TypeError("invalid webhook verification input")
  const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body
  if (bytes.byteLength > 2 * 1024 * 1024) throw new TypeError("webhook payload is too large")
  const timestamp = Number(headers.timestamp)
  if (!Number.isSafeInteger(timestamp)) throw new TypeError("invalid webhook timestamp")
  const tolerance = options.toleranceSeconds ?? 300
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000)
  if (tolerance < 0 || Math.abs(now - timestamp) > tolerance) {
    throw new TypeError("webhook timestamp is outside the allowed tolerance")
  }
  const prefix = new TextEncoder().encode(`${headers.timestamp}.`)
  const signed = new Uint8Array(prefix.length + bytes.length)
  signed.set(prefix)
  signed.set(bytes, prefix.length)
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, signed))
  const expected = `v1=${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`
  const supplied = new TextEncoder().encode(headers.signature)
  const wanted = new TextEncoder().encode(expected)
  let mismatch = supplied.length ^ wanted.length
  for (let index = 0; index < Math.max(supplied.length, wanted.length); index += 1) {
    mismatch |= (supplied[index] ?? 0) ^ (wanted[index] ?? 0)
  }
  if (mismatch !== 0) throw new TypeError("invalid webhook signature")
  let payload: unknown
  try {
    payload = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new TypeError("invalid webhook JSON")
  }
  if (typeof payload !== "object" || payload === null || (payload as Record<string, unknown>).id !== headers.id) {
    throw new TypeError("webhook id does not match the signed payload")
  }
  return payload as Record<string, unknown>
}

export class AnatoliaCoreError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly code = "request_failed",
    public readonly requestId?: string,
    public readonly retryable = false,
    public readonly retryAfter?: number,
  ) {
    super(message)
    this.name = "AnatoliaCoreError"
  }
}

export class AnatoliaCore {
  private readonly apiKey: string
  private readonly baseUrl: string
  private readonly timeoutMs: number
  private readonly fetcher: typeof fetch

  constructor(options: ClientOptions) {
    const baseUrl = options.baseUrl ?? "https://console.anatoliacore.com/api/public/v1"
    const parsed = new URL(baseUrl)
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new TypeError("baseUrl must be a credential-free HTTPS URL")
    }
    if (!options.apiKey.startsWith("ac_live_") || options.apiKey.length > 256) {
      throw new TypeError("apiKey has an invalid format")
    }
    this.apiKey = options.apiKey
    this.baseUrl = baseUrl.replace(/\/$/, "")
    this.timeoutMs = options.timeoutMs ?? 30_000
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs < 1_000 || this.timeoutMs > 300_000) {
      throw new TypeError("timeoutMs must be between 1000 and 300000")
    }
    this.fetcher = options.fetch ?? globalThis.fetch
  }

  async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown
      params?: Record<string, string | number | undefined>
      idempotencyKey?: string | undefined
    } = {},
  ): Promise<T> {
    return (await this.requestWithMetadata<T>(method, path, options)).data
  }

  async requestWithMetadata<T>(
    method: string,
    path: string,
    options: {
      body?: unknown
      params?: Record<string, string | number | undefined>
      idempotencyKey?: string | undefined
    } = {},
  ): Promise<ApiResponse<T>> {
    if (!path.startsWith("/") || path.startsWith("//")) throw new TypeError("path must be API-relative")
    const url = new URL(this.baseUrl + path)
    for (const [key, value] of Object.entries(options.params ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value))
    }
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs)
    const headers: Record<string, string> = {
      Accept: "application/json",
      "X-API-Key": this.apiKey,
      "User-Agent": "anatoliacore-typescript/1.0.0",
    }
    if (options.body !== undefined) headers["Content-Type"] = "application/json"
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())) {
      headers["Idempotency-Key"] = options.idempotencyKey ?? crypto.randomUUID()
    }
    try {
      const init: RequestInit = {
        method,
        headers,
        redirect: "error",
        signal: controller.signal,
      }
      if (options.body !== undefined) init.body = JSON.stringify(options.body)
      const response = await this.fetcher(url, init)
      if (!response.ok) {
        let body: ApiErrorBody = {}
        try {
          body = (await response.json()) as ApiErrorBody
        } catch {
          // The stable fallback below avoids exposing a proxy response body.
        }
        const retryAfterHeader = response.headers.get("Retry-After")
        const retryAfter = retryAfterHeader === null ? undefined : Number(retryAfterHeader)
        throw new AnatoliaCoreError(
          body.error?.message ?? (typeof body.detail === "string" ? body.detail : "AnatoliaCore API request failed"),
          response.status,
          body.error?.code,
          body.error?.request_id,
          body.error?.retryable ?? response.status >= 500,
          retryAfter !== undefined && Number.isFinite(retryAfter) ? retryAfter : undefined,
        )
      }
      const operationId = response.headers.get("X-Operation-ID") ?? undefined
      const operationLocation = response.headers.get("Operation-Location") ?? undefined
      if (response.status === 204) return { data: undefined as T, operationId, operationLocation }
      if (!(response.headers.get("Content-Type") ?? "").includes("application/json")) {
        throw new AnatoliaCoreError("API returned an unexpected content type", response.status)
      }
      return { data: (await response.json()) as T, operationId, operationLocation }
    } catch (error) {
      if (error instanceof AnatoliaCoreError) throw error
      throw new AnatoliaCoreError("Could not reach the AnatoliaCore API", undefined, "network_error", undefined, true)
    } finally {
      clearTimeout(timeout)
    }
  }

  listInstances(params: { page?: number; perPage?: number; status?: string } = {}) {
    return this.request<Record<string, unknown>[]>("GET", "/instances", {
      params: { page: params.page ?? 1, per_page: params.perPage ?? 20, status: params.status },
    })
  }

  getInstance(id: string) {
    return this.request<Record<string, unknown>>("GET", `/instances/${encodeURIComponent(id)}`)
  }

  createInstance(data: Record<string, unknown>, idempotencyKey?: string) {
    return this.request<Record<string, unknown>>("POST", "/instances", { body: data, idempotencyKey })
  }

  powerInstance(id: string, action: "power_on" | "power_off" | "reboot" | "hard_reset", idempotencyKey?: string) {
    return this.request<Record<string, unknown>>("POST", `/instances/${encodeURIComponent(id)}/power`, {
      body: { action },
      idempotencyKey,
    })
  }

  getOperation(id: string) {
    return this.request<Record<string, unknown>>("GET", `/operations/${encodeURIComponent(id)}`)
  }

  async waitOperation(id: string, timeoutMs = 300_000) {
    const deadline = Date.now() + timeoutMs
    let delayMs = 500
    for (;;) {
      const operation = await this.getOperation(id)
      const status = operation.status
      if (["succeeded", "failed", "needs_attention", "cancelled"].includes(String(status))) {
        return operation
      }
      if (Date.now() >= deadline) {
        throw new AnatoliaCoreError(
          "Timed out waiting for operation",
          undefined,
          "operation_timeout",
          undefined,
          true,
        )
      }
      await new Promise((resolve) => setTimeout(resolve, delayMs))
      delayMs = Math.min(Math.round(delayMs * 1.7), 5_000)
    }
  }

  cancelOperation(id: string, idempotencyKey?: string) {
    return this.request<Record<string, unknown>>("POST", `/operations/${encodeURIComponent(id)}/cancel`, {
      idempotencyKey,
    })
  }

  listInstanceTypes() {
    return this.request<Record<string, unknown>[]>("GET", "/instance-types")
  }
}
