/**
 * VaultGuard – Centralized API Client (Phase 9)
 *
 * Implements:
 * - Base URL resolution from NEXT_PUBLIC_API_BASE_URL
 * - In-memory access token storage (zero persistence in localStorage/sessionStorage)
 * - Automatic CSRF header injection (X-VaultGuard-Request: "1")
 * - Automatic credential inclusion (credentials: "include") for HttpOnly cookies
 * - Concurrency-safe automatic refresh token rotation on 401 Unauthorized
 * - Unified ApiError handling and structured error responses
 * - Zero plaintext/credential logging
 */

import type { ApiResponse, RefreshResponseData } from "./types";

export class ApiError extends Error {
  public status: number;
  public errors?: Array<{ field: string; message: string }>;

  constructor(message: string, status: number, errors?: Array<{ field: string; message: string }>) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errors = errors;
  }
}

// In-memory access token (never persisted to browser storage)
let activeAccessToken: string | null = null;

// Session expiration callback listeners
type SessionExpiredHandler = () => void;
const sessionExpiredHandlers = new Set<SessionExpiredHandler>();

export function onSessionExpired(handler: SessionExpiredHandler): () => void {
  sessionExpiredHandlers.add(handler);
  return () => {
    sessionExpiredHandlers.delete(handler);
  };
}

function notifySessionExpired(): void {
  activeAccessToken = null;
  sessionExpiredHandlers.forEach((handler) => {
    try {
      handler();
    } catch {
      // Ignore listener error
    }
  });
}

export function setAccessToken(token: string | null): void {
  activeAccessToken = token;
}

export function getAccessToken(): string | null {
  return activeAccessToken;
}

export function getApiBaseUrl(): string {
  if (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_BASE_URL) {
    return process.env.NEXT_PUBLIC_API_BASE_URL.replace(/\/+$/, "");
  }
  return "";
}
// Single in-flight refresh promise to prevent refresh races
let refreshPromise: Promise<string | null> | null = null;

async function executeTokenRefresh(): Promise<string | null> {
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = (async () => {
    try {
      const baseUrl = getApiBaseUrl();
      const res = await fetch(`${baseUrl}/api/auth/refresh`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-VaultGuard-Request": "1"
        }
      });

      if (!res.ok) {
        notifySessionExpired();
        return null;
      }

      const json: ApiResponse<RefreshResponseData> = await res.json();
      if (json.success && json.data?.token) {
        setAccessToken(json.data.token);
        return json.data.token;
      }

      notifySessionExpired();
      return null;
    } catch {
      notifySessionExpired();
      return null;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  skipAuth?: boolean;
  retryOn401?: boolean;
}

export async function apiClient<T = unknown>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const { body, skipAuth = false, retryOn401 = true, headers: customHeaders, ...rest } = options;
  const baseUrl = getApiBaseUrl();
  const url = endpoint.startsWith("http") ? endpoint : `${baseUrl}${endpoint.startsWith("/") ? "" : "/"}${endpoint}`;

  const headers = new Headers(customHeaders);
  headers.set("X-VaultGuard-Request", "1");

  if (body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (!skipAuth && activeAccessToken) {
    headers.set("Authorization", `Bearer ${activeAccessToken}`);
  }

  const fetchOptions: RequestInit = {
    ...rest,
    headers,
    credentials: "include",
    body: body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined
  };

  let response: Response;
  try {
    response = await fetch(url, fetchOptions);
  } catch (err: any) {
    if (err?.name === "AbortError" || fetchOptions.signal?.aborted) {
      throw err;
    }
    throw new ApiError(
      `Network error: Failed to connect to server at ${baseUrl}. Ensure backend is running.`,
      0
    );
  }

  // Handle 401 Unauthorized for token refresh
  if (
    response.status === 401 &&
    retryOn401 &&
    !endpoint.includes("/api/auth/login") &&
    !endpoint.includes("/api/auth/refresh") &&
    !endpoint.includes("/api/auth/register")
  ) {
    const newToken = await executeTokenRefresh();
    if (newToken) {
      // Retry request once with the new access token
      const retryHeaders = new Headers(customHeaders);
      retryHeaders.set("X-VaultGuard-Request", "1");
      if (body !== undefined && !retryHeaders.has("Content-Type")) {
        retryHeaders.set("Content-Type", "application/json");
      }
      retryHeaders.set("Authorization", `Bearer ${newToken}`);

      const retryRes = await fetch(url, {
        ...rest,
        headers: retryHeaders,
        credentials: "include",
        body: body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined
      });

      if (retryRes.ok) {
        return (await retryRes.json()) as T;
      }
      response = retryRes;
    }
  }

  let responseData: any = null;
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    try {
      responseData = await response.json();
    } catch {
      responseData = null;
    }
  }

  if (!response.ok) {
    const errorMessage =
      responseData?.message ||
      (response.status === 404 ? "Requested resource not found." : "An unexpected server error occurred.");
    throw new ApiError(errorMessage, response.status, responseData?.errors);
  }

  return responseData as T;
}
