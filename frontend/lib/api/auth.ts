/**
 * VaultGuard – Authentication API Service (Phase 9)
 *
 * Implements client-side calls for registration, login, refresh, logout, and profile.
 * Ensures strict zero-knowledge: master password is NEVER accepted or passed here.
 */

import { apiClient, setAccessToken } from "./client";
import type {
  ApiResponse,
  LoginRequest,
  LoginResponseData,
  RefreshResponseData,
  RegisterRequest,
  SafeUser
} from "./types";

export const authApi = {
  /**
   * Registers a new user account with backend.
   * Transmits account password (hashed via Argon2id on server) and non-secret KDF metadata.
   * Master password and derived encryption key are NEVER sent.
   */
  async register(data: RegisterRequest): Promise<SafeUser> {
    const res = await apiClient<ApiResponse<SafeUser>>("/api/auth/register", {
      method: "POST",
      skipAuth: true,
      body: data
    });
    if (!res.data) {
      throw new Error("Registration succeeded but no user data was returned.");
    }
    return res.data;
  },

  /**
   * Authenticates user credentials with backend.
   * Returns JWT access token and user KDF metadata.
   * Sets HttpOnly refresh token cookie on backend.
   */
  async login(data: LoginRequest): Promise<LoginResponseData> {
    const res = await apiClient<ApiResponse<LoginResponseData>>("/api/auth/login", {
      method: "POST",
      skipAuth: true,
      body: data
    });
    if (!res.data?.token) {
      throw new Error("Login succeeded but no access token was returned.");
    }
    setAccessToken(res.data.token);
    return res.data;
  },

  /**
   * Refreshes the active session via rotating HttpOnly refresh token.
   */
  async refresh(): Promise<RefreshResponseData> {
    const res = await apiClient<ApiResponse<RefreshResponseData>>("/api/auth/refresh", {
      method: "POST",
      skipAuth: true
    });
    if (!res.data?.token) {
      throw new Error("Token refresh succeeded but no access token was returned.");
    }
    setAccessToken(res.data.token);
    return res.data;
  },

  /**
   * Logs out the user by revoking server session and clearing refresh cookie.
   */
  async logout(): Promise<void> {
    try {
      await apiClient<ApiResponse<{ success: boolean }>>("/api/auth/logout", {
        method: "POST"
      });
    } finally {
      setAccessToken(null);
    }
  },

  /**
   * Retrieves current authenticated user profile and KDF parameters.
   */
  async getMe(): Promise<SafeUser> {
    const res = await apiClient<ApiResponse<SafeUser>>("/api/auth/me", {
      method: "GET"
    });
    if (!res.data) {
      throw new Error("Profile retrieval succeeded but no user data was returned.");
    }
    return res.data;
  }
};
