/**
 * VaultGuard – Canonical Encoding and Binary Conversion (Phase 8)
 *
 * Implements strict Base64 encoding/decoding and UTF-8 byte conversions.
 * Enforces canonical representation without whitespace, ambiguous padding, or trailing bits.
 */

import { CryptographicError } from "./types";

const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Encodes a Uint8Array buffer to a standard canonical Base64 string.
 */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new CryptographicError("Expected Uint8Array for Base64 encoding.");
  }

  // Fast path using Buffer if in Node.js environment
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
  }

  // Browser standard conversion
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decodes a canonical Base64 string into a Uint8Array.
 * Rejects non-strings, non-Base64 characters, invalid padding, and roundtrip mismatches.
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  if (typeof base64 !== "string") {
    throw new CryptographicError("Expected a string for Base64 decoding.");
  }

  const trimmed = base64.trim();
  if (trimmed.length === 0) {
    throw new CryptographicError("Cannot decode empty Base64 string.");
  }

  if (trimmed.length % 4 !== 0) {
    throw new CryptographicError("Invalid Base64 length (must be a multiple of 4).");
  }

  if (!BASE64_REGEX.test(trimmed)) {
    throw new CryptographicError("String contains invalid Base64 characters.");
  }

  try {
    let bytes: Uint8Array;

    if (typeof Buffer !== "undefined") {
      const buf = Buffer.from(trimmed, "base64");
      // Roundtrip check to prevent ambiguous trailing bits
      if (buf.toString("base64") !== trimmed) {
        throw new CryptographicError("Non-canonical Base64 encoding detected.");
      }
      bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } else {
      const binary = atob(trimmed);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      // Roundtrip check
      if (uint8ArrayToBase64(bytes) !== trimmed) {
        throw new CryptographicError("Non-canonical Base64 encoding detected.");
      }
    }

    return bytes;
  } catch (err: any) {
    if (err instanceof CryptographicError) throw err;
    throw new CryptographicError(`Failed to decode Base64: ${err?.message || "Unknown error"}`);
  }
}

/**
 * Converts a UTF-8 string to a Uint8Array.
 */
export function stringToUtf8Bytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts a Uint8Array to a UTF-8 string.
 */
export function utf8BytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Concatenates two Uint8Arrays into a single contiguous Uint8Array.
 */
export function concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.byteLength + b.byteLength);
  result.set(a, 0);
  result.set(b, a.byteLength);
  return result;
}
