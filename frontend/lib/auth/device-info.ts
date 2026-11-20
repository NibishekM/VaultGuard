/**
 * VaultGuard – Client Device Fingerprint Helper (Phase 9)
 *
 * Generates and persists a stable client device identifier in localStorage.
 * Detects browser and OS for display in Settings > Devices.
 */

const DEVICE_ID_KEY = "vg_device_identifier";

export function getOrCreateDeviceIdentifier(): string {
  if (typeof window === "undefined") return "default-ssr";

  try {
    let id = localStorage.getItem(DEVICE_ID_KEY);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(DEVICE_ID_KEY, id);
    }
    return id;
  } catch {
    return "default-client";
  }
}

export function getDeviceName(): string {
  if (typeof navigator === "undefined") return "Browser Session";

  const ua = navigator.userAgent;
  let browser = "Browser";
  if (ua.includes("Firefox")) browser = "Firefox";
  else if (ua.includes("Edg")) browser = "Edge";
  else if (ua.includes("Chrome")) browser = "Chrome";
  else if (ua.includes("Safari")) browser = "Safari";

  let os = "Device";
  if (ua.includes("Win")) os = "Windows";
  else if (ua.includes("Mac")) os = "macOS";
  else if (ua.includes("Linux")) os = "Linux";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";

  return `${browser} on ${os}`;
}
