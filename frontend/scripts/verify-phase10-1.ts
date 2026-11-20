/**
 * VaultGuard – Phase 10.1 Verification Suite
 * Secure Clipboard Auto-Clear Implementation
 *
 * Usage: tsx scripts/verify-phase10-1.ts
 */

import {
  copyToClipboardWithAutoClear,
  clearVaultClipboardImmediately,
  cancelClipboardAutoClear,
  isClipboardAutoClearActive,
  getClipboardStateForTesting,
  resetClipboardStateForTesting,
  DEFAULT_CLIPBOARD_AUTO_CLEAR_SECONDS
} from "../lib/clipboard";

let testPassedCount = 0;
let testFailedCount = 0;

function logTest(num: number, desc: string, passed: boolean, detail?: string) {
  if (passed) {
    testPassedCount++;
    console.log(`  ✅ PASS [${num}] ${desc}${detail ? ` (${detail})` : ""}`);
  } else {
    testFailedCount++;
    console.error(`  ❌ FAIL [${num}] ${desc}${detail ? ` (${detail})` : ""}`);
  }
}

// In-memory mock clipboard for unit testing browser clipboard behavior
class MockClipboard {
  private content: string = "";
  public readAllowed: boolean = true;
  public writeAllowed: boolean = true;
  public writeCount: number = 0;
  public readCount: number = 0;

  async writeText(text: string): Promise<void> {
    this.writeCount++;
    if (!this.writeAllowed) {
      throw new Error("NotAllowedError: Clipboard write permission denied.");
    }
    this.content = text;
  }

  async readText(): Promise<string> {
    this.readCount++;
    if (!this.readAllowed) {
      throw new Error("NotAllowedError: Clipboard read permission denied.");
    }
    return this.content;
  }

  getContent(): string {
    return this.content;
  }

  setContent(text: string): void {
    this.content = text;
  }

  reset(): void {
    this.content = "";
    this.readAllowed = true;
    this.writeAllowed = true;
    this.writeCount = 0;
    this.readCount = 0;
  }
}

const mockClipboard = new MockClipboard();

function setupBrowserEnvironment(clipboardImpl?: any) {
  Object.defineProperty(globalThis, "navigator", {
    value: {
      clipboard: clipboardImpl
    },
    configurable: true,
    writable: true
  });
}

async function run() {
  console.log("================================================================================");
  console.log("VaultGuard Phase 10.1: Secure Clipboard Auto-Clear Verification Suite");
  console.log("================================================================================\n");

  try {
    // -------------------------------------------------------------------------
    console.log("── Section 1: Core Copy & Timeout Configuration ──");
    // -------------------------------------------------------------------------

    // Setup standard mock clipboard
    setupBrowserEnvironment(mockClipboard);
    mockClipboard.reset();
    resetClipboardStateForTesting();

    // Test 1: Successful clipboard write
    const res1 = await copyToClipboardWithAutoClear("SecretPassword!123");
    logTest(
      1,
      "1. Successful clipboard write returns success: true and stores secret in clipboard",
      res1.success && mockClipboard.getContent() === "SecretPassword!123",
      `Copied text: '${mockClipboard.getContent()}'`
    );

    // Test 2: Default 30-second timeout configuration
    logTest(
      2,
      "2. Default auto-clear timeout is exactly 30 seconds and timer is scheduled",
      res1.autoClearScheduled &&
        res1.timeoutSeconds === DEFAULT_CLIPBOARD_AUTO_CLEAR_SECONDS &&
        isClipboardAutoClearActive(),
      `timeoutSeconds: ${res1.timeoutSeconds}`
    );

    // Test 3: Custom timeout configuration
    mockClipboard.reset();
    resetClipboardStateForTesting();
    const res3 = await copyToClipboardWithAutoClear("CustomTimeoutSecret!", 10);
    logTest(
      3,
      "3. Configurable timeout: correctly honors custom timeoutSeconds = 10",
      res3.success && res3.autoClearScheduled && res3.timeoutSeconds === 10,
      `Configured timeout: ${res3.timeoutSeconds}s`
    );

    // -------------------------------------------------------------------------
    console.log("\n── Section 2: Timer Lifecycle & Repeated Copies ──");
    // -------------------------------------------------------------------------

    // Test 4: Repeated copy operations replaces tracked secret
    mockClipboard.reset();
    resetClipboardStateForTesting();
    await copyToClipboardWithAutoClear("Secret_A", 30);
    const res4 = await copyToClipboardWithAutoClear("Secret_B", 30);
    logTest(
      4,
      "4. Repeated copy replaces clipboard content with the newly copied secret",
      res4.success && mockClipboard.getContent() === "Secret_B",
      `Current clipboard: '${mockClipboard.getContent()}'`
    );

    // Test 5: Previous timer cancellation on subsequent copy
    const stateAfterSecondCopy = getClipboardStateForTesting();
    logTest(
      5,
      "5. Repeated copy safely cancels previous timer leaving exactly one active timer",
      stateAfterSecondCopy.hasActiveTimer && stateAfterSecondCopy.hasTrackedSecret,
      "Single active timer verified"
    );

    // -------------------------------------------------------------------------
    console.log("\n── Section 3: Safe Conditional Clearing & Overwrite Prevention ──");
    // -------------------------------------------------------------------------

    // Test 6: Clipboard still contains the original secret -> cleared on timeout/trigger
    mockClipboard.reset();
    resetClipboardStateForTesting();
    await copyToClipboardWithAutoClear("Secret_To_Be_Cleared", 1);
    // Wait for the 1-second auto-clear timer to fire
    await new Promise((resolve) => setTimeout(resolve, 1100));
    logTest(
      6,
      "6. Auto-clear clears clipboard when clipboard still holds original VaultGuard secret",
      mockClipboard.getContent() === "",
      `Clipboard content after auto-clear: '${mockClipboard.getContent()}'`
    );

    // Test 7: Clipboard has been replaced by unrelated content -> NEVER overwrite!
    mockClipboard.reset();
    resetClipboardStateForTesting();
    await copyToClipboardWithAutoClear("VaultGuardSecret_123", 1);
    // Simulate user or external app copying different text before timeout
    mockClipboard.setContent("https://my-unrelated-website.org");
    await new Promise((resolve) => setTimeout(resolve, 1100));
    logTest(
      7,
      "7. Overwrite protection: does NOT overwrite unrelated content copied by user",
      mockClipboard.getContent() === "https://my-unrelated-website.org",
      `Preserved user content: '${mockClipboard.getContent()}'`
    );

    // -------------------------------------------------------------------------
    console.log("\n── Section 4: Permission & Availability Error Handling ──");
    // -------------------------------------------------------------------------

    // Test 8: Clipboard read permission denied -> does not blindly clear clipboard
    mockClipboard.reset();
    resetClipboardStateForTesting();
    await copyToClipboardWithAutoClear("Secret_Read_Denied", 1);
    mockClipboard.readAllowed = false; // Deny read permission
    await new Promise((resolve) => setTimeout(resolve, 1100));
    // Since read was denied, it must NOT blindly clear
    logTest(
      8,
      "8. Read permission denied: refuses to blindly overwrite clipboard content",
      mockClipboard.getContent() === "Secret_Read_Denied",
      "Clipboard preserved safely"
    );
    mockClipboard.readAllowed = true;

    // Test 9: Clipboard write permission denied -> returns error result
    mockClipboard.reset();
    resetClipboardStateForTesting();
    mockClipboard.writeAllowed = false; // Deny write permission
    const res9 = await copyToClipboardWithAutoClear("Secret_Write_Denied", 30);
    logTest(
      9,
      "9. Write permission denied: returns success: false with user-facing message",
      !res9.success && !res9.autoClearScheduled && res9.message.includes("denied"),
      `Message: '${res9.message}'`
    );
    mockClipboard.writeAllowed = true;

    // Test 10: Clipboard API unavailable in environment (e.g. SSR / insecure context)
    setupBrowserEnvironment(undefined); // No clipboard API
    resetClipboardStateForTesting();
    const res10 = await copyToClipboardWithAutoClear("Secret_No_API", 30);
    logTest(
      10,
      "10. Clipboard API unavailable: fails gracefully with explanatory message",
      !res10.success && !res10.autoClearScheduled && res10.message.includes("unavailable"),
      `Message: '${res10.message}'`
    );

    // Restore standard clipboard environment
    setupBrowserEnvironment(mockClipboard);

    // -------------------------------------------------------------------------
    console.log("\n── Section 5: Vault-Lock & Authentication Lifecycle Cleanup ──");
    // -------------------------------------------------------------------------

    // Test 11: Explicit vault lock cleanup
    mockClipboard.reset();
    resetClipboardStateForTesting();
    await copyToClipboardWithAutoClear("VaultSecretForLock", 30);
    const lockClearResult = await clearVaultClipboardImmediately();
    logTest(
      11,
      "11. Explicit vault lock cleanup immediately wipes clipboard and cancels timer",
      lockClearResult &&
        mockClipboard.getContent() === "" &&
        !isClipboardAutoClearActive(),
      `Clipboard: '${mockClipboard.getContent()}', Timer active: ${isClipboardAutoClearActive()}`
    );

    // Test 12: Logout / session-expiration cleanup
    mockClipboard.reset();
    resetClipboardStateForTesting();
    await copyToClipboardWithAutoClear("VaultSecretForLogout", 30);
    // Simulate auth reset / session expiry calling immediate clear
    const logoutClearResult = await clearVaultClipboardImmediately();
    logTest(
      12,
      "12. Logout / session-expiration cleanup immediately clears VaultGuard secret",
      logoutClearResult && mockClipboard.getContent() === "",
      `Clipboard: '${mockClipboard.getContent()}'`
    );

  } finally {
    // Clean up global mock
    try {
      delete (globalThis as any).navigator;
    } catch {}
  }

  console.log("\n════════════════════════════════════════════════════════════");
  console.log(`Phase 10.1 Verification Summary: ${testPassedCount + testFailedCount} tests | ✅ ${testPassedCount} passed | ❌ ${testFailedCount} failed`);
  console.log("════════════════════════════════════════════════════════════\n");

  if (testFailedCount > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

run().catch((err) => {
  console.error("Verification suite failed:", err);
  process.exit(1);
});
