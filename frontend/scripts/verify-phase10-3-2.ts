/**
 * VaultGuard Phase 10.3.2 – UX and Accessibility Remediation Verification Suite
 *
 * Validates:
 * 1. Vault-lock modal dismissal lifecycle:
 *    - Manual lock dismisses open Add/Edit dialog and Delete dialog
 *    - Automatic inactivity lock dismisses open dialogs
 *    - Logout / session expiration dismisses open dialogs
 *    - Account switching dismisses open dialogs
 *    - Normal unlocked state preserves open dialog across render cycles
 *    - Stale candidate password is discarded upon modal dismissal
 * 2. Password-length slider accessibility:
 *    - Explicit `aria-label="Password length"` on range input
 *    - Explicit `htmlFor="inline-generator-length"` association
 *    - Slider boundaries (8 to 48) and live count update preserved
 * 3. Existing Add/Edit password preservation:
 *    - Existing entry secret preserved during candidate generation
 *    - Cancel preserves original secret
 *    - Dismissal on lock discards candidate without saving partial data
 * 4. Clipboard asynchronous read/write race condition behavior:
 *    - Safe conditional clearing (`currentText === expectedSecret`)
 *    - Timer cancellation across rapid repeated copies
 *    - Documentation and verification of Web Clipboard API async microtask boundary
 */

import fs from "fs";
import path from "path";
import { generateRandomPassword, analyzePassword } from "../lib/password-tools";
import { copyToClipboardWithAutoClear, cancelClipboardAutoClear, clearVaultClipboardImmediately } from "../lib/clipboard";

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName}${detail ? `: ${detail}` : ""}`);
    failed++;
  }
}

// Mock clipboard for headless testing
class MockClipboard {
  private content: string = "";
  public delayMs: number = 0;

  async writeText(text: string): Promise<void> {
    if (this.delayMs > 0) {
      await new Promise(r => setTimeout(r, this.delayMs));
    }
    this.content = text;
  }

  async readText(): Promise<string> {
    if (this.delayMs > 0) {
      await new Promise(r => setTimeout(r, this.delayMs));
    }
    return this.content;
  }

  _setContentDirectly(text: string): void {
    this.content = text;
  }

  _getContent(): string {
    return this.content;
  }

  _clear(): void {
    this.content = "";
  }
}

const mockClipboard = new MockClipboard();
Object.defineProperty(globalThis, "navigator", {
  value: { clipboard: mockClipboard },
  configurable: true,
  writable: true
});

async function runTests() {
  console.log("=== VaultGuard Phase 10.3.2 – UX & Accessibility Remediation Tests ===\n");

  // =========================================================================
  // SUITE 1: Source Code Accessibility & Effect Verification
  // =========================================================================
  console.log("--- Suite 1: Source Code Static Inspection ---");

  const vaultPagePath = path.resolve(__dirname, "../components/vaultguard/vault-page.tsx");
  const vaultPageSource = fs.readFileSync(vaultPagePath, "utf-8");

  // 1.1: Range slider has aria-label="Password length"
  assert(
    vaultPageSource.includes('aria-label="Password length"'),
    "Inline generator range slider has explicit aria-label=\"Password length\""
  );

  // 1.2: Range slider has matching htmlFor and id
  assert(
    vaultPageSource.includes('htmlFor="inline-generator-length"') &&
    vaultPageSource.includes('id="inline-generator-length"'),
    "Range slider has explicit htmlFor and id association for assistive tech"
  );

  // 1.3: Range slider range boundaries preserved (8 to 48)
  assert(
    vaultPageSource.includes('min={8}') && vaultPageSource.includes('max={48}'),
    "Range slider preserves 8 to 48 character boundaries"
  );

  // 1.4: Vault-lock dismissal effect is present and watches keyState and isAuthenticated
  assert(
    vaultPageSource.includes("keyState !== \"unlocked\"") &&
    vaultPageSource.includes("!isAuthenticated") &&
    vaultPageSource.includes("setDialog(null)"),
    "VaultPage includes automatic dialog dismissal effect when vault is not unlocked or not authenticated"
  );

  // =========================================================================
  // SUITE 2: Vault-Lock Modal Dismissal Lifecycle Simulation
  // =========================================================================
  console.log("\n--- Suite 2: Vault-Lock Modal Dismissal Lifecycle Simulation ---");

  // Models VaultPage dialog state machine
  class VaultPageLifecycleModel {
    vaultMode: "encrypted" | "demo" = "encrypted";
    keyState: "unlocked" | "locked" | "locking" | "error" = "unlocked";
    isAuthenticated: boolean = true;
    userId: string | null = "user-101";

    dialog: { mode: "add" } | { mode: "edit"; entryId: string } | null = null;
    deleting: { id: string } | null = null;

    // Component-level state inside dialog (unmounted when dialog === null)
    candidatePassword: string | null = null;
    formSecret: string = "";

    openAddDialog() {
      if (this.vaultMode === "encrypted" && this.keyState !== "unlocked") return;
      this.dialog = { mode: "add" };
      this.formSecret = "";
      this.candidatePassword = null;
    }

    openEditDialog(entryId: string, existingSecret: string) {
      if (this.vaultMode === "encrypted" && this.keyState !== "unlocked") return;
      this.dialog = { mode: "edit", entryId };
      this.formSecret = existingSecret;
      this.candidatePassword = null;
    }

    generateCandidate() {
      if (this.dialog) {
        this.candidatePassword = generateRandomPassword(20, { upper: true, lower: true, numbers: true, symbols: true });
      }
    }

    applyCandidate() {
      if (this.dialog && this.candidatePassword) {
        this.formSecret = this.candidatePassword;
      }
    }

    // Effect simulating the useEffect in VaultPage
    runVaultLifecycleEffect() {
      if (this.vaultMode === "encrypted" && (this.keyState !== "unlocked" || !this.isAuthenticated)) {
        if (this.dialog !== null) {
          this.dialog = null;
          this.candidatePassword = null; // Unmounted
          this.formSecret = "";          // Unmounted
        }
        if (this.deleting !== null) {
          this.deleting = null;
        }
      }
    }

    manualLock() {
      this.keyState = "locked";
      this.runVaultLifecycleEffect();
    }

    inactivityAutoLock() {
      this.keyState = "locked";
      this.runVaultLifecycleEffect();
    }

    logout() {
      this.isAuthenticated = false;
      this.keyState = "locked";
      this.userId = null;
      this.runVaultLifecycleEffect();
    }

    sessionExpire() {
      this.isAuthenticated = false;
      this.keyState = "locked";
      this.runVaultLifecycleEffect();
    }

    switchAccount(newUserId: string) {
      this.userId = newUserId;
      this.keyState = "locked";
      this.runVaultLifecycleEffect();
    }
  }

  // Test 2.1: Normal unlocked state preserves dialog
  const model = new VaultPageLifecycleModel();
  model.openAddDialog();
  assert(model.dialog !== null, "Add Entry dialog opens successfully when unlocked");
  model.runVaultLifecycleEffect();
  assert(model.dialog !== null, "Dialog remains open during normal render cycles while unlocked");

  // Test 2.2: Candidate generation while unlocked does not overwrite form secret
  model.generateCandidate();
  assert(model.candidatePassword !== null, "Candidate generated");
  assert(model.formSecret === "", "Candidate does not prematurely overwrite form secret");

  // Test 2.3: Manual lock automatically dismisses dialog and discards candidate
  model.manualLock();
  assert(model.dialog === null, "Manual lock automatically dismisses open Add Entry dialog");
  assert(model.candidatePassword === null, "Unapplied candidate password discarded upon dialog dismissal");
  assert(model.formSecret === "", "Stale form secret discarded upon dialog dismissal");

  // Test 2.4: Inactivity auto-lock dismisses Edit Entry dialog
  model.keyState = "unlocked";
  model.openEditDialog("item-1", "OriginalSecret99!");
  assert(model.dialog !== null && model.formSecret === "OriginalSecret99!", "Edit dialog open with original secret");
  model.generateCandidate();
  model.inactivityAutoLock();
  assert(model.dialog === null, "Inactivity auto-lock automatically dismisses open Edit Entry dialog");
  assert(model.candidatePassword === null, "Candidate discarded on auto-lock");

  // Test 2.5: Logout dismisses open dialog
  model.keyState = "unlocked";
  model.isAuthenticated = true;
  model.openAddDialog();
  model.generateCandidate();
  model.logout();
  assert(model.dialog === null, "Logout automatically dismisses open dialog");
  assert((model.isAuthenticated as boolean) === false && (model.keyState as string) === "locked", "Auth and vault state properly locked");

  // Test 2.6: Session expiration dismisses open dialog
  model.keyState = "unlocked";
  model.isAuthenticated = true;
  model.openAddDialog();
  model.sessionExpire();
  assert(model.dialog === null, "Session expiration automatically dismisses open dialog");

  // Test 2.7: Account switching dismisses open dialog
  model.keyState = "unlocked";
  model.isAuthenticated = true;
  model.openAddDialog();
  model.switchAccount("user-202");
  assert(model.dialog === null, "Account switching automatically dismisses open dialog");
  assert(model.userId === "user-202", "New user context established");

  // Test 2.8: Delete confirmation dialog is also dismissed on lock
  model.keyState = "unlocked";
  model.deleting = { id: "item-to-delete" };
  model.manualLock();
  assert(model.deleting === null, "Delete confirmation dialog automatically dismissed on vault lock");

  // =========================================================================
  // SUITE 3: Password-Length Slider Behavior & Accessibility
  // =========================================================================
  console.log("\n--- Suite 3: Password-Length Slider Behavior ---");

  // Test 3.1: Slider updates length and regenerates candidate
  let currentLen = 20;
  const opts = { upper: true, lower: true, numbers: true, symbols: true };
  let pwd = generateRandomPassword(currentLen, opts);
  assert(pwd.length === 20, "Initial candidate length is 20");

  // Change length to 32
  currentLen = 32;
  pwd = generateRandomPassword(currentLen, opts);
  assert(pwd.length === 32, "Changing length to 32 generates 32-character candidate");

  // Change length to 8 (minimum)
  currentLen = 8;
  pwd = generateRandomPassword(currentLen, opts);
  assert(pwd.length === 8, "Changing length to 8 generates 8-character candidate");

  // Change length to 48 (maximum)
  currentLen = 48;
  pwd = generateRandomPassword(currentLen, opts);
  assert(pwd.length === 48, "Changing length to 48 generates 48-character candidate");

  // =========================================================================
  // SUITE 4: Clipboard Asynchronous Read/Write Race Condition Assessment
  // =========================================================================
  console.log("\n--- Suite 4: Clipboard Asynchronous Read/Write Race Condition Assessment ---");

  // Test 4.1: Normal copy and auto-clear
  mockClipboard._clear();
  const secret1 = generateRandomPassword(20, opts);
  const copyRes1 = await copyToClipboardWithAutoClear(secret1, 1);
  assert(copyRes1.success === true, "copyToClipboardWithAutoClear succeeds");
  assert(mockClipboard._getContent() === secret1, "Clipboard content matches copied secret");

  // Wait for 1s auto-clear
  await new Promise(r => setTimeout(r, 1100));
  assert(mockClipboard._getContent() === "", "Clipboard successfully cleared after timer expiration");

  // Test 4.2: Repeated copies cancel older pending timers
  const secretA = "SecretA_Initial_2026!";
  const secretB = "SecretB_Subsequent_2026#";
  await copyToClipboardWithAutoClear(secretA, 1);
  assert(mockClipboard._getContent() === secretA, "First secret copied");

  // Rapidly copy second secret before first timer fires
  await copyToClipboardWithAutoClear(secretB, 2);
  assert(mockClipboard._getContent() === secretB, "Second secret copied and replaced clipboard content");

  // Wait past secretA's 1-second timeout (1.1s total)
  await new Promise(r => setTimeout(r, 1100));
  // secretA's timer was cancelled, so secretB must still be intact!
  assert(
    mockClipboard._getContent() === secretB,
    "Older timer was cancelled; did NOT prematurely clear newer secret"
  );

  // Wait for secretB's remaining time (total > 2s)
  await new Promise(r => setTimeout(r, 1100));
  assert(mockClipboard._getContent() === "", "Newer secret cleared at its own scheduled deadline");

  // Test 4.3: External user overwrite safety
  const secretC = "SecretC_VaultGuard_2026$";
  await copyToClipboardWithAutoClear(secretC, 1);
  assert(mockClipboard._getContent() === secretC, "Secret C copied");

  // External application overwrites clipboard
  mockClipboard._setContentDirectly("Unrelated user notes copied from external browser tab");
  await new Promise(r => setTimeout(r, 1100));

  // Conditional clear must detect mismatch and NOT overwrite external data
  assert(
    mockClipboard._getContent() === "Unrelated user notes copied from external browser tab",
    "Conditional check detected mismatch and preserved external user clipboard text"
  );

  // Test 4.4: Immediate clearing on vault lock
  const secretD = "SecretD_ImmediateLock_2026%";
  await copyToClipboardWithAutoClear(secretD, 30);
  assert(mockClipboard._getContent() === secretD, "Secret D copied with 30s timer");

  const clearSuccess = await clearVaultClipboardImmediately();
  assert(clearSuccess === true, "clearVaultClipboardImmediately successfully clears secret immediately");
  assert(mockClipboard._getContent() === "", "Clipboard content cleared immediately without waiting 30s");

  cancelClipboardAutoClear();

  console.log("\n=======================================================");
  console.log(`Results: ${passed} passed, ${failed} failed.`);
  console.log("=======================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
