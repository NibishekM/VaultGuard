/**
 * VaultGuard – Encrypted Local Persistence Layer (IndexedDB) (Phase 8 & 9.1)
 *
 * Persists ONLY encrypted vault records and non-secret KDF metadata.
 * Invariants:
 * - Plaintext credentials, decrypted items, and master passwords are NEVER persisted.
 * - Derived CryptoKeys are NEVER persisted.
 * - Account-scoped isolation: Encrypted caches and metadata are scoped to the active account.
 * - Operates independently of React components.
 * - Handles SSR / headless environments safely.
 */

import { VAULT_CRYPTO_CONSTANTS } from "../crypto/constants";
import { CryptographicError, type EncryptedVaultRecord, type VaultKdfMetadata } from "../crypto/types";

const DB_NAME = VAULT_CRYPTO_CONSTANTS.INDEXEDDB_NAME;
const DB_VERSION = VAULT_CRYPTO_CONSTANTS.INDEXEDDB_VERSION;
const STORE_ITEMS = VAULT_CRYPTO_CONSTANTS.STORE_ENCRYPTED_ITEMS;
const STORE_METADATA = VAULT_CRYPTO_CONSTANTS.STORE_METADATA;

// Active storage user ID for account-scoped isolation
let activeStorageUserId: string | null = null;

export function setActiveStorageUser(userId: string | null): void {
  activeStorageUserId = userId;
}

export function getActiveStorageUser(): string | null {
  return activeStorageUserId;
}

function getEffectiveUserKey(explicitUserId?: string | null): string {
  if (explicitUserId !== undefined) {
    return explicitUserId || "local";
  }
  return activeStorageUserId || "local";
}

function getScopedMetadataKey(key: string, explicitUserId?: string | null): string {
  const u = explicitUserId !== undefined ? explicitUserId : activeStorageUserId;
  return u ? `${u}:${key}` : key;
}

// In-memory fallback for environments without native IndexedDB (e.g. Node tests, SSR)
class MemoryStore {
  private items = new Map<string, EncryptedVaultRecord>();
  private metadata = new Map<string, any>();

  saveItem(item: EncryptedVaultRecord): void {
    this.items.set(item.id, { ...item });
  }

  getItem(id: string, userKey: string): EncryptedVaultRecord | null {
    const item = this.items.get(id);
    if (!item) return null;
    const itemUser = item.userId || "local";
    if (itemUser !== userKey) return null;
    return { ...item };
  }

  listItems(userKey: string): EncryptedVaultRecord[] {
    return Array.from(this.items.values())
      .filter((item) => (item.userId || "local") === userKey)
      .map((item) => ({ ...item }));
  }

  deleteItem(id: string, userKey?: string): void {
    if (userKey) {
      const item = this.items.get(id);
      if (item && (item.userId || "local") === userKey) {
        this.items.delete(id);
      }
    } else {
      this.items.delete(id);
    }
  }

  clearUserItems(userKey: string): void {
    for (const [id, item] of this.items.entries()) {
      if ((item.userId || "local") === userKey) {
        this.items.delete(id);
      }
    }
  }

  clearUserMetadata(userKey: string): void {
    for (const key of this.metadata.keys()) {
      if (userKey === "local") {
        if (!key.includes(":") || key.startsWith("local:")) {
          this.metadata.delete(key);
        }
      } else {
        if (key.startsWith(`${userKey}:`)) {
          this.metadata.delete(key);
        }
      }
    }
  }

  clearItems(): void {
    this.items.clear();
  }

  saveMetadata(key: string, value: any): void {
    this.metadata.set(key, { ...value });
  }

  getMetadata(key: string): any {
    const val = this.metadata.get(key);
    return val ? { ...val } : null;
  }

  clear(): void {
    this.items.clear();
    this.metadata.clear();
  }
}

const memoryStoreFallback = new MemoryStore();

function isIndexedDBAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.indexedDB !== "undefined";
}

/**
 * Opens or initializes the local encrypted IndexedDB database.
 */
export function openVaultDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!isIndexedDBAvailable()) {
      reject(new CryptographicError("IndexedDB is not available in this environment."));
      return;
    }

    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // 1. Store for encrypted vault records
      if (!db.objectStoreNames.contains(STORE_ITEMS)) {
        const itemStore = db.createObjectStore(STORE_ITEMS, { keyPath: "id" });
        itemStore.createIndex("updatedAt", "updatedAt", { unique: false });
      }

      // 2. Store for KDF metadata and vault configuration
      if (!db.objectStoreNames.contains(STORE_METADATA)) {
        db.createObjectStore(STORE_METADATA, { keyPath: "id" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new CryptographicError(`Failed to open IndexedDB: ${request.error?.message}`));
    request.onblocked = () => reject(new CryptographicError("IndexedDB upgrade blocked by another open connection."));
  });
}

/**
 * Validates that an encrypted record strictly conforms to zero-knowledge requirements.
 * Rejects any record containing forbidden plaintext keys.
 */
function validateEncryptedRecord(record: unknown): asserts record is EncryptedVaultRecord {
  if (!record || typeof record !== "object") {
    throw new CryptographicError("Record must be a valid object.");
  }

  const r = record as Record<string, unknown>;

  if (typeof r.id !== "string" || r.id.length === 0) {
    throw new CryptographicError("Encrypted record missing valid id.");
  }

  if (typeof r.encryptedPayload !== "string" || r.encryptedPayload.length === 0) {
    throw new CryptographicError("Encrypted record missing encryptedPayload.");
  }

  if (typeof r.initializationVector !== "string" || r.initializationVector.length === 0) {
    throw new CryptographicError("Encrypted record missing initializationVector.");
  }

  if (typeof r.authenticationTag !== "string" || r.authenticationTag.length === 0) {
    throw new CryptographicError("Encrypted record missing authenticationTag.");
  }

  if (r.encryptionAlgorithm !== VAULT_CRYPTO_CONSTANTS.ENCRYPTION_ALGORITHM) {
    throw new CryptographicError(`Invalid encryption algorithm: ${r.encryptionAlgorithm}`);
  }

  // Security invariant: never allow plaintext password or secret keys in storage record
  const forbiddenKeys = ["password", "plaintext", "secret", "masterPassword", "key", "service", "username"];
  for (const key of forbiddenKeys) {
    if (key in r && r[key] !== undefined) {
      throw new CryptographicError(`Security violation: Plaintext field '${key}' found on encrypted storage record.`);
    }
  }
}

/**
 * Saves or updates an encrypted vault item in IndexedDB scoped to active user.
 * Phase 9.2 (Fix B): Enforces targetUserId validation and rejects/discards writes
 * if the target user does not match the active storage user.
 */
export async function saveEncryptedRecord(
  record: EncryptedVaultRecord,
  targetUserId?: string | null
): Promise<void> {
  validateEncryptedRecord(record);

  // If targetUserId is explicitly provided, validate it matches the record's userId
  if (targetUserId !== undefined && record.userId && record.userId !== targetUserId) {
    throw new CryptographicError("Target user ID does not match record user ID.");
  }

  // Cross-account guard: Discard write if targetUserId does not match active storage user
  if (targetUserId !== undefined && targetUserId !== activeStorageUserId) {
    return;
  }

  const effectiveUserId = targetUserId !== undefined ? targetUserId : activeStorageUserId;
  const effectiveRecord: EncryptedVaultRecord = {
    ...record,
    userId: effectiveUserId || "local"
  };

  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.saveItem(effectiveRecord);
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_ITEMS], "readwrite");
    const store = tx.objectStore(STORE_ITEMS);
    const req = store.put(effectiveRecord);

    req.onsuccess = () => resolve();
    req.onerror = () => reject(new CryptographicError(`Failed to save encrypted record: ${req.error?.message}`));
  });
}

/**
 * Retrieves a single encrypted vault item by ID scoped to active user.
 */
export async function getEncryptedRecord(id: string): Promise<EncryptedVaultRecord | null> {
  const userKey = getEffectiveUserKey();

  if (!isIndexedDBAvailable()) {
    return memoryStoreFallback.getItem(id, userKey);
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_ITEMS], "readonly");
    const store = tx.objectStore(STORE_ITEMS);
    const req = store.get(id);

    req.onsuccess = () => {
      const rec = req.result as EncryptedVaultRecord | undefined;
      if (!rec) {
        resolve(null);
        return;
      }
      const itemUser = rec.userId || "local";
      if (itemUser !== userKey) {
        resolve(null);
        return;
      }
      resolve(rec);
    };
    req.onerror = () => reject(new CryptographicError(`Failed to get encrypted record: ${req.error?.message}`));
  });
}

/**
 * Lists all encrypted vault items from IndexedDB for the active user.
 */
export async function listEncryptedRecords(): Promise<EncryptedVaultRecord[]> {
  const userKey = getEffectiveUserKey();

  if (!isIndexedDBAvailable()) {
    return memoryStoreFallback.listItems(userKey);
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_ITEMS], "readonly");
    const store = tx.objectStore(STORE_ITEMS);
    const req = store.getAll();

    req.onsuccess = () => {
      const allRecords = (req.result || []) as EncryptedVaultRecord[];
      const userRecords = allRecords.filter((rec) => (rec.userId || "local") === userKey);
      resolve(userRecords);
    };
    req.onerror = () => reject(new CryptographicError(`Failed to list encrypted records: ${req.error?.message}`));
  });
}

/**
 * Deletes an encrypted vault item from IndexedDB.
 * Phase 9.2 (Fix B): Scoped to targetUserId if provided.
 */
export async function deleteEncryptedRecord(
  id: string,
  targetUserId?: string | null
): Promise<void> {
  // Cross-account guard: Discard delete if targetUserId does not match active storage user
  if (targetUserId !== undefined && targetUserId !== activeStorageUserId) {
    return;
  }

  const userKey = getEffectiveUserKey(targetUserId);

  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.deleteItem(id, userKey);
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_ITEMS], "readwrite");
    const store = tx.objectStore(STORE_ITEMS);
    const getReq = store.get(id);

    getReq.onsuccess = () => {
      const existing = getReq.result as EncryptedVaultRecord | undefined;
      if (existing) {
        const itemUser = existing.userId || "local";
        if (itemUser === userKey) {
          store.delete(id);
        }
      }
      resolve();
    };
    getReq.onerror = () => resolve();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new CryptographicError(`Failed to delete encrypted record: ${tx.error?.message}`));
  });
}

/**
 * Deletes all encrypted records from IndexedDB for the active user.
 */
export async function clearAllEncryptedRecords(): Promise<void> {
  const userKey = getEffectiveUserKey();

  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.clearUserItems(userKey);
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_ITEMS], "readwrite");
    const store = tx.objectStore(STORE_ITEMS);
    const req = store.getAll();

    req.onsuccess = () => {
      const records = (req.result || []) as EncryptedVaultRecord[];
      for (const rec of records) {
        if ((rec.userId || "local") === userKey) {
          store.delete(rec.id);
        }
      }
      resolve();
    };
    req.onerror = () => reject(new CryptographicError(`Failed to clear encrypted records: ${req.error?.message}`));
  });
}

/**
 * Purges account-specific cached records and metadata on logout or account switch.
 */
export async function clearAccountCache(userId?: string | null): Promise<void> {
  const targetUser = userId !== undefined ? userId || "local" : activeStorageUserId || "local";

  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.clearUserItems(targetUser);
    memoryStoreFallback.clearUserMetadata(targetUser);
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_ITEMS, STORE_METADATA], "readwrite");
    const itemStore = tx.objectStore(STORE_ITEMS);
    const metaStore = tx.objectStore(STORE_METADATA);

    // 1. Clear items for this user
    const itemReq = itemStore.getAll();
    itemReq.onsuccess = () => {
      const records = (itemReq.result || []) as EncryptedVaultRecord[];
      for (const rec of records) {
        if ((rec.userId || "local") === targetUser) {
          itemStore.delete(rec.id);
        }
      }
    };

    // 2. Clear metadata keys for this user
    const metaReq = metaStore.getAllKeys();
    metaReq.onsuccess = () => {
      const keys = (metaReq.result || []) as string[];
      for (const key of keys) {
        if (targetUser === "local") {
          if (!key.includes(":") || key.startsWith("local:")) {
            metaStore.delete(key);
          }
        } else {
          if (key.startsWith(`${targetUser}:`)) {
            metaStore.delete(key);
          }
        }
      }
    };

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new CryptographicError("Failed to clear account cache."));
  });
}

/**
 * Persists the non-secret Vault KDF metadata in IndexedDB scoped to user.
 */
export async function saveKdfMetadata(meta: VaultKdfMetadata, userId?: string | null): Promise<void> {
  const scopedId = getScopedMetadataKey("kdf_metadata", userId);
  const record = {
    id: scopedId,
    ...meta,
    updatedAt: new Date().toISOString()
  };

  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.saveMetadata(scopedId, record);
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_METADATA], "readwrite");
    const store = tx.objectStore(STORE_METADATA);
    const req = store.put(record);

    req.onsuccess = () => resolve();
    req.onerror = () => reject(new CryptographicError(`Failed to save KDF metadata: ${req.error?.message}`));
  });
}

/**
 * Saves encrypted auth verification record (canary) to IndexedDB scoped to user.
 */
export async function saveAuthVerification(
  verification: {
    encryptedPayload: string;
    initializationVector: string;
    authenticationTag: string;
    encryptionAlgorithm: string;
    encryptionVersion: number;
  },
  userId?: string | null
): Promise<void> {
  const scopedId = getScopedMetadataKey("auth_verification", userId);
  const record = {
    id: scopedId,
    ...verification,
    updatedAt: new Date().toISOString()
  };

  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.saveMetadata(scopedId, record);
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_METADATA], "readwrite");
    const store = tx.objectStore(STORE_METADATA);
    const req = store.put(record);

    req.onsuccess = () => resolve();
    req.onerror = () => reject(new CryptographicError(`Failed to save auth verification: ${req.error?.message}`));
  });
}

/**
 * Retrieves the encrypted auth verification record (canary) from IndexedDB scoped to user.
 */
export async function getAuthVerification(userId?: string | null): Promise<{
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: "AES-256-GCM";
  encryptionVersion: 1;
} | null> {
  const scopedId = getScopedMetadataKey("auth_verification", userId);

  if (!isIndexedDBAvailable()) {
    const rec = memoryStoreFallback.getMetadata(scopedId);
    if (!rec) return null;
    return {
      encryptedPayload: rec.encryptedPayload,
      initializationVector: rec.initializationVector,
      authenticationTag: rec.authenticationTag,
      encryptionAlgorithm: rec.encryptionAlgorithm,
      encryptionVersion: rec.encryptionVersion
    };
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_METADATA], "readonly");
    const store = tx.objectStore(STORE_METADATA);
    const req = store.get(scopedId);

    req.onsuccess = () => {
      const rec = req.result;
      if (!rec) {
        // Fallback for legacy un-scoped record if querying for local
        if (!userId && !activeStorageUserId) {
          resolve(null);
          return;
        }
        resolve(null);
        return;
      }
      resolve({
        encryptedPayload: rec.encryptedPayload,
        initializationVector: rec.initializationVector,
        authenticationTag: rec.authenticationTag,
        encryptionAlgorithm: rec.encryptionAlgorithm,
        encryptionVersion: rec.encryptionVersion
      });
    };
    req.onerror = () => reject(new CryptographicError(`Failed to get auth verification: ${req.error?.message}`));
  });
}

/**
 * Persists the local synchronization cursor in IndexedDB scoped to user.
 * Phase 9.2 (Fix B): Discards write if userId is provided and does not match active storage user.
 */
export async function saveSyncCursor(cursor: number, userId?: string | null): Promise<void> {
  // Cross-account guard: Discard write if userId does not match active storage user
  if (userId !== undefined && userId !== activeStorageUserId) {
    return;
  }

  const scopedId = getScopedMetadataKey("sync_cursor", userId);
  const record = {
    id: scopedId,
    cursor,
    updatedAt: new Date().toISOString()
  };

  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.saveMetadata(scopedId, record);
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_METADATA], "readwrite");
    const store = tx.objectStore(STORE_METADATA);
    const req = store.put(record);

    req.onsuccess = () => resolve();
    req.onerror = () => reject(new CryptographicError(`Failed to save sync cursor: ${req.error?.message}`));
  });
}

/**
 * Retrieves the local synchronization cursor from IndexedDB scoped to user.
 */
export async function getSyncCursor(userId?: string | null): Promise<number> {
  const scopedId = getScopedMetadataKey("sync_cursor", userId);

  if (!isIndexedDBAvailable()) {
    const rec = memoryStoreFallback.getMetadata(scopedId);
    return typeof rec?.cursor === "number" ? rec.cursor : 0;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_METADATA], "readonly");
    const store = tx.objectStore(STORE_METADATA);
    const req = store.get(scopedId);

    req.onsuccess = () => {
      const rec = req.result;
      resolve(typeof rec?.cursor === "number" ? rec.cursor : 0);
    };
    req.onerror = () => resolve(0);
  });
}

/**
 * Retrieves the Vault KDF metadata from IndexedDB scoped to user.
 */
export async function getKdfMetadata(userId?: string | null): Promise<VaultKdfMetadata | null> {
  const scopedId = getScopedMetadataKey("kdf_metadata", userId);

  if (!isIndexedDBAvailable()) {
    const rec = memoryStoreFallback.getMetadata(scopedId);
    if (!rec) return null;
    return {
      vaultKdfSalt: rec.vaultKdfSalt,
      vaultKdfAlgorithm: rec.vaultKdfAlgorithm,
      vaultKdfParameters: rec.vaultKdfParameters
    };
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_METADATA], "readonly");
    const store = tx.objectStore(STORE_METADATA);
    const req = store.get(scopedId);

    req.onsuccess = () => {
      const rec = req.result;
      if (!rec) {
        resolve(null);
        return;
      }
      resolve({
        vaultKdfSalt: rec.vaultKdfSalt,
        vaultKdfAlgorithm: rec.vaultKdfAlgorithm,
        vaultKdfParameters: rec.vaultKdfParameters
      });
    };
    req.onerror = () => reject(new CryptographicError(`Failed to get KDF metadata: ${req.error?.message}`));
  });
}

/**
 * Checks whether the local vault has been initialized with a master password and salt.
 */
export async function isVaultInitialized(userId?: string | null): Promise<boolean> {
  const metadata = await getKdfMetadata(userId);
  return metadata !== null && Boolean(metadata.vaultKdfSalt);
}

/**
 * Resets the entire local database (items and metadata).
 */
export async function resetVaultDatabase(): Promise<void> {
  if (!isIndexedDBAvailable()) {
    memoryStoreFallback.clear();
    return;
  }

  const db = await openVaultDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_ITEMS, STORE_METADATA], "readwrite");
    tx.objectStore(STORE_ITEMS).clear();
    tx.objectStore(STORE_METADATA).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new CryptographicError("Failed to reset vault database."));
  });
}
