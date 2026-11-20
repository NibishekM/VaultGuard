-- AlterTable
ALTER TABLE `users` ADD COLUMN `syncVersion` INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE `vault_items` ADD COLUMN `syncVersion` INTEGER NOT NULL DEFAULT 0;

-- Backfill existing vault records with unique, ordered synchronization versions per user (including soft-deleted records)
UPDATE `vault_items` v
JOIN (
  SELECT `id`, ROW_NUMBER() OVER (PARTITION BY `userId` ORDER BY `createdAt` ASC, `id` ASC) as row_num
  FROM `vault_items`
) ranked ON v.`id` = ranked.`id`
SET v.`syncVersion` = ranked.row_num;

-- Set each user's syncVersion to the highest version assigned to their existing vault records
UPDATE `users` u
JOIN (
  SELECT `userId`, MAX(`syncVersion`) as maxVersion
  FROM `vault_items`
  GROUP BY `userId`
) m ON u.`id` = m.`userId`
SET u.`syncVersion` = m.maxVersion;

-- CreateIndex
CREATE INDEX `vault_items_userId_syncVersion_idx` ON `vault_items`(`userId`, `syncVersion`);

-- CreateIndex
CREATE INDEX `vault_items_syncVersion_idx` ON `vault_items`(`syncVersion`);
