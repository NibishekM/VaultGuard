-- CreateTable
CREATE TABLE `users` (
    `id` VARCHAR(36) NOT NULL,
    `email` VARCHAR(255) NOT NULL,
    `emailNormalized` VARCHAR(255) NOT NULL,
    `passwordHash` VARCHAR(255) NOT NULL,
    `vaultKdfSalt` VARCHAR(255) NOT NULL,
    `vaultKdfAlgorithm` VARCHAR(50) NOT NULL DEFAULT 'PBKDF2-HMAC-SHA256',
    `vaultKdfParameters` JSON NOT NULL,
    `accountStatus` ENUM('ACTIVE', 'LOCKED', 'DISABLED') NOT NULL DEFAULT 'ACTIVE',
    `emailVerifiedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `users_email_key`(`email`),
    UNIQUE INDEX `users_emailNormalized_key`(`emailNormalized`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `vault_items` (
    `id` VARCHAR(36) NOT NULL,
    `userId` VARCHAR(36) NOT NULL,
    `encryptedPayload` MEDIUMBLOB NOT NULL,
    `initializationVector` VARBINARY(32) NOT NULL,
    `authenticationTag` VARBINARY(16) NOT NULL,
    `encryptionAlgorithm` VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    `encryptionVersion` INTEGER NOT NULL DEFAULT 1,
    `revision` INTEGER NOT NULL DEFAULT 1,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,
    `deletedAt` DATETIME(3) NULL,

    INDEX `vault_items_userId_idx`(`userId`),
    INDEX `vault_items_updatedAt_idx`(`updatedAt`),
    INDEX `vault_items_deletedAt_idx`(`deletedAt`),
    INDEX `vault_items_userId_deletedAt_idx`(`userId`, `deletedAt`),
    INDEX `vault_items_userId_updatedAt_idx`(`userId`, `updatedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `devices` (
    `id` VARCHAR(36) NOT NULL,
    `userId` VARCHAR(36) NOT NULL,
    `deviceIdentifier` VARCHAR(255) NOT NULL,
    `deviceName` VARCHAR(255) NULL,
    `lastSeenAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `devices_userId_idx`(`userId`),
    UNIQUE INDEX `devices_userId_deviceIdentifier_key`(`userId`, `deviceIdentifier`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `vault_items` ADD CONSTRAINT `vault_items_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `devices` ADD CONSTRAINT `devices_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
