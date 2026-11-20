-- CreateTable
CREATE TABLE `vault_verifications` (
    `id` VARCHAR(36) NOT NULL,
    `userId` VARCHAR(36) NOT NULL,
    `encryptedPayload` MEDIUMBLOB NOT NULL,
    `initializationVector` VARBINARY(32) NOT NULL,
    `authenticationTag` VARBINARY(16) NOT NULL,
    `encryptionAlgorithm` VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    `encryptionVersion` INTEGER NOT NULL DEFAULT 1,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `vault_verifications_userId_key`(`userId`),
    INDEX `vault_verifications_userId_idx`(`userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `vault_verifications` ADD CONSTRAINT `vault_verifications_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
