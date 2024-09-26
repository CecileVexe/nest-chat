/*
  Warnings:

  - You are about to drop the column `fisrtName` on the `user` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE `user` DROP COLUMN `fisrtName`,
    ADD COLUMN `firstName` VARCHAR(191) NULL;
