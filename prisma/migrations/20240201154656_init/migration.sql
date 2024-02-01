/*
  Warnings:

  - Added the required column `adminParameters` to the `Staking` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Staking" ADD COLUMN     "adminParameters" JSONB NOT NULL;
