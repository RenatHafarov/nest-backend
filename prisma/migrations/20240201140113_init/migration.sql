/*
  Warnings:

  - Added the required column `stacking` to the `nfts` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "nfts" ADD COLUMN     "stacking" INTEGER NOT NULL;
