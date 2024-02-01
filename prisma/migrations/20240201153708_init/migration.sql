/*
  Warnings:

  - The primary key for the `Staking` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- AlterTable
ALTER TABLE "Staking" DROP CONSTRAINT "Staking_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ALTER COLUMN "nftId" SET DATA TYPE TEXT,
ALTER COLUMN "amount" SET DATA TYPE TEXT,
ADD CONSTRAINT "Staking_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Staking_id_seq";
