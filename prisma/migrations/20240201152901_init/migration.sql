-- CreateTable
CREATE TABLE "Staking" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "nftId" INTEGER NOT NULL,
    "amount" DECIMAL(65,30) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Staking_pkey" PRIMARY KEY ("id")
);
