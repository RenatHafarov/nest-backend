-- CreateTable
CREATE TABLE "nfts" (
    "nftId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "categoryes" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "nfts_pkey" PRIMARY KEY ("nftId")
);
