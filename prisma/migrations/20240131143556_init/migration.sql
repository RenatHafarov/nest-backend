-- CreateTable
CREATE TABLE "categoryes" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "nftid" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "categoryes_pkey" PRIMARY KEY ("id")
);
