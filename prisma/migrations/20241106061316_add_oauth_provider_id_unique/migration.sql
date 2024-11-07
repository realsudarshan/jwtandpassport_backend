/*
  Warnings:

  - A unique constraint covering the columns `[oauthProviderId]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "User_oauthProviderId_key" ON "User"("oauthProviderId");
