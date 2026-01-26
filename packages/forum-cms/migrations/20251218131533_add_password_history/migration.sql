-- Add passwordHistory column to User table
ALTER TABLE "User"
ADD COLUMN "passwordHistory" JSONB;
