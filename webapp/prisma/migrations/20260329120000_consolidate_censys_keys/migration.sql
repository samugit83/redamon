-- Consolidate Censys credentials from 4 fields to 2.
-- The legacy Search API v2 (censys_api_id / censys_api_secret) is replaced
-- by the Platform API v3 (censys_api_token / censys_org_id).
--
-- If a user already stored a platform token in censys_api_token, keep it.
-- Otherwise, no data migration is needed since the old API ID/Secret pair
-- is fundamentally different credentials (Basic Auth vs Bearer PAT).

ALTER TABLE "user_settings" DROP COLUMN IF EXISTS "censys_api_id";
ALTER TABLE "user_settings" DROP COLUMN IF EXISTS "censys_api_secret";
