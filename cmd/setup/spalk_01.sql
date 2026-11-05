-- Spalk: the generic OIDC IdP's "email verified" option (see SPALK.md).
ALTER TABLE IF EXISTS projections.idp_templates6_oidc ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN;
