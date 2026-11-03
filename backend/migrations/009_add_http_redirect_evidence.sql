-- Additive redirect evidence storage. Existing final_url values are retained
-- unchanged and remain legacy/unverified when this column is NULL.
ALTER TABLE domain_states
    ADD COLUMN http_redirect_evidence jsonb;
