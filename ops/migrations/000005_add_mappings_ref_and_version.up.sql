ALTER TABLE ONLY mappings ADD COLUMN ref text;
ALTER TABLE ONLY mappings ADD COLUMN version text;
CREATE UNIQUE INDEX idx_mappings_ref_version ON mappings (ref, version) WHERE ref IS NOT NULL;
