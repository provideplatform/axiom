DROP INDEX idx_mappings_ref_version;

ALTER TABLE ONLY mappings DROP COLUMN ref;
ALTER TABLE ONLY mappings DROP COLUMN version;
