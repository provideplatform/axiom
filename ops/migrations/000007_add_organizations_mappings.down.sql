-- ALTER TABLE ONLY mappings_organizations DROP CONSTRAINT mappings_mapping_id_mappings_id_foreign;
-- ALTER TABLE ONLY mappings_organizations DROP CONSTRAINT organizations_organization_id_organizations_id_foreign;

DROP TABLE mappings_organizations;

-- DROP INDEX idx_mappings_workgroup_id;

-- ALTER TABLE ONLY public.mappings ADD COLUMN organization_id uuid;

-- CREATE INDEX idx_mappings_organization_id_workgroup_id ON public.mappings USING btree (organization_id, workgroup_id);

