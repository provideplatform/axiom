-- organizations_mappings join table

CREATE TABLE organizations_mappings (
    organization_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    mapping_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    permissions integer DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY organizations_mappings ADD CONSTRAINT organizations_mappings_pkey PRIMARY KEY (mapping_id, organization_id);
-- ALTER TABLE ONLY organizations_mappings ADD CONSTRAINT mappings_mapping_id_mappings_id_foreign FOREIGN KEY (mapping_id) REFERENCES mappings(id) ON UPDATE CASCADE ON DELETE CASCADE;

-- ALTER TABLE ONLY organizations_mappings ADD CONSTRAINT mappings_organization_id_organizations_id_foreign FOREIGN KEY (organization_id) REFERENCES organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;

-- -- remove organization_id from mappings

-- DROP INDEX idx_mappings_organization_id_workgroup_id;

-- ALTER TABLE ONLY public.mappings DROP COLUMN organization_id;

-- -- index workgroup_id

-- CREATE INDEX idx_mappings_workgroup_id ON public.mappings USING btree (workgroup_id);