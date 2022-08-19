-- organizations_mappings join table

CREATE TABLE organizations_mappings (
    organization_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    mapping_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    permissions integer DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY organizations_mappings ADD CONSTRAINT organizations_mappings_pkey PRIMARY KEY (mapping_id, organization_id);
