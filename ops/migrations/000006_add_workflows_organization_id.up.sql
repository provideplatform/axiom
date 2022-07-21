ALTER TABLE ONLY workflows ADD COLUMN organization_id uuid;

CREATE INDEX idx_workflows_organization_id ON public.workflows USING btree (organization_id);