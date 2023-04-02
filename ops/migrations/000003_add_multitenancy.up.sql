/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *
 *  * Copyright 2017-2022 Provide Technologies Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 *
 *
 */

ALTER TABLE ONLY mappings DROP CONSTRAINT mappings_workgroup_id_foreign;
ALTER TABLE ONLY workgroups_participants DROP CONSTRAINT workgroups_participants_workgroup_id_foreign;
ALTER TABLE ONLY workflows DROP CONSTRAINT workflows_workgroup_id_foreign;
ALTER TABLE ONLY workgroups DROP CONSTRAINT workgroups_pkey;

ALTER TABLE ONLY workgroups ADD COLUMN organization_id uuid NOT NULL;
CREATE UNIQUE INDEX idx_workgroups_id ON workgroups USING btree (id);
CREATE INDEX idx_workgroups_organization_id ON workgroups USING btree (organization_id);
ALTER TABLE ONLY workgroups ADD CONSTRAINT workgroups_pkey PRIMARY KEY (id, organization_id);

ALTER TABLE ONLY mappings
  ADD CONSTRAINT mappings_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY workgroups_participants
  ADD CONSTRAINT workgroups_participants_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY workflows
  ADD CONSTRAINT workflows_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

CREATE TABLE subjectaccounts (
    id varchar(64) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    subject_id uuid NOT NULL,
    type text NOT NULL,
    refresh_token text NOT NULL,
    vault_id uuid NOT NULL,
    credentials_secret_id uuid,
    metadata_secret_id uuid,
    recovery_policy_secret_id uuid,
    role_secret_id uuid,
    security_policies_secret_id uuid,
    bpiaccountids json DEFAULT '[]'
);

ALTER TABLE subjectaccounts OWNER TO axiom;
ALTER TABLE ONLY subjectaccounts ADD CONSTRAINT subjectaccounts_pkey PRIMARY KEY (id);
CREATE INDEX idx_subjectaccounts_subject_id ON subjectaccounts USING btree (subject_id);
