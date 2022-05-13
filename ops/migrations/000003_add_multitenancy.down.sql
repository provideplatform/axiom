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

DROP INDEX idx_workgroups_organization_id;
DROP INDEX idx_workgroups_id_organization_id;
ALTER TABLE ONLY workgroups DROP COLUMN organization_id;

ALTER TABLE ONLY workgroups DROP CONSTRAINT workgroups_pkey;
ALTER TABLE ONLY workgroups ADD CONSTRAINT workgroups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY subjectaccounts DROP CONSTRAINT subjectaccounts_pkey;
DROP TABLE subjectaccounts;

ALTER TABLE ONLY mappings DROP CONSTRAINT mappings_workgroup_id_foreign;
ALTER TABLE ONLY workgroups_participants DROP CONSTRAINT workgroups_participants_workgroup_id_foreign;
ALTER TABLE ONLY workflows DROP CONSTRAINT workflows_workgroup_id_foreign;
ALTER TABLE ONLY workgroups DROP CONSTRAINT workgroups_pkey;

ALTER TABLE ONLY workgroups
    ADD CONSTRAINT workgroups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workgroups_participants
  ADD CONSTRAINT workgroups_participants_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY workflows
  ADD CONSTRAINT workflows_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY mappings
  ADD CONSTRAINT mappings_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;
