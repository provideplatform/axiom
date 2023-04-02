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

CREATE TABLE public.systems (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    name text NOT NULL,
    type varchar(64) NOT NULL,
    description text,
    organization_id uuid NOT NULL,
    workgroup_id uuid NOT NULL,
    vault_id uuid NOT NULL,
    secret_id uuid NOT NULL
);

ALTER TABLE public.systems OWNER TO axiom;

ALTER TABLE ONLY public.systems ADD CONSTRAINT systems_pkey PRIMARY KEY (id);

CREATE INDEX idx_systems_type ON public.systems USING btree (type);
CREATE INDEX idx_systems_organization_id_workgroup_id ON public.systems USING btree (organization_id, workgroup_id);
CREATE INDEX idx_systems_vault_id_secret_id ON public.systems USING btree (vault_id, secret_id);

ALTER TABLE ONLY public.systems ADD CONSTRAINT systems_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES public.workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;
