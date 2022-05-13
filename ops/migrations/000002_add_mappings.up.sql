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

--
-- Name: mappings; Type: TABLE; Schema: public; Owner: baseline
--

CREATE TABLE public.mappings (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    name text NOT NULL,
    type varchar(64),
    description text,
    organization_id uuid NOT NULL,
    workgroup_id uuid NOT NULL
);

ALTER TABLE public.mappings OWNER TO baseline;

ALTER TABLE ONLY public.mappings
    ADD CONSTRAINT mappings_pkey PRIMARY KEY (id);

CREATE INDEX idx_mappings_type ON public.mappings USING btree (type);
CREATE INDEX idx_mappings_organization_id_workgroup_id ON public.mappings USING btree (organization_id, workgroup_id);

ALTER TABLE ONLY public.mappings
  ADD CONSTRAINT mappings_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES public.workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

CREATE TABLE public.mappingmodels (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    mapping_id uuid NOT NULL,
    type text NOT NULL,
    primary_key text NOT NULL,
    description text,
    standard text
);

ALTER TABLE public.mappingmodels OWNER TO baseline;

ALTER TABLE ONLY public.mappingmodels
    ADD CONSTRAINT mappingmodels_pkey PRIMARY KEY (id);

CREATE INDEX idx_mappingmodels_type ON public.mappingmodels USING btree (type);
CREATE INDEX idx_mappingmodels_mapping_id ON public.mappingmodels USING btree (mapping_id);
CREATE INDEX idx_mappingmodels_standard ON public.mappingmodels USING btree (standard);

ALTER TABLE ONLY public.mappingmodels
  ADD CONSTRAINT mappingmodels_mapping_id_foreign FOREIGN KEY (mapping_id) REFERENCES public.mappings(id) ON UPDATE CASCADE ON DELETE CASCADE;

CREATE TABLE public.mappingfields (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    mappingmodel_id uuid NOT NULL,
    name text NOT NULL,
    type varchar(64) NOT NULL,
    description text,
    default_value varchar(64),
    is_primary_key bool NOT NULL DEFAULT false
);

ALTER TABLE public.mappingfields OWNER TO baseline;

ALTER TABLE ONLY public.mappingfields
    ADD CONSTRAINT mappingfields_pkey PRIMARY KEY (id);

CREATE INDEX idx_mappingfields_mappingmodel_id ON public.mappingfields USING btree (mappingmodel_id);
CREATE INDEX idx_mappingfields_type ON public.mappingfields USING btree (type);

ALTER TABLE ONLY public.mappingfields
  ADD CONSTRAINT mappingfields_mappingmodel_id_foreign FOREIGN KEY (mappingmodel_id) REFERENCES public.mappingmodels(id) ON UPDATE CASCADE ON DELETE CASCADE;
