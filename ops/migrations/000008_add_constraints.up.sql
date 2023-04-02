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

CREATE TABLE public.constraints (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expression text NOT NULL,
    description text,
    execution_requirement boolean NOT NULL,
    finality_requirement boolean NOT NULL,
    workstep_id uuid NOT NULL
);

ALTER TABLE public.constraints OWNER TO axiom;

ALTER TABLE ONLY public.constraints ADD CONSTRAINT constraints_pkey PRIMARY KEY (id);

CREATE INDEX idx_constraints_workstep_id ON public.constraints USING btree (workstep_id);

ALTER TABLE ONLY public.constraints
    ADD CONSTRAINT constraints_workstep_id_foreign FOREIGN KEY (workstep_id) REFERENCES public.worksteps(id) ON UPDATE CASCADE ON DELETE CASCADE;
