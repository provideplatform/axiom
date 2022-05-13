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

ALTER TABLE ONLY mappings ADD COLUMN ref_mapping_id uuid;
CREATE INDEX idx_mappings_ref_mapping_id ON public.mappings USING btree (ref_mapping_id);
ALTER TABLE ONLY public.mappings
  ADD CONSTRAINT mappings_ref_mapping_id_foreign FOREIGN KEY (ref_mapping_id) REFERENCES public.mappings(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY mappingfields ADD COLUMN ref_field_id uuid;
CREATE INDEX idx_mappingfields_ref_field_id ON public.mappingfields USING btree (ref_field_id);
ALTER TABLE ONLY public.mappingfields
  ADD CONSTRAINT mappingfields_ref_field_id_foreign FOREIGN KEY (ref_field_id) REFERENCES public.mappingfields(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY mappingmodels ADD COLUMN ref_model_id uuid;
CREATE INDEX idx_mappingmodels_ref_model_id ON public.mappingmodels USING btree (ref_model_id);
ALTER TABLE ONLY public.mappingmodels
  ADD CONSTRAINT mappingmodels_ref_model_id_foreign FOREIGN KEY (ref_model_id) REFERENCES public.mappingmodels(id) ON UPDATE CASCADE ON DELETE CASCADE;
