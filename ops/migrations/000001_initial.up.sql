--
-- PostgreSQL database dump
--

-- Dumped from database version 10.6
-- Dumped by pg_dump version 10.11 (Ubuntu 10.11-1.pgdg16.04+1)

-- The following portion of the pg_dump output should not run during migrations:
-- SET statement_timeout = 0;
-- SET lock_timeout = 0;
-- SET idle_in_transaction_session_timeout = 0;
-- SET client_encoding = 'UTF8';
-- SET standard_conforming_strings = on;
-- SELECT pg_catalog.set_config('search_path', '', false);
-- SET check_function_bodies = false;
-- SET xmloption = content;
-- SET client_min_messages = warning;
-- SET row_security = off;

DO
$do$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE  rolname = 'baseline') THEN
      CREATE ROLE baseline WITH SUPERUSER LOGIN PASSWORD 'prvdbaseline';
   END IF;
END
$do$;

SET ROLE baseline;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


ALTER USER current_user WITH NOSUPERUSER;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: workgroups; Type: TABLE; Schema: public; Owner: baseline
--

CREATE TABLE public.workgroups (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    name text NOT NULL,
    description text,
    privacy_policy bytea,
    security_policy bytea,
    tokenization_policy bytea
);


ALTER TABLE public.workgroups OWNER TO baseline;

--
-- Name: workgroups workgroups_pkey; Type: CONSTRAINT; Schema: public; Owner: baseline
--

ALTER TABLE ONLY public.workgroups
    ADD CONSTRAINT workgroups_pkey PRIMARY KEY (id);

CREATE TABLE public.workgroups_participants (
    workgroup_id uuid NOT NULL,
    participant varchar(64) NOT NULL
);

CREATE INDEX idx_workgroups_participants_workgroup_id_participant ON public.workgroups_participants USING btree (workgroup_id, participant);

ALTER TABLE ONLY public.workgroups_participants
  ADD CONSTRAINT workgroups_participants_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES public.workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

--
-- Name: workflows; Type: TABLE; Schema: public; Owner: baseline
--

CREATE TABLE public.workflows (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    name text NOT NULL,
    description text,
    shield text,
    status text NOT NULL,
    version text,
    workgroup_id uuid NOT NULL,
    workflow_id uuid
);


ALTER TABLE public.workflows OWNER TO baseline;

--
-- Name: workflows workflows_pkey; Type: CONSTRAINT; Schema: public; Owner: baseline
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_pkey PRIMARY KEY (id);

CREATE INDEX idx_workflows_workgroup_id ON public.workflows USING btree (workgroup_id);
CREATE INDEX idx_workflows_workflow_id ON public.workflows USING btree (workflow_id);

ALTER TABLE ONLY public.workflows
  ADD CONSTRAINT workflows_workgroup_id_foreign FOREIGN KEY (workgroup_id) REFERENCES public.workgroups(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY public.workflows
  ADD CONSTRAINT workflows_workflow_id_foreign FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON UPDATE CASCADE ON DELETE CASCADE;

CREATE TABLE public.workflows_participants (
    workflow_id uuid NOT NULL,
    participant varchar(64) NOT NULL
);

CREATE INDEX idx_workflows_participants_workflow_id_participant ON public.workflows_participants USING btree (workflow_id, participant);

ALTER TABLE ONLY public.workflows_participants
  ADD CONSTRAINT workflows_participants_workgroup_id_foreign FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON UPDATE CASCADE ON DELETE CASCADE;

--
-- Name: worksteps; Type: TABLE; Schema: public; Owner: baseline
--

CREATE TABLE public.worksteps (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    description text,
    circuit_id uuid,
    created_at timestamp with time zone NOT NULL,
    require_finality boolean default false NOT NULL,
    workflow_id uuid NOT NULL,
    workstep_id uuid
);


ALTER TABLE public.worksteps OWNER TO baseline;

--
-- Name: worksteps worksteps_pkey; Type: CONSTRAINT; Schema: public; Owner: baseline
--

ALTER TABLE ONLY public.worksteps
    ADD CONSTRAINT worksteps_pkey PRIMARY KEY (id);

CREATE INDEX idx_worksteps_workflow_id ON public.worksteps USING btree (workflow_id);
CREATE INDEX idx_worksteps_workstep_id ON public.worksteps USING btree (workstep_id);

ALTER TABLE ONLY public.worksteps
  ADD CONSTRAINT worksteps_workflow_id_foreign FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY public.worksteps
  ADD CONSTRAINT worksteps_workstep_id_foreign FOREIGN KEY (workstep_id) REFERENCES public.worksteps(id) ON UPDATE CASCADE ON DELETE CASCADE;

CREATE TABLE public.worksteps_participants (
    workstep_id uuid NOT NULL,
    participant varchar(64) NOT NULL
);

CREATE INDEX idx_worksteps_participants_workstep_id_participant ON public.worksteps_participants USING btree (workstep_id, participant);

ALTER TABLE ONLY public.worksteps_participants
  ADD CONSTRAINT worksteps_participants_workgroup_id_foreign FOREIGN KEY (workstep_id) REFERENCES public.worksteps(id) ON UPDATE CASCADE ON DELETE CASCADE;
