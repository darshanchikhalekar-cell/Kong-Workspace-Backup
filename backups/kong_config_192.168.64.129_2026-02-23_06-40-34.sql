--
-- PostgreSQL database dump
--

\restrict cR2wocwLRr4ds07076Olv5ORVGyja4AejC18mKIXkdPPVkrgYbm7TjBiHJIAdya

-- Dumped from database version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: batch_delete_expired_rows(); Type: FUNCTION; Schema: public; Owner: kong
--

CREATE FUNCTION public.batch_delete_expired_rows() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
          EXECUTE FORMAT('WITH rows AS (SELECT ctid FROM %s WHERE %s < CURRENT_TIMESTAMP AT TIME ZONE ''UTC'' ORDER BY %s LIMIT 2 FOR UPDATE SKIP LOCKED) DELETE FROM %s WHERE ctid = ANY (ARRAY (SELECT ctid FROM rows))', TG_TABLE_NAME, TG_ARGV[0], TG_ARGV[0], TG_TABLE_NAME);
          RETURN NULL;
        END;
      $$;


ALTER FUNCTION public.batch_delete_expired_rows() OWNER TO kong;

--
-- Name: batch_delete_expired_rows_and_gen_deltas(); Type: FUNCTION; Schema: public; Owner: kong
--

CREATE FUNCTION public.batch_delete_expired_rows_and_gen_deltas() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
          DECLARE
            -- SQL query to fetch expired records
            query_expired_record TEXT;

            -- record to store the expired record
            expired_record RECORD;

            -- new version to be inserted in clustering_sync_version
            -- which associated with the generated delta that
            -- deletes the expired record
            new_version integer;

            -- default_ws_id to be used in the delta
            default_ws_id UUID;

            -- unused variable to acquire lock on clustering_sync_lock
            unused_var integer;
          BEGIN
            -- %1$I means consider the first argument as an database identifier like table name
            -- %2$I does the same for the second argument

            -- has ws_id ?
            IF (SELECT TG_ARGV[2]) THEN
              query_expired_record := FORMAT('
                SELECT id, ws_id
                FROM %1$I
                WHERE %2$I < CURRENT_TIMESTAMP AT TIME ZONE ''UTC''
                ORDER BY %2$I
                LIMIT 2
                FOR UPDATE SKIP LOCKED
              ', TG_TABLE_NAME, TG_ARGV[0]);
            ELSE
              query_expired_record := FORMAT('
                SELECT id
                FROM %1$I
                WHERE %2$I < CURRENT_TIMESTAMP AT TIME ZONE ''UTC''
                ORDER BY %2$I
                LIMIT 2
                FOR UPDATE SKIP LOCKED
              ', TG_TABLE_NAME, TG_ARGV[0]);
            END IF;

            SELECT id INTO default_ws_id FROM workspaces WHERE name = 'default';

            FOR expired_record IN EXECUTE query_expired_record LOOP
              -- %2$L means consider the second argument as a literal value,
              -- such as add quotes around TEXT
              EXECUTE FORMAT('
                DELETE FROM %1$I
                WHERE id = %2$L
              ', TG_TABLE_NAME, expired_record.id);

              SELECT id INTO unused_var FROM clustering_sync_lock FOR UPDATE;
              INSERT INTO clustering_sync_version DEFAULT VALUES RETURNING version INTO new_version;

              -- has ws_id ?
              IF (SELECT TG_ARGV[2]) THEN
                INSERT INTO clustering_sync_delta (version, type, pk, ws_id, entity)
                VALUES (new_version, TG_ARGV[1], json_build_object('id', expired_record.id), expired_record.ws_id, null);
              ELSE
                INSERT INTO clustering_sync_delta (version, type, pk, ws_id, entity)
                VALUES (new_version, TG_ARGV[1], json_build_object('id', expired_record.id), default_ws_id, null);
              END IF;

              UPDATE clustering_sync_lock SET id=1;
            END LOOP;

            RETURN NULL;
          END;
        $_$;


ALTER FUNCTION public.batch_delete_expired_rows_and_gen_deltas() OWNER TO kong;

--
-- Name: lock_basicauth_brute_force_metrics(text); Type: FUNCTION; Schema: public; Owner: kong
--

CREATE FUNCTION public.lock_basicauth_brute_force_metrics(name text) RETURNS record
    LANGUAGE plpgsql
    AS $_$
      DECLARE
        ret_val RECORD;
      BEGIN
        BEGIN
          DELETE FROM basicauth_brute_force_locks WHERE key = $1 and ttl < NOW();
          INSERT INTO basicauth_brute_force_locks (key, ttl) values ($1, NOW() + MAKE_INTERVAL(secs => 5));
        EXCEPTION WHEN unique_violation THEN
          ret_val := (0, 0, FALSE);
          RETURN ret_val;
        END;
        SELECT count, cast(extract(epoch from ttl - now()) as INTEGER), true from basicauth_brute_force_metrics WHERE key = $1 INTO ret_val;
        IF ret_val IS NULL THEN
          ret_val := (0, 0, TRUE);
        END IF;
        RETURN ret_val;
      END$_$;


ALTER FUNCTION public.lock_basicauth_brute_force_metrics(name text) OWNER TO kong;

--
-- Name: sync_tags(); Type: FUNCTION; Schema: public; Owner: kong
--

CREATE FUNCTION public.sync_tags() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
          IF (TG_OP = 'TRUNCATE') THEN
            DELETE FROM tags WHERE entity_name = TG_TABLE_NAME;
            RETURN NULL;
          ELSIF (TG_OP = 'DELETE') THEN
            DELETE FROM tags WHERE entity_id = OLD.id;
            RETURN OLD;
          ELSE

          -- Triggered by INSERT/UPDATE
          -- Do an upsert on the tags table
          -- So we don't need to migrate pre 1.1 entities
          INSERT INTO tags VALUES (NEW.id, TG_TABLE_NAME, NEW.tags)
          ON CONFLICT (entity_id) DO UPDATE
                  SET tags=EXCLUDED.tags;
          END IF;
          RETURN NEW;
        END;
      $$;


ALTER FUNCTION public.sync_tags() OWNER TO kong;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ace_auth_strategies; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ace_auth_strategies (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone,
    type text NOT NULL,
    config jsonb NOT NULL,
    ws_id uuid
);


ALTER TABLE public.ace_auth_strategies OWNER TO kong;

--
-- Name: ace_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ace_credentials (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone,
    api_key_hash text,
    client_id text,
    portal_id text,
    application_id text,
    organization_id text,
    auth_strategy_id uuid,
    ws_id uuid,
    cache_key text,
    consumer_custom_id text,
    consumer_group_name text
);


ALTER TABLE public.ace_credentials OWNER TO kong;

--
-- Name: ace_operation_groups; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ace_operation_groups (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone,
    ratelimiting jsonb,
    entity_id text,
    entity_type text,
    tags text[],
    ws_id uuid
);


ALTER TABLE public.ace_operation_groups OWNER TO kong;

--
-- Name: ace_operation_groups_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ace_operation_groups_credentials (
    id uuid NOT NULL,
    operation_group_id uuid,
    credential_id uuid,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone,
    tags text[],
    ws_id uuid,
    cache_key text
);


ALTER TABLE public.ace_operation_groups_credentials OWNER TO kong;

--
-- Name: ace_operation_groups_operations; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ace_operation_groups_operations (
    id uuid NOT NULL,
    operation_group_id uuid,
    operation_id uuid,
    ratelimiting jsonb,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone,
    tags text[],
    ws_id uuid,
    cache_key text
);


ALTER TABLE public.ace_operation_groups_operations OWNER TO kong;

--
-- Name: ace_operations; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ace_operations (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone,
    expression text NOT NULL,
    priority numeric DEFAULT 0,
    tags text[],
    api_id text,
    ws_id uuid
);


ALTER TABLE public.ace_operations OWNER TO kong;

--
-- Name: acls; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.acls (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid,
    "group" text,
    cache_key text,
    tags text[],
    ws_id uuid
);


ALTER TABLE public.acls OWNER TO kong;

--
-- Name: acme_storage; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.acme_storage (
    id uuid NOT NULL,
    key text,
    value text,
    created_at timestamp with time zone,
    ttl timestamp with time zone
);


ALTER TABLE public.acme_storage OWNER TO kong;

--
-- Name: admins; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.admins (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid,
    rbac_user_id uuid,
    rbac_token_enabled boolean NOT NULL,
    email text,
    status integer,
    username text,
    custom_id text,
    username_lower text
);


ALTER TABLE public.admins OWNER TO kong;

--
-- Name: application_instances; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.application_instances (
    id uuid NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    status integer,
    service_id uuid,
    application_id uuid,
    composite_id text,
    suspended boolean NOT NULL,
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid
);


ALTER TABLE public.application_instances OWNER TO kong;

--
-- Name: applications; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.applications (
    id uuid NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    name text,
    description text,
    redirect_uri text,
    meta text,
    developer_id uuid,
    consumer_id uuid,
    custom_id text,
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid
);


ALTER TABLE public.applications OWNER TO kong;

--
-- Name: audit_objects; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.audit_objects (
    id uuid NOT NULL,
    request_id character(32),
    entity_key uuid,
    dao_name text NOT NULL,
    operation character(6) NOT NULL,
    entity text,
    rbac_user_id uuid,
    signature text,
    ttl timestamp with time zone DEFAULT ((CURRENT_TIMESTAMP(0) AT TIME ZONE 'utc'::text) + '720:00:00'::interval),
    removed_from_entity text,
    request_timestamp timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'utc'::text)
);


ALTER TABLE public.audit_objects OWNER TO kong;

--
-- Name: audit_requests; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.audit_requests (
    request_id character(32) NOT NULL,
    request_timestamp timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'utc'::text),
    client_ip text NOT NULL,
    path text NOT NULL,
    method text NOT NULL,
    payload text,
    status integer NOT NULL,
    rbac_user_id uuid,
    workspace uuid,
    signature text,
    ttl timestamp with time zone DEFAULT ((CURRENT_TIMESTAMP(0) AT TIME ZONE 'utc'::text) + '720:00:00'::interval),
    removed_from_payload text,
    rbac_user_name text,
    request_source text
);


ALTER TABLE public.audit_requests OWNER TO kong;

--
-- Name: basicauth_brute_force_locks; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.basicauth_brute_force_locks (
    key text NOT NULL,
    ttl timestamp with time zone
);


ALTER TABLE public.basicauth_brute_force_locks OWNER TO kong;

--
-- Name: basicauth_brute_force_metrics; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.basicauth_brute_force_metrics (
    key text NOT NULL,
    count integer,
    ttl timestamp with time zone
);


ALTER TABLE public.basicauth_brute_force_metrics OWNER TO kong;

--
-- Name: basicauth_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.basicauth_credentials (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid,
    username text,
    password text,
    tags text[],
    ws_id uuid
);


ALTER TABLE public.basicauth_credentials OWNER TO kong;

--
-- Name: ca_certificates; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ca_certificates (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    cert text NOT NULL,
    tags text[],
    cert_digest text NOT NULL,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.ca_certificates OWNER TO kong;

--
-- Name: certificates; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.certificates (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    cert text,
    key text,
    tags text[],
    ws_id uuid,
    cert_alt text,
    key_alt text,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.certificates OWNER TO kong;

--
-- Name: cluster_events; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.cluster_events (
    id uuid NOT NULL,
    node_id uuid NOT NULL,
    at timestamp with time zone NOT NULL,
    nbf timestamp with time zone,
    expire_at timestamp with time zone NOT NULL,
    channel text,
    data text
);


ALTER TABLE public.cluster_events OWNER TO kong;

--
-- Name: clustering_data_planes; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.clustering_data_planes (
    id uuid NOT NULL,
    hostname text NOT NULL,
    ip text NOT NULL,
    last_seen timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    config_hash text NOT NULL,
    ttl timestamp with time zone,
    version text,
    sync_status text DEFAULT 'unknown'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    labels jsonb,
    cert_details jsonb,
    rpc_capabilities text[]
);


ALTER TABLE public.clustering_data_planes OWNER TO kong;

--
-- Name: clustering_rpc_requests; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.clustering_rpc_requests (
    id bigint NOT NULL,
    node_id uuid NOT NULL,
    reply_to uuid NOT NULL,
    ttl timestamp with time zone NOT NULL,
    payload json NOT NULL
);


ALTER TABLE public.clustering_rpc_requests OWNER TO kong;

--
-- Name: clustering_rpc_requests_id_seq; Type: SEQUENCE; Schema: public; Owner: kong
--

CREATE SEQUENCE public.clustering_rpc_requests_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.clustering_rpc_requests_id_seq OWNER TO kong;

--
-- Name: clustering_rpc_requests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kong
--

ALTER SEQUENCE public.clustering_rpc_requests_id_seq OWNED BY public.clustering_rpc_requests.id;


--
-- Name: clustering_sync_delta; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.clustering_sync_delta (
    version bigint NOT NULL,
    type text NOT NULL,
    pk json NOT NULL,
    ws_id uuid NOT NULL,
    entity json
);


ALTER TABLE public.clustering_sync_delta OWNER TO kong;

--
-- Name: clustering_sync_lock; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.clustering_sync_lock (
    id integer NOT NULL
);


ALTER TABLE public.clustering_sync_lock OWNER TO kong;

--
-- Name: clustering_sync_version; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.clustering_sync_version (
    version bigint NOT NULL
);


ALTER TABLE public.clustering_sync_version OWNER TO kong;

--
-- Name: clustering_sync_version_version_seq; Type: SEQUENCE; Schema: public; Owner: kong
--

CREATE SEQUENCE public.clustering_sync_version_version_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.clustering_sync_version_version_seq OWNER TO kong;

--
-- Name: clustering_sync_version_version_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kong
--

ALTER SEQUENCE public.clustering_sync_version_version_seq OWNED BY public.clustering_sync_version.version;


--
-- Name: consumer_group_consumers; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.consumer_group_consumers (
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_group_id uuid NOT NULL,
    consumer_id uuid NOT NULL,
    cache_key text,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.consumer_group_consumers OWNER TO kong;

--
-- Name: consumer_group_plugins; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.consumer_group_plugins (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_group_id uuid,
    name text NOT NULL,
    cache_key text,
    config jsonb NOT NULL,
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.consumer_group_plugins OWNER TO kong;

--
-- Name: consumer_groups; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.consumer_groups (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    name text,
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid,
    tags text[],
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.consumer_groups OWNER TO kong;

--
-- Name: consumer_reset_secrets; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.consumer_reset_secrets (
    id uuid NOT NULL,
    consumer_id uuid,
    secret text,
    status integer,
    client_addr text,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'utc'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'utc'::text)
);


ALTER TABLE public.consumer_reset_secrets OWNER TO kong;

--
-- Name: consumers; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.consumers (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    username text,
    custom_id text,
    tags text[],
    ws_id uuid,
    username_lower text,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    type integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.consumers OWNER TO kong;

--
-- Name: credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.credentials (
    id uuid NOT NULL,
    consumer_id uuid,
    consumer_type integer,
    plugin text NOT NULL,
    credential_data json,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, ('now'::text)::timestamp(0) with time zone),
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.credentials OWNER TO kong;

--
-- Name: custom_plugins; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.custom_plugins (
    id uuid NOT NULL,
    ws_id uuid,
    name text NOT NULL,
    schema text NOT NULL,
    handler text NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp with time zone,
    tags text[]
);


ALTER TABLE public.custom_plugins OWNER TO kong;

--
-- Name: degraphql_routes; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.degraphql_routes (
    id uuid NOT NULL,
    service_id uuid,
    methods text[],
    uri text,
    query text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.degraphql_routes OWNER TO kong;

--
-- Name: developers; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.developers (
    id uuid NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    email text,
    status integer,
    meta text,
    custom_id text,
    consumer_id uuid,
    rbac_user_id uuid,
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid
);


ALTER TABLE public.developers OWNER TO kong;

--
-- Name: document_objects; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.document_objects (
    id uuid NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    service_id uuid,
    path text,
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid
);


ALTER TABLE public.document_objects OWNER TO kong;

--
-- Name: event_hooks; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.event_hooks (
    id uuid,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    source text NOT NULL,
    event text,
    handler text NOT NULL,
    on_change boolean,
    snooze integer,
    config json NOT NULL,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.event_hooks OWNER TO kong;

--
-- Name: files; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.files (
    id uuid NOT NULL,
    path text NOT NULL,
    checksum text,
    contents text,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'utc'::text),
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.files OWNER TO kong;

--
-- Name: graphql_ratelimiting_advanced_cost_decoration; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.graphql_ratelimiting_advanced_cost_decoration (
    id uuid NOT NULL,
    service_id uuid,
    type_path text,
    add_arguments text[],
    add_constant double precision,
    mul_arguments text[],
    mul_constant double precision,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.graphql_ratelimiting_advanced_cost_decoration OWNER TO kong;

--
-- Name: group_rbac_roles; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.group_rbac_roles (
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    group_id uuid NOT NULL,
    rbac_role_id uuid NOT NULL,
    workspace_id uuid,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.group_rbac_roles OWNER TO kong;

--
-- Name: groups; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.groups (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    name text,
    comment text,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.groups OWNER TO kong;

--
-- Name: header_cert_auth_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.header_cert_auth_credentials (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid NOT NULL,
    subject_name text NOT NULL,
    ca_certificate_id uuid,
    cache_key text,
    tags text[],
    ws_id uuid
);


ALTER TABLE public.header_cert_auth_credentials OWNER TO kong;

--
-- Name: hmacauth_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.hmacauth_credentials (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid,
    username text,
    secret text,
    tags text[],
    ws_id uuid
);


ALTER TABLE public.hmacauth_credentials OWNER TO kong;

--
-- Name: jwt_secrets; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.jwt_secrets (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid,
    key text,
    secret text,
    algorithm text,
    rsa_public_key text,
    tags text[],
    ws_id uuid
);


ALTER TABLE public.jwt_secrets OWNER TO kong;

--
-- Name: jwt_signer_jwks; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.jwt_signer_jwks (
    id uuid NOT NULL,
    name text NOT NULL,
    keys jsonb[] NOT NULL,
    previous jsonb[],
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.jwt_signer_jwks OWNER TO kong;

--
-- Name: key_sets; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.key_sets (
    id uuid NOT NULL,
    name text,
    tags text[],
    ws_id uuid,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


ALTER TABLE public.key_sets OWNER TO kong;

--
-- Name: keyauth_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.keyauth_credentials (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid,
    key text,
    tags text[],
    ttl timestamp with time zone,
    ws_id uuid
);


ALTER TABLE public.keyauth_credentials OWNER TO kong;

--
-- Name: keyauth_enc_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.keyauth_enc_credentials (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid,
    key text,
    key_ident text,
    ws_id uuid,
    tags text[],
    ttl timestamp with time zone
);


ALTER TABLE public.keyauth_enc_credentials OWNER TO kong;

--
-- Name: keyring_keys; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.keyring_keys (
    id text NOT NULL,
    recovery_key_id text NOT NULL,
    key_encrypted text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.keyring_keys OWNER TO kong;

--
-- Name: keyring_meta; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.keyring_meta (
    id text NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.keyring_meta OWNER TO kong;

--
-- Name: keys; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.keys (
    id uuid NOT NULL,
    set_id uuid,
    name text,
    cache_key text,
    ws_id uuid,
    kid text,
    jwk text,
    pem jsonb,
    tags text[],
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    x5t text
);


ALTER TABLE public.keys OWNER TO kong;

--
-- Name: konnect_applications; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.konnect_applications (
    id uuid NOT NULL,
    ws_id uuid,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    client_id text,
    scopes text[],
    tags text[],
    consumer_groups text[],
    auth_strategy_id text,
    application_context jsonb,
    exhausted_scopes text[]
);


ALTER TABLE public.konnect_applications OWNER TO kong;

--
-- Name: legacy_files; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.legacy_files (
    id uuid NOT NULL,
    auth boolean NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    contents text,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'utc'::text),
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.legacy_files OWNER TO kong;

--
-- Name: license_data; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.license_data (
    node_id uuid NOT NULL,
    req_cnt bigint,
    license_creation_date timestamp without time zone,
    year smallint NOT NULL,
    month smallint NOT NULL
);


ALTER TABLE public.license_data OWNER TO kong;

--
-- Name: license_llm_data; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.license_llm_data (
    id uuid NOT NULL,
    model_name text NOT NULL,
    license_creation_date timestamp without time zone,
    year smallint NOT NULL,
    week_of_year smallint NOT NULL,
    month smallint DEFAULT 0 NOT NULL,
    day smallint DEFAULT 0 NOT NULL,
    hour smallint DEFAULT 0 NOT NULL
);


ALTER TABLE public.license_llm_data OWNER TO kong;

--
-- Name: licenses; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.licenses (
    id uuid NOT NULL,
    payload text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    checksum text
);


ALTER TABLE public.licenses OWNER TO kong;

--
-- Name: locks; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.locks (
    key text NOT NULL,
    owner text,
    ttl timestamp with time zone
);


ALTER TABLE public.locks OWNER TO kong;

--
-- Name: login_attempts; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.login_attempts (
    consumer_id uuid NOT NULL,
    attempts json DEFAULT '{}'::json,
    ttl timestamp with time zone,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    attempt_type text DEFAULT 'login'::text NOT NULL
);


ALTER TABLE public.login_attempts OWNER TO kong;

--
-- Name: mtls_auth_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.mtls_auth_credentials (
    id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    consumer_id uuid NOT NULL,
    subject_name text NOT NULL,
    ca_certificate_id uuid,
    cache_key text,
    ws_id uuid,
    tags text[]
);


ALTER TABLE public.mtls_auth_credentials OWNER TO kong;

--
-- Name: oauth2_authorization_codes; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.oauth2_authorization_codes (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    credential_id uuid,
    service_id uuid,
    code text,
    authenticated_userid text,
    scope text,
    ttl timestamp with time zone,
    challenge text,
    challenge_method text,
    ws_id uuid,
    plugin_id uuid
);


ALTER TABLE public.oauth2_authorization_codes OWNER TO kong;

--
-- Name: oauth2_credentials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.oauth2_credentials (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    name text,
    consumer_id uuid,
    client_id text,
    client_secret text,
    redirect_uris text[],
    tags text[],
    client_type text,
    hash_secret boolean,
    ws_id uuid
);


ALTER TABLE public.oauth2_credentials OWNER TO kong;

--
-- Name: oauth2_tokens; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.oauth2_tokens (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    credential_id uuid,
    service_id uuid,
    access_token text,
    refresh_token text,
    token_type text,
    expires_in integer,
    authenticated_userid text,
    scope text,
    ttl timestamp with time zone,
    ws_id uuid
);


ALTER TABLE public.oauth2_tokens OWNER TO kong;

--
-- Name: oic_issuers; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.oic_issuers (
    id uuid NOT NULL,
    issuer text,
    configuration text,
    keys text,
    secret text,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.oic_issuers OWNER TO kong;

--
-- Name: oic_jwks; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.oic_jwks (
    id uuid NOT NULL,
    jwks jsonb
);


ALTER TABLE public.oic_jwks OWNER TO kong;

--
-- Name: parameters; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.parameters (
    key text NOT NULL,
    value text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.parameters OWNER TO kong;

--
-- Name: partials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.partials (
    id uuid,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    type text NOT NULL,
    config json NOT NULL,
    ws_id uuid,
    name text,
    tags text[]
);


ALTER TABLE public.partials OWNER TO kong;

--
-- Name: plugins; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.plugins (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    name text NOT NULL,
    consumer_id uuid,
    service_id uuid,
    route_id uuid,
    config jsonb NOT NULL,
    enabled boolean NOT NULL,
    cache_key text,
    protocols text[],
    tags text[],
    ws_id uuid,
    instance_name text,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    ordering jsonb,
    consumer_group_id uuid
);


ALTER TABLE public.plugins OWNER TO kong;

--
-- Name: plugins_partials; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.plugins_partials (
    id uuid,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    path text,
    plugin_id uuid,
    partial_id uuid
);


ALTER TABLE public.plugins_partials OWNER TO kong;

--
-- Name: ratelimiting_metrics; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ratelimiting_metrics (
    identifier text NOT NULL,
    period text NOT NULL,
    period_date timestamp with time zone NOT NULL,
    service_id uuid DEFAULT '00000000-0000-0000-0000-000000000000'::uuid NOT NULL,
    route_id uuid DEFAULT '00000000-0000-0000-0000-000000000000'::uuid NOT NULL,
    value integer,
    ttl timestamp with time zone
);


ALTER TABLE public.ratelimiting_metrics OWNER TO kong;

--
-- Name: rbac_role_endpoints; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.rbac_role_endpoints (
    role_id uuid NOT NULL,
    workspace text NOT NULL,
    endpoint text NOT NULL,
    actions smallint NOT NULL,
    comment text,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    negative boolean NOT NULL,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.rbac_role_endpoints OWNER TO kong;

--
-- Name: rbac_role_entities; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.rbac_role_entities (
    role_id uuid NOT NULL,
    entity_id text NOT NULL,
    entity_type text NOT NULL,
    actions smallint NOT NULL,
    negative boolean NOT NULL,
    comment text,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.rbac_role_entities OWNER TO kong;

--
-- Name: rbac_roles; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.rbac_roles (
    id uuid NOT NULL,
    name text NOT NULL,
    comment text,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    is_default boolean DEFAULT false,
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.rbac_roles OWNER TO kong;

--
-- Name: rbac_user_groups; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.rbac_user_groups (
    user_id uuid NOT NULL,
    group_id uuid NOT NULL
);


ALTER TABLE public.rbac_user_groups OWNER TO kong;

--
-- Name: rbac_user_roles; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.rbac_user_roles (
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    role_source text
);


ALTER TABLE public.rbac_user_roles OWNER TO kong;

--
-- Name: rbac_users; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.rbac_users (
    id uuid NOT NULL,
    name text NOT NULL,
    user_token text NOT NULL,
    user_token_ident text,
    comment text,
    enabled boolean NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    ws_id uuid DEFAULT '00b2c6cc-ac81-44d8-b3d4-5c764f851be1'::uuid,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.rbac_users OWNER TO kong;

--
-- Name: response_ratelimiting_metrics; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.response_ratelimiting_metrics (
    identifier text NOT NULL,
    period text NOT NULL,
    period_date timestamp with time zone NOT NULL,
    service_id uuid DEFAULT '00000000-0000-0000-0000-000000000000'::uuid NOT NULL,
    route_id uuid DEFAULT '00000000-0000-0000-0000-000000000000'::uuid NOT NULL,
    value integer
);


ALTER TABLE public.response_ratelimiting_metrics OWNER TO kong;

--
-- Name: rl_counters; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.rl_counters (
    key text NOT NULL,
    namespace text NOT NULL,
    window_start integer NOT NULL,
    window_size integer NOT NULL,
    count integer
);


ALTER TABLE public.rl_counters OWNER TO kong;

--
-- Name: routes; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.routes (
    id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    service_id uuid,
    protocols text[],
    methods text[],
    hosts text[],
    paths text[],
    snis text[],
    sources jsonb[],
    destinations jsonb[],
    regex_priority bigint,
    strip_path boolean,
    preserve_host boolean,
    tags text[],
    https_redirect_status_code integer,
    headers jsonb,
    path_handling text DEFAULT 'v0'::text,
    ws_id uuid,
    request_buffering boolean,
    response_buffering boolean,
    expression text,
    priority bigint
);


ALTER TABLE public.routes OWNER TO kong;

--
-- Name: schema_meta; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.schema_meta (
    key text NOT NULL,
    subsystem text NOT NULL,
    last_executed text,
    executed text[],
    pending text[]
);


ALTER TABLE public.schema_meta OWNER TO kong;

--
-- Name: services; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.services (
    id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    retries bigint,
    protocol text,
    host text,
    port bigint,
    path text,
    connect_timeout bigint,
    write_timeout bigint,
    read_timeout bigint,
    tags text[],
    client_certificate_id uuid,
    tls_verify boolean,
    tls_verify_depth smallint,
    ca_certificates uuid[],
    ws_id uuid,
    enabled boolean DEFAULT true,
    tls_sans jsonb
);


ALTER TABLE public.services OWNER TO kong;

--
-- Name: session_metadatas; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.session_metadatas (
    id uuid NOT NULL,
    session_id uuid,
    sid text,
    subject text,
    audience text,
    created_at timestamp with time zone
);


ALTER TABLE public.session_metadatas OWNER TO kong;

--
-- Name: sessions; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.sessions (
    id uuid NOT NULL,
    session_id text,
    expires integer,
    data text,
    created_at timestamp with time zone,
    ttl timestamp with time zone
);


ALTER TABLE public.sessions OWNER TO kong;

--
-- Name: sm_vaults; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.sm_vaults (
    id uuid NOT NULL,
    ws_id uuid,
    prefix text,
    name text NOT NULL,
    description text,
    config jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    updated_at timestamp with time zone,
    tags text[]
);


ALTER TABLE public.sm_vaults OWNER TO kong;

--
-- Name: snis; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.snis (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    name text NOT NULL,
    certificate_id uuid,
    tags text[],
    ws_id uuid,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.snis OWNER TO kong;

--
-- Name: tags; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.tags (
    entity_id uuid NOT NULL,
    entity_name text,
    tags text[]
);


ALTER TABLE public.tags OWNER TO kong;

--
-- Name: targets; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.targets (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'::text),
    upstream_id uuid,
    target text NOT NULL,
    weight integer NOT NULL,
    tags text[],
    ws_id uuid,
    cache_key text,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'::text),
    failover boolean
);


ALTER TABLE public.targets OWNER TO kong;

--
-- Name: upstreams; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.upstreams (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC'::text),
    name text,
    hash_on text,
    hash_fallback text,
    hash_on_header text,
    hash_fallback_header text,
    hash_on_cookie text,
    hash_on_cookie_path text,
    slots integer NOT NULL,
    healthchecks jsonb,
    tags text[],
    algorithm text,
    host_header text,
    client_certificate_id uuid,
    ws_id uuid,
    hash_on_query_arg text,
    hash_fallback_query_arg text,
    hash_on_uri_capture text,
    hash_fallback_uri_capture text,
    use_srv_name boolean DEFAULT false,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    sticky_sessions_cookie text,
    sticky_sessions_cookie_path text
);


ALTER TABLE public.upstreams OWNER TO kong;

--
-- Name: vault_auth_vaults; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vault_auth_vaults (
    id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    protocol text,
    host text,
    port bigint,
    mount text,
    vault_token text,
    kv text
);


ALTER TABLE public.vault_auth_vaults OWNER TO kong;

--
-- Name: vaults; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vaults (
    id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    protocol text,
    host text,
    port bigint,
    mount text,
    vault_token text
);


ALTER TABLE public.vaults OWNER TO kong;

--
-- Name: vitals_code_classes_by_cluster; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_code_classes_by_cluster (
    code_class integer NOT NULL,
    at timestamp with time zone NOT NULL,
    duration integer NOT NULL,
    count integer
);


ALTER TABLE public.vitals_code_classes_by_cluster OWNER TO kong;

--
-- Name: vitals_code_classes_by_workspace; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_code_classes_by_workspace (
    workspace_id uuid NOT NULL,
    code_class integer NOT NULL,
    at timestamp with time zone NOT NULL,
    duration integer NOT NULL,
    count integer
);


ALTER TABLE public.vitals_code_classes_by_workspace OWNER TO kong;

--
-- Name: vitals_codes_by_consumer_route; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_codes_by_consumer_route (
    consumer_id uuid NOT NULL,
    service_id uuid,
    route_id uuid NOT NULL,
    code integer NOT NULL,
    at timestamp with time zone NOT NULL,
    duration integer NOT NULL,
    count integer
)
WITH (autovacuum_vacuum_scale_factor='0.01', autovacuum_analyze_scale_factor='0.01');


ALTER TABLE public.vitals_codes_by_consumer_route OWNER TO kong;

--
-- Name: vitals_codes_by_route; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_codes_by_route (
    service_id uuid,
    route_id uuid NOT NULL,
    code integer NOT NULL,
    at timestamp with time zone NOT NULL,
    duration integer NOT NULL,
    count integer
)
WITH (autovacuum_vacuum_scale_factor='0.01', autovacuum_analyze_scale_factor='0.01');


ALTER TABLE public.vitals_codes_by_route OWNER TO kong;

--
-- Name: vitals_locks; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_locks (
    key text NOT NULL,
    expiry timestamp with time zone
);


ALTER TABLE public.vitals_locks OWNER TO kong;

--
-- Name: vitals_node_meta; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_node_meta (
    node_id uuid NOT NULL,
    first_report timestamp without time zone,
    last_report timestamp without time zone,
    hostname text
);


ALTER TABLE public.vitals_node_meta OWNER TO kong;

--
-- Name: vitals_stats_days; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_stats_days (
    node_id uuid NOT NULL,
    at integer NOT NULL,
    l2_hit integer DEFAULT 0,
    l2_miss integer DEFAULT 0,
    plat_min integer,
    plat_max integer,
    ulat_min integer,
    ulat_max integer,
    requests integer DEFAULT 0,
    plat_count integer DEFAULT 0,
    plat_total integer DEFAULT 0,
    ulat_count integer DEFAULT 0,
    ulat_total integer DEFAULT 0
);


ALTER TABLE public.vitals_stats_days OWNER TO kong;

--
-- Name: vitals_stats_hours; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_stats_hours (
    at integer NOT NULL,
    l2_hit integer DEFAULT 0,
    l2_miss integer DEFAULT 0,
    plat_min integer,
    plat_max integer
);


ALTER TABLE public.vitals_stats_hours OWNER TO kong;

--
-- Name: vitals_stats_minutes; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_stats_minutes (
    node_id uuid NOT NULL,
    at integer NOT NULL,
    l2_hit integer DEFAULT 0,
    l2_miss integer DEFAULT 0,
    plat_min integer,
    plat_max integer,
    ulat_min integer,
    ulat_max integer,
    requests integer DEFAULT 0,
    plat_count integer DEFAULT 0,
    plat_total integer DEFAULT 0,
    ulat_count integer DEFAULT 0,
    ulat_total integer DEFAULT 0
);


ALTER TABLE public.vitals_stats_minutes OWNER TO kong;

--
-- Name: vitals_stats_seconds; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.vitals_stats_seconds (
    node_id uuid NOT NULL,
    at integer NOT NULL,
    l2_hit integer DEFAULT 0,
    l2_miss integer DEFAULT 0,
    plat_min integer,
    plat_max integer,
    ulat_min integer,
    ulat_max integer,
    requests integer DEFAULT 0,
    plat_count integer DEFAULT 0,
    plat_total integer DEFAULT 0,
    ulat_count integer DEFAULT 0,
    ulat_total integer DEFAULT 0
);


ALTER TABLE public.vitals_stats_seconds OWNER TO kong;

--
-- Name: workspace_entities; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.workspace_entities (
    workspace_id uuid NOT NULL,
    workspace_name text,
    entity_id text NOT NULL,
    entity_type text,
    unique_field_name text NOT NULL,
    unique_field_value text
);


ALTER TABLE public.workspace_entities OWNER TO kong;

--
-- Name: workspace_entity_counters; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.workspace_entity_counters (
    workspace_id uuid NOT NULL,
    entity_type text NOT NULL,
    count integer
);


ALTER TABLE public.workspace_entity_counters OWNER TO kong;

--
-- Name: workspaces; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.workspaces (
    id uuid NOT NULL,
    name text,
    comment text,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text),
    meta jsonb,
    config jsonb,
    updated_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.workspaces OWNER TO kong;

--
-- Name: ws_migrations_backup; Type: TABLE; Schema: public; Owner: kong
--

CREATE TABLE public.ws_migrations_backup (
    entity_type text,
    entity_id text,
    unique_field_name text,
    unique_field_value text,
    created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'::text)
);


ALTER TABLE public.ws_migrations_backup OWNER TO kong;

--
-- Name: clustering_rpc_requests id; Type: DEFAULT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.clustering_rpc_requests ALTER COLUMN id SET DEFAULT nextval('public.clustering_rpc_requests_id_seq'::regclass);


--
-- Name: clustering_sync_version version; Type: DEFAULT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.clustering_sync_version ALTER COLUMN version SET DEFAULT nextval('public.clustering_sync_version_version_seq'::regclass);


--
-- Data for Name: ace_auth_strategies; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ace_auth_strategies (id, created_at, updated_at, type, config, ws_id) FROM stdin;
\.


--
-- Data for Name: ace_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ace_credentials (id, created_at, updated_at, api_key_hash, client_id, portal_id, application_id, organization_id, auth_strategy_id, ws_id, cache_key, consumer_custom_id, consumer_group_name) FROM stdin;
\.


--
-- Data for Name: ace_operation_groups; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ace_operation_groups (id, created_at, updated_at, ratelimiting, entity_id, entity_type, tags, ws_id) FROM stdin;
\.


--
-- Data for Name: ace_operation_groups_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ace_operation_groups_credentials (id, operation_group_id, credential_id, created_at, updated_at, tags, ws_id, cache_key) FROM stdin;
\.


--
-- Data for Name: ace_operation_groups_operations; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ace_operation_groups_operations (id, operation_group_id, operation_id, ratelimiting, created_at, updated_at, tags, ws_id, cache_key) FROM stdin;
\.


--
-- Data for Name: ace_operations; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ace_operations (id, created_at, updated_at, expression, priority, tags, api_id, ws_id) FROM stdin;
\.


--
-- Data for Name: acls; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.acls (id, created_at, consumer_id, "group", cache_key, tags, ws_id) FROM stdin;
0c0fbb7f-5599-4411-bda5-a1c3219e227e	2026-02-11 10:36:17+00	a3fbc29f-1c1f-4f2b-bb9a-09c3df62bd9a	Premium	acls:a3fbc29f-1c1f-4f2b-bb9a-09c3df62bd9a:Premium::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
67e988c1-467e-4655-a11d-e47f5691ba28	2026-02-11 10:46:35+00	94e991b3-b956-4816-a7f4-f2f7d6327ad8	Default	acls:94e991b3-b956-4816-a7f4-f2f7d6327ad8:Default::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
\.


--
-- Data for Name: acme_storage; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.acme_storage (id, key, value, created_at, ttl) FROM stdin;
\.


--
-- Data for Name: admins; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.admins (id, created_at, updated_at, consumer_id, rbac_user_id, rbac_token_enabled, email, status, username, custom_id, username_lower) FROM stdin;
\.


--
-- Data for Name: application_instances; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.application_instances (id, created_at, updated_at, status, service_id, application_id, composite_id, suspended, ws_id) FROM stdin;
\.


--
-- Data for Name: applications; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.applications (id, created_at, updated_at, name, description, redirect_uri, meta, developer_id, consumer_id, custom_id, ws_id) FROM stdin;
\.


--
-- Data for Name: audit_objects; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.audit_objects (id, request_id, entity_key, dao_name, operation, entity, rbac_user_id, signature, ttl, removed_from_entity, request_timestamp) FROM stdin;
\.


--
-- Data for Name: audit_requests; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.audit_requests (request_id, request_timestamp, client_ip, path, method, payload, status, rbac_user_id, workspace, signature, ttl, removed_from_payload, rbac_user_name, request_source) FROM stdin;
\.


--
-- Data for Name: basicauth_brute_force_locks; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.basicauth_brute_force_locks (key, ttl) FROM stdin;
\.


--
-- Data for Name: basicauth_brute_force_metrics; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.basicauth_brute_force_metrics (key, count, ttl) FROM stdin;
\.


--
-- Data for Name: basicauth_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.basicauth_credentials (id, created_at, consumer_id, username, password, tags, ws_id) FROM stdin;
d5570971-60a5-4ccd-b328-e2f3eab181bd	2026-02-05 07:02:42+00	25018837-a876-403b-8a0d-e26ac2a21db8	abc	11175fb96773627fcadca8d83a095d1e2c10d48c	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
1269a6e6-7e24-451a-9fdd-068a76e32f8c	2026-02-11 08:05:42+00	a3fbc29f-1c1f-4f2b-bb9a-09c3df62bd9a	xyz	c931a71c37e24f5a15709e90e9bc7632e6cb2dc7	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
2708ecf8-e7fd-495f-aaf2-3202ee8c38a2	2026-02-11 08:07:11+00	94e991b3-b956-4816-a7f4-f2f7d6327ad8	qwe	ef299e265915ff1264cfd6320d2114a5d878ff22	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
\.


--
-- Data for Name: ca_certificates; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ca_certificates (id, created_at, cert, tags, cert_digest, updated_at) FROM stdin;
\.


--
-- Data for Name: certificates; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.certificates (id, created_at, cert, key, tags, ws_id, cert_alt, key_alt, updated_at) FROM stdin;
c50ae3b3-b50f-4862-b2f2-c615fb5db3c4	2026-01-20 07:17:18+00	-----BEGIN CERTIFICATE-----\nMIIDrTCCApWgAwIBAgIUBO3YbHRXH6xIPSe6Fa4FdO2Mmf0wDQYJKoZIhvcNAQEL\nBQAwZjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEfMB0GCSqGSIb3DQEJARYQZGVtby5l\neGFtcGxlLmNvbTAeFw0yNjAxMjAwNzExMjBaFw0yNzAxMjAwNzExMjBaMGYxCzAJ\nBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\ndCBXaWRnaXRzIFB0eSBMdGQxHzAdBgkqhkiG9w0BCQEWEGRlbW8uZXhhbXBsZS5j\nb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp5NqzhCZu1Vwlw0U6\nA/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9reJ2Qp\n4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E1bLT\n+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPemBOJv\n9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEseTs+\nUlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgpurlM\nr71VAgMBAAGjUzBRMB0GA1UdDgQWBBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAfBgNV\nHSMEGDAWgBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAPBgNVHRMBAf8EBTADAQH/MA0G\nCSqGSIb3DQEBCwUAA4IBAQBl/RgPaHdFtfxFtrSefTWndOfAbTGXm28LUEz2P6u+\nYtjzkrjrUNC+tMBRKSI8HaAOMQofVx93Y1Ugv1IUhmFmVXfjKk0oGJEE/Lw9BPDO\nv2ZtrWDPSPEPEuKfnA8iugo75c+lGumN5sqN4gTJ6NnY+jVIaReevSR0AgtvwrIk\nYRxOz5o4eljHnmFqXLmruLO5ONslL+Q269FaP97ltB/D/MDnqww7SlOn4VLwOsLP\nnuiIhWdamjF/kufdJE3y+9eUI2cZQkg4JhmhzUXleFH+3aY+E8OG9IoXjVMWI4T4\n5bkV4tiRj2EirnE+TwpiYHxaMhrK/oBaLXLq2OKK7EpQ\n-----END CERTIFICATE-----	-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCp5NqzhCZu1Vwl\nw0U6A/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9re\nJ2Qp4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E\n1bLT+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPem\nBOJv9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEs\neTs+UlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgp\nurlMr71VAgMBAAECggEAEYoCiPtY02Lb8TsUQ73DPnaAQTtPvVizz8HJIwGpXXjP\nQw/BvJ/Etm9OHmOCSXhi0Zs9zn+cJTJS2VHkPY2oDvCrqyhiRKgLYnylcw57HUgI\naMB3z53FuCXAFtUJM0Qcjp7c9drdPnQ2hRuBq3AjBm5diATfGzkph0qpVoQIScVI\nK1Vfgc7gz5sRZ2yB7kqFovYJusPQ6CFLVenrs2yXeOZ80Wu6JPBBDT5ly0LbktFx\nzUbd9lSIbdIAJX+sJFf5TUdhuaUgv2xBYG0DMy7jJgL+b3byOvccyCkmOEVCgzxF\nYKyz76bi29KvonkldVacRugbk+c59GskkJ1xM7USwQKBgQDqwQ+kuDZqO8es6+g/\nLT0W2BmIVK4WqKkzEPkGCYASpLorx+OFCatw1B+29I8LDwPN7YJXY3Mf+5qEP4Jh\n0/jLdMwjIfJTaXyL2dsgb7Fqc9WigMHFifMb6TqS1KHJK67s5/7Gu5q/7v6zExEX\ntl5m08FkslLFyZpyCazVFhY6QQKBgQC5RRHXUBki/IQtxgaNG2g1OLgHNYCowaM9\nm4QuJ4KL9jqo3z7lkpi+UQ2Z7gaXlU5t/vvyrJGQEVQw/bWKS93YWabjcPBpGSbO\n5JcGObvzvLg6IMG++CMUsPFRzic20qaayLJCNa4tKVyDnoyFqSPeGg0Ko3a403Dp\nq6CpP0N2FQKBgBZx4wcCveEmWg8Edy4jKyYV/0rznbl44sSJKOYU3nPp4Arzj6NW\nq1ecUHPzqgGKq/hybvXgAk/ahImEcPjdhXoebq4lPsAO4+OTLspJI5NkA9cHrH8w\nk1fl0r3bKqTLUmxAOjHSGhejyCJi/k1gGGKIeIMiMZvLjMK+fhHZjMKBAoGAXB8u\n9tvaE95xrvz3RvSoxUX1o4gD+GWIUNriR7zXmdaOZmfTM33IO2G8HJ0RZBAWlnUi\nPBF4s6UaMt4EhcahgbFaXV9L+0ZJWLirK6pLfa+J/0VIcTea4e/1nlKehxEJTI+c\nq3VbrRMS8FNG1jM7JXXYpECRiOeCDn6LfXx6g90CgYEA6MYqlCN/ybYHYqmN92CC\n+xThdw4M+knhz/K0oy+kCiDsY0wHzxQWlQITedqWGUWpT2kW6Y0dG8b3Iqp25YRH\nJMq7D2p7UjtS9TJIbZjpbIyiupDWqTYbLO1kFVW+L4dM4/0cMATig+uRo/qIEP9T\nuzELVN9H6YPP/j2vRoZ6vpM=\n-----END PRIVATE KEY-----	{"Demo Certificate"}	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	\N	2026-01-20 07:17:18+00
a92370b5-dd0d-4113-b748-578eaefd7f3d	2026-01-20 09:34:40+00	-----BEGIN CERTIFICATE-----\nMIIDrTCCApWgAwIBAgIUBO3YbHRXH6xIPSe6Fa4FdO2Mmf0wDQYJKoZIhvcNAQEL\nBQAwZjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEfMB0GCSqGSIb3DQEJARYQZGVtby5l\neGFtcGxlLmNvbTAeFw0yNjAxMjAwNzExMjBaFw0yNzAxMjAwNzExMjBaMGYxCzAJ\nBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\ndCBXaWRnaXRzIFB0eSBMdGQxHzAdBgkqhkiG9w0BCQEWEGRlbW8uZXhhbXBsZS5j\nb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp5NqzhCZu1Vwlw0U6\nA/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9reJ2Qp\n4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E1bLT\n+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPemBOJv\n9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEseTs+\nUlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgpurlM\nr71VAgMBAAGjUzBRMB0GA1UdDgQWBBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAfBgNV\nHSMEGDAWgBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAPBgNVHRMBAf8EBTADAQH/MA0G\nCSqGSIb3DQEBCwUAA4IBAQBl/RgPaHdFtfxFtrSefTWndOfAbTGXm28LUEz2P6u+\nYtjzkrjrUNC+tMBRKSI8HaAOMQofVx93Y1Ugv1IUhmFmVXfjKk0oGJEE/Lw9BPDO\nv2ZtrWDPSPEPEuKfnA8iugo75c+lGumN5sqN4gTJ6NnY+jVIaReevSR0AgtvwrIk\nYRxOz5o4eljHnmFqXLmruLO5ONslL+Q269FaP97ltB/D/MDnqww7SlOn4VLwOsLP\nnuiIhWdamjF/kufdJE3y+9eUI2cZQkg4JhmhzUXleFH+3aY+E8OG9IoXjVMWI4T4\n5bkV4tiRj2EirnE+TwpiYHxaMhrK/oBaLXLq2OKK7EpQ\n-----END CERTIFICATE-----	-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCp5NqzhCZu1Vwl\nw0U6A/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9re\nJ2Qp4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E\n1bLT+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPem\nBOJv9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEs\neTs+UlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgp\nurlMr71VAgMBAAECggEAEYoCiPtY02Lb8TsUQ73DPnaAQTtPvVizz8HJIwGpXXjP\nQw/BvJ/Etm9OHmOCSXhi0Zs9zn+cJTJS2VHkPY2oDvCrqyhiRKgLYnylcw57HUgI\naMB3z53FuCXAFtUJM0Qcjp7c9drdPnQ2hRuBq3AjBm5diATfGzkph0qpVoQIScVI\nK1Vfgc7gz5sRZ2yB7kqFovYJusPQ6CFLVenrs2yXeOZ80Wu6JPBBDT5ly0LbktFx\nzUbd9lSIbdIAJX+sJFf5TUdhuaUgv2xBYG0DMy7jJgL+b3byOvccyCkmOEVCgzxF\nYKyz76bi29KvonkldVacRugbk+c59GskkJ1xM7USwQKBgQDqwQ+kuDZqO8es6+g/\nLT0W2BmIVK4WqKkzEPkGCYASpLorx+OFCatw1B+29I8LDwPN7YJXY3Mf+5qEP4Jh\n0/jLdMwjIfJTaXyL2dsgb7Fqc9WigMHFifMb6TqS1KHJK67s5/7Gu5q/7v6zExEX\ntl5m08FkslLFyZpyCazVFhY6QQKBgQC5RRHXUBki/IQtxgaNG2g1OLgHNYCowaM9\nm4QuJ4KL9jqo3z7lkpi+UQ2Z7gaXlU5t/vvyrJGQEVQw/bWKS93YWabjcPBpGSbO\n5JcGObvzvLg6IMG++CMUsPFRzic20qaayLJCNa4tKVyDnoyFqSPeGg0Ko3a403Dp\nq6CpP0N2FQKBgBZx4wcCveEmWg8Edy4jKyYV/0rznbl44sSJKOYU3nPp4Arzj6NW\nq1ecUHPzqgGKq/hybvXgAk/ahImEcPjdhXoebq4lPsAO4+OTLspJI5NkA9cHrH8w\nk1fl0r3bKqTLUmxAOjHSGhejyCJi/k1gGGKIeIMiMZvLjMK+fhHZjMKBAoGAXB8u\n9tvaE95xrvz3RvSoxUX1o4gD+GWIUNriR7zXmdaOZmfTM33IO2G8HJ0RZBAWlnUi\nPBF4s6UaMt4EhcahgbFaXV9L+0ZJWLirK6pLfa+J/0VIcTea4e/1nlKehxEJTI+c\nq3VbrRMS8FNG1jM7JXXYpECRiOeCDn6LfXx6g90CgYEA6MYqlCN/ybYHYqmN92CC\n+xThdw4M+knhz/K0oy+kCiDsY0wHzxQWlQITedqWGUWpT2kW6Y0dG8b3Iqp25YRH\nJMq7D2p7UjtS9TJIbZjpbIyiupDWqTYbLO1kFVW+L4dM4/0cMATig+uRo/qIEP9T\nuzELVN9H6YPP/j2vRoZ6vpM=\n-----END PRIVATE KEY-----\n	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	\N	2026-01-20 09:34:40+00
0483822a-c4a8-41c4-983c-5d3ec226844d	2026-01-20 09:38:59+00	-----BEGIN CERTIFICATE-----\nMIIDrTCCApWgAwIBAgIUBO3YbHRXH6xIPSe6Fa4FdO2Mmf0wDQYJKoZIhvcNAQEL\nBQAwZjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEfMB0GCSqGSIb3DQEJARYQZGVtby5l\neGFtcGxlLmNvbTAeFw0yNjAxMjAwNzExMjBaFw0yNzAxMjAwNzExMjBaMGYxCzAJ\nBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\ndCBXaWRnaXRzIFB0eSBMdGQxHzAdBgkqhkiG9w0BCQEWEGRlbW8uZXhhbXBsZS5j\nb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp5NqzhCZu1Vwlw0U6\nA/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9reJ2Qp\n4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E1bLT\n+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPemBOJv\n9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEseTs+\nUlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgpurlM\nr71VAgMBAAGjUzBRMB0GA1UdDgQWBBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAfBgNV\nHSMEGDAWgBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAPBgNVHRMBAf8EBTADAQH/MA0G\nCSqGSIb3DQEBCwUAA4IBAQBl/RgPaHdFtfxFtrSefTWndOfAbTGXm28LUEz2P6u+\nYtjzkrjrUNC+tMBRKSI8HaAOMQofVx93Y1Ugv1IUhmFmVXfjKk0oGJEE/Lw9BPDO\nv2ZtrWDPSPEPEuKfnA8iugo75c+lGumN5sqN4gTJ6NnY+jVIaReevSR0AgtvwrIk\nYRxOz5o4eljHnmFqXLmruLO5ONslL+Q269FaP97ltB/D/MDnqww7SlOn4VLwOsLP\nnuiIhWdamjF/kufdJE3y+9eUI2cZQkg4JhmhzUXleFH+3aY+E8OG9IoXjVMWI4T4\n5bkV4tiRj2EirnE+TwpiYHxaMhrK/oBaLXLq2OKK7EpQ\n-----END CERTIFICATE-----	-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCp5NqzhCZu1Vwl\nw0U6A/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9re\nJ2Qp4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E\n1bLT+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPem\nBOJv9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEs\neTs+UlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgp\nurlMr71VAgMBAAECggEAEYoCiPtY02Lb8TsUQ73DPnaAQTtPvVizz8HJIwGpXXjP\nQw/BvJ/Etm9OHmOCSXhi0Zs9zn+cJTJS2VHkPY2oDvCrqyhiRKgLYnylcw57HUgI\naMB3z53FuCXAFtUJM0Qcjp7c9drdPnQ2hRuBq3AjBm5diATfGzkph0qpVoQIScVI\nK1Vfgc7gz5sRZ2yB7kqFovYJusPQ6CFLVenrs2yXeOZ80Wu6JPBBDT5ly0LbktFx\nzUbd9lSIbdIAJX+sJFf5TUdhuaUgv2xBYG0DMy7jJgL+b3byOvccyCkmOEVCgzxF\nYKyz76bi29KvonkldVacRugbk+c59GskkJ1xM7USwQKBgQDqwQ+kuDZqO8es6+g/\nLT0W2BmIVK4WqKkzEPkGCYASpLorx+OFCatw1B+29I8LDwPN7YJXY3Mf+5qEP4Jh\n0/jLdMwjIfJTaXyL2dsgb7Fqc9WigMHFifMb6TqS1KHJK67s5/7Gu5q/7v6zExEX\ntl5m08FkslLFyZpyCazVFhY6QQKBgQC5RRHXUBki/IQtxgaNG2g1OLgHNYCowaM9\nm4QuJ4KL9jqo3z7lkpi+UQ2Z7gaXlU5t/vvyrJGQEVQw/bWKS93YWabjcPBpGSbO\n5JcGObvzvLg6IMG++CMUsPFRzic20qaayLJCNa4tKVyDnoyFqSPeGg0Ko3a403Dp\nq6CpP0N2FQKBgBZx4wcCveEmWg8Edy4jKyYV/0rznbl44sSJKOYU3nPp4Arzj6NW\nq1ecUHPzqgGKq/hybvXgAk/ahImEcPjdhXoebq4lPsAO4+OTLspJI5NkA9cHrH8w\nk1fl0r3bKqTLUmxAOjHSGhejyCJi/k1gGGKIeIMiMZvLjMK+fhHZjMKBAoGAXB8u\n9tvaE95xrvz3RvSoxUX1o4gD+GWIUNriR7zXmdaOZmfTM33IO2G8HJ0RZBAWlnUi\nPBF4s6UaMt4EhcahgbFaXV9L+0ZJWLirK6pLfa+J/0VIcTea4e/1nlKehxEJTI+c\nq3VbrRMS8FNG1jM7JXXYpECRiOeCDn6LfXx6g90CgYEA6MYqlCN/ybYHYqmN92CC\n+xThdw4M+knhz/K0oy+kCiDsY0wHzxQWlQITedqWGUWpT2kW6Y0dG8b3Iqp25YRH\nJMq7D2p7UjtS9TJIbZjpbIyiupDWqTYbLO1kFVW+L4dM4/0cMATig+uRo/qIEP9T\nuzELVN9H6YPP/j2vRoZ6vpM=\n-----END PRIVATE KEY-----\n	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	\N	2026-01-20 09:38:59+00
6ed6f33f-680d-4c05-adb0-2ef4d7863bfb	2026-01-30 08:52:14+00	-----BEGIN CERTIFICATE-----\nMIIDrTCCApWgAwIBAgIUBO3YbHRXH6xIPSe6Fa4FdO2Mmf0wDQYJKoZIhvcNAQEL\nBQAwZjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEfMB0GCSqGSIb3DQEJARYQZGVtby5l\neGFtcGxlLmNvbTAeFw0yNjAxMjAwNzExMjBaFw0yNzAxMjAwNzExMjBaMGYxCzAJ\nBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\ndCBXaWRnaXRzIFB0eSBMdGQxHzAdBgkqhkiG9w0BCQEWEGRlbW8uZXhhbXBsZS5j\nb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp5NqzhCZu1Vwlw0U6\nA/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9reJ2Qp\n4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E1bLT\n+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPemBOJv\n9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEseTs+\nUlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgpurlM\nr71VAgMBAAGjUzBRMB0GA1UdDgQWBBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAfBgNV\nHSMEGDAWgBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAPBgNVHRMBAf8EBTADAQH/MA0G\nCSqGSIb3DQEBCwUAA4IBAQBl/RgPaHdFtfxFtrSefTWndOfAbTGXm28LUEz2P6u+\nYtjzkrjrUNC+tMBRKSI8HaAOMQofVx93Y1Ugv1IUhmFmVXfjKk0oGJEE/Lw9BPDO\nv2ZtrWDPSPEPEuKfnA8iugo75c+lGumN5sqN4gTJ6NnY+jVIaReevSR0AgtvwrIk\nYRxOz5o4eljHnmFqXLmruLO5ONslL+Q269FaP97ltB/D/MDnqww7SlOn4VLwOsLP\nnuiIhWdamjF/kufdJE3y+9eUI2cZQkg4JhmhzUXleFH+3aY+E8OG9IoXjVMWI4T4\n5bkV4tiRj2EirnE+TwpiYHxaMhrK/oBaLXLq2OKK7EpQ\n-----END CERTIFICATE-----	-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCp5NqzhCZu1Vwl\nw0U6A/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9re\nJ2Qp4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E\n1bLT+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPem\nBOJv9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEs\neTs+UlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgp\nurlMr71VAgMBAAECggEAEYoCiPtY02Lb8TsUQ73DPnaAQTtPvVizz8HJIwGpXXjP\nQw/BvJ/Etm9OHmOCSXhi0Zs9zn+cJTJS2VHkPY2oDvCrqyhiRKgLYnylcw57HUgI\naMB3z53FuCXAFtUJM0Qcjp7c9drdPnQ2hRuBq3AjBm5diATfGzkph0qpVoQIScVI\nK1Vfgc7gz5sRZ2yB7kqFovYJusPQ6CFLVenrs2yXeOZ80Wu6JPBBDT5ly0LbktFx\nzUbd9lSIbdIAJX+sJFf5TUdhuaUgv2xBYG0DMy7jJgL+b3byOvccyCkmOEVCgzxF\nYKyz76bi29KvonkldVacRugbk+c59GskkJ1xM7USwQKBgQDqwQ+kuDZqO8es6+g/\nLT0W2BmIVK4WqKkzEPkGCYASpLorx+OFCatw1B+29I8LDwPN7YJXY3Mf+5qEP4Jh\n0/jLdMwjIfJTaXyL2dsgb7Fqc9WigMHFifMb6TqS1KHJK67s5/7Gu5q/7v6zExEX\ntl5m08FkslLFyZpyCazVFhY6QQKBgQC5RRHXUBki/IQtxgaNG2g1OLgHNYCowaM9\nm4QuJ4KL9jqo3z7lkpi+UQ2Z7gaXlU5t/vvyrJGQEVQw/bWKS93YWabjcPBpGSbO\n5JcGObvzvLg6IMG++CMUsPFRzic20qaayLJCNa4tKVyDnoyFqSPeGg0Ko3a403Dp\nq6CpP0N2FQKBgBZx4wcCveEmWg8Edy4jKyYV/0rznbl44sSJKOYU3nPp4Arzj6NW\nq1ecUHPzqgGKq/hybvXgAk/ahImEcPjdhXoebq4lPsAO4+OTLspJI5NkA9cHrH8w\nk1fl0r3bKqTLUmxAOjHSGhejyCJi/k1gGGKIeIMiMZvLjMK+fhHZjMKBAoGAXB8u\n9tvaE95xrvz3RvSoxUX1o4gD+GWIUNriR7zXmdaOZmfTM33IO2G8HJ0RZBAWlnUi\nPBF4s6UaMt4EhcahgbFaXV9L+0ZJWLirK6pLfa+J/0VIcTea4e/1nlKehxEJTI+c\nq3VbrRMS8FNG1jM7JXXYpECRiOeCDn6LfXx6g90CgYEA6MYqlCN/ybYHYqmN92CC\n+xThdw4M+knhz/K0oy+kCiDsY0wHzxQWlQITedqWGUWpT2kW6Y0dG8b3Iqp25YRH\nJMq7D2p7UjtS9TJIbZjpbIyiupDWqTYbLO1kFVW+L4dM4/0cMATig+uRo/qIEP9T\nuzELVN9H6YPP/j2vRoZ6vpM=\n-----END PRIVATE KEY-----	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	\N	2026-01-30 08:52:14+00
c69a29b4-0762-441d-a0ca-a81d5db45e7c	2026-01-30 09:12:59+00	-----BEGIN CERTIFICATE-----\nMIIDrTCCApWgAwIBAgIUBO3YbHRXH6xIPSe6Fa4FdO2Mmf0wDQYJKoZIhvcNAQEL\nBQAwZjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEfMB0GCSqGSIb3DQEJARYQZGVtby5l\neGFtcGxlLmNvbTAeFw0yNjAxMjAwNzExMjBaFw0yNzAxMjAwNzExMjBaMGYxCzAJ\nBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\ndCBXaWRnaXRzIFB0eSBMdGQxHzAdBgkqhkiG9w0BCQEWEGRlbW8uZXhhbXBsZS5j\nb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp5NqzhCZu1Vwlw0U6\nA/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9reJ2Qp\n4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E1bLT\n+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPemBOJv\n9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEseTs+\nUlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgpurlM\nr71VAgMBAAGjUzBRMB0GA1UdDgQWBBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAfBgNV\nHSMEGDAWgBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAPBgNVHRMBAf8EBTADAQH/MA0G\nCSqGSIb3DQEBCwUAA4IBAQBl/RgPaHdFtfxFtrSefTWndOfAbTGXm28LUEz2P6u+\nYtjzkrjrUNC+tMBRKSI8HaAOMQofVx93Y1Ugv1IUhmFmVXfjKk0oGJEE/Lw9BPDO\nv2ZtrWDPSPEPEuKfnA8iugo75c+lGumN5sqN4gTJ6NnY+jVIaReevSR0AgtvwrIk\nYRxOz5o4eljHnmFqXLmruLO5ONslL+Q269FaP97ltB/D/MDnqww7SlOn4VLwOsLP\nnuiIhWdamjF/kufdJE3y+9eUI2cZQkg4JhmhzUXleFH+3aY+E8OG9IoXjVMWI4T4\n5bkV4tiRj2EirnE+TwpiYHxaMhrK/oBaLXLq2OKK7EpQ\n-----END CERTIFICATE-----	-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCp5NqzhCZu1Vwl\nw0U6A/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9re\nJ2Qp4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E\n1bLT+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPem\nBOJv9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEs\neTs+UlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgp\nurlMr71VAgMBAAECggEAEYoCiPtY02Lb8TsUQ73DPnaAQTtPvVizz8HJIwGpXXjP\nQw/BvJ/Etm9OHmOCSXhi0Zs9zn+cJTJS2VHkPY2oDvCrqyhiRKgLYnylcw57HUgI\naMB3z53FuCXAFtUJM0Qcjp7c9drdPnQ2hRuBq3AjBm5diATfGzkph0qpVoQIScVI\nK1Vfgc7gz5sRZ2yB7kqFovYJusPQ6CFLVenrs2yXeOZ80Wu6JPBBDT5ly0LbktFx\nzUbd9lSIbdIAJX+sJFf5TUdhuaUgv2xBYG0DMy7jJgL+b3byOvccyCkmOEVCgzxF\nYKyz76bi29KvonkldVacRugbk+c59GskkJ1xM7USwQKBgQDqwQ+kuDZqO8es6+g/\nLT0W2BmIVK4WqKkzEPkGCYASpLorx+OFCatw1B+29I8LDwPN7YJXY3Mf+5qEP4Jh\n0/jLdMwjIfJTaXyL2dsgb7Fqc9WigMHFifMb6TqS1KHJK67s5/7Gu5q/7v6zExEX\ntl5m08FkslLFyZpyCazVFhY6QQKBgQC5RRHXUBki/IQtxgaNG2g1OLgHNYCowaM9\nm4QuJ4KL9jqo3z7lkpi+UQ2Z7gaXlU5t/vvyrJGQEVQw/bWKS93YWabjcPBpGSbO\n5JcGObvzvLg6IMG++CMUsPFRzic20qaayLJCNa4tKVyDnoyFqSPeGg0Ko3a403Dp\nq6CpP0N2FQKBgBZx4wcCveEmWg8Edy4jKyYV/0rznbl44sSJKOYU3nPp4Arzj6NW\nq1ecUHPzqgGKq/hybvXgAk/ahImEcPjdhXoebq4lPsAO4+OTLspJI5NkA9cHrH8w\nk1fl0r3bKqTLUmxAOjHSGhejyCJi/k1gGGKIeIMiMZvLjMK+fhHZjMKBAoGAXB8u\n9tvaE95xrvz3RvSoxUX1o4gD+GWIUNriR7zXmdaOZmfTM33IO2G8HJ0RZBAWlnUi\nPBF4s6UaMt4EhcahgbFaXV9L+0ZJWLirK6pLfa+J/0VIcTea4e/1nlKehxEJTI+c\nq3VbrRMS8FNG1jM7JXXYpECRiOeCDn6LfXx6g90CgYEA6MYqlCN/ybYHYqmN92CC\n+xThdw4M+knhz/K0oy+kCiDsY0wHzxQWlQITedqWGUWpT2kW6Y0dG8b3Iqp25YRH\nJMq7D2p7UjtS9TJIbZjpbIyiupDWqTYbLO1kFVW+L4dM4/0cMATig+uRo/qIEP9T\nuzELVN9H6YPP/j2vRoZ6vpM=\n-----END PRIVATE KEY-----\n	{Certi12527}	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	\N	2026-01-30 09:12:59+00
de74e47f-0361-41fe-91a0-8c3b020b92ad	2026-01-30 10:09:51+00	-----BEGIN CERTIFICATE-----\nMIIDrTCCApWgAwIBAgIUBO3YbHRXH6xIPSe6Fa4FdO2Mmf0wDQYJKoZIhvcNAQEL\nBQAwZjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEfMB0GCSqGSIb3DQEJARYQZGVtby5l\neGFtcGxlLmNvbTAeFw0yNjAxMjAwNzExMjBaFw0yNzAxMjAwNzExMjBaMGYxCzAJ\nBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\ndCBXaWRnaXRzIFB0eSBMdGQxHzAdBgkqhkiG9w0BCQEWEGRlbW8uZXhhbXBsZS5j\nb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp5NqzhCZu1Vwlw0U6\nA/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9reJ2Qp\n4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E1bLT\n+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPemBOJv\n9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEseTs+\nUlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgpurlM\nr71VAgMBAAGjUzBRMB0GA1UdDgQWBBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAfBgNV\nHSMEGDAWgBQ1Y4Cx8TDNVcrAYoJnxZrFOPsaOjAPBgNVHRMBAf8EBTADAQH/MA0G\nCSqGSIb3DQEBCwUAA4IBAQBl/RgPaHdFtfxFtrSefTWndOfAbTGXm28LUEz2P6u+\nYtjzkrjrUNC+tMBRKSI8HaAOMQofVx93Y1Ugv1IUhmFmVXfjKk0oGJEE/Lw9BPDO\nv2ZtrWDPSPEPEuKfnA8iugo75c+lGumN5sqN4gTJ6NnY+jVIaReevSR0AgtvwrIk\nYRxOz5o4eljHnmFqXLmruLO5ONslL+Q269FaP97ltB/D/MDnqww7SlOn4VLwOsLP\nnuiIhWdamjF/kufdJE3y+9eUI2cZQkg4JhmhzUXleFH+3aY+E8OG9IoXjVMWI4T4\n5bkV4tiRj2EirnE+TwpiYHxaMhrK/oBaLXLq2OKK7EpQ\n-----END CERTIFICATE-----	-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCp5NqzhCZu1Vwl\nw0U6A/3Gr2xsUBA4KvOikEoxFjJFuPMjySC3MO1mqeSc5gpiuZXsAU1W+eKcm9re\nJ2Qp4eKt8sLM8xXJWvkCvCUu4z2LGy8gyodA+tahhxlJwn8DchB32QLpi9LCGv8E\n1bLT+mE1HEXTMlHAdju0v4Ul3HGx1iTiZ3pktLcO6pCK3LJWpNJI3NzJjYwFLPem\nBOJv9tazBQO4LCvrcnzTaHBOSR8Rchakp85l0KIGr8OIQzZ3awQmj6s+gvvycGEs\neTs+UlYFujIy/EsTpGIy5Bnjqp4betUwZ/SqXtM43EuOzmTydqELmWLNQvBGFAgp\nurlMr71VAgMBAAECggEAEYoCiPtY02Lb8TsUQ73DPnaAQTtPvVizz8HJIwGpXXjP\nQw/BvJ/Etm9OHmOCSXhi0Zs9zn+cJTJS2VHkPY2oDvCrqyhiRKgLYnylcw57HUgI\naMB3z53FuCXAFtUJM0Qcjp7c9drdPnQ2hRuBq3AjBm5diATfGzkph0qpVoQIScVI\nK1Vfgc7gz5sRZ2yB7kqFovYJusPQ6CFLVenrs2yXeOZ80Wu6JPBBDT5ly0LbktFx\nzUbd9lSIbdIAJX+sJFf5TUdhuaUgv2xBYG0DMy7jJgL+b3byOvccyCkmOEVCgzxF\nYKyz76bi29KvonkldVacRugbk+c59GskkJ1xM7USwQKBgQDqwQ+kuDZqO8es6+g/\nLT0W2BmIVK4WqKkzEPkGCYASpLorx+OFCatw1B+29I8LDwPN7YJXY3Mf+5qEP4Jh\n0/jLdMwjIfJTaXyL2dsgb7Fqc9WigMHFifMb6TqS1KHJK67s5/7Gu5q/7v6zExEX\ntl5m08FkslLFyZpyCazVFhY6QQKBgQC5RRHXUBki/IQtxgaNG2g1OLgHNYCowaM9\nm4QuJ4KL9jqo3z7lkpi+UQ2Z7gaXlU5t/vvyrJGQEVQw/bWKS93YWabjcPBpGSbO\n5JcGObvzvLg6IMG++CMUsPFRzic20qaayLJCNa4tKVyDnoyFqSPeGg0Ko3a403Dp\nq6CpP0N2FQKBgBZx4wcCveEmWg8Edy4jKyYV/0rznbl44sSJKOYU3nPp4Arzj6NW\nq1ecUHPzqgGKq/hybvXgAk/ahImEcPjdhXoebq4lPsAO4+OTLspJI5NkA9cHrH8w\nk1fl0r3bKqTLUmxAOjHSGhejyCJi/k1gGGKIeIMiMZvLjMK+fhHZjMKBAoGAXB8u\n9tvaE95xrvz3RvSoxUX1o4gD+GWIUNriR7zXmdaOZmfTM33IO2G8HJ0RZBAWlnUi\nPBF4s6UaMt4EhcahgbFaXV9L+0ZJWLirK6pLfa+J/0VIcTea4e/1nlKehxEJTI+c\nq3VbrRMS8FNG1jM7JXXYpECRiOeCDn6LfXx6g90CgYEA6MYqlCN/ybYHYqmN92CC\n+xThdw4M+knhz/K0oy+kCiDsY0wHzxQWlQITedqWGUWpT2kW6Y0dG8b3Iqp25YRH\nJMq7D2p7UjtS9TJIbZjpbIyiupDWqTYbLO1kFVW+L4dM4/0cMATig+uRo/qIEP9T\nuzELVN9H6YPP/j2vRoZ6vpM=\n-----END PRIVATE KEY-----	{CertiFinalworking}	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	\N	2026-01-30 10:09:51+00
\.


--
-- Data for Name: cluster_events; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.cluster_events (id, node_id, at, nbf, expire_at, channel, data) FROM stdin;
\.


--
-- Data for Name: clustering_data_planes; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.clustering_data_planes (id, hostname, ip, last_seen, config_hash, ttl, version, sync_status, updated_at, labels, cert_details, rpc_capabilities) FROM stdin;
\.


--
-- Data for Name: clustering_rpc_requests; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.clustering_rpc_requests (id, node_id, reply_to, ttl, payload) FROM stdin;
\.


--
-- Data for Name: clustering_sync_delta; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.clustering_sync_delta (version, type, pk, ws_id, entity) FROM stdin;
\.


--
-- Data for Name: clustering_sync_lock; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.clustering_sync_lock (id) FROM stdin;
1
\.


--
-- Data for Name: clustering_sync_version; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.clustering_sync_version (version) FROM stdin;
\.


--
-- Data for Name: consumer_group_consumers; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.consumer_group_consumers (created_at, consumer_group_id, consumer_id, cache_key, updated_at) FROM stdin;
\.


--
-- Data for Name: consumer_group_plugins; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.consumer_group_plugins (id, created_at, consumer_group_id, name, cache_key, config, ws_id, updated_at) FROM stdin;
\.


--
-- Data for Name: consumer_groups; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.consumer_groups (id, created_at, name, ws_id, tags, updated_at) FROM stdin;
\.


--
-- Data for Name: consumer_reset_secrets; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.consumer_reset_secrets (id, consumer_id, secret, status, client_addr, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: consumers; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.consumers (id, created_at, username, custom_id, tags, ws_id, username_lower, updated_at, type) FROM stdin;
f3c10206-5c8b-47d8-bbb3-328be6a10e9e	2026-01-19 10:44:18+00	Demo_Consumer	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	demo_consumer	2026-01-19 10:44:18+00	0
ae4e19df-4111-4b78-9c1e-8c72a3ae66a6	2026-01-19 10:48:20+00	Demo_Consumer2	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	demo_consumer2	2026-01-19 10:48:20+00	0
874a51ac-e5ec-4895-9b2c-11ee1b159ddd	2026-01-23 05:34:00+00	Demo_Consumer3	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	demo_consumer3	2026-01-23 05:34:00+00	0
953d0329-2630-4681-b349-2cc2f69c1f20	2026-01-30 06:06:42+00	sdsd	\N	{}	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	sdsd	2026-01-30 06:06:42+00	0
f4af315f-1fea-43f7-b42e-b9f7fbf4f6b6	2026-01-30 08:11:25+00	Demo_Consumer25	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	demo_consumer25	2026-01-30 08:11:25+00	0
530ed47f-f1b3-41af-a1bd-2669c090eb78	2026-01-30 08:16:54+00	Demo_Consumer26	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	demo_consumer26	2026-01-30 08:16:54+00	0
25018837-a876-403b-8a0d-e26ac2a21db8	2026-02-02 06:30:18+00	Cars24	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	cars24	2026-02-02 06:30:18+00	0
44fac004-747b-43f5-ae1a-f22853c0814d	2026-02-02 06:32:13+00	Cars_35	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	cars_35	2026-02-02 06:32:13+00	0
91897186-bd8f-4a81-aaa5-e4eea566db57	2026-02-04 06:03:39+00	raju_client	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	raju_client	2026-02-04 06:03:39+00	0
94e991b3-b956-4816-a7f4-f2f7d6327ad8	2026-02-06 05:22:04+00	partner-basic	\N	{}	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	partner-basic	2026-02-12 06:31:44+00	0
a3fbc29f-1c1f-4f2b-bb9a-09c3df62bd9a	2026-02-06 05:21:17+00	partner-premium	\N	{}	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	partner-premium	2026-02-12 06:32:11+00	0
\.


--
-- Data for Name: credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.credentials (id, consumer_id, consumer_type, plugin, credential_data, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: custom_plugins; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.custom_plugins (id, ws_id, name, schema, handler, created_at, updated_at, tags) FROM stdin;
\.


--
-- Data for Name: degraphql_routes; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.degraphql_routes (id, service_id, methods, uri, query, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: developers; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.developers (id, created_at, updated_at, email, status, meta, custom_id, consumer_id, rbac_user_id, ws_id) FROM stdin;
\.


--
-- Data for Name: document_objects; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.document_objects (id, created_at, updated_at, service_id, path, ws_id) FROM stdin;
\.


--
-- Data for Name: event_hooks; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.event_hooks (id, created_at, source, event, handler, on_change, snooze, config, updated_at) FROM stdin;
\.


--
-- Data for Name: files; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.files (id, path, checksum, contents, created_at, ws_id, updated_at) FROM stdin;
\.


--
-- Data for Name: graphql_ratelimiting_advanced_cost_decoration; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.graphql_ratelimiting_advanced_cost_decoration (id, service_id, type_path, add_arguments, add_constant, mul_arguments, mul_constant, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: group_rbac_roles; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.group_rbac_roles (created_at, group_id, rbac_role_id, workspace_id, updated_at) FROM stdin;
\.


--
-- Data for Name: groups; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.groups (id, created_at, name, comment, updated_at) FROM stdin;
\.


--
-- Data for Name: header_cert_auth_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.header_cert_auth_credentials (id, created_at, consumer_id, subject_name, ca_certificate_id, cache_key, tags, ws_id) FROM stdin;
\.


--
-- Data for Name: hmacauth_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.hmacauth_credentials (id, created_at, consumer_id, username, secret, tags, ws_id) FROM stdin;
\.


--
-- Data for Name: jwt_secrets; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.jwt_secrets (id, created_at, consumer_id, key, secret, algorithm, rsa_public_key, tags, ws_id) FROM stdin;
\.


--
-- Data for Name: jwt_signer_jwks; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.jwt_signer_jwks (id, name, keys, previous, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: key_sets; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.key_sets (id, name, tags, ws_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: keyauth_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.keyauth_credentials (id, created_at, consumer_id, key, tags, ttl, ws_id) FROM stdin;
27af21f0-f241-4da1-9bd4-770e67f948b5	2026-01-19 10:44:19+00	f3c10206-5c8b-47d8-bbb3-328be6a10e9e	LyAekqLgbfXlUijMYvLnrYdVmKtyfzYL	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
82adb20e-474c-4207-a06c-42529a70e29f	2026-01-19 10:48:21+00	ae4e19df-4111-4b78-9c1e-8c72a3ae66a6	71SINXzSO9vcLTxE5AEkRNltKiYM7zY2	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
6af1dc98-d71c-47fe-be75-83e3da4315c7	2026-01-23 05:34:02+00	874a51ac-e5ec-4895-9b2c-11ee1b159ddd	BrlVUdwA7aeHjyYFUiZ1kbHx22mXvLmw	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
66cc543c-7a4c-43f1-b2dd-dc5f757b1518	2026-01-30 08:11:26+00	f4af315f-1fea-43f7-b42e-b9f7fbf4f6b6	7ASchRtMxsiiW1ihcZSfL64Nddoz6f0x	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
59352579-530e-4e55-8262-75796267cd5e	2026-01-30 08:16:54+00	530ed47f-f1b3-41af-a1bd-2669c090eb78	ILCh7EmkXOcJ6PwDYCupDJl5lNTH9hTO	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
dc8c2e6f-bba9-4507-aa57-1dd9acee0800	2026-02-02 06:30:18+00	25018837-a876-403b-8a0d-e26ac2a21db8	XywgDZuBFaEsUjgS9Hi5pQkZ6MfAlilC	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
5f81580f-8715-4d7f-9af4-f48e0c98d9c3	2026-02-02 06:32:13+00	44fac004-747b-43f5-ae1a-f22853c0814d	irl2NyDBXIYkbnLtGD6Ppl3LNPeXfOME	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
adfdf0dd-f637-4b13-93cd-eff7da78d41e	2026-02-04 06:03:39+00	91897186-bd8f-4a81-aaa5-e4eea566db57	hwRzExGIqG0Qh0HUadrFR0OoILL0XiKl	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
5afdcc23-00f4-48d7-9ae5-c68619f0785d	2026-02-06 05:21:40+00	a3fbc29f-1c1f-4f2b-bb9a-09c3df62bd9a	14J3gKZou7WWNPZ13qB6mRAPWfFrEtez	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
ec1d3aaa-d62f-41ce-910e-c033015f687a	2026-02-06 05:22:12+00	94e991b3-b956-4816-a7f4-f2f7d6327ad8	yJREge03BLPurxXwMtIQ5R6EUIqP7Jv2	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1
\.


--
-- Data for Name: keyauth_enc_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.keyauth_enc_credentials (id, created_at, consumer_id, key, key_ident, ws_id, tags, ttl) FROM stdin;
\.


--
-- Data for Name: keyring_keys; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.keyring_keys (id, recovery_key_id, key_encrypted, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: keyring_meta; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.keyring_meta (id, state, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: keys; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.keys (id, set_id, name, cache_key, ws_id, kid, jwk, pem, tags, created_at, updated_at, x5t) FROM stdin;
\.


--
-- Data for Name: konnect_applications; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.konnect_applications (id, ws_id, created_at, client_id, scopes, tags, consumer_groups, auth_strategy_id, application_context, exhausted_scopes) FROM stdin;
\.


--
-- Data for Name: legacy_files; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.legacy_files (id, auth, name, type, contents, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: license_data; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.license_data (node_id, req_cnt, license_creation_date, year, month) FROM stdin;
47d48e97-8f88-411f-9b79-f212ac7b4138	0	2017-07-20 00:00:00	2026	1
5a889b88-7bcc-432f-b49a-4cbf58b5cafa	0	2017-07-20 00:00:00	2026	1
05db5ccf-35c8-4e30-b26e-82c449666955	39	2017-07-20 00:00:00	2026	1
6d2f842f-8ab8-495d-9bbf-5eff7d71adb2	0	2017-07-20 00:00:00	2026	1
dfbc407c-58d4-4b40-9f2d-4e2c6b250377	0	2017-07-20 00:00:00	2026	1
f719647f-c8e1-43fd-bbc7-03c2443f6dd3	508	2017-07-20 00:00:00	2026	2
ce89bb90-f9dc-4843-8b33-0efc472bd601	0	2017-07-20 00:00:00	2026	1
20bd3559-3802-486b-8a53-c5c1bee1f229	2	2017-07-20 00:00:00	2026	1
4b18ff6e-4f5e-4221-8c0c-9cee2babc025	12	2017-07-20 00:00:00	2026	2
76c8d3e7-b590-4191-97de-6838c1fb2219	0	2017-07-20 00:00:00	2026	2
151be2ee-b2bf-4b9b-886d-c5a633aaeccd	0	2017-07-20 00:00:00	2026	1
4e8efe55-e7aa-4283-bfd7-567112865245	0	2017-07-20 00:00:00	2026	1
fe79cefe-bfc8-43d0-9393-e4394f35e23c	31	2017-07-20 00:00:00	2026	1
8950cec3-c1af-4168-b0bf-64531f647744	0	2017-07-20 00:00:00	2026	1
bb82532e-ac49-4de8-9a69-e6bd820514e2	0	2017-07-20 00:00:00	2026	1
b5eb2559-486a-45a0-a6aa-15e689c40a0e	0	2017-07-20 00:00:00	2026	1
56245e75-a6ce-4ac7-b7b0-0361a61998c4	0	2017-07-20 00:00:00	2026	1
6251e5b5-56d5-4b45-9d1e-d6a23d4e1288	0	2017-07-20 00:00:00	2026	1
51578b43-1eea-4ab5-8ecc-1fd64b7a413e	26	2017-07-20 00:00:00	2026	1
c27377cc-ed78-42c8-a945-a4739dcc9dbf	0	2017-07-20 00:00:00	2026	1
b1683bc3-86f8-409e-8255-612d517ab41d	0	2017-07-20 00:00:00	2026	1
337880dc-218a-4472-912b-cde550bb50fe	0	2017-07-20 00:00:00	2026	1
ccf93f6f-7e00-47c9-92bf-fab69dcd905b	0	2017-07-20 00:00:00	2026	2
63e83a00-7170-4afd-b7c1-bad63e02e3e4	0	2017-07-20 00:00:00	2026	1
2f1f27ce-8954-4dab-a791-98be33d647d4	0	2017-07-20 00:00:00	2026	1
d67b717f-07a2-4cf6-ac22-06ca347c32ec	0	2017-07-20 00:00:00	2026	1
9edbc2fb-f912-4db3-ac37-267228801c74	0	2017-07-20 00:00:00	2026	1
5778dd9f-ccf7-4605-aed0-f9cf8c5e94ad	0	2017-07-20 00:00:00	2026	1
1fc221b4-4ba4-4679-bb9d-06a113bf02ce	0	2017-07-20 00:00:00	2026	2
e74bb27e-aa37-4732-a01b-b85f6319e6d3	36	2017-07-20 00:00:00	2026	2
28fae655-f4d7-4d36-9647-ab30ca177a4a	2	2017-07-20 00:00:00	2026	1
7238cf71-5e3b-464a-86ff-90a85af8333f	0	2017-07-20 00:00:00	2026	2
b1214aef-c600-46db-a175-f02a2e3a82c3	0	2017-07-20 00:00:00	2026	1
66bf987a-d596-433d-bd60-02cf378c9095	0	2017-07-20 00:00:00	2026	1
66e92be9-7155-456b-bf81-9c9871761541	0	2017-07-20 00:00:00	2026	1
b176397e-68f3-4752-9788-0bcc08400e10	0	2017-07-20 00:00:00	2026	1
41b61b9e-520b-4bae-8c9e-50ebcdf0d69d	0	2017-07-20 00:00:00	2026	1
243e99ce-0ea1-4fd8-b3a1-bf88d881a7c3	0	2017-07-20 00:00:00	2026	1
de2d46a5-b06e-42e8-bd95-5390cd699b19	5	2017-07-20 00:00:00	2026	2
\.


--
-- Data for Name: license_llm_data; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.license_llm_data (id, model_name, license_creation_date, year, week_of_year, month, day, hour) FROM stdin;
\.


--
-- Data for Name: licenses; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.licenses (id, payload, created_at, updated_at, checksum) FROM stdin;
\.


--
-- Data for Name: locks; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.locks (key, owner, ttl) FROM stdin;
\.


--
-- Data for Name: login_attempts; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.login_attempts (consumer_id, attempts, ttl, created_at, updated_at, attempt_type) FROM stdin;
\.


--
-- Data for Name: mtls_auth_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.mtls_auth_credentials (id, created_at, consumer_id, subject_name, ca_certificate_id, cache_key, ws_id, tags) FROM stdin;
\.


--
-- Data for Name: oauth2_authorization_codes; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.oauth2_authorization_codes (id, created_at, credential_id, service_id, code, authenticated_userid, scope, ttl, challenge, challenge_method, ws_id, plugin_id) FROM stdin;
\.


--
-- Data for Name: oauth2_credentials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.oauth2_credentials (id, created_at, name, consumer_id, client_id, client_secret, redirect_uris, tags, client_type, hash_secret, ws_id) FROM stdin;
\.


--
-- Data for Name: oauth2_tokens; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.oauth2_tokens (id, created_at, credential_id, service_id, access_token, refresh_token, token_type, expires_in, authenticated_userid, scope, ttl, ws_id) FROM stdin;
\.


--
-- Data for Name: oic_issuers; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.oic_issuers (id, issuer, configuration, keys, secret, created_at) FROM stdin;
\.


--
-- Data for Name: oic_jwks; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.oic_jwks (id, jwks) FROM stdin;
c3cfba2d-1617-453f-a416-52e6edb5f9a0	{"keys": [{"k": "qEIgx7Cwx-NjfXZ96a3xPHyP2Mjy4NneHVWs2hy1txQ", "alg": "HS256", "kid": "VjLF5TKM_LyohGb--CEZCLP6d3Yl3Y25r9LB2_wsbsc", "kty": "oct", "use": "sig"}, {"k": "DgX8JCLSsOlnpY3M5Lv01q09byUZsujoEMRE1LnVwewCI81nP2p67OrwvjlQF6-v", "alg": "HS384", "kid": "BEvzzRjFvCBTKB9z3ZX2ntYRykhKpD--BtUa_NXWv9k", "kty": "oct", "use": "sig"}, {"k": "KHCMklepn7AXb9NTMfIpAx1NDlbTJAEBtLCIf_LEeBFqdVvA1KdWEoZ1O4H0m-pcdWCyXJPhYzDGQEQwEAr7zA", "alg": "HS512", "kid": "yUP23ZZxlDY4VhHqBJVjm2Mbl6X5HhRGL43sJbSb6AU", "kty": "oct", "use": "sig"}, {"d": "jgfB9MCVbc8netWjy0ZStv2abad0V_y7SGDUO3LsN008YtRIRq2KsSECCBaYEw-w5quMkjtPxQGa2Iblny3d18WPtyQtqaQYd_XZbqbXq5fnp60L5eSk3Zj3i67COcUspj9wIt-dzJBzAaaA4NwDqkXHdRmv8uT2YG14pRDrajpqyh19LrpAwfXdjUcNqWRg_c2Eq5nEbQnBUPnzYibLOYJgNmTZhUZudQmv0L5F-c0Ig_eG8mt_CUHeIoJtcIhEhmpANCvA9tvwyjMPRASdH_Eya61eQobbztRBgBLyFpwvp9VkUVIrZZhcDq5SfJRd5Y0Qds7-5pRFN2VNCRIJ", "e": "AQAB", "n": "rPA_TGqWmBHBpUZ2Q3j9P2SI4ZGqKBwYrkAPWr6-JWj1kxqwEjctzklMmYjUD2i7dtnjridt48YC3SeQKX2z7Uuty-Pdqygw1l2Ii2qR5SJ9GzClExqIr6DS0ZvrMG9J3we3aWWsMiQ4tFNq4RazBE53msroAyS5Z6qVPnKIWRIup-Uzmw0kDjWkKXKqdm5tS3ST7TF8MHJaDUVLrctGh7ZGxoBLcQZgUuPSyFJPkaqJO2G2LtMmALj4kCs6YXu4dPC3J3OaUFDgrSO3jGfqg9D_Z-a0b4hegq6PuYMKuBvSsnvDbP6hYGOQfxzrkdYf6Vguv9Haeg7ZT7aJGN9vxQ", "p": "2Wx9TyKm1ZyxUyH6VfofDX6b5_iYkfAcsUruvjw5O5Efw4z5Y6edY8fb5CVRLXZIKYBu3fSefvC0r8EEKjo30yL0tzWu5ZH9BxVwbAiS0yCO9KGwkAkjnGksTJqmv020fJGUfKF76oq8GtCbqAdVfPjAJQQyG1Xtf-J48eSg6Jk", "q": "y581ob-re9Eklc77ZekMDXMht0A_f1_sua2pVBU2gdRuNaMhKQhE0kDLfFx4C559dFk8dRkXMewX4g20OoblR5JLaqTZwuK3zw_Ehk53yZeL7IBaUYcXmdDVSRyh6ms_vBVP7qOt9FzKJ0PqbaYEnrUIGsLHrAN35RcynHZ0oA0", "dp": "neSsZ5CpiY0eNVoCeveGH32naOFeovS1UYcyM5J2max9Xbx9y4IIyVJ1fIwhFJvGMeVkHemsRFE3Vj8ccDIRIlJLVtU0auEG2GMYXkwnnA0T49Gb8C3C3659DjBtEZYzkRcDtzJqU9xmWC7QK0kQKw5WM0uFu9Y-AFYOMNQwilk", "dq": "i6_B3B-gJYW5YmgnAKeaVBO6entB1EDbJhnjgsI2rWQs4vDxC7QXemFm9v58gAQPLmUVW4OF7QJ48-PQ0yG9YpcS06sZlF9yF0NK35QvCwXCwNDgpPNXFnc0Cj7xON6wT3gTaLOy32NUbxFhXi05GCM61xjuX6vVcTyzxLBim3U", "qi": "ik42yVbyXPZqUjhvpzkD8WjUTl4ik5Q1Sg_qV4zkwOV59yqqbHX0Vmq_aQ2mQcWpcAWK1YNsEjHpzr_aiOWdkazl2W9pCYETjZvbF2ZKynMtTbjpzLFYzTpD4PqpTRPjFB7l0jLJY1KOordlN_4ZtCU0fGQEO2bsqykOpIknBhw", "alg": "RS256", "kid": "Wdrd0GgYxWZz6MVYzZONtOUxQhtaKrg3q2Fs-PUE0zI", "kty": "RSA", "use": "sig"}, {"d": "A3atBSWuggXefMBKdFkKu_G1FYXe_8wSWRh9N9V9gmuNcYRddUT71wJ2kIZqfT1nIPf7EhyvsAC6Yu3HyMrhcWJ4G8aEx17UATBhjKLyw4UnT-hlt9Q6R6EHRM6WpSZl2x3CzuhYI1GkqhpmaCo4Vo_gPU_1oolNuPpQedVgiUb-OyMdsUD1BnXBj1ElI-8epJbxeC6E5zWnYD5Gw9BaPJUUS5WEJ6L-d8JJpw7DxIvSMXvvVLCmZks7WnlULFEk9WCvSz-cWp83A3zVPRdzMuE_f84BedIcErB5URC3_XNS8rOMMFMtPG9FwYdbXpq0aZw5G0hrsieHdiQIlpDsHQ", "e": "AQAB", "n": "wiouSmMO_3D2lDrzLFuU6scWdt0P9ak5FIhVyOEHANexpxWoXEE_dHvpET99qhsj2lQgjdgSK2rOK4zpXhI6BkS94CKoPnqVkLAIGyMTu3kqys2ZqX37jsswP5jl7m29ex9AEnVxv1qTIOBYJw17wKsqWcr-935MC_U-jOUxldMwHCqOOTjWs6fTOgVxxADBlyeQoW8rSd9RpPfzYZm4jqQEZD2vvAyNcy9agutaqAxHqIeTO3FCSLrwnkocDpHoUYtCtZZ4jP05RxobNqgIxz54icoTojejujPg8sW2gWXltBmuHGQTXi3BmUeO0vVag1RRiwj-6qmbu6kO1vmlhw", "p": "9b5mfVxEGOSzNIAkDMSzO9PqaWVNLPXJsoe6GrxNahYFw94Fr_xTkIVjrYEQAw1FEzKwb7Nfbd1Y5kzztJS2RMMe5P6zh9duPe-JrHVOec2D-hur7Z2wJY562N7QOUjDC3nNykkUl5KO7C1AXz5BMwZlA4p4RtlLUHd_KwEBs90", "q": "ykSx-ZoSmh4d5JRX8uCOysnaFZx0N2pwXm3St7t_oUZDLzB3x1ArBV3fIyHke878GRl7bYi7FFuCdq6Y-OxURCvaKUSx8fTb8DFC2XnsBZ7FUBLZoBqslflNAwxtggBuVfW97ESxIlGd8oLi76Xkj2bl21nG46S81eN4e-THSrM", "dp": "2zrK8Bc54QNWJAYVIxbv1vXM782htfRnxc9z5ZoLbhLLfds6M6_lVM7LB-RVxoM2FlRoNp5NChQn1PzdhUIOAPYZP61BuHQmMzbZGXNlWSBRFvVMwiSlGjwruAG-vPv-lORLBKWBq17iBiywesdtHvobb7c-aeY8XELevhydyjk", "dq": "Ygyk3aMja1Q4F2sVqyXR8lmg_yLlb0uIhy3jnK8mcm5V-RUcqyCgiix0E1rFoIK40A37OCC012x4tMF0ZA5j1twPGDw1ql2RFEE876FbmWnaqjNJDYSArv63p0ep-f_tfHvwggzWdRVtZHawPY2EW0N9HzTI5ecgpupqqFxBg2M", "qi": "RxeL3gsX-SA21gizrWNZvcVPRszW7E-ZurJMMyfBbj9JKTCjY73swwEKIkUlZOaWVw2GZzLNIhYPr-O3WzkfQSA1DXLrxVoRWESV1QvDV0rHTekUekkzcfNUrpipRpbvuvvQk2EcRneP42lwEhg9e_QWe2nxekepLnI-1tJoq5w", "alg": "RS384", "kid": "1ap2XWXeqgLxIcmrxbnb0fccq0ePCPhcnbiWnPPrrcA", "kty": "RSA", "use": "sig"}, {"d": "DBfEhsoGiJ01mC-Ma2JDVSRxTz09FwvVT0FzYOFxdjWRGprOKK-wUgK2SAhRnzEOb7z5rdlHUn9cuA8H3Q3oS7sZGpLESBBvYy4CKrmNoIMBpbdOnbitbhu6Bb1GTMONZ3ZYAwrmz26N31kQr69Z2q54Gbg0GJCYwaKoiaOS7bs0ZWIS7r4bdtmF2PQiIQmK4iL4vEiSBuS0G1FBpMPJCfdyZCnvnHDZQrJdBZjvSMR_CHHk7kVSLjxeVFitnE7yyFozNmLp8x9Ro2bR1SuVMtAqnpGTl8wVmnk5yl1Vs1SLG7X839cb9GAC57OzpkVdP7bsbRyWPbv7Ry0vjEKEIw", "e": "AQAB", "n": "pv6fNonJEUrkTdiZ22kAOohxnup3yOKTaRM_Hv-BioQH9OtDtv199ye-e4qs5NKkQq02ZB06U4Vv9iIRty8QusArLAAwoO4I4TGHTJwOLBrV9IafDwVNsSUqBN7tOKPikQApEhxiMUlnkoxXUZbgxz5RewyaftrqB_hHE2FVRZuVxVjdCq_5Ywa_ObakOsV-JteLm7l6aM8otchWMvPh_jsG1Cb2_TxU32X_8EbvLdkbjAKdtXyxkGzMJX0vKRsfZHQ7uENNFHfnAomaYFqVbUKnagupNRdO0gQBASsc-_Qhf6Y9GL3GmFR_xnfCQ2TZA_OBUw3bw9bpA2-o8uTgeQ", "p": "3EM10Dfnyx_AsUUNn_vhzPmJup_uzvNHKGPiFg1ADPAXDfrHUxZrWz59Ji4lcuCYnI7WgATVbVD-pbj8XywENo5p-JQ8t8Jf8pHXjlEOwkZeiSMt7ngOQODkOP_mx9HwHj19ySQRpSf7l8OYAPWOeYLUjlkyAzbqKL-j9ST3KAM", "q": "whbiPVqo60vJx4SEBp5wQqhz1-kMXQnONz_xsDqODnHqhb-wQoHEXBs3bGSWsKaOTNyqy-6VUMSsaecao7iNjNb1QeCeSUKrbWcBlL2PgJAxeY1UsuxzKfGVN4QrJa-rwgLDDiY--x90Oxalo_qhi3QzkwnFXnZY11yKAb6fotM", "dp": "JTEMEx59eyTfao9YX50uYWf5Q5PhxPv7FezXrhWKrSSVH_0qTvNIKV4Bz8KW_DDEVBsiSPeH-i9k8CKuKnvKMlQVvK17GyQtA05w8Uzqiw9Kwyk3hj6rWXUf1CgRlcfzHYgQhzgZ6qM3rkaOkgrkhcv7jBWvhi9tlnfVfX1CZnU", "dq": "korIot5yr8V3QkdRj9XMmOerH5f8F7sxkhGboB116H4mPnnu0Sg9Y_XAsPx5skLvKiVqZ7Np1aPJMeSl_nt3lKEwaF755AKMgHvHe9BsKvuz_zyweK-CfGbE7TfDhB7RJhkDwQkrgFvNXFfLFLZFho9j6V71QE9G4MQkBxEwYrU", "qi": "LNcYBn0DujuKvBdkqRWewhs7G3agtaTj2WYQbRBAMl5BlAvfU0_LUSDNybOp2OKvVDUMQOzYH4cL95f-w2kuJ8hd7D6QdEnZ84s536LmSVQ6mg2enLeUru3MezgN1HcPz3N2kxTgrhi2mZKdUMrQFt4vHr9fx_Ms0uNmng4Gl2Y", "alg": "RS512", "kid": "vOQsXuIwsCXIgVkouVjOmwRs-bQDqRLgvY24byv51Mo", "kty": "RSA", "use": "sig"}, {"d": "Dr2KvHAO8zOBHu6P2RmKr0ViDN7d3DZm1z9m2YMraVUAAhDqTgf8uZIqd3Bc1UaOQwcf-hNq3G_TDK584Kk1JYA-dqIw2fheWt9GaJIt_wcB9M7PHaJBIFNpLIRiG1IILs732wFzmmgFJJSZ7JHAv1Ww63Dc_tj0fksk9ceJVDq6lK-YoLLOkuglMdorWOsG4e-xKD0UfEgmshzpAHvEeiS404J8MMzqLbRtEknYWZlquv6tPbRwbT2BEBD8VGSAtDVFJvGeiaa7cEDD_miBZhWHTodb-6ivHZB1ROkwUPde_OB6W3OQt_dtg27VIL2ghezKJ_3XwPLJ7NhouTE6tQ", "e": "AQAB", "n": "6MDG-elzBGBc6nw1ZLcsnQoqgz-bCSzvyZ0iUbntdyiyz_pZL1tc5IPfaLCqlSohGJpiNLLN8DDRfoGvNZLgnjtFiS8vClhIfPCBRTWqR00wzsvYbd-qTTGm3nMxmkyjAjLtJ8VxNCBqX0dc_fm6bl8QQrk_-XV9QVOvAqbpMfC_rM5EQbXC83J7F6vcBKZGLfNt9HWoeSS2tmuxsmYm6QCzjQu2z2nfltbtemVctnQ0tgHTWWHNNaxKdoToYh8skwx4N815vSqUU1nCX9vD0uHXm9qTb5LZ1wHGWDYvFtXYmeiCihXSgyPAppkzCJRUSO1xs3E0S6S_rJmWbAKNfw", "p": "-CDfn7578Cd16G1fjA4V7JXXzpQyxaImXIllCEtWItDYyVNUP92u2KI_laxYt2-GJpLRkcezqS_FtCikO_Qi26jD2KEVCF8XbTLJZ1YE549gnpyKsT9U1_3qJ8o-Q0-lSJXDHZsdnaFUMg3MAhZkBoaqdL-_xZ3-GuAeWICnipM", "q": "8CMJHVL_JkwkiOuISH6a-JsQXD4Lo3EnD93qb7VJQb-Sd8Pj1J4WQI55gQY2q-k4-apVZ0MupDZiizp5--FOMH1cD520T7xN3bLqk8XOm3bLrSLMWge9S-Dzq6tkXr0f2a1F2p85FS1MFrtSE1XgqNM8KuK7OWZ4bELqee1VCOU", "dp": "xpKIZG8tAKST186wCIW9RfklHE291CxQRv4tvNWNuY8p7vShF_txUi2GdWHYHfVChtw4m1IWle-FaQidZt2ah_Any9Yd3vU66kkapXhRtH8p88WTuQXWAIVUP0O7UGMNA2nXHHpm2R-jIeuouILyycY74_MQpjYqhZeWsX1El8E", "dq": "sfiVWblYRk7qSNueznOecR-jOWn2gDRtSdIjXJUT7PmJGOACa2KahU_SdzBetnwL8OUvlG9zEtsHn75AB9BMfZ167EvqBao-X0-pkMlqPUgG3ZNLtnHD9oeKsDE_GwO5pj9H5SZaTPqcSMCdrJzZ-uVK01Hkhj8OgtX5J1Ig0o0", "qi": "Tapq0QTbe5uGM5GrBRkWt9TJtvho68_IwFH-Y5IaCrIFINjYw6m-eLYv-dG1TNzkOGmbr0OHtHRKj9xFuTLCjesGDR5PHnOlWqhcmVXiJwcbmQItOTnTuFtIGgcusxke3UDCj0yc5gqtYpKiCX5GsCvgMpQq6KbI16rzi9ILyBw", "alg": "PS256", "kid": "bWGx2mMAMa1JfvOglS21Xolsj-R5t6TVzCxNurMK3-w", "kty": "RSA", "use": "sig"}, {"d": "Kr8-nlLbR3YdcyqMIomM_2-wNVV9gVeFDNA_LEMP27NCq_BB89Vja9igOlSYGlrNJabJpu6W0Jf6SYzR29j0BZcUIPIV0z9QJd8J49oLv2-quspjAyf6GTmXSgJIOcNO33Vp-IVLk_A8d2tM0iA4q_fTEy6sFPyZL4wnkgXUwNULagejYpht9RoThfQjBSWDmC3zbYFGjznrgHXwXqIOLK6zKF5R43mrPNGMPMGMl6zVy3W1GYbbpfJ7b11sHhp1idUgwqbuv5-2FFJHMjHpFStSMg4R_T5cNh3mrXQQUjPDMudJ2uvqOD-jZJsz-SFTxichd9HpHGpSua4W9mzUYQ", "e": "AQAB", "n": "x0EQDSLqRAydxlFpeogvW6IwA5mBi2qq8JVgJVR8X1HCXuECL8PUCGBbPObFpLkgavy1vnTs1KTLqZtDrAEptJqT_hLp4jujKZJQBVDDEVKzyn1f35JpoF4bTeJ4rmvNEaFYmO5gc0mjpPUUaycpOcOId3llOn7WfThtgRThUF82O0fAgERXufSpRhHVRQ5X4S5ELgSfBhPhwVBkWelil5nd46qU7cdXrk9JD3UEEvOD_d0qhKMb2F1y25PgHk10JJTgcWdi5hchxGY82--JdooElk6vZ8lpsUI2cJRsuEt8otWc_R4hy3KVSLkFM1N9e0lRVCu13OfoSYC2BmbX3w", "p": "6diXkBCErT6K5djDMMgRO5DV7wuqexZtTGfsP1ht-6VkbUMTy45wqjGjo5aWXczyaIb6I8RyIKm7PpsesadKpgQPgm6HR5Jr2tWfqIvFfR4yyMNVCGhJLzgUtQZPoIO6ZtWdZm_mnj-JXPXCGMEaruTcJXeblOGMr8DpFC_5jUU", "q": "2iGFoVs2u-7-sNrHKN8CV0ahY5CIPbWF59KzcS0i5em-lUcy5QPxr1XWYPglMqs2icwuQBUc28cHjy8JHDFpI41atsu_hqH9eNI4ND2lJTJ2IB-Wmgvy1mUvBUAfZzh_gegfJUAhNPWN-DqE3DLoh_OGKL-7vMwZeGfzBeXMSNM", "dp": "soWXr3Ps1hWZFD-XQ_Z4sXCw4f2V-MH2Tw5HXVS1IhfxwzgiNJRZjpS2yHx97r43kXT6IbQnLKhnOjRSCm4cnwEalgirXgh6LmZHrPSHoC0duAbnM7PpqxK1PD3FLFVkSH1r3HgxJz56L22u8Bb7t-kf57qYG-DU9pffWHoHmcE", "dq": "jA3f_hVR1GMEdstR-sUNfLol34aqY2zMuGdJvc4sTRDCxJg9blwU7u4fQo2xXJIf52QJAi5MJDTrfpzFratwBVq6NwolRC14UP4xBiHaikKXI9MEYI5xcgTvpuBgCWd2PxOqA8HkUFultw7jxXqOYNQUfM92nCcz52Je4JeGje8", "qi": "ZLwhvnO29ByNqCFx8B-Ca8H06KmhI_1y3Qo19i_-9ZUIeQDOn8N52eCtMwLpSetx51DbdY_vQCVGK6AlMINEgSAMUeVhqEAn49hsmTPxAFqeqIfm2j8G0EhnZ-Pcda6pwg3IPSOnBD6m7tsGfiA6xbSjaVxNFf2Q1a189DnEFyw", "alg": "PS384", "kid": "rOLMhjCTff8sTUdtsgoKds6beD3xur5wErbMTuqQUYo", "kty": "RSA", "use": "sig"}, {"d": "DDFeKl9y_QZziOxHhRHGZRSEV74VmuLGV4GozUBWAao2chUrLgWcmJih8mpUNSCCMdaxRTbLhUQQaNsgiObPvEnfBFS4cDJTWr1B_xWVCxe1vVRiTPb0r4vSO_E8ARTE1I3lBjKeP9nll31h_A3hT9svQSMLbnFYrK_8Igfsfbpk7y1jXPKBpLvbvR-zQJzNSwBq5BRcnaa0kq2kXfQ0RSxldekMWLNC2mgueH_UR7kTx_LrL2fDJEssJFiQZ2HVcgV3yA-LY9QJ1hSPWrw5JiUJHQxBBS-gkbiNz9ipMyJ106mYrX7MqYsCPjmvnBmNyuhzyyRWHFPH_1k09OkegQ", "e": "AQAB", "n": "qv_3AFzEXhYNqVLNEjQ7wpVqdQoZXOCtPRU3w5UF-KvODeTJjmyA-FfKsu-LZHTCf3kvfdb0AYLburqqmF6zFybNjl24gQAjxtceGDDfjP9VWpAO-Yy3xNzDO6Ec_1SGZl-8u1Zqvhq0F5woLgKYSB8RYj3viX4dzb7aeYLnmkS50WFVsiX3jotq9Lc6_ih2I24xm6VkadA0YJK23d_kARkKkxn4t_FXVWC7ZJx4LX0Ac6z_Gkt2K3M4o1WlA2YgVefaKCvLDfntNm328fA149zO5YmLJYKH0UQFbZawWobNx_V5kEdDLI9bu7OvL_n853kWQltCjkc3ICxDLdZ-2Q", "p": "2AcvPTPFTjodO9RDrprmtF93q9wHmBwwpdG4irOfzt-ZpefU50Af3FbZdUdAHIPgSccUcsUsOmqDpgDfEGmt92GLUTN_3y0fscgGGb1W3JO8xNEZd4BKIM4IGkQv7ySQ897Il8J8P8wL1okP8baQ24x5Pq2NiwnAVCsqiCuxpNE", "q": "yqPihX44ayNfT-NKKrFfyHWxuJ1O-3hyITDHRR0EMVLEAFhM_2dLnaKZ2hm6irDS68HeOXuxJRINS8WmXWHh9_yVaQsPU9XtXqZtQ4YHhf7fRZ_I_EioHi_uGQw7JSVTNAWVm61H2sOiQ-JG8nYBUqJ6PkQ2AmyXveqyR1r_W4k", "dp": "UB9iCu4PqPLu8sjIjZMQLCgYZ5qFCoqyFF5TdsYmaIEQKLNyiI6FAqEHqHLTuX_ECTkYQXUV8VieGUzLbvfzOQRpuqVCMRE4ZyTL9nH-LHNzGQCA1Iy1cbNY1_0gVi8WwAyKE5djo_nXDivpyPmwgm14bqHKFJ56Qf18meKy0XE", "dq": "pdVCrt6hy0QSXy1x58hqy4FN5PiPx4pFVFY37Z6WbMr_7gxVTvq4zhNgdzVxDMkyg4-PjllkmiLQ0L66rFdLdwe1Ola7v28mJ7xpVMYd6BGxpKfj8lp_gtzUrJju2jJWig875UAEuso5Q_as-wWJhZfEFKr7zDYUZG7qYSzeJ4k", "qi": "jbxSgKPsQVmIBaGdpg88tncEI5JYdHf0ZPVvZXZd_35Mmwi4Wact__OaSr6aHBOj1EwwvKuSzO2Mm5Iz9WrDl1LicIKm36_3MXJtvvm_r21cb071D87CRMvdGdF0XMt-8SZy8RhXXoKM7zawmJhpwBaHXDPDP6DS-rCZT7xTtuA", "alg": "PS512", "kid": "rPIN7RKVPeHcQAnRYVAgZBfxuPm-wMBH3qOn94tq3wE", "kty": "RSA", "use": "sig"}, {"d": "N0iAJ_xiZE-w4HJqowSazK4srmzMk7bqxrsz2SoQILY", "x": "V9JI1L79hWfwxMDCKspySAac1DczyxhvrRwMqsBkxkA", "y": "qsdo78stjbeVTXil3G6ubkddpNOutfRmk441AV9UsEQ", "alg": "ES256", "crv": "P-256", "kid": "6332VlM-sUTw6rS_1hlAzOwqPZ7yurANe_hBWYgYw-U", "kty": "EC", "use": "sig"}, {"d": "0UREghg0zBP13zNHJ56VmUIc4w4MtlL4-ND2jKtesefGm0-39MmkD95NXIgFLbo3", "x": "m4ApeKJhUfBHCqmN8NUxQd8STqYqQWQFYIbeTJFwM13irh8Ftxis_iEwwXMnGEsj", "y": "yegSbQ5LZ_okGlLXG8WclxuChVlGK5w8nAnNrbQvoYoyN0YKY7rODEU3IWCeR3Xf", "alg": "ES384", "crv": "P-384", "kid": "BQOMIj70E8dBBo4NGOTzV4PHsaRzP877DNP79LadZS4", "kty": "EC", "use": "sig"}, {"d": "7BCNyqf0uO9TZ4T8sQ8TLFa2gwLWAmzk8cRE5VG33I7oJWZOr78jFx_q7KTbz4Vz7t5iGr2GV2PQHhLfuOIR0CY", "x": "bDzJUCDhp9zGJDUZHBFgwo6ORT8BhDuXG2xu5uxYJjavhoyG0iFOYUPs2FwmvB3-4cLnuaI3Illr1cuGvCgLVpo", "y": "vf26x1xcbKGGnJIIAs1sfowSRr-mdPUZQqYK0FNhlvYSWyWGYnG3MboU89d3qD4prj96TBvbgWoy7NI0NLgWamo", "alg": "ES512", "crv": "P-521", "kid": "myvZsyXVZa-aAQLjZdZQZ69hpVThC_I34E4kKwavEc4", "kty": "EC", "use": "sig"}, {"d": "-yehF7a8OinszJymMDJbRHe3qWhFj9IaTfhOI5kjTPg", "x": "7W2jnTMoeWlvfRQRnhPknvVLtWiZayGZPULZiExBUOU", "alg": "EdDSA", "crv": "Ed25519", "kid": "sW-T3xs12GTbfDaOLoY-VSC7MvJ1Sv1kuB0m7I47ohw", "kty": "OKP", "use": "sig"}, {"d": "Xtq5vfdFKfA5CFMVYR05IPW262z-rPH2IAlCl9ubY12yDe_4hQcnm9xatCjLCJxDyxg26Wyy7XLQ", "x": "Xk_rTBmzkwfc4duQFRLSAl42NAm6x15-wec3QX-0YHAOPKzl5gSlfW-Zm7Bw-0wlmvKQL2ANcVKA", "alg": "EdDSA", "crv": "Ed448", "kid": "XF285ayhlUHWoCbDRaUEiOfVTk1DigOBKs1YEysc73A", "kty": "OKP", "use": "sig"}]}
\.


--
-- Data for Name: parameters; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.parameters (key, value, created_at, updated_at) FROM stdin;
cluster_id	20ea5a11-8636-4536-9bb5-1f60fc4b1620	\N	2026-01-14 11:06:14+00
\.


--
-- Data for Name: partials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.partials (id, created_at, updated_at, type, config, ws_id, name, tags) FROM stdin;
\.


--
-- Data for Name: plugins; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.plugins (id, created_at, name, consumer_id, service_id, route_id, config, enabled, cache_key, protocols, tags, ws_id, instance_name, updated_at, ordering, consumer_group_id) FROM stdin;
69c3af62-1062-4d92-878a-d2197d3b8f7c	2026-02-05 07:03:16+00	jwt	\N	\N	\N	{"realm": null, "anonymous": null, "cookie_names": [], "header_names": ["authorization"], "key_claim_name": "iss", "uri_param_names": ["jwt"], "claims_to_verify": null, "run_on_preflight": true, "secret_is_base64": false, "maximum_expiration": 0}	f	plugins:jwt:::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-05 07:12:49+00	\N	\N
2a1c8f23-4edb-478f-9cd4-c662ce2d905b	2026-01-21 09:22:23+00	add-response-header	\N	\N	\N	{}	f	plugins:add-response-header:::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-01-23 06:22:24+00	\N	\N
45d2d8cb-02dd-47db-9be4-1395b926ee4c	2026-01-21 09:26:22+00	request-id-injector	\N	\N	\N	{}	f	plugins:request-id-injector:::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-01-23 06:22:26+00	\N	\N
713cb4e3-3ec9-4ed1-8ef7-08a48e3f35f9	2026-01-21 09:24:16+00	json-to-xml	\N	\N	\N	{}	f	plugins:json-to-xml:::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-01-23 06:22:29+00	\N	\N
c0f4c0db-ab25-4951-ac30-23713b69e6ad	2026-02-02 04:57:08+00	add-fixed-header	\N	\N	\N	{}	f	plugins:add-fixed-header:::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-02 04:58:51+00	\N	\N
e3c3d69b-667e-4d42-ac74-05632a393e7a	2026-02-12 06:34:29+00	acl	\N	\N	fb6473f4-57a8-4088-ba18-ea39c9d223ef	{"deny": null, "allow": ["Default"], "hide_groups_header": false, "include_consumer_groups": false, "always_use_authenticated_groups": false}	t	plugins:acl:fb6473f4-57a8-4088-ba18-ea39c9d223ef::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 06:34:29+00	\N	\N
12e9ebd6-c269-419d-a245-acce2d3e5f3e	2026-02-06 06:30:27+00	rate-limiting	\N	2d7bf6aa-0539-455c-9b98-4c49e0a64639	b2bc2d19-3ff1-41d8-8811-6b1ca8c99c76	{"day": null, "hour": null, "path": null, "year": null, "month": null, "redis": {"ssl": false, "host": null, "port": 6379, "timeout": 2000, "database": 0, "password": null, "username": null, "ssl_verify": false, "server_name": null, "cloud_authentication": {"aws_region": null, "auth_provider": null, "aws_cache_name": null, "azure_client_id": null, "azure_tenant_id": null, "aws_access_key_id": null, "aws_is_serverless": true, "aws_assume_role_arn": null, "azure_client_secret": null, "aws_role_session_name": null, "aws_secret_access_key": null, "gcp_service_account_json": null}}, "minute": 2, "policy": "local", "second": null, "limit_by": "consumer", "sync_rate": -1, "error_code": 429, "header_name": null, "error_message": "API rate limit exceeded", "fault_tolerant": true, "hide_client_headers": false}	t	plugins:rate-limiting:b2bc2d19-3ff1-41d8-8811-6b1ca8c99c76:2d7bf6aa-0539-455c-9b98-4c49e0a64639:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-06 06:30:27+00	\N	\N
287b44dd-55fd-404c-abf8-4489ae678397	2026-02-06 06:48:54+00	key-auth	\N	2d7bf6aa-0539-455c-9b98-4c49e0a64639	\N	{"realm": null, "anonymous": null, "key_names": ["apikey"], "key_in_body": false, "key_in_query": true, "key_in_header": true, "identity_realms": [{"id": null, "scope": "cp", "region": null}], "hide_credentials": false, "run_on_preflight": true}	t	plugins:key-auth::2d7bf6aa-0539-455c-9b98-4c49e0a64639:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https,ws,wss}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-06 06:48:54+00	\N	\N
366cbae6-8d3c-452a-a1dc-62ff22739b04	2026-02-06 05:39:29+00	response-transformer	\N	2d7bf6aa-0539-455c-9b98-4c49e0a64639	9a7fc34b-3803-4d5f-ac20-809c48347736	{"add": {"json": [], "headers": [], "json_types": []}, "append": {"json": [], "headers": [], "json_types": []}, "remove": {"json": ["city"], "headers": []}, "rename": {"json": [], "headers": []}, "replace": {"json": [], "headers": [], "json_types": []}}	t	plugins:response-transformer:9a7fc34b-3803-4d5f-ac20-809c48347736:2d7bf6aa-0539-455c-9b98-4c49e0a64639:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-06 06:07:32+00	\N	\N
3a7c61f2-2609-4036-9301-6f05c237e3b6	2026-02-06 05:40:30+00	response-transformer	\N	2d7bf6aa-0539-455c-9b98-4c49e0a64639	b2bc2d19-3ff1-41d8-8811-6b1ca8c99c76	{"add": {"json": [], "headers": [], "json_types": []}, "append": {"json": [], "headers": [], "json_types": []}, "remove": {"json": ["state", "city"], "headers": []}, "rename": {"json": [], "headers": []}, "replace": {"json": [], "headers": [], "json_types": []}}	t	plugins:response-transformer:b2bc2d19-3ff1-41d8-8811-6b1ca8c99c76:2d7bf6aa-0539-455c-9b98-4c49e0a64639:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-06 06:08:40+00	\N	\N
a96f38c4-ade9-45b1-847a-f17388d2cbdb	2026-02-06 06:29:23+00	rate-limiting	\N	2d7bf6aa-0539-455c-9b98-4c49e0a64639	9a7fc34b-3803-4d5f-ac20-809c48347736	{"day": null, "hour": null, "path": null, "year": null, "month": null, "redis": {"ssl": false, "host": null, "port": 6379, "timeout": 2000, "database": 0, "password": null, "username": null, "ssl_verify": false, "server_name": null, "cloud_authentication": {"aws_region": null, "auth_provider": null, "aws_cache_name": null, "azure_client_id": null, "azure_tenant_id": null, "aws_access_key_id": null, "aws_is_serverless": true, "aws_assume_role_arn": null, "azure_client_secret": null, "aws_role_session_name": null, "aws_secret_access_key": null, "gcp_service_account_json": null}}, "minute": 5, "policy": "local", "second": null, "limit_by": "consumer", "sync_rate": -1, "error_code": 429, "header_name": null, "error_message": "API rate limit exceeded", "fault_tolerant": true, "hide_client_headers": false}	t	plugins:rate-limiting:9a7fc34b-3803-4d5f-ac20-809c48347736:2d7bf6aa-0539-455c-9b98-4c49e0a64639:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-06 06:29:23+00	\N	\N
1085db0c-94db-48d9-a745-a293dac98ce8	2026-02-11 11:08:16+00	acl	\N	ed1f3298-55d7-4a0c-a157-1fd01771b62d	a9984dcb-3442-4ade-9718-4f1f975ee5c3	{"deny": null, "allow": ["Default"], "hide_groups_header": false, "include_consumer_groups": false, "always_use_authenticated_groups": false}	t	plugins:acl:a9984dcb-3442-4ade-9718-4f1f975ee5c3:ed1f3298-55d7-4a0c-a157-1fd01771b62d:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-11 11:08:16+00	\N	\N
41a382ff-8563-45e7-8e5d-d9e1996081ae	2026-02-11 10:28:29+00	key-auth	\N	ed1f3298-55d7-4a0c-a157-1fd01771b62d	\N	{"realm": null, "anonymous": null, "key_names": ["apikey"], "key_in_body": false, "key_in_query": true, "key_in_header": true, "identity_realms": [{"id": null, "scope": "cp", "region": null}], "hide_credentials": false, "run_on_preflight": true}	t	plugins:key-auth::ed1f3298-55d7-4a0c-a157-1fd01771b62d:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https,ws,wss}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-11 10:28:29+00	\N	\N
846764b3-121c-4c66-970f-7fc420d468d7	2026-02-11 11:10:13+00	response-transformer	\N	ed1f3298-55d7-4a0c-a157-1fd01771b62d	a9984dcb-3442-4ade-9718-4f1f975ee5c3	{"add": {"json": [], "headers": [], "json_types": []}, "append": {"json": [], "headers": [], "json_types": []}, "remove": {"json": ["city"], "headers": []}, "rename": {"json": [], "headers": []}, "replace": {"json": [], "headers": [], "json_types": []}}	t	plugins:response-transformer:a9984dcb-3442-4ade-9718-4f1f975ee5c3:ed1f3298-55d7-4a0c-a157-1fd01771b62d:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-11 11:10:13+00	\N	\N
0b0d6a42-e0ae-4400-a5f7-7c3226ddb27a	2026-02-12 05:34:20+00	ip-restriction	\N	2d7bf6aa-0539-455c-9b98-4c49e0a64639	\N	{"deny": ["192.168.64.1"], "allow": [], "status": null, "message": null}	f	plugins:ip-restriction::2d7bf6aa-0539-455c-9b98-4c49e0a64639:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{http,https,tcp,tls,grpc,grpcs}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 05:47:28+00	\N	\N
2f07da5b-459e-4e37-b47f-fb868d8df899	2026-02-11 10:52:42+00	acl	\N	\N	22e95c7a-df7f-4370-9c6c-534469bf025f	{"deny": null, "allow": ["Premium"], "hide_groups_header": false, "include_consumer_groups": false, "always_use_authenticated_groups": false}	t	plugins:acl:22e95c7a-df7f-4370-9c6c-534469bf025f::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-11 10:52:42+00	\N	\N
6323d017-f366-46bb-925d-c504094eccc1	2026-02-12 06:33:55+00	acl	\N	dd7e10d5-3742-4eb7-8f13-4b8b60852d6d	c77a91fe-259c-4ef6-860c-661e499e1d53	{"deny": null, "allow": ["Premium"], "hide_groups_header": false, "include_consumer_groups": false, "always_use_authenticated_groups": false}	t	plugins:acl:c77a91fe-259c-4ef6-860c-661e499e1d53:dd7e10d5-3742-4eb7-8f13-4b8b60852d6d:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 06:33:55+00	\N	\N
5c38bade-d74c-42c8-86e6-c2467dee16ff	2026-02-12 06:31:15+00	key-auth	\N	dd7e10d5-3742-4eb7-8f13-4b8b60852d6d	\N	{"realm": null, "anonymous": null, "key_names": ["apikey"], "key_in_body": false, "key_in_query": true, "key_in_header": true, "identity_realms": [{"id": null, "scope": "cp", "region": null}], "hide_credentials": false, "run_on_preflight": true}	t	plugins:key-auth::dd7e10d5-3742-4eb7-8f13-4b8b60852d6d:::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https,ws,wss}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 06:31:15+00	\N	\N
55a10d41-6bbd-48ed-9c31-c92c72bbb6dd	2026-02-12 06:35:50+00	rate-limiting	\N	\N	fb6473f4-57a8-4088-ba18-ea39c9d223ef	{"day": null, "hour": null, "path": null, "year": null, "month": null, "redis": {"ssl": false, "host": null, "port": 6379, "timeout": 2000, "database": 0, "password": null, "username": null, "ssl_verify": false, "server_name": null, "cloud_authentication": {"aws_region": null, "auth_provider": null, "aws_cache_name": null, "azure_client_id": null, "azure_tenant_id": null, "aws_access_key_id": null, "aws_is_serverless": true, "aws_assume_role_arn": null, "azure_client_secret": null, "aws_role_session_name": null, "aws_secret_access_key": null, "gcp_service_account_json": null}}, "minute": 3, "policy": "local", "second": null, "limit_by": "consumer", "sync_rate": -1, "error_code": 429, "header_name": null, "error_message": "API rate limit exceeded", "fault_tolerant": true, "hide_client_headers": false}	t	plugins:rate-limiting:fb6473f4-57a8-4088-ba18-ea39c9d223ef::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 06:35:50+00	\N	\N
1ac8e6fd-ca24-42c3-a4f2-e33423ef09f2	2026-02-12 06:37:08+00	response-transformer	\N	\N	fb6473f4-57a8-4088-ba18-ea39c9d223ef	{"add": {"json": [], "headers": [], "json_types": []}, "append": {"json": [], "headers": [], "json_types": []}, "remove": {"json": ["city", "state"], "headers": []}, "rename": {"json": [], "headers": []}, "replace": {"json": [], "headers": [], "json_types": []}}	t	plugins:response-transformer:fb6473f4-57a8-4088-ba18-ea39c9d223ef::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 06:37:08+00	\N	\N
cf2ad923-7193-428f-a07c-7e0fd186fcc1	2026-02-12 06:46:59+00	rate-limiting	\N	\N	c77a91fe-259c-4ef6-860c-661e499e1d53	{"day": null, "hour": null, "path": null, "year": null, "month": null, "redis": {"ssl": false, "host": null, "port": 6379, "timeout": 2000, "database": 0, "password": null, "username": null, "ssl_verify": false, "server_name": null, "cloud_authentication": {"aws_region": null, "auth_provider": null, "aws_cache_name": null, "azure_client_id": null, "azure_tenant_id": null, "aws_access_key_id": null, "aws_is_serverless": true, "aws_assume_role_arn": null, "azure_client_secret": null, "aws_role_session_name": null, "aws_secret_access_key": null, "gcp_service_account_json": null}}, "minute": 5, "policy": "local", "second": null, "limit_by": "consumer", "sync_rate": -1, "error_code": 429, "header_name": null, "error_message": "API rate limit exceeded", "fault_tolerant": true, "hide_client_headers": false}	t	plugins:rate-limiting:c77a91fe-259c-4ef6-860c-661e499e1d53::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{grpc,grpcs,http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 06:46:59+00	\N	\N
b3080e20-eb6d-46a5-b95d-b94682a1bc43	2026-02-12 08:57:06+00	ip-restriction	\N	\N	fb6473f4-57a8-4088-ba18-ea39c9d223ef	{"deny": ["192.168.64.1"], "allow": null, "status": null, "message": null}	f	plugins:ip-restriction:fb6473f4-57a8-4088-ba18-ea39c9d223ef::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{http,https,tcp,tls,grpc,grpcs}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-12 09:02:06+00	\N	\N
eb68f079-564a-4433-9ea5-2ff49c89fe53	2026-02-13 06:36:03+00	http-log	\N	\N	\N	{"queue": {"max_bytes": null, "max_entries": 10000, "max_batch_size": 1, "max_retry_time": 60, "max_retry_delay": 60, "concurrency_limit": 1, "initial_retry_delay": 0.01, "max_coalescing_delay": 1}, "method": "POST", "headers": {}, "timeout": 10000, "keepalive": 60000, "queue_size": null, "ssl_verify": null, "retry_count": null, "content_type": "application/json", "flush_timeout": null, "http_endpoint": "http://192.168.0.181:8080", "custom_fields_by_lua": {}}	t	plugins:http-log:::::00b2c6cc-ac81-44d8-b3d4-5c764f851be1	{http,https}	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	\N	2026-02-19 04:35:56+00	\N	\N
\.


--
-- Data for Name: plugins_partials; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.plugins_partials (id, created_at, updated_at, path, plugin_id, partial_id) FROM stdin;
\.


--
-- Data for Name: ratelimiting_metrics; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ratelimiting_metrics (identifier, period, period_date, service_id, route_id, value, ttl) FROM stdin;
\.


--
-- Data for Name: rbac_role_endpoints; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.rbac_role_endpoints (role_id, workspace, endpoint, actions, comment, created_at, negative, updated_at) FROM stdin;
e5ef101f-34d2-40db-87ae-d68546c5ccd5	*	*	1	\N	2026-01-14 11:06:13+00	f	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	*	15	\N	2026-01-14 11:06:13+00	f	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/rbac/*	15	\N	2026-01-14 11:06:13+00	t	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/rbac/*/*	15	\N	2026-01-14 11:06:13+00	t	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/rbac/*/*/*	15	\N	2026-01-14 11:06:13+00	t	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/rbac/*/*/*/*	15	\N	2026-01-14 11:06:13+00	t	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/rbac/*/*/*/*/*	15	\N	2026-01-14 11:06:13+00	t	2026-01-14 11:06:14+00
de060e80-106f-4a0d-9e02-2120eae36985	*	*	15	\N	2026-01-14 11:06:13+00	f	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/admins	15	\N	2026-01-14 11:06:14+00	t	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/admins/*	15	\N	2026-01-14 11:06:14+00	t	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/groups	15	\N	2026-01-14 11:06:14+00	t	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	*	/groups/*	15	\N	2026-01-14 11:06:14+00	t	2026-01-14 11:06:14+00
\.


--
-- Data for Name: rbac_role_entities; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.rbac_role_entities (role_id, entity_id, entity_type, actions, negative, comment, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: rbac_roles; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.rbac_roles (id, name, comment, created_at, is_default, ws_id, updated_at) FROM stdin;
e5ef101f-34d2-40db-87ae-d68546c5ccd5	read-only	Read access to all endpoints, across all workspaces	2026-01-14 11:06:13+00	f	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	2026-01-14 11:06:14+00
786b4013-db86-47d2-8245-7573b31d0698	admin	Full access to all endpoints, across all workspaces—except RBAC Admin API	2026-01-14 11:06:13+00	f	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	2026-01-14 11:06:14+00
de060e80-106f-4a0d-9e02-2120eae36985	super-admin	Full access to all endpoints, across all workspaces	2026-01-14 11:06:13+00	f	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	2026-01-14 11:06:14+00
\.


--
-- Data for Name: rbac_user_groups; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.rbac_user_groups (user_id, group_id) FROM stdin;
\.


--
-- Data for Name: rbac_user_roles; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.rbac_user_roles (user_id, role_id, role_source) FROM stdin;
\.


--
-- Data for Name: rbac_users; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.rbac_users (id, name, user_token, user_token_ident, comment, enabled, created_at, ws_id, updated_at) FROM stdin;
\.


--
-- Data for Name: response_ratelimiting_metrics; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.response_ratelimiting_metrics (identifier, period, period_date, service_id, route_id, value) FROM stdin;
\.


--
-- Data for Name: rl_counters; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.rl_counters (key, namespace, window_start, window_size, count) FROM stdin;
\.


--
-- Data for Name: routes; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.routes (id, created_at, updated_at, name, service_id, protocols, methods, hosts, paths, snis, sources, destinations, regex_priority, strip_path, preserve_host, tags, https_redirect_status_code, headers, path_handling, ws_id, request_buffering, response_buffering, expression, priority) FROM stdin;
b2bc2d19-3ff1-41d8-8811-6b1ca8c99c76	2026-02-06 06:02:18+00	2026-02-06 06:02:18+00	print2fields	2d7bf6aa-0539-455c-9b98-4c49e0a64639	{http,https}	{GET}	\N	{/v1/print2fields}	\N	\N	\N	0	t	f	{}	426	\N	v0	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	t	\N	\N
9a7fc34b-3803-4d5f-ac20-809c48347736	2026-02-06 05:29:27+00	2026-02-06 06:04:52+00	print_full_json	2d7bf6aa-0539-455c-9b98-4c49e0a64639	{http,https}	{GET}	\N	{/v1/printfulljson}	\N	\N	\N	0	t	f	{}	426	\N	v0	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	t	\N	\N
22e95c7a-df7f-4370-9c6c-534469bf025f	2026-02-11 07:38:10+00	2026-02-11 07:38:10+00	json-route	ed1f3298-55d7-4a0c-a157-1fd01771b62d	{http,https}	{GET}	\N	{/api/mock}	\N	\N	\N	0	t	f	{}	426	\N	v0	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	t	\N	\N
a9984dcb-3442-4ade-9718-4f1f975ee5c3	2026-02-11 11:06:41+00	2026-02-11 11:07:36+00	3fields	ed1f3298-55d7-4a0c-a157-1fd01771b62d	{http,https}	{GET}	\N	{/api/mock/1}	\N	\N	\N	0	t	f	{}	426	\N	v0	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	t	\N	\N
fb6473f4-57a8-4088-ba18-ea39c9d223ef	2026-02-12 06:29:30+00	2026-02-12 06:29:30+00	basic-route	dd7e10d5-3742-4eb7-8f13-4b8b60852d6d	{http,https}	{GET}	\N	{/api/basic-info}	\N	\N	\N	0	t	f	{}	426	\N	v0	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	t	\N	\N
c77a91fe-259c-4ef6-860c-661e499e1d53	2026-02-12 06:30:38+00	2026-02-12 06:30:38+00	premium-route	dd7e10d5-3742-4eb7-8f13-4b8b60852d6d	{http,https}	{GET}	\N	{/api/full-info}	\N	\N	\N	0	t	f	{}	426	\N	v0	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	t	\N	\N
\.


--
-- Data for Name: schema_meta; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.schema_meta (key, subsystem, last_executed, executed, pending) FROM stdin;
schema_meta	saml	001_370_to_380	{001_370_to_380}	{}
schema_meta	acme	003_350_to_360	{000_base_acme,001_280_to_300,002_320_to_330,003_350_to_360}	{}
schema_meta	ai-proxy	001_360_to_370	{001_360_to_370}	{}
schema_meta	enterprise.acl	001_1500_to_2100	{001_1500_to_2100}	{}
schema_meta	key-auth	004_320_to_330	{000_base_key_auth,002_130_to_140,003_200_to_210,004_320_to_330}	{}
schema_meta	core	028_3120_to_3130	{000_base,003_100_to_110,004_110_to_120,005_120_to_130,006_130_to_140,007_140_to_150,008_150_to_200,009_200_to_210,010_210_to_211,011_212_to_213,012_213_to_220,013_220_to_230,014_230_to_260,015_260_to_270,016_270_to_280,016_280_to_300,017_300_to_310,018_310_to_320,019_320_to_330,020_330_to_340,021_340_to_350,022_350_to_360,023_360_to_370,024_380_to_390,025_390_to_3100,026_3100_to_3110,027_3110_to_3120,028_3120_to_3130}	{}
schema_meta	ace	001_312_to_313	{000_base_ace,001_312_to_313}	\N
schema_meta	ai-rate-limiting-advanced	003_390_to_3100	{001_370_to_380,002_370_to_380,003_390_to_3100}	{}
schema_meta	rate-limiting	006_350_to_360	{000_base_rate_limiting,003_10_to_112,004_200_to_210,005_320_to_330,006_350_to_360}	{}
schema_meta	acl	004_212_to_213	{000_base_acl,002_130_to_140,003_200_to_210,004_212_to_213}	{}
schema_meta	basic-auth	003_200_to_210	{000_base_basic_auth,002_130_to_140,003_200_to_210}	{}
schema_meta	key-auth-enc	001_200_to_210	{000_base_key_auth_enc,001_200_to_210}	{}
schema_meta	bot-detection	001_200_to_210	{001_200_to_210}	{}
schema_meta	canary	001_200_to_210	{001_200_to_210}	{}
schema_meta	degraphql	000_base	{000_base}	\N
schema_meta	file-log	001_340_to_3100	{001_340_to_3100}	\N
schema_meta	graphql-proxy-cache-advanced	002_370_to_380	{001_370_to_380,002_370_to_380}	{}
schema_meta	enterprise	026_31200_to_31300	{000_base,006_1301_to_1500,006_1301_to_1302,010_1500_to_2100,007_1500_to_1504,008_1504_to_1505,007_1500_to_2100,009_1506_to_1507,009_2100_to_2200,010_2200_to_2211,010_2200_to_2300,010_2200_to_2300_1,011_2300_to_2600,012_2600_to_2700,012_2600_to_2700_1,013_2700_to_2800,014_2800_to_3000,015_3000_to_3100,016_3100_to_3200,017_3200_to_3300,018_3300_to_3400,019_3500_to_3600,020_3600_to_3700,021_3700_to_3800,021_3700_to_3800_1,023_3900_to_31000,023_3900_to_31000_1,023_3900_to_31000_2,023_3900_to_31000_3,023_3900_to_31000_4,024_31000_to_31100,024_31000_to_31100_1,025_31100_to_31200,026_31200_to_31300}	{}
schema_meta	openid-connect	004_370_to_380	{000_base_openid_connect,001_14_to_15,002_200_to_210,003_280_to_300,004_370_to_380}	{}
schema_meta	konnect-application-auth	004_exhausted_scopes_addition	{000_base_konnect_applications,001_consumer_group_addition,002_strategy_id_addition,003_application_context,004_exhausted_scopes_addition}	\N
schema_meta	graphql-rate-limiting-advanced	002_370_to_380	{000_base_gql_rate_limiting,001_370_to_380,002_370_to_380}	{}
schema_meta	header-cert-auth	000_base_header_cert_auth	{000_base_header_cert_auth}	\N
schema_meta	hmac-auth	003_200_to_210	{000_base_hmac_auth,002_130_to_140,003_200_to_210}	{}
schema_meta	http-log	001_280_to_300	{001_280_to_300}	{}
schema_meta	ip-restriction	001_200_to_210	{001_200_to_210}	{}
schema_meta	opentelemetry	001_331_to_332	{001_331_to_332}	{}
schema_meta	mtls-auth	002_2200_to_2300	{000_base_mtls_auth,001_200_to_210,002_2200_to_2300}	{}
schema_meta	jwt	003_200_to_210	{000_base_jwt,002_130_to_140,003_200_to_210}	{}
schema_meta	jwt-signer	001_200_to_210	{000_base_jwt_signer,001_200_to_210}	\N
schema_meta	post-function	001_280_to_300	{001_280_to_300}	{}
schema_meta	pre-function	001_280_to_300	{001_280_to_300}	{}
schema_meta	oauth2	007_320_to_330	{000_base_oauth2,003_130_to_140,004_200_to_210,005_210_to_211,006_320_to_330,007_320_to_330}	{}
schema_meta	session	003_330_to_3100	{000_base_session,001_add_ttl_index,002_320_to_330,003_330_to_3100}	\N
schema_meta	rate-limiting-advanced	002_370_to_380	{001_370_to_380,002_370_to_380}	{}
schema_meta	proxy-cache-advanced	002_370_to_380	{001_370_to_380,002_370_to_380}	{}
schema_meta	upstream-timeout	000_31000_to_31100	{000_31000_to_31100}	\N
schema_meta	response-ratelimiting	001_350_to_360	{000_base_response_rate_limiting,001_350_to_360}	{}
schema_meta	vault-auth	002_300_to_310	{000_base_vault_auth,001_280_to_300,002_300_to_310}	\N
schema_meta	enterprise.acme	001_3900_to_31000	{001_3900_to_31000}	\N
schema_meta	enterprise.basic-auth	003_3800_to_3900	{001_1500_to_2100,002_2100_to_31300,003_3800_to_3900}	{}
schema_meta	enterprise.hmac-auth	001_1500_to_2100	{001_1500_to_2100}	{}
schema_meta	enterprise.jwt	001_1500_to_2100	{001_1500_to_2100}	{}
schema_meta	enterprise.key-auth	002_3900_to_31000	{001_1500_to_2100,001_3800_to_3900,002_3900_to_31000}	{}
schema_meta	enterprise.key-auth-enc	003_3900_to_31000	{001_1500_to_2100,002_3100_to_3200,002_2800_to_3200,003_3900_to_31000}	{}
schema_meta	enterprise.mtls-auth	002_2200_to_2300	{001_1500_to_2100,002_2200_to_2300}	{}
schema_meta	enterprise.oauth2	002_2200_to_2211	{001_1500_to_2100,002_2200_to_2211}	{}
schema_meta	enterprise.request-transformer-advanced	001_1500_to_2100	{001_1500_to_2100}	{}
schema_meta	enterprise.response-transformer-advanced	001_1500_to_2100	{001_1500_to_2100}	{}
\.


--
-- Data for Name: services; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.services (id, created_at, updated_at, name, retries, protocol, host, port, path, connect_timeout, write_timeout, read_timeout, tags, client_certificate_id, tls_verify, tls_verify_depth, ca_certificates, ws_id, enabled, tls_sans) FROM stdin;
2d7bf6aa-0539-455c-9b98-4c49e0a64639	2026-02-06 05:27:08+00	2026-02-06 05:34:37+00	Mask_Fields	5	https	mocktarget.apigee.net	443	/json	60000	60000	60000	\N	\N	\N	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	\N
ed1f3298-55d7-4a0c-a157-1fd01771b62d	2026-02-11 07:37:12+00	2026-02-11 07:42:45+00	mock-json-service	5	https	mocktarget.apigee.net	443	/json	60000	60000	60000	\N	\N	\N	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	\N
dd7e10d5-3742-4eb7-8f13-4b8b60852d6d	2026-02-12 06:28:14+00	2026-02-12 06:28:14+00	partner-data-service	5	https	mocktarget.apigee.net	443	/json	60000	60000	60000	\N	\N	\N	\N	\N	00b2c6cc-ac81-44d8-b3d4-5c764f851be1	t	\N
\.


--
-- Data for Name: session_metadatas; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.session_metadatas (id, session_id, sid, subject, audience, created_at) FROM stdin;
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.sessions (id, session_id, expires, data, created_at, ttl) FROM stdin;
\.


--
-- Data for Name: sm_vaults; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.sm_vaults (id, ws_id, prefix, name, description, config, created_at, updated_at, tags) FROM stdin;
\.


--
-- Data for Name: snis; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.snis (id, created_at, name, certificate_id, tags, ws_id, updated_at) FROM stdin;
\.


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.tags (entity_id, entity_name, tags) FROM stdin;
b2bc2d19-3ff1-41d8-8811-6b1ca8c99c76	routes	{}
9a7fc34b-3803-4d5f-ac20-809c48347736	routes	{}
f3c10206-5c8b-47d8-bbb3-328be6a10e9e	consumers	\N
27af21f0-f241-4da1-9bd4-770e67f948b5	keyauth_credentials	\N
ae4e19df-4111-4b78-9c1e-8c72a3ae66a6	consumers	\N
82adb20e-474c-4207-a06c-42529a70e29f	keyauth_credentials	\N
c50ae3b3-b50f-4862-b2f2-c615fb5db3c4	certificates	{"Demo Certificate"}
a92370b5-dd0d-4113-b748-578eaefd7f3d	certificates	\N
0483822a-c4a8-41c4-983c-5d3ec226844d	certificates	\N
874a51ac-e5ec-4895-9b2c-11ee1b159ddd	consumers	\N
6af1dc98-d71c-47fe-be75-83e3da4315c7	keyauth_credentials	\N
366cbae6-8d3c-452a-a1dc-62ff22739b04	plugins	\N
3a7c61f2-2609-4036-9301-6f05c237e3b6	plugins	\N
a96f38c4-ade9-45b1-847a-f17388d2cbdb	plugins	\N
12e9ebd6-c269-419d-a245-acce2d3e5f3e	plugins	\N
287b44dd-55fd-404c-abf8-4489ae678397	plugins	\N
2a1c8f23-4edb-478f-9cd4-c662ce2d905b	plugins	\N
45d2d8cb-02dd-47db-9be4-1395b926ee4c	plugins	\N
713cb4e3-3ec9-4ed1-8ef7-08a48e3f35f9	plugins	\N
22e95c7a-df7f-4370-9c6c-534469bf025f	routes	{}
ed1f3298-55d7-4a0c-a157-1fd01771b62d	services	\N
953d0329-2630-4681-b349-2cc2f69c1f20	consumers	{}
f4af315f-1fea-43f7-b42e-b9f7fbf4f6b6	consumers	\N
66cc543c-7a4c-43f1-b2dd-dc5f757b1518	keyauth_credentials	\N
530ed47f-f1b3-41af-a1bd-2669c090eb78	consumers	\N
59352579-530e-4e55-8262-75796267cd5e	keyauth_credentials	\N
6ed6f33f-680d-4c05-adb0-2ef4d7863bfb	certificates	\N
c69a29b4-0762-441d-a0ca-a81d5db45e7c	certificates	{Certi12527}
de74e47f-0361-41fe-91a0-8c3b020b92ad	certificates	{CertiFinalworking}
1269a6e6-7e24-451a-9fdd-068a76e32f8c	basicauth_credentials	\N
2708ecf8-e7fd-495f-aaf2-3202ee8c38a2	basicauth_credentials	\N
c0f4c0db-ab25-4951-ac30-23713b69e6ad	plugins	\N
25018837-a876-403b-8a0d-e26ac2a21db8	consumers	\N
dc8c2e6f-bba9-4507-aa57-1dd9acee0800	keyauth_credentials	\N
44fac004-747b-43f5-ae1a-f22853c0814d	consumers	\N
5f81580f-8715-4d7f-9af4-f48e0c98d9c3	keyauth_credentials	\N
91897186-bd8f-4a81-aaa5-e4eea566db57	consumers	\N
adfdf0dd-f637-4b13-93cd-eff7da78d41e	keyauth_credentials	\N
41a382ff-8563-45e7-8e5d-d9e1996081ae	plugins	\N
0c0fbb7f-5599-4411-bda5-a1c3219e227e	acls	\N
67e988c1-467e-4655-a11d-e47f5691ba28	acls	\N
d5570971-60a5-4ccd-b328-e2f3eab181bd	basicauth_credentials	\N
69c3af62-1062-4d92-878a-d2197d3b8f7c	plugins	\N
2f07da5b-459e-4e37-b47f-fb868d8df899	plugins	\N
a9984dcb-3442-4ade-9718-4f1f975ee5c3	routes	{}
1085db0c-94db-48d9-a745-a293dac98ce8	plugins	\N
846764b3-121c-4c66-970f-7fc420d468d7	plugins	\N
0b0d6a42-e0ae-4400-a5f7-7c3226ddb27a	plugins	\N
dd7e10d5-3742-4eb7-8f13-4b8b60852d6d	services	\N
fb6473f4-57a8-4088-ba18-ea39c9d223ef	routes	{}
c77a91fe-259c-4ef6-860c-661e499e1d53	routes	{}
5c38bade-d74c-42c8-86e6-c2467dee16ff	plugins	\N
94e991b3-b956-4816-a7f4-f2f7d6327ad8	consumers	{}
a3fbc29f-1c1f-4f2b-bb9a-09c3df62bd9a	consumers	{}
6323d017-f366-46bb-925d-c504094eccc1	plugins	\N
e3c3d69b-667e-4d42-ac74-05632a393e7a	plugins	\N
55a10d41-6bbd-48ed-9c31-c92c72bbb6dd	plugins	\N
1ac8e6fd-ca24-42c3-a4f2-e33423ef09f2	plugins	\N
cf2ad923-7193-428f-a07c-7e0fd186fcc1	plugins	\N
5afdcc23-00f4-48d7-9ae5-c68619f0785d	keyauth_credentials	\N
ec1d3aaa-d62f-41ce-910e-c033015f687a	keyauth_credentials	\N
b3080e20-eb6d-46a5-b95d-b94682a1bc43	plugins	\N
2d7bf6aa-0539-455c-9b98-4c49e0a64639	services	\N
eb68f079-564a-4433-9ea5-2ff49c89fe53	plugins	\N
\.


--
-- Data for Name: targets; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.targets (id, created_at, upstream_id, target, weight, tags, ws_id, cache_key, updated_at, failover) FROM stdin;
\.


--
-- Data for Name: upstreams; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.upstreams (id, created_at, name, hash_on, hash_fallback, hash_on_header, hash_fallback_header, hash_on_cookie, hash_on_cookie_path, slots, healthchecks, tags, algorithm, host_header, client_certificate_id, ws_id, hash_on_query_arg, hash_fallback_query_arg, hash_on_uri_capture, hash_fallback_uri_capture, use_srv_name, updated_at, sticky_sessions_cookie, sticky_sessions_cookie_path) FROM stdin;
\.


--
-- Data for Name: vault_auth_vaults; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vault_auth_vaults (id, created_at, updated_at, name, protocol, host, port, mount, vault_token, kv) FROM stdin;
\.


--
-- Data for Name: vaults; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vaults (id, created_at, updated_at, name, protocol, host, port, mount, vault_token) FROM stdin;
\.


--
-- Data for Name: vitals_code_classes_by_cluster; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_code_classes_by_cluster (code_class, at, duration, count) FROM stdin;
\.


--
-- Data for Name: vitals_code_classes_by_workspace; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_code_classes_by_workspace (workspace_id, code_class, at, duration, count) FROM stdin;
\.


--
-- Data for Name: vitals_codes_by_consumer_route; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_codes_by_consumer_route (consumer_id, service_id, route_id, code, at, duration, count) FROM stdin;
\.


--
-- Data for Name: vitals_codes_by_route; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_codes_by_route (service_id, route_id, code, at, duration, count) FROM stdin;
\.


--
-- Data for Name: vitals_locks; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_locks (key, expiry) FROM stdin;
delete_status_codes	\N
\.


--
-- Data for Name: vitals_node_meta; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_node_meta (node_id, first_report, last_report, hostname) FROM stdin;
\.


--
-- Data for Name: vitals_stats_days; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_stats_days (node_id, at, l2_hit, l2_miss, plat_min, plat_max, ulat_min, ulat_max, requests, plat_count, plat_total, ulat_count, ulat_total) FROM stdin;
\.


--
-- Data for Name: vitals_stats_hours; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_stats_hours (at, l2_hit, l2_miss, plat_min, plat_max) FROM stdin;
\.


--
-- Data for Name: vitals_stats_minutes; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_stats_minutes (node_id, at, l2_hit, l2_miss, plat_min, plat_max, ulat_min, ulat_max, requests, plat_count, plat_total, ulat_count, ulat_total) FROM stdin;
\.


--
-- Data for Name: vitals_stats_seconds; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.vitals_stats_seconds (node_id, at, l2_hit, l2_miss, plat_min, plat_max, ulat_min, ulat_max, requests, plat_count, plat_total, ulat_count, ulat_total) FROM stdin;
\.


--
-- Data for Name: workspace_entities; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.workspace_entities (workspace_id, workspace_name, entity_id, entity_type, unique_field_name, unique_field_value) FROM stdin;
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	default	e5ef101f-34d2-40db-87ae-d68546c5ccd5	rbac_roles	id	e5ef101f-34d2-40db-87ae-d68546c5ccd5
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	default	e5ef101f-34d2-40db-87ae-d68546c5ccd5	rbac_roles	name	default:read-only
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	default	786b4013-db86-47d2-8245-7573b31d0698	rbac_roles	id	786b4013-db86-47d2-8245-7573b31d0698
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	default	786b4013-db86-47d2-8245-7573b31d0698	rbac_roles	name	default:admin
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	default	de060e80-106f-4a0d-9e02-2120eae36985	rbac_roles	id	de060e80-106f-4a0d-9e02-2120eae36985
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	default	de060e80-106f-4a0d-9e02-2120eae36985	rbac_roles	name	default:super-admin
\.


--
-- Data for Name: workspace_entity_counters; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.workspace_entity_counters (workspace_id, entity_type, count) FROM stdin;
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	rbac_roles	3
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	basicauth_credentials	3
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	acls	2
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	services	3
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	certificates	6
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	routes	6
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	plugins	23
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	consumers	11
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	keyauth_credentials	10
\.


--
-- Data for Name: workspaces; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.workspaces (id, name, comment, created_at, meta, config, updated_at) FROM stdin;
00b2c6cc-ac81-44d8-b3d4-5c764f851be1	default	\N	2026-01-14 11:06:12+00	\N	\N	2026-01-14 11:06:12+00
\.


--
-- Data for Name: ws_migrations_backup; Type: TABLE DATA; Schema: public; Owner: kong
--

COPY public.ws_migrations_backup (entity_type, entity_id, unique_field_name, unique_field_value, created_at) FROM stdin;
\.


--
-- Name: clustering_rpc_requests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kong
--

SELECT pg_catalog.setval('public.clustering_rpc_requests_id_seq', 1, false);


--
-- Name: clustering_sync_version_version_seq; Type: SEQUENCE SET; Schema: public; Owner: kong
--

SELECT pg_catalog.setval('public.clustering_sync_version_version_seq', 1, false);


--
-- Name: ace_auth_strategies ace_auth_strategies_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_auth_strategies
    ADD CONSTRAINT ace_auth_strategies_pkey PRIMARY KEY (id);


--
-- Name: ace_credentials ace_credentials_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_credentials
    ADD CONSTRAINT ace_credentials_cache_key_key UNIQUE (cache_key);


--
-- Name: ace_credentials ace_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_credentials
    ADD CONSTRAINT ace_credentials_pkey PRIMARY KEY (id);


--
-- Name: ace_operation_groups_credentials ace_operation_groups_credentials_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_credentials
    ADD CONSTRAINT ace_operation_groups_credentials_cache_key_key UNIQUE (cache_key);


--
-- Name: ace_operation_groups_credentials ace_operation_groups_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_credentials
    ADD CONSTRAINT ace_operation_groups_credentials_pkey PRIMARY KEY (id);


--
-- Name: ace_operation_groups_operations ace_operation_groups_operations_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_operations
    ADD CONSTRAINT ace_operation_groups_operations_cache_key_key UNIQUE (cache_key);


--
-- Name: ace_operation_groups_operations ace_operation_groups_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_operations
    ADD CONSTRAINT ace_operation_groups_operations_pkey PRIMARY KEY (id);


--
-- Name: ace_operation_groups ace_operation_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups
    ADD CONSTRAINT ace_operation_groups_pkey PRIMARY KEY (id);


--
-- Name: ace_operations ace_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operations
    ADD CONSTRAINT ace_operations_pkey PRIMARY KEY (id);


--
-- Name: acls acls_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.acls
    ADD CONSTRAINT acls_cache_key_key UNIQUE (cache_key);


--
-- Name: acls acls_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.acls
    ADD CONSTRAINT acls_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: acls acls_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.acls
    ADD CONSTRAINT acls_pkey PRIMARY KEY (id);


--
-- Name: acme_storage acme_storage_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.acme_storage
    ADD CONSTRAINT acme_storage_key_key UNIQUE (key);


--
-- Name: acme_storage acme_storage_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.acme_storage
    ADD CONSTRAINT acme_storage_pkey PRIMARY KEY (id);


--
-- Name: admins admins_custom_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_custom_id_key UNIQUE (custom_id);


--
-- Name: admins admins_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_pkey PRIMARY KEY (id);


--
-- Name: admins admins_username_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_username_key UNIQUE (username);


--
-- Name: application_instances application_instances_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.application_instances
    ADD CONSTRAINT application_instances_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: application_instances application_instances_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.application_instances
    ADD CONSTRAINT application_instances_pkey PRIMARY KEY (id);


--
-- Name: application_instances application_instances_ws_id_composite_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.application_instances
    ADD CONSTRAINT application_instances_ws_id_composite_id_unique UNIQUE (ws_id, composite_id);


--
-- Name: applications applications_custom_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_custom_id_key UNIQUE (custom_id);


--
-- Name: applications applications_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: applications applications_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_pkey PRIMARY KEY (id);


--
-- Name: audit_objects audit_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.audit_objects
    ADD CONSTRAINT audit_objects_pkey PRIMARY KEY (id);


--
-- Name: audit_requests audit_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.audit_requests
    ADD CONSTRAINT audit_requests_pkey PRIMARY KEY (request_id);


--
-- Name: basicauth_credentials basicauth_credentials_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.basicauth_credentials
    ADD CONSTRAINT basicauth_credentials_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: basicauth_credentials basicauth_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.basicauth_credentials
    ADD CONSTRAINT basicauth_credentials_pkey PRIMARY KEY (id);


--
-- Name: basicauth_credentials basicauth_credentials_ws_id_username_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.basicauth_credentials
    ADD CONSTRAINT basicauth_credentials_ws_id_username_unique UNIQUE (ws_id, username);


--
-- Name: ca_certificates ca_certificates_cert_digest_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ca_certificates
    ADD CONSTRAINT ca_certificates_cert_digest_key UNIQUE (cert_digest);


--
-- Name: ca_certificates ca_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ca_certificates
    ADD CONSTRAINT ca_certificates_pkey PRIMARY KEY (id);


--
-- Name: certificates certificates_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: certificates certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);


--
-- Name: cluster_events cluster_events_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.cluster_events
    ADD CONSTRAINT cluster_events_pkey PRIMARY KEY (id);


--
-- Name: clustering_data_planes clustering_data_planes_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.clustering_data_planes
    ADD CONSTRAINT clustering_data_planes_pkey PRIMARY KEY (id);


--
-- Name: clustering_rpc_requests clustering_rpc_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.clustering_rpc_requests
    ADD CONSTRAINT clustering_rpc_requests_pkey PRIMARY KEY (id);


--
-- Name: clustering_sync_lock clustering_sync_lock_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.clustering_sync_lock
    ADD CONSTRAINT clustering_sync_lock_pkey PRIMARY KEY (id);


--
-- Name: clustering_sync_version clustering_sync_version_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.clustering_sync_version
    ADD CONSTRAINT clustering_sync_version_pkey PRIMARY KEY (version);


--
-- Name: consumer_group_consumers consumer_group_consumers_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_consumers
    ADD CONSTRAINT consumer_group_consumers_cache_key_key UNIQUE (cache_key);


--
-- Name: consumer_group_consumers consumer_group_consumers_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_consumers
    ADD CONSTRAINT consumer_group_consumers_pkey PRIMARY KEY (consumer_group_id, consumer_id);


--
-- Name: consumer_group_plugins consumer_group_plugins_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_plugins
    ADD CONSTRAINT consumer_group_plugins_cache_key_key UNIQUE (cache_key);


--
-- Name: consumer_group_plugins consumer_group_plugins_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_plugins
    ADD CONSTRAINT consumer_group_plugins_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: consumer_group_plugins consumer_group_plugins_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_plugins
    ADD CONSTRAINT consumer_group_plugins_pkey PRIMARY KEY (id);


--
-- Name: consumer_groups consumer_groups_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_groups
    ADD CONSTRAINT consumer_groups_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: consumer_groups consumer_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_groups
    ADD CONSTRAINT consumer_groups_pkey PRIMARY KEY (id);


--
-- Name: consumer_groups consumer_groups_ws_id_name_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_groups
    ADD CONSTRAINT consumer_groups_ws_id_name_unique UNIQUE (ws_id, name);


--
-- Name: consumer_reset_secrets consumer_reset_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_reset_secrets
    ADD CONSTRAINT consumer_reset_secrets_pkey PRIMARY KEY (id);


--
-- Name: consumers consumers_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumers
    ADD CONSTRAINT consumers_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: consumers consumers_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumers
    ADD CONSTRAINT consumers_pkey PRIMARY KEY (id);


--
-- Name: consumers consumers_ws_id_custom_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumers
    ADD CONSTRAINT consumers_ws_id_custom_id_unique UNIQUE (ws_id, custom_id);


--
-- Name: consumers consumers_ws_id_username_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumers
    ADD CONSTRAINT consumers_ws_id_username_unique UNIQUE (ws_id, username);


--
-- Name: credentials credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);


--
-- Name: custom_plugins custom_plugins_id_ws_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.custom_plugins
    ADD CONSTRAINT custom_plugins_id_ws_id_key UNIQUE (id, ws_id);


--
-- Name: custom_plugins custom_plugins_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.custom_plugins
    ADD CONSTRAINT custom_plugins_name_key UNIQUE (name);


--
-- Name: custom_plugins custom_plugins_name_ws_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.custom_plugins
    ADD CONSTRAINT custom_plugins_name_ws_id_key UNIQUE (name, ws_id);


--
-- Name: custom_plugins custom_plugins_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.custom_plugins
    ADD CONSTRAINT custom_plugins_pkey PRIMARY KEY (id);


--
-- Name: degraphql_routes degraphql_routes_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.degraphql_routes
    ADD CONSTRAINT degraphql_routes_pkey PRIMARY KEY (id);


--
-- Name: developers developers_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.developers
    ADD CONSTRAINT developers_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: developers developers_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.developers
    ADD CONSTRAINT developers_pkey PRIMARY KEY (id);


--
-- Name: developers developers_ws_id_custom_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.developers
    ADD CONSTRAINT developers_ws_id_custom_id_unique UNIQUE (ws_id, custom_id);


--
-- Name: developers developers_ws_id_email_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.developers
    ADD CONSTRAINT developers_ws_id_email_unique UNIQUE (ws_id, email);


--
-- Name: document_objects document_objects_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.document_objects
    ADD CONSTRAINT document_objects_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: document_objects document_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.document_objects
    ADD CONSTRAINT document_objects_pkey PRIMARY KEY (id);


--
-- Name: document_objects document_objects_ws_id_path_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.document_objects
    ADD CONSTRAINT document_objects_ws_id_path_unique UNIQUE (ws_id, path);


--
-- Name: event_hooks event_hooks_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.event_hooks
    ADD CONSTRAINT event_hooks_id_key UNIQUE (id);


--
-- Name: files files_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: files files_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_pkey PRIMARY KEY (id);


--
-- Name: files files_ws_id_path_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_ws_id_path_unique UNIQUE (ws_id, path);


--
-- Name: graphql_ratelimiting_advanced_cost_decoration graphql_ratelimiting_advanced_cost_decoration_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.graphql_ratelimiting_advanced_cost_decoration
    ADD CONSTRAINT graphql_ratelimiting_advanced_cost_decoration_pkey PRIMARY KEY (id);


--
-- Name: group_rbac_roles group_rbac_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.group_rbac_roles
    ADD CONSTRAINT group_rbac_roles_pkey PRIMARY KEY (group_id, rbac_role_id);


--
-- Name: groups groups_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_name_key UNIQUE (name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: header_cert_auth_credentials header_cert_auth_credentials_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.header_cert_auth_credentials
    ADD CONSTRAINT header_cert_auth_credentials_cache_key_key UNIQUE (cache_key);


--
-- Name: header_cert_auth_credentials header_cert_auth_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.header_cert_auth_credentials
    ADD CONSTRAINT header_cert_auth_credentials_pkey PRIMARY KEY (id);


--
-- Name: hmacauth_credentials hmacauth_credentials_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.hmacauth_credentials
    ADD CONSTRAINT hmacauth_credentials_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: hmacauth_credentials hmacauth_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.hmacauth_credentials
    ADD CONSTRAINT hmacauth_credentials_pkey PRIMARY KEY (id);


--
-- Name: hmacauth_credentials hmacauth_credentials_ws_id_username_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.hmacauth_credentials
    ADD CONSTRAINT hmacauth_credentials_ws_id_username_unique UNIQUE (ws_id, username);


--
-- Name: jwt_secrets jwt_secrets_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.jwt_secrets
    ADD CONSTRAINT jwt_secrets_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: jwt_secrets jwt_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.jwt_secrets
    ADD CONSTRAINT jwt_secrets_pkey PRIMARY KEY (id);


--
-- Name: jwt_secrets jwt_secrets_ws_id_key_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.jwt_secrets
    ADD CONSTRAINT jwt_secrets_ws_id_key_unique UNIQUE (ws_id, key);


--
-- Name: jwt_signer_jwks jwt_signer_jwks_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.jwt_signer_jwks
    ADD CONSTRAINT jwt_signer_jwks_name_key UNIQUE (name);


--
-- Name: jwt_signer_jwks jwt_signer_jwks_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.jwt_signer_jwks
    ADD CONSTRAINT jwt_signer_jwks_pkey PRIMARY KEY (id);


--
-- Name: key_sets key_sets_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.key_sets
    ADD CONSTRAINT key_sets_name_key UNIQUE (name);


--
-- Name: key_sets key_sets_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.key_sets
    ADD CONSTRAINT key_sets_pkey PRIMARY KEY (id);


--
-- Name: keyauth_credentials keyauth_credentials_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_credentials
    ADD CONSTRAINT keyauth_credentials_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: keyauth_credentials keyauth_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_credentials
    ADD CONSTRAINT keyauth_credentials_pkey PRIMARY KEY (id);


--
-- Name: keyauth_credentials keyauth_credentials_ws_id_key_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_credentials
    ADD CONSTRAINT keyauth_credentials_ws_id_key_unique UNIQUE (ws_id, key);


--
-- Name: keyauth_enc_credentials keyauth_enc_credentials_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_enc_credentials
    ADD CONSTRAINT keyauth_enc_credentials_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: keyauth_enc_credentials keyauth_enc_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_enc_credentials
    ADD CONSTRAINT keyauth_enc_credentials_pkey PRIMARY KEY (id);


--
-- Name: keyauth_enc_credentials keyauth_enc_credentials_ws_id_key_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_enc_credentials
    ADD CONSTRAINT keyauth_enc_credentials_ws_id_key_unique UNIQUE (ws_id, key);


--
-- Name: keyring_keys keyring_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyring_keys
    ADD CONSTRAINT keyring_keys_pkey PRIMARY KEY (id);


--
-- Name: keyring_meta keyring_meta_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyring_meta
    ADD CONSTRAINT keyring_meta_pkey PRIMARY KEY (id);


--
-- Name: keys keys_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_cache_key_key UNIQUE (cache_key);


--
-- Name: keys keys_kid_set_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_kid_set_id_key UNIQUE (kid, set_id);


--
-- Name: keys keys_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_name_key UNIQUE (name);


--
-- Name: keys keys_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_pkey PRIMARY KEY (id);


--
-- Name: keys keys_x5t_set_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_x5t_set_id_unique UNIQUE (x5t, set_id);


--
-- Name: konnect_applications konnect_applications_client_id_ws_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.konnect_applications
    ADD CONSTRAINT konnect_applications_client_id_ws_id_key UNIQUE (client_id, ws_id);


--
-- Name: konnect_applications konnect_applications_id_ws_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.konnect_applications
    ADD CONSTRAINT konnect_applications_id_ws_id_key UNIQUE (id, ws_id);


--
-- Name: konnect_applications konnect_applications_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.konnect_applications
    ADD CONSTRAINT konnect_applications_pkey PRIMARY KEY (id);


--
-- Name: legacy_files legacy_files_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.legacy_files
    ADD CONSTRAINT legacy_files_name_key UNIQUE (name);


--
-- Name: legacy_files legacy_files_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.legacy_files
    ADD CONSTRAINT legacy_files_pkey PRIMARY KEY (id);


--
-- Name: license_llm_data license_llm_data_model_name_year_month_day_hour_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.license_llm_data
    ADD CONSTRAINT license_llm_data_model_name_year_month_day_hour_key UNIQUE (model_name, year, month, day, hour);


--
-- Name: licenses licenses_checksum_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_checksum_key UNIQUE (checksum);


--
-- Name: licenses licenses_payload_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_payload_key UNIQUE (payload);


--
-- Name: licenses licenses_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_pkey PRIMARY KEY (id);


--
-- Name: locks locks_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.locks
    ADD CONSTRAINT locks_pkey PRIMARY KEY (key);


--
-- Name: login_attempts login_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.login_attempts
    ADD CONSTRAINT login_attempts_pkey PRIMARY KEY (consumer_id, attempt_type);


--
-- Name: mtls_auth_credentials mtls_auth_credentials_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.mtls_auth_credentials
    ADD CONSTRAINT mtls_auth_credentials_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: mtls_auth_credentials mtls_auth_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.mtls_auth_credentials
    ADD CONSTRAINT mtls_auth_credentials_pkey PRIMARY KEY (id);


--
-- Name: mtls_auth_credentials mtls_auth_credentials_ws_id_cache_key_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.mtls_auth_credentials
    ADD CONSTRAINT mtls_auth_credentials_ws_id_cache_key_unique UNIQUE (ws_id, cache_key);


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_pkey PRIMARY KEY (id);


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_ws_id_code_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_ws_id_code_unique UNIQUE (ws_id, code);


--
-- Name: oauth2_credentials oauth2_credentials_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_credentials
    ADD CONSTRAINT oauth2_credentials_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: oauth2_credentials oauth2_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_credentials
    ADD CONSTRAINT oauth2_credentials_pkey PRIMARY KEY (id);


--
-- Name: oauth2_credentials oauth2_credentials_ws_id_client_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_credentials
    ADD CONSTRAINT oauth2_credentials_ws_id_client_id_unique UNIQUE (ws_id, client_id);


--
-- Name: oauth2_tokens oauth2_tokens_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_tokens
    ADD CONSTRAINT oauth2_tokens_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: oauth2_tokens oauth2_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_tokens
    ADD CONSTRAINT oauth2_tokens_pkey PRIMARY KEY (id);


--
-- Name: oauth2_tokens oauth2_tokens_ws_id_access_token_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_tokens
    ADD CONSTRAINT oauth2_tokens_ws_id_access_token_unique UNIQUE (ws_id, access_token);


--
-- Name: oauth2_tokens oauth2_tokens_ws_id_refresh_token_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_tokens
    ADD CONSTRAINT oauth2_tokens_ws_id_refresh_token_unique UNIQUE (ws_id, refresh_token);


--
-- Name: oic_issuers oic_issuers_issuer_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oic_issuers
    ADD CONSTRAINT oic_issuers_issuer_key UNIQUE (issuer);


--
-- Name: oic_issuers oic_issuers_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oic_issuers
    ADD CONSTRAINT oic_issuers_pkey PRIMARY KEY (id);


--
-- Name: oic_jwks oic_jwks_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oic_jwks
    ADD CONSTRAINT oic_jwks_pkey PRIMARY KEY (id);


--
-- Name: parameters parameters_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.parameters
    ADD CONSTRAINT parameters_pkey PRIMARY KEY (key);


--
-- Name: partials partials_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.partials
    ADD CONSTRAINT partials_id_key UNIQUE (id);


--
-- Name: plugins plugins_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_cache_key_key UNIQUE (cache_key);


--
-- Name: plugins plugins_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: plugins_partials plugins_partials_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins_partials
    ADD CONSTRAINT plugins_partials_id_key UNIQUE (id);


--
-- Name: plugins plugins_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_pkey PRIMARY KEY (id);


--
-- Name: plugins plugins_ws_id_instance_name_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_ws_id_instance_name_unique UNIQUE (ws_id, instance_name);


--
-- Name: ratelimiting_metrics ratelimiting_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ratelimiting_metrics
    ADD CONSTRAINT ratelimiting_metrics_pkey PRIMARY KEY (identifier, period, period_date, service_id, route_id);


--
-- Name: rbac_role_endpoints rbac_role_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_role_endpoints
    ADD CONSTRAINT rbac_role_endpoints_pkey PRIMARY KEY (role_id, workspace, endpoint);


--
-- Name: rbac_role_entities rbac_role_entities_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_role_entities
    ADD CONSTRAINT rbac_role_entities_pkey PRIMARY KEY (role_id, entity_id);


--
-- Name: rbac_roles rbac_roles_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_roles
    ADD CONSTRAINT rbac_roles_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: rbac_roles rbac_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_roles
    ADD CONSTRAINT rbac_roles_pkey PRIMARY KEY (id);


--
-- Name: rbac_roles rbac_roles_ws_id_name_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_roles
    ADD CONSTRAINT rbac_roles_ws_id_name_unique UNIQUE (ws_id, name);


--
-- Name: rbac_user_groups rbac_user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_user_groups
    ADD CONSTRAINT rbac_user_groups_pkey PRIMARY KEY (user_id, group_id);


--
-- Name: rbac_user_roles rbac_user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_user_roles
    ADD CONSTRAINT rbac_user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: rbac_users rbac_users_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_users
    ADD CONSTRAINT rbac_users_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: rbac_users rbac_users_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_users
    ADD CONSTRAINT rbac_users_pkey PRIMARY KEY (id);


--
-- Name: rbac_users rbac_users_user_token_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_users
    ADD CONSTRAINT rbac_users_user_token_key UNIQUE (user_token);


--
-- Name: rbac_users rbac_users_ws_id_name_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_users
    ADD CONSTRAINT rbac_users_ws_id_name_unique UNIQUE (ws_id, name);


--
-- Name: response_ratelimiting_metrics response_ratelimiting_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.response_ratelimiting_metrics
    ADD CONSTRAINT response_ratelimiting_metrics_pkey PRIMARY KEY (identifier, period, period_date, service_id, route_id);


--
-- Name: rl_counters rl_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rl_counters
    ADD CONSTRAINT rl_counters_pkey PRIMARY KEY (key, namespace, window_start, window_size);


--
-- Name: routes routes_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.routes
    ADD CONSTRAINT routes_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: routes routes_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.routes
    ADD CONSTRAINT routes_pkey PRIMARY KEY (id);


--
-- Name: routes routes_ws_id_name_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.routes
    ADD CONSTRAINT routes_ws_id_name_unique UNIQUE (ws_id, name);


--
-- Name: schema_meta schema_meta_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.schema_meta
    ADD CONSTRAINT schema_meta_pkey PRIMARY KEY (key, subsystem);


--
-- Name: services services_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);


--
-- Name: services services_ws_id_name_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_ws_id_name_unique UNIQUE (ws_id, name);


--
-- Name: session_metadatas session_metadatas_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.session_metadatas
    ADD CONSTRAINT session_metadatas_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_session_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_session_id_key UNIQUE (session_id);


--
-- Name: sm_vaults sm_vaults_id_ws_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.sm_vaults
    ADD CONSTRAINT sm_vaults_id_ws_id_key UNIQUE (id, ws_id);


--
-- Name: sm_vaults sm_vaults_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.sm_vaults
    ADD CONSTRAINT sm_vaults_pkey PRIMARY KEY (id);


--
-- Name: sm_vaults sm_vaults_prefix_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.sm_vaults
    ADD CONSTRAINT sm_vaults_prefix_key UNIQUE (prefix);


--
-- Name: sm_vaults sm_vaults_prefix_ws_id_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.sm_vaults
    ADD CONSTRAINT sm_vaults_prefix_ws_id_key UNIQUE (prefix, ws_id);


--
-- Name: snis snis_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.snis
    ADD CONSTRAINT snis_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: snis snis_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.snis
    ADD CONSTRAINT snis_name_key UNIQUE (name);


--
-- Name: snis snis_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.snis
    ADD CONSTRAINT snis_pkey PRIMARY KEY (id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (entity_id);


--
-- Name: targets targets_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_cache_key_key UNIQUE (cache_key);


--
-- Name: targets targets_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: targets targets_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (id);


--
-- Name: upstreams upstreams_id_ws_id_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_id_ws_id_unique UNIQUE (id, ws_id);


--
-- Name: upstreams upstreams_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_pkey PRIMARY KEY (id);


--
-- Name: upstreams upstreams_ws_id_name_unique; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_ws_id_name_unique UNIQUE (ws_id, name);


--
-- Name: vault_auth_vaults vault_auth_vaults_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vault_auth_vaults
    ADD CONSTRAINT vault_auth_vaults_name_key UNIQUE (name);


--
-- Name: vault_auth_vaults vault_auth_vaults_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vault_auth_vaults
    ADD CONSTRAINT vault_auth_vaults_pkey PRIMARY KEY (id);


--
-- Name: vaults vaults_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vaults
    ADD CONSTRAINT vaults_name_key UNIQUE (name);


--
-- Name: vaults vaults_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vaults
    ADD CONSTRAINT vaults_pkey PRIMARY KEY (id);


--
-- Name: vitals_code_classes_by_cluster vitals_code_classes_by_cluster_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_code_classes_by_cluster
    ADD CONSTRAINT vitals_code_classes_by_cluster_pkey PRIMARY KEY (code_class, duration, at);


--
-- Name: vitals_code_classes_by_workspace vitals_code_classes_by_workspace_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_code_classes_by_workspace
    ADD CONSTRAINT vitals_code_classes_by_workspace_pkey PRIMARY KEY (workspace_id, code_class, duration, at);


--
-- Name: vitals_codes_by_consumer_route vitals_codes_by_consumer_route_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_codes_by_consumer_route
    ADD CONSTRAINT vitals_codes_by_consumer_route_pkey PRIMARY KEY (consumer_id, route_id, code, duration, at);


--
-- Name: vitals_codes_by_route vitals_codes_by_route_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_codes_by_route
    ADD CONSTRAINT vitals_codes_by_route_pkey PRIMARY KEY (route_id, code, duration, at);


--
-- Name: vitals_locks vitals_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_locks
    ADD CONSTRAINT vitals_locks_pkey PRIMARY KEY (key);


--
-- Name: vitals_node_meta vitals_node_meta_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_node_meta
    ADD CONSTRAINT vitals_node_meta_pkey PRIMARY KEY (node_id);


--
-- Name: vitals_stats_days vitals_stats_days_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_stats_days
    ADD CONSTRAINT vitals_stats_days_pkey PRIMARY KEY (node_id, at);


--
-- Name: vitals_stats_hours vitals_stats_hours_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_stats_hours
    ADD CONSTRAINT vitals_stats_hours_pkey PRIMARY KEY (at);


--
-- Name: vitals_stats_minutes vitals_stats_minutes_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_stats_minutes
    ADD CONSTRAINT vitals_stats_minutes_pkey PRIMARY KEY (node_id, at);


--
-- Name: vitals_stats_seconds vitals_stats_seconds_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.vitals_stats_seconds
    ADD CONSTRAINT vitals_stats_seconds_pkey PRIMARY KEY (node_id, at);


--
-- Name: workspace_entities workspace_entities_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.workspace_entities
    ADD CONSTRAINT workspace_entities_pkey PRIMARY KEY (workspace_id, entity_id, unique_field_name);


--
-- Name: workspace_entity_counters workspace_entity_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.workspace_entity_counters
    ADD CONSTRAINT workspace_entity_counters_pkey PRIMARY KEY (workspace_id, entity_type);


--
-- Name: workspaces workspaces_name_key; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_name_key UNIQUE (name);


--
-- Name: workspaces workspaces_pkey; Type: CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_pkey PRIMARY KEY (id);


--
-- Name: ace_auth_strategies_ws_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_auth_strategies_ws_id_idx ON public.ace_auth_strategies USING btree (ws_id);


--
-- Name: ace_credentials_ws_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_credentials_ws_id_idx ON public.ace_credentials USING btree (ws_id);


--
-- Name: ace_operation_groups_credentials_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operation_groups_credentials_tags_idx ON public.ace_operation_groups_credentials USING gin (tags);


--
-- Name: ace_operation_groups_credentials_ws_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operation_groups_credentials_ws_id_idx ON public.ace_operation_groups_credentials USING btree (ws_id);


--
-- Name: ace_operation_groups_operations_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operation_groups_operations_tags_idx ON public.ace_operation_groups_operations USING gin (tags);


--
-- Name: ace_operation_groups_operations_ws_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operation_groups_operations_ws_id_idx ON public.ace_operation_groups_operations USING btree (ws_id);


--
-- Name: ace_operation_groups_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operation_groups_tags_idx ON public.ace_operation_groups USING gin (tags);


--
-- Name: ace_operation_groups_ws_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operation_groups_ws_id_idx ON public.ace_operation_groups USING btree (ws_id);


--
-- Name: ace_operations_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operations_tags_idx ON public.ace_operations USING gin (tags);


--
-- Name: ace_operations_ws_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ace_operations_ws_id_idx ON public.ace_operations USING btree (ws_id);


--
-- Name: acls_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX acls_consumer_id_idx ON public.acls USING btree (consumer_id);


--
-- Name: acls_group_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX acls_group_idx ON public.acls USING btree ("group");


--
-- Name: acls_tags_idex_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX acls_tags_idex_tags_idx ON public.acls USING gin (tags);


--
-- Name: acme_storage_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX acme_storage_ttl_idx ON public.acme_storage USING btree (ttl);


--
-- Name: applications_developer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX applications_developer_id_idx ON public.applications USING btree (developer_id);


--
-- Name: audit_objects_request_timestamp_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX audit_objects_request_timestamp_idx ON public.audit_objects USING btree (request_timestamp);


--
-- Name: audit_objects_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX audit_objects_ttl_idx ON public.audit_objects USING btree (ttl);


--
-- Name: audit_requests_request_timestamp_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX audit_requests_request_timestamp_idx ON public.audit_requests USING btree (request_timestamp);


--
-- Name: audit_requests_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX audit_requests_ttl_idx ON public.audit_requests USING btree (ttl);


--
-- Name: basicauth_brute_force_locks_key_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE UNIQUE INDEX basicauth_brute_force_locks_key_idx ON public.basicauth_brute_force_locks USING btree (key);


--
-- Name: basicauth_brute_force_metrics_key_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE UNIQUE INDEX basicauth_brute_force_metrics_key_idx ON public.basicauth_brute_force_metrics USING btree (key);


--
-- Name: basicauth_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX basicauth_consumer_id_idx ON public.basicauth_credentials USING btree (consumer_id);


--
-- Name: basicauth_tags_idex_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX basicauth_tags_idex_tags_idx ON public.basicauth_credentials USING gin (tags);


--
-- Name: certificates_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX certificates_tags_idx ON public.certificates USING gin (tags);


--
-- Name: cluster_events_at_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX cluster_events_at_idx ON public.cluster_events USING btree (at);


--
-- Name: cluster_events_channel_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX cluster_events_channel_idx ON public.cluster_events USING btree (channel);


--
-- Name: cluster_events_expire_at_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX cluster_events_expire_at_idx ON public.cluster_events USING btree (expire_at);


--
-- Name: clustering_data_planes_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX clustering_data_planes_ttl_idx ON public.clustering_data_planes USING btree (ttl);


--
-- Name: clustering_rpc_requests_node_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX clustering_rpc_requests_node_id_idx ON public.clustering_rpc_requests USING btree (node_id);


--
-- Name: clustering_sync_delta_version_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX clustering_sync_delta_version_idx ON public.clustering_sync_delta USING btree (version);


--
-- Name: consumer_group_consumers_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumer_group_consumers_consumer_id_idx ON public.consumer_group_consumers USING btree (consumer_id);


--
-- Name: consumer_group_consumers_group_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumer_group_consumers_group_id_idx ON public.consumer_group_consumers USING btree (consumer_group_id);


--
-- Name: consumer_group_plugins_group_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumer_group_plugins_group_id_idx ON public.consumer_group_plugins USING btree (consumer_group_id);


--
-- Name: consumer_group_plugins_plugin_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumer_group_plugins_plugin_name_idx ON public.consumer_group_plugins USING btree (name);


--
-- Name: consumer_groups_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumer_groups_name_idx ON public.consumer_groups USING btree (name);


--
-- Name: consumer_groups_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumer_groups_tags_idx ON public.consumer_groups USING gin (tags);


--
-- Name: consumer_reset_secrets_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumer_reset_secrets_consumer_id_idx ON public.consumer_reset_secrets USING btree (consumer_id);


--
-- Name: consumers_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumers_tags_idx ON public.consumers USING gin (tags);


--
-- Name: consumers_type_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumers_type_idx ON public.consumers USING btree (type);


--
-- Name: consumers_username_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX consumers_username_idx ON public.consumers USING btree (lower(username));


--
-- Name: credentials_consumer_id_plugin; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX credentials_consumer_id_plugin ON public.credentials USING btree (consumer_id, plugin);


--
-- Name: credentials_consumer_type; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX credentials_consumer_type ON public.credentials USING btree (consumer_id);


--
-- Name: custom_plugins_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX custom_plugins_tags_idx ON public.custom_plugins USING gin (tags);


--
-- Name: degraphql_routes_fkey_service; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX degraphql_routes_fkey_service ON public.degraphql_routes USING btree (service_id);


--
-- Name: developers_rbac_user_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX developers_rbac_user_id_idx ON public.developers USING btree (rbac_user_id);


--
-- Name: files_path_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX files_path_idx ON public.files USING btree (path);


--
-- Name: graphql_ratelimiting_advanced_cost_decoration_fkey_service; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX graphql_ratelimiting_advanced_cost_decoration_fkey_service ON public.graphql_ratelimiting_advanced_cost_decoration USING btree (service_id);


--
-- Name: groups_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX groups_name_idx ON public.groups USING btree (name);


--
-- Name: header_cert_auth_common_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX header_cert_auth_common_name_idx ON public.header_cert_auth_credentials USING btree (subject_name);


--
-- Name: header_cert_auth_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX header_cert_auth_consumer_id_idx ON public.header_cert_auth_credentials USING btree (consumer_id);


--
-- Name: header_cert_auth_credentials_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX header_cert_auth_credentials_tags_idx ON public.header_cert_auth_credentials USING gin (tags);


--
-- Name: hmacauth_credentials_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX hmacauth_credentials_consumer_id_idx ON public.hmacauth_credentials USING btree (consumer_id);


--
-- Name: hmacauth_tags_idex_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX hmacauth_tags_idex_tags_idx ON public.hmacauth_credentials USING gin (tags);


--
-- Name: jwt_secrets_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX jwt_secrets_consumer_id_idx ON public.jwt_secrets USING btree (consumer_id);


--
-- Name: jwt_secrets_secret_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX jwt_secrets_secret_idx ON public.jwt_secrets USING btree (secret);


--
-- Name: jwtsecrets_tags_idex_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX jwtsecrets_tags_idex_tags_idx ON public.jwt_secrets USING gin (tags);


--
-- Name: key_sets_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX key_sets_tags_idx ON public.key_sets USING gin (tags);


--
-- Name: keyauth_credentials_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keyauth_credentials_consumer_id_idx ON public.keyauth_credentials USING btree (consumer_id);


--
-- Name: keyauth_credentials_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keyauth_credentials_ttl_idx ON public.keyauth_credentials USING btree (ttl);


--
-- Name: keyauth_enc_credentials_consum; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keyauth_enc_credentials_consum ON public.keyauth_enc_credentials USING btree (consumer_id);


--
-- Name: keyauth_enc_credentials_ttl; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keyauth_enc_credentials_ttl ON public.keyauth_enc_credentials USING btree (ttl);


--
-- Name: keyauth_enc_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keyauth_enc_tags_idx ON public.keyauth_enc_credentials USING gin (tags);


--
-- Name: keyauth_tags_idex_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keyauth_tags_idex_tags_idx ON public.keyauth_credentials USING gin (tags);


--
-- Name: keys_fkey_key_sets; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keys_fkey_key_sets ON public.keys USING btree (set_id);


--
-- Name: keys_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX keys_tags_idx ON public.keys USING gin (tags);


--
-- Name: keys_x5t_with_null_set_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE UNIQUE INDEX keys_x5t_with_null_set_id_idx ON public.keys USING btree (x5t) WHERE (set_id IS NULL);


--
-- Name: konnect_applications_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX konnect_applications_tags_idx ON public.konnect_applications USING gin (tags);


--
-- Name: legacy_files_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX legacy_files_name_idx ON public.legacy_files USING btree (name);


--
-- Name: license_data_key_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE UNIQUE INDEX license_data_key_idx ON public.license_data USING btree (node_id, license_creation_date, year, month);


--
-- Name: license_llm_data_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX license_llm_data_idx ON public.license_llm_data USING btree (id, model_name, year, month, day, hour);


--
-- Name: locks_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX locks_ttl_idx ON public.locks USING btree (ttl);


--
-- Name: login_attempts_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX login_attempts_ttl_idx ON public.login_attempts USING btree (ttl);


--
-- Name: mtls_auth_common_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX mtls_auth_common_name_idx ON public.mtls_auth_credentials USING btree (subject_name);


--
-- Name: mtls_auth_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX mtls_auth_consumer_id_idx ON public.mtls_auth_credentials USING btree (consumer_id);


--
-- Name: mtls_auth_credentials_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX mtls_auth_credentials_tags_idx ON public.mtls_auth_credentials USING gin (tags);


--
-- Name: oauth2_authorization_codes_authenticated_userid_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_authorization_codes_authenticated_userid_idx ON public.oauth2_authorization_codes USING btree (authenticated_userid);


--
-- Name: oauth2_authorization_codes_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_authorization_codes_ttl_idx ON public.oauth2_authorization_codes USING btree (ttl);


--
-- Name: oauth2_authorization_credential_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_authorization_credential_id_idx ON public.oauth2_authorization_codes USING btree (credential_id);


--
-- Name: oauth2_authorization_service_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_authorization_service_id_idx ON public.oauth2_authorization_codes USING btree (service_id);


--
-- Name: oauth2_credentials_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_credentials_consumer_id_idx ON public.oauth2_credentials USING btree (consumer_id);


--
-- Name: oauth2_credentials_secret_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_credentials_secret_idx ON public.oauth2_credentials USING btree (client_secret);


--
-- Name: oauth2_credentials_tags_idex_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_credentials_tags_idex_tags_idx ON public.oauth2_credentials USING gin (tags);


--
-- Name: oauth2_tokens_authenticated_userid_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_tokens_authenticated_userid_idx ON public.oauth2_tokens USING btree (authenticated_userid);


--
-- Name: oauth2_tokens_credential_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_tokens_credential_id_idx ON public.oauth2_tokens USING btree (credential_id);


--
-- Name: oauth2_tokens_service_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_tokens_service_id_idx ON public.oauth2_tokens USING btree (service_id);


--
-- Name: oauth2_tokens_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX oauth2_tokens_ttl_idx ON public.oauth2_tokens USING btree (ttl);


--
-- Name: partials_name; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX partials_name ON public.partials USING btree (name);


--
-- Name: partials_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX partials_tags_idx ON public.partials USING gin (tags);


--
-- Name: partials_workspace_id; Type: INDEX; Schema: public; Owner: kong
--

CREATE UNIQUE INDEX partials_workspace_id ON public.partials USING btree (ws_id, id);


--
-- Name: partials_workspace_name; Type: INDEX; Schema: public; Owner: kong
--

CREATE UNIQUE INDEX partials_workspace_name ON public.partials USING btree (ws_id, name);


--
-- Name: plugins_consumer_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX plugins_consumer_id_idx ON public.plugins USING btree (consumer_id);


--
-- Name: plugins_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX plugins_name_idx ON public.plugins USING btree (name);


--
-- Name: plugins_partials_link; Type: INDEX; Schema: public; Owner: kong
--

CREATE UNIQUE INDEX plugins_partials_link ON public.plugins_partials USING btree (plugin_id, partial_id, path) WHERE (path IS NOT NULL);


--
-- Name: plugins_route_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX plugins_route_id_idx ON public.plugins USING btree (route_id);


--
-- Name: plugins_service_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX plugins_service_id_idx ON public.plugins USING btree (service_id);


--
-- Name: plugins_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX plugins_tags_idx ON public.plugins USING gin (tags);


--
-- Name: ratelimiting_metrics_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ratelimiting_metrics_idx ON public.ratelimiting_metrics USING btree (service_id, route_id, period_date, period);


--
-- Name: ratelimiting_metrics_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX ratelimiting_metrics_ttl_idx ON public.ratelimiting_metrics USING btree (ttl);


--
-- Name: rbac_role_default_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX rbac_role_default_idx ON public.rbac_roles USING btree (is_default);


--
-- Name: rbac_role_endpoints_role_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX rbac_role_endpoints_role_idx ON public.rbac_role_endpoints USING btree (role_id);


--
-- Name: rbac_role_entities_role_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX rbac_role_entities_role_idx ON public.rbac_role_entities USING btree (role_id);


--
-- Name: rbac_roles_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX rbac_roles_name_idx ON public.rbac_roles USING btree (name);


--
-- Name: rbac_token_ident_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX rbac_token_ident_idx ON public.rbac_users USING btree (user_token_ident);


--
-- Name: rbac_users_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX rbac_users_name_idx ON public.rbac_users USING btree (name);


--
-- Name: rbac_users_token_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX rbac_users_token_idx ON public.rbac_users USING btree (user_token);


--
-- Name: routes_service_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX routes_service_id_idx ON public.routes USING btree (service_id);


--
-- Name: routes_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX routes_tags_idx ON public.routes USING gin (tags);


--
-- Name: services_fkey_client_certificate; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX services_fkey_client_certificate ON public.services USING btree (client_certificate_id);


--
-- Name: services_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX services_tags_idx ON public.services USING gin (tags);


--
-- Name: session_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX session_id_idx ON public.session_metadatas USING btree (session_id);


--
-- Name: session_sessions_expires_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX session_sessions_expires_idx ON public.sessions USING btree (expires);


--
-- Name: sessions_ttl_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX sessions_ttl_idx ON public.sessions USING btree (ttl);


--
-- Name: sm_vaults_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX sm_vaults_tags_idx ON public.sm_vaults USING gin (tags);


--
-- Name: snis_certificate_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX snis_certificate_id_idx ON public.snis USING btree (certificate_id);


--
-- Name: snis_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX snis_tags_idx ON public.snis USING gin (tags);


--
-- Name: subject_audience_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX subject_audience_idx ON public.session_metadatas USING btree (subject, audience);


--
-- Name: sync_key_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX sync_key_idx ON public.rl_counters USING btree (namespace, window_start);


--
-- Name: tags_entity_name_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX tags_entity_name_idx ON public.tags USING btree (entity_name);


--
-- Name: tags_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX tags_tags_idx ON public.tags USING gin (tags);


--
-- Name: targets_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX targets_tags_idx ON public.targets USING gin (tags);


--
-- Name: targets_target_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX targets_target_idx ON public.targets USING btree (target);


--
-- Name: targets_upstream_id_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX targets_upstream_id_idx ON public.targets USING btree (upstream_id);


--
-- Name: upstreams_fkey_client_certificate; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX upstreams_fkey_client_certificate ON public.upstreams USING btree (client_certificate_id);


--
-- Name: upstreams_tags_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX upstreams_tags_idx ON public.upstreams USING gin (tags);


--
-- Name: vcbr_svc_ts_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX vcbr_svc_ts_idx ON public.vitals_codes_by_route USING btree (service_id, duration, at);


--
-- Name: workspace_entities_composite_idx; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX workspace_entities_composite_idx ON public.workspace_entities USING btree (workspace_id, entity_type, unique_field_name);


--
-- Name: workspace_entities_idx_entity_id; Type: INDEX; Schema: public; Owner: kong
--

CREATE INDEX workspace_entities_idx_entity_id ON public.workspace_entities USING btree (entity_id);


--
-- Name: ace_operation_groups_credentials ace_operation_groups_credentials_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER ace_operation_groups_credentials_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.ace_operation_groups_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: ace_operation_groups_operations ace_operation_groups_operations_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER ace_operation_groups_operations_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.ace_operation_groups_operations FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: ace_operation_groups ace_operation_groups_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER ace_operation_groups_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.ace_operation_groups FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: ace_operations ace_operations_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER ace_operations_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.ace_operations FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: acls acls_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER acls_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.acls FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: acme_storage acme_storage_ttl_delta_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER acme_storage_ttl_delta_trigger AFTER INSERT ON public.acme_storage FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows_and_gen_deltas('ttl', 'acme_storage', 'false');


--
-- Name: basicauth_brute_force_locks basicauth_brute_force_locks_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER basicauth_brute_force_locks_ttl_trigger AFTER INSERT ON public.basicauth_brute_force_locks FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('ttl');


--
-- Name: basicauth_brute_force_metrics basicauth_brute_force_metrics_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER basicauth_brute_force_metrics_ttl_trigger AFTER INSERT ON public.basicauth_brute_force_metrics FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('ttl');


--
-- Name: basicauth_credentials basicauth_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER basicauth_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.basicauth_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: ca_certificates ca_certificates_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER ca_certificates_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.ca_certificates FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: certificates certificates_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER certificates_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.certificates FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: cluster_events cluster_events_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER cluster_events_ttl_trigger AFTER INSERT ON public.cluster_events FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('expire_at');


--
-- Name: clustering_data_planes clustering_data_planes_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER clustering_data_planes_ttl_trigger AFTER INSERT ON public.clustering_data_planes FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('ttl');


--
-- Name: consumer_groups consumer_groups_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER consumer_groups_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.consumer_groups FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: consumers consumers_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER consumers_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.consumers FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: custom_plugins custom_plugins_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER custom_plugins_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.custom_plugins FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: header_cert_auth_credentials header_cert_auth_credentials_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER header_cert_auth_credentials_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.header_cert_auth_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: hmacauth_credentials hmacauth_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER hmacauth_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.hmacauth_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: jwt_secrets jwtsecrets_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER jwtsecrets_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.jwt_secrets FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: key_sets key_sets_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER key_sets_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.key_sets FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: keyauth_credentials keyauth_credentials_ttl_delta_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER keyauth_credentials_ttl_delta_trigger AFTER INSERT ON public.keyauth_credentials FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows_and_gen_deltas('ttl', 'keyauth_credentials', 'true');


--
-- Name: keyauth_enc_credentials keyauth_enc_credentials_ttl_delta_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER keyauth_enc_credentials_ttl_delta_trigger AFTER INSERT ON public.keyauth_enc_credentials FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows_and_gen_deltas('ttl', 'keyauth_enc_credentials', 'true');


--
-- Name: keyauth_enc_credentials keyauth_enc_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER keyauth_enc_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.keyauth_enc_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: keyauth_credentials keyauth_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER keyauth_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.keyauth_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: keys keys_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER keys_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.keys FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: konnect_applications konnect_applications_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER konnect_applications_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.konnect_applications FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: mtls_auth_credentials mtls_auth_credentials_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER mtls_auth_credentials_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.mtls_auth_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER oauth2_authorization_codes_ttl_trigger AFTER INSERT ON public.oauth2_authorization_codes FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('ttl');


--
-- Name: oauth2_credentials oauth2_credentials_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER oauth2_credentials_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.oauth2_credentials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: oauth2_tokens oauth2_tokens_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER oauth2_tokens_ttl_trigger AFTER INSERT ON public.oauth2_tokens FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('ttl');


--
-- Name: partials partials_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER partials_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.partials FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: plugins plugins_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER plugins_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.plugins FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: ratelimiting_metrics ratelimiting_metrics_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER ratelimiting_metrics_ttl_trigger AFTER INSERT ON public.ratelimiting_metrics FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('ttl');


--
-- Name: routes routes_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER routes_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.routes FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: services services_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER services_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.services FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: sessions sessions_ttl_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER sessions_ttl_trigger AFTER INSERT ON public.sessions FOR EACH STATEMENT EXECUTE FUNCTION public.batch_delete_expired_rows('ttl');


--
-- Name: sm_vaults sm_vaults_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER sm_vaults_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.sm_vaults FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: snis snis_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER snis_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.snis FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: targets targets_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER targets_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.targets FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: upstreams upstreams_sync_tags_trigger; Type: TRIGGER; Schema: public; Owner: kong
--

CREATE TRIGGER upstreams_sync_tags_trigger AFTER INSERT OR DELETE OR UPDATE OF tags ON public.upstreams FOR EACH ROW EXECUTE FUNCTION public.sync_tags();


--
-- Name: ace_auth_strategies ace_auth_strategies_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_auth_strategies
    ADD CONSTRAINT ace_auth_strategies_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: ace_credentials ace_credentials_auth_strategy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_credentials
    ADD CONSTRAINT ace_credentials_auth_strategy_id_fkey FOREIGN KEY (auth_strategy_id) REFERENCES public.ace_auth_strategies(id) ON DELETE CASCADE;


--
-- Name: ace_credentials ace_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_credentials
    ADD CONSTRAINT ace_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: ace_operation_groups_credentials ace_operation_groups_credentials_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_credentials
    ADD CONSTRAINT ace_operation_groups_credentials_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.ace_credentials(id) ON DELETE CASCADE;


--
-- Name: ace_operation_groups_credentials ace_operation_groups_credentials_operation_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_credentials
    ADD CONSTRAINT ace_operation_groups_credentials_operation_group_id_fkey FOREIGN KEY (operation_group_id) REFERENCES public.ace_operation_groups(id) ON DELETE CASCADE;


--
-- Name: ace_operation_groups_credentials ace_operation_groups_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_credentials
    ADD CONSTRAINT ace_operation_groups_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: ace_operation_groups_operations ace_operation_groups_operations_operation_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_operations
    ADD CONSTRAINT ace_operation_groups_operations_operation_group_id_fkey FOREIGN KEY (operation_group_id) REFERENCES public.ace_operation_groups(id) ON DELETE CASCADE;


--
-- Name: ace_operation_groups_operations ace_operation_groups_operations_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_operations
    ADD CONSTRAINT ace_operation_groups_operations_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES public.ace_operations(id) ON DELETE CASCADE;


--
-- Name: ace_operation_groups_operations ace_operation_groups_operations_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups_operations
    ADD CONSTRAINT ace_operation_groups_operations_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: ace_operation_groups ace_operation_groups_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operation_groups
    ADD CONSTRAINT ace_operation_groups_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: ace_operations ace_operations_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.ace_operations
    ADD CONSTRAINT ace_operations_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: acls acls_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.acls
    ADD CONSTRAINT acls_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id) ON DELETE CASCADE;


--
-- Name: acls acls_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.acls
    ADD CONSTRAINT acls_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: admins admins_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id);


--
-- Name: admins admins_rbac_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_rbac_user_id_fkey FOREIGN KEY (rbac_user_id) REFERENCES public.rbac_users(id);


--
-- Name: application_instances application_instances_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.application_instances
    ADD CONSTRAINT application_instances_application_id_fkey FOREIGN KEY (application_id, ws_id) REFERENCES public.applications(id, ws_id);


--
-- Name: application_instances application_instances_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.application_instances
    ADD CONSTRAINT application_instances_service_id_fkey FOREIGN KEY (service_id, ws_id) REFERENCES public.services(id, ws_id);


--
-- Name: application_instances application_instances_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.application_instances
    ADD CONSTRAINT application_instances_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: applications applications_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id);


--
-- Name: applications applications_developer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_developer_id_fkey FOREIGN KEY (developer_id, ws_id) REFERENCES public.developers(id, ws_id);


--
-- Name: applications applications_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: basicauth_credentials basicauth_credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.basicauth_credentials
    ADD CONSTRAINT basicauth_credentials_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id) ON DELETE CASCADE;


--
-- Name: basicauth_credentials basicauth_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.basicauth_credentials
    ADD CONSTRAINT basicauth_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: certificates certificates_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: clustering_sync_delta clustering_sync_delta_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.clustering_sync_delta
    ADD CONSTRAINT clustering_sync_delta_version_fkey FOREIGN KEY (version) REFERENCES public.clustering_sync_version(version) ON DELETE CASCADE;


--
-- Name: consumer_group_consumers consumer_group_consumers_consumer_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_consumers
    ADD CONSTRAINT consumer_group_consumers_consumer_group_id_fkey FOREIGN KEY (consumer_group_id) REFERENCES public.consumer_groups(id) ON DELETE CASCADE;


--
-- Name: consumer_group_consumers consumer_group_consumers_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_consumers
    ADD CONSTRAINT consumer_group_consumers_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id) ON DELETE CASCADE;


--
-- Name: consumer_group_plugins consumer_group_plugins_consumer_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_plugins
    ADD CONSTRAINT consumer_group_plugins_consumer_group_id_fkey FOREIGN KEY (consumer_group_id, ws_id) REFERENCES public.consumer_groups(id, ws_id) ON DELETE CASCADE;


--
-- Name: consumer_group_plugins consumer_group_plugins_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_group_plugins
    ADD CONSTRAINT consumer_group_plugins_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: consumer_groups consumer_groups_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_groups
    ADD CONSTRAINT consumer_groups_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: consumer_reset_secrets consumer_reset_secrets_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumer_reset_secrets
    ADD CONSTRAINT consumer_reset_secrets_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id) ON DELETE CASCADE;


--
-- Name: consumers consumers_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.consumers
    ADD CONSTRAINT consumers_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: credentials credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id) ON DELETE CASCADE;


--
-- Name: custom_plugins custom_plugins_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.custom_plugins
    ADD CONSTRAINT custom_plugins_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: degraphql_routes degraphql_routes_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.degraphql_routes
    ADD CONSTRAINT degraphql_routes_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.services(id) ON DELETE CASCADE;


--
-- Name: developers developers_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.developers
    ADD CONSTRAINT developers_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id);


--
-- Name: developers developers_rbac_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.developers
    ADD CONSTRAINT developers_rbac_user_id_fkey FOREIGN KEY (rbac_user_id, ws_id) REFERENCES public.rbac_users(id, ws_id);


--
-- Name: developers developers_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.developers
    ADD CONSTRAINT developers_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: document_objects document_objects_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.document_objects
    ADD CONSTRAINT document_objects_service_id_fkey FOREIGN KEY (service_id, ws_id) REFERENCES public.services(id, ws_id);


--
-- Name: document_objects document_objects_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.document_objects
    ADD CONSTRAINT document_objects_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: files files_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: graphql_ratelimiting_advanced_cost_decoration graphql_ratelimiting_advanced_cost_decoration_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.graphql_ratelimiting_advanced_cost_decoration
    ADD CONSTRAINT graphql_ratelimiting_advanced_cost_decoration_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.services(id) ON DELETE CASCADE;


--
-- Name: group_rbac_roles group_rbac_roles_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.group_rbac_roles
    ADD CONSTRAINT group_rbac_roles_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: group_rbac_roles group_rbac_roles_rbac_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.group_rbac_roles
    ADD CONSTRAINT group_rbac_roles_rbac_role_id_fkey FOREIGN KEY (rbac_role_id) REFERENCES public.rbac_roles(id) ON DELETE CASCADE;


--
-- Name: group_rbac_roles group_rbac_roles_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.group_rbac_roles
    ADD CONSTRAINT group_rbac_roles_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: header_cert_auth_credentials header_cert_auth_credentials_ca_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.header_cert_auth_credentials
    ADD CONSTRAINT header_cert_auth_credentials_ca_certificate_id_fkey FOREIGN KEY (ca_certificate_id) REFERENCES public.ca_certificates(id) ON DELETE CASCADE;


--
-- Name: header_cert_auth_credentials header_cert_auth_credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.header_cert_auth_credentials
    ADD CONSTRAINT header_cert_auth_credentials_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id) ON DELETE CASCADE;


--
-- Name: header_cert_auth_credentials header_cert_auth_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.header_cert_auth_credentials
    ADD CONSTRAINT header_cert_auth_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: hmacauth_credentials hmacauth_credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.hmacauth_credentials
    ADD CONSTRAINT hmacauth_credentials_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id) ON DELETE CASCADE;


--
-- Name: hmacauth_credentials hmacauth_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.hmacauth_credentials
    ADD CONSTRAINT hmacauth_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: jwt_secrets jwt_secrets_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.jwt_secrets
    ADD CONSTRAINT jwt_secrets_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id) ON DELETE CASCADE;


--
-- Name: jwt_secrets jwt_secrets_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.jwt_secrets
    ADD CONSTRAINT jwt_secrets_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: key_sets key_sets_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.key_sets
    ADD CONSTRAINT key_sets_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: keyauth_credentials keyauth_credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_credentials
    ADD CONSTRAINT keyauth_credentials_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id) ON DELETE CASCADE;


--
-- Name: keyauth_credentials keyauth_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_credentials
    ADD CONSTRAINT keyauth_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: keyauth_enc_credentials keyauth_enc_credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_enc_credentials
    ADD CONSTRAINT keyauth_enc_credentials_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id) ON DELETE CASCADE;


--
-- Name: keyauth_enc_credentials keyauth_enc_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keyauth_enc_credentials
    ADD CONSTRAINT keyauth_enc_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: keys keys_set_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_set_id_fkey FOREIGN KEY (set_id) REFERENCES public.key_sets(id) ON DELETE CASCADE;


--
-- Name: keys keys_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: konnect_applications konnect_applications_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.konnect_applications
    ADD CONSTRAINT konnect_applications_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: login_attempts login_attempts_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.login_attempts
    ADD CONSTRAINT login_attempts_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES public.consumers(id) ON DELETE CASCADE;


--
-- Name: mtls_auth_credentials mtls_auth_credentials_ca_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.mtls_auth_credentials
    ADD CONSTRAINT mtls_auth_credentials_ca_certificate_id_fkey FOREIGN KEY (ca_certificate_id) REFERENCES public.ca_certificates(id) ON DELETE CASCADE;


--
-- Name: mtls_auth_credentials mtls_auth_credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.mtls_auth_credentials
    ADD CONSTRAINT mtls_auth_credentials_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id) ON DELETE CASCADE;


--
-- Name: mtls_auth_credentials mtls_auth_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.mtls_auth_credentials
    ADD CONSTRAINT mtls_auth_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id);


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_credential_id_fkey FOREIGN KEY (credential_id, ws_id) REFERENCES public.oauth2_credentials(id, ws_id) ON DELETE CASCADE;


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.plugins(id) ON DELETE CASCADE;


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_service_id_fkey FOREIGN KEY (service_id, ws_id) REFERENCES public.services(id, ws_id) ON DELETE CASCADE;


--
-- Name: oauth2_authorization_codes oauth2_authorization_codes_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: oauth2_credentials oauth2_credentials_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_credentials
    ADD CONSTRAINT oauth2_credentials_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id) ON DELETE CASCADE;


--
-- Name: oauth2_credentials oauth2_credentials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_credentials
    ADD CONSTRAINT oauth2_credentials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: oauth2_tokens oauth2_tokens_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_tokens
    ADD CONSTRAINT oauth2_tokens_credential_id_fkey FOREIGN KEY (credential_id, ws_id) REFERENCES public.oauth2_credentials(id, ws_id) ON DELETE CASCADE;


--
-- Name: oauth2_tokens oauth2_tokens_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_tokens
    ADD CONSTRAINT oauth2_tokens_service_id_fkey FOREIGN KEY (service_id, ws_id) REFERENCES public.services(id, ws_id) ON DELETE CASCADE;


--
-- Name: oauth2_tokens oauth2_tokens_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.oauth2_tokens
    ADD CONSTRAINT oauth2_tokens_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: partials partials_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.partials
    ADD CONSTRAINT partials_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: plugins plugins_consumer_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_consumer_group_id_fkey FOREIGN KEY (consumer_group_id) REFERENCES public.consumer_groups(id) ON DELETE CASCADE;


--
-- Name: plugins plugins_consumer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_consumer_id_fkey FOREIGN KEY (consumer_id, ws_id) REFERENCES public.consumers(id, ws_id) ON DELETE CASCADE;


--
-- Name: plugins_partials plugins_partials_partial_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins_partials
    ADD CONSTRAINT plugins_partials_partial_id_fkey FOREIGN KEY (partial_id) REFERENCES public.partials(id) ON DELETE CASCADE;


--
-- Name: plugins_partials plugins_partials_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins_partials
    ADD CONSTRAINT plugins_partials_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.plugins(id) ON DELETE CASCADE;


--
-- Name: plugins plugins_route_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_route_id_fkey FOREIGN KEY (route_id, ws_id) REFERENCES public.routes(id, ws_id) ON DELETE CASCADE;


--
-- Name: plugins plugins_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_service_id_fkey FOREIGN KEY (service_id, ws_id) REFERENCES public.services(id, ws_id) ON DELETE CASCADE;


--
-- Name: plugins plugins_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.plugins
    ADD CONSTRAINT plugins_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: rbac_role_endpoints rbac_role_endpoints_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_role_endpoints
    ADD CONSTRAINT rbac_role_endpoints_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.rbac_roles(id) ON DELETE CASCADE;


--
-- Name: rbac_role_entities rbac_role_entities_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_role_entities
    ADD CONSTRAINT rbac_role_entities_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.rbac_roles(id) ON DELETE CASCADE;


--
-- Name: rbac_roles rbac_roles_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_roles
    ADD CONSTRAINT rbac_roles_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: rbac_user_groups rbac_user_groups_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_user_groups
    ADD CONSTRAINT rbac_user_groups_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: rbac_user_groups rbac_user_groups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_user_groups
    ADD CONSTRAINT rbac_user_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.rbac_users(id) ON DELETE CASCADE;


--
-- Name: rbac_user_roles rbac_user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_user_roles
    ADD CONSTRAINT rbac_user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.rbac_roles(id) ON DELETE CASCADE;


--
-- Name: rbac_user_roles rbac_user_roles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_user_roles
    ADD CONSTRAINT rbac_user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.rbac_users(id) ON DELETE CASCADE;


--
-- Name: rbac_users rbac_users_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.rbac_users
    ADD CONSTRAINT rbac_users_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: routes routes_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.routes
    ADD CONSTRAINT routes_service_id_fkey FOREIGN KEY (service_id, ws_id) REFERENCES public.services(id, ws_id);


--
-- Name: routes routes_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.routes
    ADD CONSTRAINT routes_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: services services_client_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_client_certificate_id_fkey FOREIGN KEY (client_certificate_id, ws_id) REFERENCES public.certificates(id, ws_id);


--
-- Name: services services_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: session_metadatas session_metadatas_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.session_metadatas
    ADD CONSTRAINT session_metadatas_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(id) ON DELETE CASCADE;


--
-- Name: sm_vaults sm_vaults_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.sm_vaults
    ADD CONSTRAINT sm_vaults_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: snis snis_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.snis
    ADD CONSTRAINT snis_certificate_id_fkey FOREIGN KEY (certificate_id, ws_id) REFERENCES public.certificates(id, ws_id);


--
-- Name: snis snis_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.snis
    ADD CONSTRAINT snis_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: targets targets_upstream_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_upstream_id_fkey FOREIGN KEY (upstream_id, ws_id) REFERENCES public.upstreams(id, ws_id) ON DELETE CASCADE;


--
-- Name: targets targets_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: upstreams upstreams_client_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_client_certificate_id_fkey FOREIGN KEY (client_certificate_id) REFERENCES public.certificates(id);


--
-- Name: upstreams upstreams_ws_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_ws_id_fkey FOREIGN KEY (ws_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_entity_counters workspace_entity_counters_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kong
--

ALTER TABLE ONLY public.workspace_entity_counters
    ADD CONSTRAINT workspace_entity_counters_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

GRANT ALL ON SCHEMA public TO kong;


--
-- PostgreSQL database dump complete
--

\unrestrict cR2wocwLRr4ds07076Olv5ORVGyja4AejC18mKIXkdPPVkrgYbm7TjBiHJIAdya

