-- SYNTHETIC test fixture of tests/rbac_upgrade_live.sh, scenario passwordless_admins: no real user, host or secret.
-- Full dump (schema and data, pg_dump --no-owner) of the database the pinned
-- redamon-webapp:rbac-7.7.2 startup list creates, plus seed/passwordless_admins.sql. Regenerate with
-- 'bash tests/rbac_upgrade_live.sh regen'; never edit by hand (README.md).
--
-- PostgreSQL database dump
--

\restrict 267p1R7KiyNeBe6mcSo6n35IlNf9y7chN9u8vwEYUDdKtIyDVh1XpoVhf8KdfmU

-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

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
-- Name: redamon_engagement_authorizations_append_only(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.redamon_engagement_authorizations_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
      BEGIN
        IF TG_OP = 'UPDATE' THEN
          RAISE EXCEPTION
            'engagement_authorizations is append-only: an authorization record cannot be '
            'changed after it is written. Record a new one instead; the history of what was '
            'authorized when is the point.'
            USING ERRCODE = 'restrict_violation';
        END IF;
        IF TG_OP = 'DELETE' THEN
          -- Deleting a project archives its records first and sets this flag for
          -- that transaction only. Any other DELETE is refused.
          IF current_setting('redamon.archiving_project', true) IS DISTINCT FROM OLD.project_id THEN
            RAISE EXCEPTION
              'engagement_authorizations is append-only: an authorization record cannot be '
              'deleted. Deleting the project archives them instead.'
              USING ERRCODE = 'restrict_violation';
          END IF;
          RETURN OLD;
        END IF;
        RETURN NEW;
      END;
      $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: act_as_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.act_as_audit (
    id text NOT NULL,
    admin_id text NOT NULL,
    target_user_id text NOT NULL,
    event text NOT NULL,
    source text DEFAULT 'api'::text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: api_key_rotation_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_key_rotation_configs (
    id text NOT NULL,
    user_id text NOT NULL,
    tool_name text NOT NULL,
    extra_keys text DEFAULT ''::text NOT NULL,
    rotate_every_n integer DEFAULT 10 NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: api_usage_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_usage_reports (
    id text NOT NULL,
    user_id text NOT NULL,
    schema_version integer DEFAULT 1 NOT NULL,
    started_at timestamp(3) without time zone NOT NULL,
    finished_at timestamp(3) without time zone NOT NULL,
    report jsonb NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    created_by_id text,
    updated_by_id text
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id text NOT NULL,
    actor_id text,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text,
    before jsonb,
    after jsonb,
    source text DEFAULT 'api'::text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: captured_http_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.captured_http_transactions (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    source text NOT NULL,
    run_id text,
    session_id text,
    member_id text,
    tool text,
    phase text,
    step_id text,
    method text NOT NULL,
    scheme text NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    path text NOT NULL,
    query text,
    req_headers jsonb NOT NULL,
    req_body text,
    req_body_ref text,
    req_body_size integer DEFAULT 0 NOT NULL,
    req_content_type text,
    status_code integer,
    resp_headers jsonb NOT NULL,
    resp_body text,
    resp_body_ref text,
    resp_body_size integer DEFAULT 0 NOT NULL,
    resp_content_type text,
    req_body_sha256 text,
    resp_body_sha256 text,
    response_time_ms integer,
    target_ip text,
    http_version text,
    is_tls boolean DEFAULT false NOT NULL,
    tls_version text,
    flow_ref text,
    is_replay boolean DEFAULT false NOT NULL,
    origin_id text,
    in_scope boolean DEFAULT true NOT NULL,
    blocked boolean DEFAULT false NOT NULL,
    error_text text,
    redacted boolean DEFAULT false NOT NULL,
    redacted_fields jsonb,
    has_set_cookie boolean DEFAULT false NOT NULL,
    had_auth boolean DEFAULT false NOT NULL,
    reflected_params boolean DEFAULT false NOT NULL,
    security_headers_missing jsonb,
    cookie_flag_issues jsonb,
    labels jsonb,
    finding_id text,
    ioc_incident_id text,
    ioc_incident_url text,
    started_at timestamp(3) without time zone NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: chat_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_messages (
    id text NOT NULL,
    conversation_id text NOT NULL,
    sequence_num integer NOT NULL,
    type text NOT NULL,
    data jsonb NOT NULL,
    member_id_key text,
    fireteam_id_key text,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: checkpoint_blobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoint_blobs (
    thread_id text NOT NULL,
    checkpoint_ns text DEFAULT ''::text NOT NULL,
    channel text NOT NULL,
    version text NOT NULL,
    type text NOT NULL,
    blob bytea
);


--
-- Name: checkpoint_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoint_migrations (
    v integer NOT NULL
);


--
-- Name: checkpoint_writes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoint_writes (
    thread_id text NOT NULL,
    checkpoint_ns text DEFAULT ''::text NOT NULL,
    checkpoint_id text NOT NULL,
    task_id text NOT NULL,
    idx integer NOT NULL,
    channel text NOT NULL,
    type text,
    blob bytea NOT NULL,
    task_path text DEFAULT ''::text NOT NULL
);


--
-- Name: checkpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoints (
    thread_id text NOT NULL,
    checkpoint_ns text DEFAULT ''::text NOT NULL,
    checkpoint_id text NOT NULL,
    parent_checkpoint_id text,
    type text,
    checkpoint jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conversations (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    session_id text NOT NULL,
    title text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    agent_running boolean DEFAULT false NOT NULL,
    current_phase text DEFAULT 'informational'::text NOT NULL,
    iteration_count integer DEFAULT 0 NOT NULL,
    active_skill_id text DEFAULT ''::text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    created_by_id text,
    updated_by_id text
);


--
-- Name: engagement_authorization_archive; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.engagement_authorization_archive (
    id text NOT NULL,
    project_id text NOT NULL,
    document_sha256 text NOT NULL,
    document_kind text NOT NULL,
    source_url text DEFAULT ''::text NOT NULL,
    program_handle text,
    issued_at timestamp(3) without time zone NOT NULL,
    recorded_at timestamp(3) without time zone NOT NULL,
    recorded_via text NOT NULL,
    recorded_by_token_id text,
    recorded_by_user_id text,
    summary text DEFAULT ''::text NOT NULL,
    archived_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    archived_reason text DEFAULT 'project_deleted'::text NOT NULL
);


--
-- Name: engagement_authorizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.engagement_authorizations (
    id text NOT NULL,
    project_id text NOT NULL,
    document_sha256 text NOT NULL,
    document_kind text NOT NULL,
    source_url text DEFAULT ''::text NOT NULL,
    program_handle text,
    issued_at timestamp(3) without time zone NOT NULL,
    recorded_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    recorded_via text DEFAULT 'mcp'::text NOT NULL,
    recorded_by_token_id text,
    recorded_by_user_id text,
    summary text DEFAULT ''::text NOT NULL,
    idempotency_key text
);


--
-- Name: fireteam_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fireteam_members (
    id text NOT NULL,
    fireteam_id text NOT NULL,
    member_id_key text NOT NULL,
    name text NOT NULL,
    task text NOT NULL,
    skills text[],
    status text DEFAULT 'running'::text NOT NULL,
    completion_reason text,
    iterations_used integer DEFAULT 0 NOT NULL,
    tokens_used integer DEFAULT 0 NOT NULL,
    findings_count integer DEFAULT 0 NOT NULL,
    wall_clock_seconds double precision,
    error_message text,
    result_blob jsonb,
    started_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    completed_at timestamp(3) without time zone
);


--
-- Name: fireteam_settings_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fireteam_settings_audit (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text,
    field text NOT NULL,
    old_value jsonb,
    new_value jsonb,
    source text DEFAULT 'api'::text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: fireteams; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fireteams (
    id text NOT NULL,
    parent_conversation_id text NOT NULL,
    parent_session_id text NOT NULL,
    fireteam_id_key text NOT NULL,
    fireteam_number integer NOT NULL,
    iteration integer NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    member_count integer NOT NULL,
    plan_rationale text,
    status_counts jsonb,
    wall_clock_seconds double precision,
    started_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    completed_at timestamp(3) without time zone
);


--
-- Name: graph_views; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.graph_views (
    id text NOT NULL,
    project_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    cypher_query text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: job_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.job_queue (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    kind text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    settings_hash text NOT NULL,
    envelope_bytes bigint NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 20 NOT NULL,
    not_before timestamp(3) without time zone,
    blocked_code text DEFAULT ''::text NOT NULL,
    blocked_reason text DEFAULT ''::text NOT NULL,
    run_id text DEFAULT ''::text NOT NULL,
    scan_job_id text,
    schedule_id text,
    batch_id text,
    error text DEFAULT ''::text NOT NULL,
    enqueued_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    dispatched_at timestamp(3) without time zone,
    started_at timestamp(3) without time zone,
    finished_at timestamp(3) without time zone,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: mcp_access_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_access_tokens (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    token_prefix text NOT NULL,
    token_hash text NOT NULL,
    scopes text[] DEFAULT ARRAY['recon:read'::text],
    profile text,
    last_used_at timestamp(3) without time zone,
    expires_at timestamp(3) without time zone,
    revoked_at timestamp(3) without time zone,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: node_filter_exemptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_filter_exemptions (
    id text NOT NULL,
    project_id text NOT NULL,
    label text NOT NULL,
    node_key text NOT NULL,
    created_by text NOT NULL,
    real_actor_user_id text,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: node_filter_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_filter_runs (
    id text NOT NULL,
    project_id text NOT NULL,
    actor_user_id text NOT NULL,
    real_actor_user_id text,
    status text DEFAULT 'running'::text NOT NULL,
    target text NOT NULL,
    version_id text NOT NULL,
    revision integer NOT NULL,
    rules jsonb NOT NULL,
    mode text NOT NULL,
    stats jsonb,
    error text,
    started_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    heartbeat_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    finished_at timestamp(3) without time zone
);


--
-- Name: plugin_data; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.plugin_data (
    id text NOT NULL,
    plugin_id text NOT NULL,
    namespace text DEFAULT 'live'::text NOT NULL,
    owner_type text NOT NULL,
    owner_id text NOT NULL,
    user_id text,
    project_id text,
    collection text NOT NULL,
    key text NOT NULL,
    value jsonb NOT NULL,
    size_bytes integer NOT NULL,
    expires_at timestamp(3) without time zone,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    CONSTRAINT plugin_data_owner_ck2 CHECK ((((owner_type = 'user'::text) AND (user_id IS NOT NULL) AND (user_id = owner_id) AND (project_id IS NULL)) OR ((owner_type = 'project'::text) AND (project_id IS NOT NULL) AND (project_id = owner_id) AND (user_id IS NULL))))
);


--
-- Name: plugin_installs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.plugin_installs (
    plugin_id text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    status text DEFAULT 'available'::text NOT NULL,
    active_version text,
    previous_version text,
    pending_version text,
    data_version integer DEFAULT 0 NOT NULL,
    previous_data_version integer,
    granted_permissions jsonb DEFAULT '[]'::jsonb NOT NULL,
    manifest jsonb,
    catalog_entry jsonb,
    installed_by text,
    installed_at timestamp(3) without time zone,
    operation_id text,
    operation_kind text,
    operation_args jsonb,
    lease_expires_at timestamp(3) without time zone,
    last_error text,
    revoked_reason text,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    CONSTRAINT plugin_installs_lease_ck1 CHECK (((operation_id IS NULL) = (lease_expires_at IS NULL))),
    CONSTRAINT plugin_installs_status_ck1 CHECK ((status = ANY (ARRAY['available'::text, 'installing'::text, 'ready'::text, 'failed'::text, 'incompatible'::text, 'updating'::text, 'uninstalling'::text])))
);


--
-- Name: plugin_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.plugin_overrides (
    id text NOT NULL,
    plugin_id text NOT NULL,
    extension_point text NOT NULL,
    scope_type text NOT NULL,
    scope_id text NOT NULL,
    user_id text,
    project_id text,
    target_group text NOT NULL,
    target_key text NOT NULL,
    change_set_id text NOT NULL,
    revision integer,
    value text NOT NULL,
    base_sha256 text NOT NULL,
    status text DEFAULT 'proposed'::text NOT NULL,
    note text,
    meta jsonb,
    created_by text NOT NULL,
    decided_by text,
    decided_at timestamp(3) without time zone,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    CONSTRAINT plugin_overrides_scope_ck2 CHECK ((((scope_type = 'user'::text) AND (user_id IS NOT NULL) AND (user_id = scope_id) AND (project_id IS NULL)) OR ((scope_type = 'project'::text) AND (project_id IS NOT NULL) AND (project_id = scope_id) AND (user_id IS NULL)))),
    CONSTRAINT plugin_overrides_status_ck2 CHECK ((status = ANY (ARRAY['proposed'::text, 'active'::text, 'rejected'::text, 'withdrawn'::text, 'superseded'::text, 'stale'::text, 'cleared'::text, 'adopted'::text])))
);


--
-- Name: plugin_platform_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.plugin_platform_state (
    key text NOT NULL,
    value jsonb NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: project_auth_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_auth_profiles (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    auth_type text DEFAULT 'none'::text NOT NULL,
    auth_header_name text DEFAULT ''::text NOT NULL,
    auth_value text DEFAULT ''::text NOT NULL,
    extra_headers jsonb DEFAULT '{}'::jsonb NOT NULL,
    scope_hosts text[] DEFAULT ARRAY[]::text[],
    recon_enabled boolean DEFAULT true NOT NULL,
    agent_enabled boolean DEFAULT true NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    status text DEFAULT 'unknown'::text NOT NULL,
    last_validated_at timestamp(3) without time zone,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: project_node_filters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_node_filters (
    project_id text NOT NULL,
    mode text DEFAULT 'denylist'::text NOT NULL,
    apply_to_scans boolean DEFAULT false NOT NULL,
    rules jsonb DEFAULT '{"kinds": {}, "version": 1}'::jsonb NOT NULL,
    revision integer DEFAULT 0 NOT NULL,
    loaded_preset jsonb,
    updated_by text,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    description text,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    created_by_id text,
    updated_by_id text,
    target_domain text DEFAULT ''::text NOT NULL,
    subdomain_list text[] DEFAULT ARRAY[]::text[],
    ip_mode boolean DEFAULT false NOT NULL,
    target_ips text[] DEFAULT ARRAY[]::text[],
    domain_batch_mode boolean DEFAULT false NOT NULL,
    domain_batch_hosts text[] DEFAULT ARRAY[]::text[],
    domain_batch_groups jsonb,
    verify_domain_ownership boolean DEFAULT false NOT NULL,
    ownership_token text DEFAULT 'your-secret-token-here'::text NOT NULL,
    ownership_txt_prefix text DEFAULT '_redamon-verify'::text NOT NULL,
    stealth_mode boolean DEFAULT false NOT NULL,
    target_guardrail_enabled boolean DEFAULT true NOT NULL,
    ai_in_pipeline boolean DEFAULT false NOT NULL,
    ai_pipeline_model text DEFAULT 'claude-opus-4-6'::text NOT NULL,
    jev_provider_id text,
    recon_preset_id text,
    loaded_preset jsonb,
    scan_modules text[] DEFAULT ARRAY['domain_discovery'::text, 'port_scan'::text, 'http_probe'::text, 'resource_enum'::text, 'vuln_scan'::text],
    update_graph_db boolean DEFAULT true NOT NULL,
    use_bruteforce_for_subdomains boolean DEFAULT false NOT NULL,
    whois_enabled boolean DEFAULT true NOT NULL,
    whois_max_retries integer DEFAULT 6 NOT NULL,
    dns_enabled boolean DEFAULT true NOT NULL,
    dns_max_retries integer DEFAULT 3 NOT NULL,
    dns_max_workers integer DEFAULT 80 NOT NULL,
    dns_record_parallelism boolean DEFAULT true NOT NULL,
    github_target_org text DEFAULT ''::text NOT NULL,
    github_target_repos text DEFAULT ''::text NOT NULL,
    github_scan_members boolean DEFAULT false NOT NULL,
    github_scan_gists boolean DEFAULT true NOT NULL,
    github_scan_commits boolean DEFAULT true NOT NULL,
    github_max_commits integer DEFAULT 100 NOT NULL,
    github_output_json boolean DEFAULT true NOT NULL,
    trufflehog_enabled boolean DEFAULT false NOT NULL,
    trufflehog_result_types text DEFAULT 'verified,unverified,unknown'::text NOT NULL,
    trufflehog_no_verification boolean DEFAULT false NOT NULL,
    trufflehog_concurrency integer DEFAULT 8 NOT NULL,
    trufflehog_include_detectors text DEFAULT ''::text NOT NULL,
    trufflehog_exclude_detectors text DEFAULT ''::text NOT NULL,
    trufflehog_filter_entropy text DEFAULT ''::text NOT NULL,
    trufflehog_detector_timeout text DEFAULT ''::text NOT NULL,
    trufflehog_max_decode_depth integer DEFAULT 5 NOT NULL,
    trufflehog_force_skip_binaries boolean DEFAULT false NOT NULL,
    trufflehog_force_skip_archives boolean DEFAULT false NOT NULL,
    trufflehog_archive_max_size text DEFAULT ''::text NOT NULL,
    trufflehog_archive_max_depth integer DEFAULT 0 NOT NULL,
    trufflehog_archive_timeout text DEFAULT ''::text NOT NULL,
    trufflehog_allow_verification_overlap boolean DEFAULT false NOT NULL,
    trufflehog_drop_unverified_jwt boolean DEFAULT false NOT NULL,
    supply_chain_sbom_file text DEFAULT ''::text NOT NULL,
    supply_chain_ecosystems text DEFAULT 'npm,PyPI,Go,Maven,crates.io,Packagist,RubyGems,NuGet'::text NOT NULL,
    supply_chain_deep_analysis_enabled boolean DEFAULT false NOT NULL,
    supply_chain_input_mode text DEFAULT 'upload'::text NOT NULL,
    supply_chain_repo_url text DEFAULT ''::text NOT NULL,
    supply_chain_repo_ref text DEFAULT ''::text NOT NULL,
    supply_chain_repo_scope text DEFAULT ''::text NOT NULL,
    supply_chain_org_name text DEFAULT ''::text NOT NULL,
    supply_chain_org_include_forks boolean DEFAULT false NOT NULL,
    supply_chain_org_include_archived boolean DEFAULT false NOT NULL,
    supply_chain_org_max_repos integer DEFAULT 50 NOT NULL,
    supply_chain_org_ref text DEFAULT ''::text NOT NULL,
    supply_chain_org_deep_analysis_enabled boolean DEFAULT false NOT NULL,
    supply_chain_recon_enabled boolean DEFAULT false NOT NULL,
    supply_chain_recon_ecosystems text DEFAULT 'npm'::text NOT NULL,
    supply_chain_recon_deep_analysis_enabled boolean DEFAULT false NOT NULL,
    sca_intel_correlation_enabled boolean DEFAULT true NOT NULL,
    supply_chain_typosquat_enabled boolean DEFAULT false NOT NULL,
    naabu_enabled boolean DEFAULT true NOT NULL,
    naabu_top_ports text DEFAULT '1000'::text NOT NULL,
    naabu_custom_ports text DEFAULT ''::text NOT NULL,
    naabu_rate_limit integer DEFAULT 1000 NOT NULL,
    naabu_threads integer DEFAULT 25 NOT NULL,
    naabu_timeout integer DEFAULT 10000 NOT NULL,
    naabu_retries integer DEFAULT 1 NOT NULL,
    naabu_scan_type text DEFAULT 's'::text NOT NULL,
    naabu_exclude_cdn boolean DEFAULT false NOT NULL,
    naabu_display_cdn boolean DEFAULT true NOT NULL,
    naabu_skip_host_discovery boolean DEFAULT true NOT NULL,
    naabu_verify_ports boolean DEFAULT true NOT NULL,
    naabu_passive_mode boolean DEFAULT false NOT NULL,
    port_scan_ai_port_catalog_enabled boolean DEFAULT true NOT NULL,
    masscan_enabled boolean DEFAULT false NOT NULL,
    masscan_top_ports text DEFAULT '1000'::text NOT NULL,
    masscan_custom_ports text DEFAULT ''::text NOT NULL,
    masscan_rate integer DEFAULT 1000 NOT NULL,
    masscan_banners boolean DEFAULT false NOT NULL,
    masscan_wait integer DEFAULT 10 NOT NULL,
    masscan_retries integer DEFAULT 1 NOT NULL,
    masscan_exclude_targets text DEFAULT ''::text NOT NULL,
    masscan_ai_port_catalog_enabled boolean DEFAULT true NOT NULL,
    nmap_enabled boolean DEFAULT true NOT NULL,
    nmap_version_detection boolean DEFAULT true NOT NULL,
    nmap_script_scan boolean DEFAULT true NOT NULL,
    nmap_timing_template text DEFAULT 'T3'::text NOT NULL,
    nmap_timeout integer DEFAULT 600 NOT NULL,
    nmap_host_timeout integer DEFAULT 300 NOT NULL,
    nmap_parallelism integer DEFAULT 5 NOT NULL,
    nmap_ai_version_regex_enabled boolean DEFAULT true NOT NULL,
    httpx_enabled boolean DEFAULT true NOT NULL,
    httpx_threads integer DEFAULT 50 NOT NULL,
    httpx_timeout integer DEFAULT 10 NOT NULL,
    httpx_retries integer DEFAULT 2 NOT NULL,
    httpx_rate_limit integer DEFAULT 50 NOT NULL,
    httpx_follow_redirects boolean DEFAULT true NOT NULL,
    httpx_max_redirects integer DEFAULT 10 NOT NULL,
    httpx_probe_status_code boolean DEFAULT true NOT NULL,
    httpx_probe_content_length boolean DEFAULT true NOT NULL,
    httpx_probe_content_type boolean DEFAULT true NOT NULL,
    httpx_probe_title boolean DEFAULT true NOT NULL,
    httpx_probe_server boolean DEFAULT true NOT NULL,
    httpx_probe_response_time boolean DEFAULT true NOT NULL,
    httpx_probe_word_count boolean DEFAULT true NOT NULL,
    httpx_probe_line_count boolean DEFAULT true NOT NULL,
    httpx_probe_tech_detect boolean DEFAULT true NOT NULL,
    httpx_probe_ip boolean DEFAULT true NOT NULL,
    httpx_probe_cname boolean DEFAULT true NOT NULL,
    httpx_probe_tls_info boolean DEFAULT true NOT NULL,
    httpx_probe_tls_grab boolean DEFAULT true NOT NULL,
    httpx_probe_favicon boolean DEFAULT true NOT NULL,
    httpx_probe_jarm boolean DEFAULT true NOT NULL,
    httpx_probe_hash text DEFAULT 'sha256'::text NOT NULL,
    httpx_include_response boolean DEFAULT true NOT NULL,
    httpx_include_response_headers boolean DEFAULT true NOT NULL,
    httpx_jev_page_type boolean DEFAULT false NOT NULL,
    httpx_probe_asn boolean DEFAULT true NOT NULL,
    httpx_probe_cdn boolean DEFAULT true NOT NULL,
    httpx_paths text[] DEFAULT ARRAY[]::text[],
    httpx_custom_headers text[] DEFAULT ARRAY['User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'::text, 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'::text, 'Accept-Language: en-US,en;q=0.9'::text, 'Accept-Encoding: gzip, deflate'::text, 'Connection: keep-alive'::text, 'Upgrade-Insecure-Requests: 1'::text, 'Sec-Fetch-Dest: document'::text, 'Sec-Fetch-Mode: navigate'::text, 'Sec-Fetch-Site: none'::text, 'Sec-Fetch-User: ?1'::text, 'Cache-Control: max-age=0'::text],
    httpx_match_codes text[] DEFAULT ARRAY[]::text[],
    httpx_filter_codes text[] DEFAULT ARRAY[]::text[],
    http_probe_ai_header_scan_enabled boolean DEFAULT true NOT NULL,
    http_probe_ai_favicon_hash_enabled boolean DEFAULT true NOT NULL,
    http_probe_ai_title_detection_enabled boolean DEFAULT true NOT NULL,
    http_probe_ai_wappalyzer_enabled boolean DEFAULT true NOT NULL,
    ip_attribution_enabled boolean DEFAULT true NOT NULL,
    ip_attribution_tls_max_probes integer DEFAULT 500 NOT NULL,
    wappalyzer_enabled boolean DEFAULT true NOT NULL,
    wappalyzer_min_confidence integer DEFAULT 50 NOT NULL,
    wappalyzer_require_html boolean DEFAULT true NOT NULL,
    wappalyzer_auto_update boolean DEFAULT true NOT NULL,
    wappalyzer_npm_version text DEFAULT '6.10.56'::text NOT NULL,
    wappalyzer_cache_ttl_hours integer DEFAULT 24 NOT NULL,
    banner_grab_enabled boolean DEFAULT true NOT NULL,
    banner_grab_timeout integer DEFAULT 5 NOT NULL,
    banner_grab_threads integer DEFAULT 20 NOT NULL,
    banner_grab_max_length integer DEFAULT 1000 NOT NULL,
    nuclei_enabled boolean DEFAULT true NOT NULL,
    nuclei_severity text[] DEFAULT ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text],
    nuclei_templates text[] DEFAULT ARRAY[]::text[],
    nuclei_exclude_templates text[] DEFAULT ARRAY[]::text[],
    nuclei_custom_templates text[] DEFAULT ARRAY[]::text[],
    nuclei_selected_custom_templates text[] DEFAULT ARRAY[]::text[],
    nuclei_rate_limit integer DEFAULT 100 NOT NULL,
    nuclei_bulk_size integer DEFAULT 25 NOT NULL,
    nuclei_concurrency integer DEFAULT 25 NOT NULL,
    nuclei_timeout integer DEFAULT 10 NOT NULL,
    nuclei_retries integer DEFAULT 1 NOT NULL,
    nuclei_max_runtime integer DEFAULT 86400 NOT NULL,
    nuclei_max_host_error integer DEFAULT 30 NOT NULL,
    nuclei_tags text[] DEFAULT ARRAY['cve'::text, 'xss'::text, 'sqli'::text, 'rce'::text, 'lfi'::text, 'ssrf'::text, 'xxe'::text, 'ssti'::text],
    nuclei_exclude_tags text[] DEFAULT ARRAY['dos'::text, 'fuzz'::text],
    nuclei_dast_mode boolean DEFAULT false NOT NULL,
    nuclei_auto_update_templates boolean DEFAULT true NOT NULL,
    nuclei_new_templates_only boolean DEFAULT false NOT NULL,
    nuclei_headless boolean DEFAULT false NOT NULL,
    nuclei_system_resolvers boolean DEFAULT true NOT NULL,
    nuclei_follow_redirects boolean DEFAULT true NOT NULL,
    nuclei_max_redirects integer DEFAULT 10 NOT NULL,
    nuclei_scan_all_ips boolean DEFAULT false NOT NULL,
    nuclei_interactsh boolean DEFAULT true NOT NULL,
    nuclei_ai_tags boolean DEFAULT false NOT NULL,
    nuclei_tags_ai_use_jev boolean DEFAULT false NOT NULL,
    nuclei_ai_response_filter boolean DEFAULT false NOT NULL,
    subdomain_takeover_enabled boolean DEFAULT false NOT NULL,
    subjack_enabled boolean DEFAULT true NOT NULL,
    subjack_threads integer DEFAULT 10 NOT NULL,
    subjack_timeout integer DEFAULT 30 NOT NULL,
    subjack_ssl boolean DEFAULT true NOT NULL,
    subjack_all boolean DEFAULT false NOT NULL,
    subjack_check_ns boolean DEFAULT false NOT NULL,
    subjack_check_ar boolean DEFAULT false NOT NULL,
    subjack_check_mail boolean DEFAULT false NOT NULL,
    subjack_run_timeout integer DEFAULT 900 NOT NULL,
    nuclei_takeovers_enabled boolean DEFAULT true NOT NULL,
    nuclei_takeover_run_timeout integer DEFAULT 1800 NOT NULL,
    takeover_ai_classifier boolean DEFAULT false NOT NULL,
    takeover_ai_use_jev boolean DEFAULT false NOT NULL,
    takeover_severity text[] DEFAULT ARRAY['critical'::text, 'high'::text, 'medium'::text],
    takeover_confidence_threshold integer DEFAULT 60 NOT NULL,
    takeover_rate_limit integer DEFAULT 50 NOT NULL,
    takeover_manual_review_auto_publish boolean DEFAULT false NOT NULL,
    takeover_cert_validation_enabled boolean DEFAULT true NOT NULL,
    baddns_enabled boolean DEFAULT false NOT NULL,
    baddns_modules text[] DEFAULT ARRAY['cname'::text, 'ns'::text, 'mx'::text, 'txt'::text, 'spf'::text],
    baddns_nameservers text[] DEFAULT ARRAY[]::text[],
    baddns_run_timeout integer DEFAULT 1800 NOT NULL,
    vhost_sni_enabled boolean DEFAULT false NOT NULL,
    vhost_sni_timeout integer DEFAULT 3 NOT NULL,
    vhost_sni_concurrency integer DEFAULT 20 NOT NULL,
    vhost_sni_baseline_size_tolerance integer DEFAULT 50 NOT NULL,
    vhost_sni_test_l7 boolean DEFAULT true NOT NULL,
    vhost_sni_test_l4 boolean DEFAULT true NOT NULL,
    vhost_sni_inject_discovered boolean DEFAULT true NOT NULL,
    vhost_sni_use_default_wordlist boolean DEFAULT true NOT NULL,
    vhost_sni_use_graph_candidates boolean DEFAULT true NOT NULL,
    vhost_sni_custom_wordlist text DEFAULT ''::text NOT NULL,
    vhost_sni_max_candidates_per_ip integer DEFAULT 2000 NOT NULL,
    tlsx_enabled boolean DEFAULT true NOT NULL,
    tlsx_scan_mode text DEFAULT 'auto'::text NOT NULL,
    tlsx_concurrency integer DEFAULT 50 NOT NULL,
    tlsx_timeout integer DEFAULT 5 NOT NULL,
    tlsx_run_timeout integer DEFAULT 900 NOT NULL,
    tlsx_retries integer DEFAULT 1 NOT NULL,
    tlsx_max_injected_hostnames integer DEFAULT 200 NOT NULL,
    tlsx_delay text DEFAULT ''::text NOT NULL,
    tlsx_include_http_ports boolean DEFAULT false NOT NULL,
    tlsx_inject_hostnames boolean DEFAULT true NOT NULL,
    tlsx_rev_ptr_sni boolean DEFAULT false NOT NULL,
    tlsx_max_hostnames_per_ip integer DEFAULT 1 NOT NULL,
    tlsx_probe_jarm boolean DEFAULT false NOT NULL,
    tlsx_version_enum boolean DEFAULT false NOT NULL,
    tlsx_cipher_enum boolean DEFAULT false NOT NULL,
    tlsx_cipher_concurrency integer DEFAULT 10 NOT NULL,
    tlsx_max_targets integer DEFAULT 2000 NOT NULL,
    web_cache_poison_enabled boolean DEFAULT false NOT NULL,
    web_cache_poison_scan_profile text DEFAULT 'safe-confirm'::text NOT NULL,
    web_cache_poison_timeout integer DEFAULT 1800 NOT NULL,
    web_cache_poison_timeout_per_req integer DEFAULT 10 NOT NULL,
    web_cache_poison_concurrency integer DEFAULT 10 NOT NULL,
    web_cache_poison_confirm_workers integer DEFAULT 6 NOT NULL,
    web_cache_poison_max_rps_per_host double precision DEFAULT 0 NOT NULL,
    web_cache_poison_min_confidence double precision DEFAULT 0.8 NOT NULL,
    web_cache_poison_allow_framework_packs boolean DEFAULT true NOT NULL,
    web_cache_poison_allow_deception boolean DEFAULT true NOT NULL,
    web_cache_poison_allow_cpdos boolean DEFAULT false NOT NULL,
    web_cache_poison_cross_vantage boolean DEFAULT false NOT NULL,
    web_cache_poison_cache_header text DEFAULT ''::text NOT NULL,
    web_cache_poison_cache_buster_param text DEFAULT 'rdmncb'::text NOT NULL,
    web_cache_poison_verify_ssl boolean DEFAULT true NOT NULL,
    web_cache_poison_behavioral_oracle boolean DEFAULT true NOT NULL,
    web_cache_poison_behavioral_delay double precision DEFAULT 1.1 NOT NULL,
    web_cache_poison_differential boolean DEFAULT true NOT NULL,
    route_exposure_enabled boolean DEFAULT false NOT NULL,
    route_exposure_max_rps double precision DEFAULT 5 NOT NULL,
    route_exposure_workers integer DEFAULT 4 NOT NULL,
    route_exposure_timeout integer DEFAULT 10 NOT NULL,
    route_exposure_max_routes_per_host integer DEFAULT 300 NOT NULL,
    route_exposure_max_routes_total integer DEFAULT 3000 NOT NULL,
    route_exposure_seed_paths boolean DEFAULT true NOT NULL,
    route_exposure_vcs_files boolean DEFAULT true NOT NULL,
    route_exposure_backup_files boolean DEFAULT true NOT NULL,
    route_exposure_version_variants boolean DEFAULT true NOT NULL,
    route_exposure_compare_logged_in boolean DEFAULT true NOT NULL,
    route_exposure_pii_detection boolean DEFAULT true NOT NULL,
    route_exposure_siblings boolean DEFAULT true NOT NULL,
    route_exposure_framework_seeds boolean DEFAULT true NOT NULL,
    route_exposure_follow_catalogs boolean DEFAULT true NOT NULL,
    route_exposure_git_walk boolean DEFAULT true NOT NULL,
    route_exposure_cross_host boolean DEFAULT false NOT NULL,
    route_exposure_cors_rider boolean DEFAULT true NOT NULL,
    route_exposure_cache_rider boolean DEFAULT true NOT NULL,
    route_exposure_jev_rank boolean DEFAULT false NOT NULL,
    route_exposure_jev_wall_check boolean DEFAULT false NOT NULL,
    route_exposure_jev_assess boolean DEFAULT false NOT NULL,
    resource_enum_ai_classifier_enabled boolean DEFAULT true NOT NULL,
    resource_enum_ai_path_classifier_enabled boolean DEFAULT true NOT NULL,
    resource_enum_ai_rag_path_flag_enabled boolean DEFAULT true NOT NULL,
    resource_enum_ai_param_injectable_flag_enabled boolean DEFAULT true NOT NULL,
    resource_enum_ai_tool_arg_path_enabled boolean DEFAULT true NOT NULL,
    resource_enum_jev_tool_health boolean DEFAULT false NOT NULL,
    ai_surface_recon_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_timeout integer DEFAULT 10 NOT NULL,
    ai_surface_recon_max_workers integer DEFAULT 5 NOT NULL,
    ai_surface_recon_user_agent text DEFAULT 'RedAmon-AISurfaceRecon/1.0'::text NOT NULL,
    ai_surface_recon_chat_shape_probe_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_mcp_handshake_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_mcp_list_tools_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_mcp_yara_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_openapi_discovery_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_model_list_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_vector_db_read_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_julius_probe_pack_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_latency_baseline_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_cache_enabled boolean DEFAULT true NOT NULL,
    ai_surface_recon_probe_pack_version text DEFAULT 'latest'::text NOT NULL,
    katana_enabled boolean DEFAULT true NOT NULL,
    katana_depth integer DEFAULT 2 NOT NULL,
    katana_max_urls integer DEFAULT 300000 NOT NULL,
    katana_rate_limit integer DEFAULT 50 NOT NULL,
    katana_timeout integer DEFAULT 3600 NOT NULL,
    katana_js_crawl boolean DEFAULT true NOT NULL,
    katana_params_only boolean DEFAULT false NOT NULL,
    katana_exclude_patterns text[] DEFAULT ARRAY['/_next/image'::text, '/_next/static'::text, '/_next/data'::text, '/__nextjs'::text, '/_nuxt/'::text, '/__nuxt'::text, '/runtime.'::text, '/polyfills.'::text, '/vendor.'::text, '/webpack'::text, '/chunk.'::text, '.chunk.js'::text, '.bundle.js'::text, 'hot-update'::text, '/static/'::text, '/public/'::text, '/dist/'::text, '/build/'::text, '/lib/'::text, '/vendor/'::text, '/node_modules/'::text, '.png'::text, '.jpg'::text, '.jpeg'::text, '.gif'::text, '.svg'::text, '.ico'::text, '.webp'::text, '.avif'::text, '.bmp'::text, '.tiff'::text, '.tif'::text, '.heic'::text, '.heif'::text, '.raw'::text, '/images/'::text, '/img/'::text, '/image/'::text, '/pics/'::text, '/pictures/'::text, '/thumbnails/'::text, '/thumb/'::text, '/thumbs/'::text, '.css'::text, '.scss'::text, '.sass'::text, '.less'::text, '.styl'::text, '.css.map'::text, '/css/'::text, '/styles/'::text, '/style/'::text, '/stylesheet/'::text, '.js.map'::text, '.min.js'::text, '/js/lib/'::text, '/js/vendor/'::text, '/js/plugins/'::text, 'jquery'::text, 'bootstrap.js'::text, 'popper.js'::text, '.woff'::text, '.woff2'::text, '.ttf'::text, '.eot'::text, '.otf'::text, '/fonts/'::text, '/font/'::text, '/webfonts/'::text, '.pdf'::text, '.doc'::text, '.docx'::text, '.xls'::text, '.xlsx'::text, '.ppt'::text, '.pptx'::text, '.txt'::text, '.rtf'::text, '.odt'::text, '.ods'::text, '.odp'::text, '.zip'::text, '.rar'::text, '.7z'::text, '.tar'::text, '.gz'::text, '.bz2'::text, '.mp3'::text, '.mp4'::text, '.avi'::text, '.mov'::text, '.wmv'::text, '.flv'::text, '.webm'::text, '.mkv'::text, '.wav'::text, '.ogg'::text, '.aac'::text, '.m4a'::text, '.flac'::text, '/video/'::text, '/videos/'::text, '/audio/'::text, '/music/'::text, '/sounds/'::text, '/wp-content/uploads/'::text, '/wp-content/themes/'::text, '/wp-includes/'::text, '/sites/default/files/'::text, '/core/assets/'::text, '/pub/static/'::text, '/pub/media/'::text, '/storage/'::text, '/staticfiles/'::text, '/packs/'::text, 'cdn.'::text, 'cdnjs.'::text, 'cloudflare.'::text, 'akamai.'::text, 'fastly.'::text, 'googleapis.com'::text, 'gstatic.com'::text, 'cloudfront.net'::text, 'unpkg.com'::text, 'jsdelivr.net'::text, 'bootstrapcdn.com'::text, 'google-analytics'::text, 'googletagmanager'::text, 'gtag/'::text, 'facebook.com/tr'::text, 'facebook.net'::text, 'analytics.'::text, 'tracking.'::text, 'pixel.'::text, 'hotjar.'::text, 'mouseflow.'::text, 'clarity.'::text, 'googlesyndication'::text, 'doubleclick'::text, 'adservice'::text, 'platform.twitter'::text, 'connect.facebook'::text, 'platform.linkedin'::text, 'maps.google'::text, 'maps.googleapis'::text, 'openstreetmap'::text, 'mapbox'::text, 'recaptcha'::text, 'hcaptcha'::text, 'captcha'::text, 'manifest.json'::text, 'sw.js'::text, 'service-worker'::text, 'browserconfig.xml'::text, 'robots.txt'::text, 'sitemap.xml'::text, '.well-known/'::text, 'favicon'::text, 'apple-touch-icon'::text, 'android-chrome'::text, '/icons/'::text, '/icon/'::text],
    katana_scope text DEFAULT 'dn'::text NOT NULL,
    katana_custom_headers text[] DEFAULT ARRAY['User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'::text, 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'::text, 'Accept-Language: en-US,en;q=0.9'::text],
    katana_parallelism integer DEFAULT 8 NOT NULL,
    katana_concurrency integer DEFAULT 15 NOT NULL,
    openapi_enabled boolean DEFAULT true NOT NULL,
    openapi_discovery_paths text[] DEFAULT ARRAY['/openapi.json'::text, '/openapi.yaml'::text, '/swagger.json'::text, '/swagger.yaml'::text, '/v3/api-docs'::text, '/v2/api-docs'::text, '/swagger/v1/swagger.json'::text, '/swagger-ui/index.html'::text, '/swagger-ui.html'::text, '/docs'::text, '/api-docs'::text, '/api-docs/'::text],
    openapi_auto_discover boolean DEFAULT false NOT NULL,
    openapi_sources jsonb DEFAULT '[]'::jsonb NOT NULL,
    openapi_timeout integer DEFAULT 10 NOT NULL,
    openapi_max_documents integer DEFAULT 50 NOT NULL,
    zap_ajax_spider_enabled boolean DEFAULT false NOT NULL,
    zap_ajax_spider_seed_mode text DEFAULT 'base_urls'::text NOT NULL,
    zap_ajax_spider_max_duration integer DEFAULT 10 NOT NULL,
    zap_ajax_spider_max_crawl_depth integer DEFAULT 5 NOT NULL,
    zap_ajax_spider_max_crawl_states integer DEFAULT 0 NOT NULL,
    zap_ajax_spider_number_of_browsers integer DEFAULT 1 NOT NULL,
    zap_ajax_spider_browser_id text DEFAULT 'firefox-headless'::text NOT NULL,
    zap_ajax_spider_event_wait integer DEFAULT 1000 NOT NULL,
    zap_ajax_spider_reload_wait integer DEFAULT 1000 NOT NULL,
    zap_ajax_spider_click_default_elems boolean DEFAULT true NOT NULL,
    zap_ajax_spider_click_elems_once boolean DEFAULT true NOT NULL,
    zap_ajax_spider_random_inputs boolean DEFAULT false NOT NULL,
    zap_ajax_spider_logout_avoidance boolean DEFAULT true NOT NULL,
    zap_ajax_spider_scope_check text DEFAULT 'Strict'::text NOT NULL,
    zap_ajax_spider_custom_headers text[] DEFAULT ARRAY[]::text[],
    zap_ajax_spider_exclude_patterns text[] DEFAULT ARRAY[]::text[],
    zap_ajax_spider_max_urls integer DEFAULT 1000 NOT NULL,
    zap_ajax_spider_parallelism integer DEFAULT 3 NOT NULL,
    zap_ajax_spider_max_seeds integer DEFAULT 250 NOT NULL,
    hakrawler_enabled boolean DEFAULT true NOT NULL,
    hakrawler_depth integer DEFAULT 2 NOT NULL,
    hakrawler_threads integer DEFAULT 5 NOT NULL,
    hakrawler_timeout integer DEFAULT 30 NOT NULL,
    hakrawler_max_urls integer DEFAULT 50000 NOT NULL,
    hakrawler_include_subs boolean DEFAULT true NOT NULL,
    hakrawler_insecure boolean DEFAULT true NOT NULL,
    hakrawler_custom_headers text[] DEFAULT ARRAY[]::text[],
    hakrawler_parallelism integer DEFAULT 5 NOT NULL,
    hakrawler_jev_seed_order boolean DEFAULT false NOT NULL,
    jsluice_enabled boolean DEFAULT true NOT NULL,
    jsluice_max_files integer DEFAULT 10000 NOT NULL,
    jsluice_timeout integer DEFAULT 300 NOT NULL,
    jsluice_extract_urls boolean DEFAULT true NOT NULL,
    jsluice_extract_secrets boolean DEFAULT true NOT NULL,
    jsluice_concurrency integer DEFAULT 5 NOT NULL,
    jsluice_parallelism integer DEFAULT 5 NOT NULL,
    jsluice_verify_urls boolean DEFAULT true NOT NULL,
    jsluice_verify_timeout integer DEFAULT 5 NOT NULL,
    jsluice_verify_rate_limit integer DEFAULT 50 NOT NULL,
    jsluice_verify_threads integer DEFAULT 50 NOT NULL,
    jsluice_verify_accept_status integer[] DEFAULT ARRAY[200, 201, 301, 302, 307, 308, 401, 403],
    jsluice_exclude_patterns text[] DEFAULT ARRAY['/_next/image'::text, '/_next/static'::text, '/_next/data'::text, '/__nextjs'::text, '/_nuxt/'::text, '/__nuxt'::text, '/runtime.'::text, '/polyfills.'::text, '/vendor.'::text, '/webpack'::text, '/chunk.'::text, '.chunk.js'::text, '.bundle.js'::text, 'hot-update'::text, '/static/'::text, '/public/'::text, '/dist/'::text, '/build/'::text, '/lib/'::text, '/vendor/'::text, '/node_modules/'::text, '.js'::text, '.mjs'::text, '.map'::text, '.css'::text, '.scss'::text, '.sass'::text, '.less'::text, '.png'::text, '.jpg'::text, '.jpeg'::text, '.gif'::text, '.svg'::text, '.ico'::text, '.webp'::text, '.avif'::text, '.woff'::text, '.woff2'::text, '.ttf'::text, '.eot'::text, '.otf'::text, '.mp3'::text, '.mp4'::text, '.avi'::text, '.mov'::text, '.wmv'::text, '.flv'::text, '.webm'::text, '.pdf'::text, '.doc'::text, '.docx'::text, '.xls'::text, '.xlsx'::text, '.ppt'::text, '.pptx'::text, '.zip'::text, '.rar'::text, '.7z'::text, '.tar'::text, '.gz'::text, '/rxjs/'::text, '/react/'::text, '/angular/'::text, '/lodash/'::text, '/zone.js/'::text],
    js_recon_enabled boolean DEFAULT false NOT NULL,
    js_recon_max_files integer DEFAULT 10000 NOT NULL,
    js_recon_timeout integer DEFAULT 900 NOT NULL,
    js_recon_concurrency integer DEFAULT 10 NOT NULL,
    js_recon_validate_keys boolean DEFAULT true NOT NULL,
    js_recon_validation_timeout integer DEFAULT 5 NOT NULL,
    js_recon_trufflehog_enabled boolean DEFAULT true NOT NULL,
    js_recon_trufflehog_results text[] DEFAULT ARRAY['verified'::text, 'unknown'::text, 'unverified'::text],
    js_recon_extract_endpoints boolean DEFAULT true NOT NULL,
    js_recon_validate_endpoints boolean DEFAULT false NOT NULL,
    js_recon_endpoint_accept_status integer[] DEFAULT ARRAY[200, 201, 204, 301, 302, 307, 308, 401, 403, 405],
    js_recon_endpoint_custom_headers text[] DEFAULT ARRAY[]::text[],
    js_recon_endpoint_concurrency integer DEFAULT 10 NOT NULL,
    js_recon_regex_patterns boolean DEFAULT true NOT NULL,
    js_recon_source_maps boolean DEFAULT true NOT NULL,
    js_recon_dependency_check boolean DEFAULT true NOT NULL,
    js_recon_dom_sinks boolean DEFAULT true NOT NULL,
    js_recon_framework_detect boolean DEFAULT true NOT NULL,
    js_recon_dev_comments boolean DEFAULT true NOT NULL,
    js_recon_include_chunks boolean DEFAULT true NOT NULL,
    js_recon_include_framework_js boolean DEFAULT true NOT NULL,
    js_recon_include_archived_js boolean DEFAULT true NOT NULL,
    js_recon_min_confidence text DEFAULT 'low'::text NOT NULL,
    js_recon_standalone_crawl_depth integer DEFAULT 3 NOT NULL,
    js_recon_standalone_crawl_scope text DEFAULT 'subdomain'::text NOT NULL,
    js_recon_uploaded_files text[] DEFAULT ARRAY[]::text[],
    js_recon_custom_patterns text DEFAULT ''::text NOT NULL,
    js_recon_custom_sourcemap_paths text DEFAULT ''::text NOT NULL,
    js_recon_custom_packages text DEFAULT ''::text NOT NULL,
    js_recon_custom_endpoint_keywords text DEFAULT ''::text NOT NULL,
    js_recon_custom_frameworks text DEFAULT ''::text NOT NULL,
    serialized_scan_enabled boolean DEFAULT false NOT NULL,
    serialized_scan_jev_rank boolean DEFAULT false NOT NULL,
    js_recon_ai_sdk_detection_enabled boolean DEFAULT true NOT NULL,
    graphql_security_enabled boolean DEFAULT false NOT NULL,
    graphql_introspection_test boolean DEFAULT true NOT NULL,
    graphql_timeout integer DEFAULT 30 NOT NULL,
    graphql_rate_limit integer DEFAULT 10 NOT NULL,
    graphql_concurrency integer DEFAULT 5 NOT NULL,
    graphql_auth_type text DEFAULT ''::text NOT NULL,
    graphql_auth_value text DEFAULT ''::text NOT NULL,
    graphql_auth_header text DEFAULT ''::text NOT NULL,
    graphql_endpoints text DEFAULT ''::text NOT NULL,
    graphql_depth_limit integer DEFAULT 10 NOT NULL,
    graphql_retry_count integer DEFAULT 3 NOT NULL,
    graphql_retry_backoff double precision DEFAULT 2.0 NOT NULL,
    graphql_verify_ssl boolean DEFAULT true NOT NULL,
    graphql_cop_enabled boolean DEFAULT false NOT NULL,
    graphql_cop_timeout integer DEFAULT 120 NOT NULL,
    graphql_cop_force_scan boolean DEFAULT false NOT NULL,
    graphql_cop_debug boolean DEFAULT false NOT NULL,
    graphql_cop_test_field_suggestions boolean DEFAULT true NOT NULL,
    graphql_cop_test_introspection boolean DEFAULT false NOT NULL,
    graphql_cop_test_graphiql boolean DEFAULT true NOT NULL,
    graphql_cop_test_get_method boolean DEFAULT true NOT NULL,
    graphql_cop_test_alias_overloading boolean DEFAULT true NOT NULL,
    graphql_cop_test_batch_query boolean DEFAULT true NOT NULL,
    graphql_cop_test_trace_mode boolean DEFAULT true NOT NULL,
    graphql_cop_test_directive_overloading boolean DEFAULT true NOT NULL,
    graphql_cop_test_circular_introspection boolean DEFAULT true NOT NULL,
    graphql_cop_test_get_mutation boolean DEFAULT true NOT NULL,
    graphql_cop_test_post_csrf boolean DEFAULT true NOT NULL,
    graphql_cop_test_unhandled_error boolean DEFAULT true NOT NULL,
    ffuf_enabled boolean DEFAULT false NOT NULL,
    ffuf_wordlist text DEFAULT '/usr/share/seclists/Discovery/Web-Content/common.txt'::text NOT NULL,
    ffuf_threads integer DEFAULT 40 NOT NULL,
    ffuf_rate integer DEFAULT 0 NOT NULL,
    ffuf_timeout integer DEFAULT 10 NOT NULL,
    ffuf_max_time integer DEFAULT 1800 NOT NULL,
    ffuf_match_codes integer[] DEFAULT ARRAY[200, 201, 204, 301, 302, 307, 308, 401, 403, 405],
    ffuf_filter_codes integer[] DEFAULT ARRAY[]::integer[],
    ffuf_filter_size text DEFAULT ''::text NOT NULL,
    ffuf_extensions text[] DEFAULT ARRAY[]::text[],
    ffuf_recursion boolean DEFAULT false NOT NULL,
    ffuf_recursion_depth integer DEFAULT 2 NOT NULL,
    ffuf_auto_calibrate boolean DEFAULT true NOT NULL,
    ffuf_follow_redirects boolean DEFAULT false NOT NULL,
    ffuf_custom_headers text[] DEFAULT ARRAY[]::text[],
    ffuf_smart_fuzz boolean DEFAULT true NOT NULL,
    ffuf_smart_fuzz_max_base_paths integer DEFAULT 20 NOT NULL,
    ffuf_parallelism integer DEFAULT 20 NOT NULL,
    ffuf_ai_extensions boolean DEFAULT false NOT NULL,
    ffuf_ai_use_jev boolean DEFAULT false NOT NULL,
    ffuf_jev_base_paths boolean DEFAULT false NOT NULL,
    arjun_enabled boolean DEFAULT true NOT NULL,
    arjun_threads integer DEFAULT 2 NOT NULL,
    arjun_timeout integer DEFAULT 15 NOT NULL,
    arjun_scan_timeout integer DEFAULT 600 NOT NULL,
    arjun_methods text[] DEFAULT ARRAY['GET'::text, 'POST'::text],
    arjun_max_endpoints integer DEFAULT 50000 NOT NULL,
    arjun_chunk_size integer DEFAULT 500 NOT NULL,
    arjun_rate_limit integer DEFAULT 0 NOT NULL,
    arjun_stable boolean DEFAULT false NOT NULL,
    arjun_passive boolean DEFAULT false NOT NULL,
    arjun_disable_redirects boolean DEFAULT false NOT NULL,
    arjun_custom_headers text[] DEFAULT ARRAY[]::text[],
    gau_enabled boolean DEFAULT false NOT NULL,
    gau_providers text[] DEFAULT ARRAY['wayback'::text, 'commoncrawl'::text, 'otx'::text, 'urlscan'::text],
    gau_max_urls integer DEFAULT 50000 NOT NULL,
    gau_timeout integer DEFAULT 60 NOT NULL,
    gau_threads integer DEFAULT 5 NOT NULL,
    gau_blacklist_extensions text[] DEFAULT ARRAY['png'::text, 'jpg'::text, 'jpeg'::text, 'gif'::text, 'svg'::text, 'ico'::text, 'webp'::text, 'avif'::text, 'css'::text, 'woff'::text, 'woff2'::text, 'ttf'::text, 'eot'::text, 'otf'::text, 'mp3'::text, 'mp4'::text, 'avi'::text, 'mov'::text, 'wmv'::text, 'flv'::text, 'webm'::text],
    gau_year_range text[] DEFAULT ARRAY[]::text[],
    gau_verbose boolean DEFAULT false NOT NULL,
    gau_verify_urls boolean DEFAULT true NOT NULL,
    gau_verify_timeout integer DEFAULT 5 NOT NULL,
    gau_verify_rate_limit integer DEFAULT 100 NOT NULL,
    gau_verify_threads integer DEFAULT 50 NOT NULL,
    gau_verify_accept_status integer[] DEFAULT ARRAY[200, 201, 301, 302, 307, 308, 401, 403],
    gau_detect_methods boolean DEFAULT true NOT NULL,
    gau_method_detect_timeout integer DEFAULT 5 NOT NULL,
    gau_method_detect_rate_limit integer DEFAULT 50 NOT NULL,
    gau_method_detect_threads integer DEFAULT 25 NOT NULL,
    gau_filter_dead_endpoints boolean DEFAULT true NOT NULL,
    gau_workers integer DEFAULT 10 NOT NULL,
    paramspider_enabled boolean DEFAULT false NOT NULL,
    paramspider_placeholder text DEFAULT 'FUZZ'::text NOT NULL,
    paramspider_timeout integer DEFAULT 120 NOT NULL,
    paramspider_workers integer DEFAULT 8 NOT NULL,
    kiterunner_enabled boolean DEFAULT false NOT NULL,
    kiterunner_wordlists text[] DEFAULT ARRAY['routes-large'::text],
    kiterunner_rate_limit integer DEFAULT 100 NOT NULL,
    kiterunner_connections integer DEFAULT 100 NOT NULL,
    kiterunner_timeout integer DEFAULT 10 NOT NULL,
    kiterunner_scan_timeout integer DEFAULT 1000 NOT NULL,
    kiterunner_threads integer DEFAULT 50 NOT NULL,
    kiterunner_ignore_status integer[] DEFAULT ARRAY[]::integer[],
    kiterunner_min_content_length integer DEFAULT 0 NOT NULL,
    kiterunner_match_status integer[] DEFAULT ARRAY[200, 201, 204, 301, 302, 401, 403, 405],
    kiterunner_headers text[] DEFAULT ARRAY[]::text[],
    kiterunner_detect_methods boolean DEFAULT true NOT NULL,
    kiterunner_method_detection_mode text DEFAULT 'bruteforce'::text NOT NULL,
    kiterunner_bruteforce_methods text[] DEFAULT ARRAY['POST'::text, 'PUT'::text, 'DELETE'::text, 'PATCH'::text],
    kiterunner_method_detect_timeout integer DEFAULT 5 NOT NULL,
    kiterunner_method_detect_rate_limit integer DEFAULT 50 NOT NULL,
    kiterunner_method_detect_threads integer DEFAULT 25 NOT NULL,
    kiterunner_parallelism integer DEFAULT 3 NOT NULL,
    cve_lookup_enabled boolean DEFAULT true NOT NULL,
    cve_lookup_source text DEFAULT 'nvd'::text NOT NULL,
    cve_lookup_max_cves integer DEFAULT 20 NOT NULL,
    cve_lookup_min_cvss double precision DEFAULT 0.0 NOT NULL,
    mitre_enabled boolean DEFAULT true NOT NULL,
    mitre_auto_update_db boolean DEFAULT true NOT NULL,
    mitre_include_cwe boolean DEFAULT true NOT NULL,
    mitre_include_capec boolean DEFAULT true NOT NULL,
    mitre_enrich_recon boolean DEFAULT true NOT NULL,
    mitre_enrich_gvm boolean DEFAULT true NOT NULL,
    mitre_cache_ttl_hours integer DEFAULT 24 NOT NULL,
    security_check_enabled boolean DEFAULT true NOT NULL,
    security_check_direct_ip_http boolean DEFAULT true NOT NULL,
    security_check_direct_ip_https boolean DEFAULT true NOT NULL,
    security_check_ip_api_exposed boolean DEFAULT true NOT NULL,
    security_check_waf_bypass boolean DEFAULT true NOT NULL,
    waf_ai_classifier boolean DEFAULT false NOT NULL,
    waf_ai_use_jev boolean DEFAULT false NOT NULL,
    security_check_tls_expiring_soon boolean DEFAULT true NOT NULL,
    security_check_tls_expiry_days integer DEFAULT 30 NOT NULL,
    security_check_tls_expired boolean DEFAULT true NOT NULL,
    security_check_tls_self_signed boolean DEFAULT true NOT NULL,
    security_check_tls_hostname_mismatch boolean DEFAULT true NOT NULL,
    security_check_tls_weak_version boolean DEFAULT true NOT NULL,
    security_check_tls_weak_cipher boolean DEFAULT true NOT NULL,
    security_check_tls_wildcard_overbroad boolean DEFAULT true NOT NULL,
    security_check_missing_referrer_policy boolean DEFAULT true NOT NULL,
    security_check_missing_permissions_policy boolean DEFAULT true NOT NULL,
    security_check_missing_coop boolean DEFAULT true NOT NULL,
    security_check_missing_corp boolean DEFAULT true NOT NULL,
    security_check_missing_coep boolean DEFAULT true NOT NULL,
    security_check_cache_control_missing boolean DEFAULT true NOT NULL,
    security_check_login_no_https boolean DEFAULT true NOT NULL,
    security_check_session_no_secure boolean DEFAULT true NOT NULL,
    security_check_session_no_httponly boolean DEFAULT true NOT NULL,
    security_check_basic_auth_no_tls boolean DEFAULT true NOT NULL,
    security_check_spf_missing boolean DEFAULT true NOT NULL,
    security_check_dmarc_missing boolean DEFAULT true NOT NULL,
    security_check_dnssec_missing boolean DEFAULT true NOT NULL,
    security_check_zone_transfer boolean DEFAULT true NOT NULL,
    security_check_admin_port_exposed boolean DEFAULT true NOT NULL,
    security_check_database_exposed boolean DEFAULT true NOT NULL,
    security_check_redis_no_auth boolean DEFAULT true NOT NULL,
    security_check_kubernetes_api_exposed boolean DEFAULT true NOT NULL,
    security_check_smtp_open_relay boolean DEFAULT true NOT NULL,
    security_check_csp_unsafe_inline boolean DEFAULT true NOT NULL,
    security_check_insecure_form_action boolean DEFAULT true NOT NULL,
    security_check_no_rate_limiting boolean DEFAULT true NOT NULL,
    security_check_open_consoles boolean DEFAULT true NOT NULL,
    security_check_debug_pages boolean DEFAULT true NOT NULL,
    security_check_unfinished_installers boolean DEFAULT true NOT NULL,
    security_check_dev_servers boolean DEFAULT true NOT NULL,
    security_check_directory_listing boolean DEFAULT true NOT NULL,
    security_check_defaced_pages boolean DEFAULT true NOT NULL,
    security_check_takeover_error_pages boolean DEFAULT true NOT NULL,
    security_check_test_certificates boolean DEFAULT true NOT NULL,
    security_check_timeout integer DEFAULT 10 NOT NULL,
    security_check_max_workers integer DEFAULT 10 NOT NULL,
    origin_discovery_enabled boolean DEFAULT false NOT NULL,
    origin_discovery_keyless boolean DEFAULT true NOT NULL,
    origin_discovery_scanners boolean DEFAULT true NOT NULL,
    origin_discovery_passive_dns boolean DEFAULT true NOT NULL,
    origin_discovery_urlscan boolean DEFAULT true NOT NULL,
    origin_discovery_max_candidates integer DEFAULT 25 NOT NULL,
    origin_discovery_max_search_calls integer DEFAULT 50 NOT NULL,
    origin_discovery_threshold integer DEFAULT 60 NOT NULL,
    origin_discovery_timeout integer DEFAULT 10 NOT NULL,
    origin_discovery_workers integer DEFAULT 10 NOT NULL,
    gvm_scan_config text DEFAULT 'Full and fast'::text NOT NULL,
    gvm_scan_targets text DEFAULT 'both'::text NOT NULL,
    gvm_port_list text DEFAULT 'All TCP and Nmap top 100 UDP'::text NOT NULL,
    gvm_task_timeout integer DEFAULT 14400 NOT NULL,
    gvm_poll_interval integer DEFAULT 30 NOT NULL,
    gvm_cleanup_after_scan boolean DEFAULT true NOT NULL,
    agent_openai_model text DEFAULT 'claude-opus-4-6'::text NOT NULL,
    agent_informational_system_prompt text DEFAULT ''::text NOT NULL,
    agent_expl_system_prompt text DEFAULT ''::text NOT NULL,
    agent_post_expl_system_prompt text DEFAULT ''::text NOT NULL,
    agent_activate_post_expl_phase boolean DEFAULT true NOT NULL,
    agent_post_expl_phase_type text DEFAULT 'statefull'::text NOT NULL,
    agent_lhost text DEFAULT ''::text NOT NULL,
    agent_lport integer,
    agent_bind_port_on_target integer,
    agent_payload_use_https boolean DEFAULT false NOT NULL,
    agent_ngrok_tunnel_enabled boolean DEFAULT false NOT NULL,
    agent_chisel_tunnel_enabled boolean DEFAULT false NOT NULL,
    agent_max_iterations integer DEFAULT 100 NOT NULL,
    agent_execution_trace_memory_steps integer DEFAULT 100 NOT NULL,
    agent_require_approval_for_exploitation boolean DEFAULT true NOT NULL,
    agent_require_approval_for_post_exploitation boolean DEFAULT true NOT NULL,
    agent_require_tool_confirmation boolean DEFAULT true NOT NULL,
    agent_tool_output_max_chars integer DEFAULT 40000 NOT NULL,
    agent_plan_max_parallel_tools integer DEFAULT 10 NOT NULL,
    agent_cypher_max_retries integer DEFAULT 3 NOT NULL,
    agent_llm_parse_max_retries integer DEFAULT 3 NOT NULL,
    agent_create_graph_image_on_init boolean DEFAULT false NOT NULL,
    agent_log_max_mb integer DEFAULT 10 NOT NULL,
    agent_log_backup_count integer DEFAULT 5 NOT NULL,
    agent_tool_phase_map jsonb DEFAULT '{"shodan": ["informational", "exploitation", "post_exploitation"], "cve_intel": ["informational", "exploitation", "post_exploitation"], "kali_shell": ["informational", "exploitation", "post_exploitation"], "web_search": ["informational", "exploitation", "post_exploitation"], "execute_gau": ["informational", "exploitation"], "google_dork": ["informational"], "msf_restart": ["exploitation", "post_exploitation"], "proxy_brain": ["informational", "exploitation", "post_exploitation"], "query_graph": ["informational", "exploitation", "post_exploitation"], "execute_code": ["informational", "exploitation", "post_exploitation"], "execute_curl": ["informational", "exploitation", "post_exploitation"], "execute_ffuf": ["informational", "exploitation"], "execute_nmap": ["informational", "exploitation", "post_exploitation"], "execute_amass": ["informational", "exploitation"], "execute_arjun": ["informational", "exploitation"], "execute_httpx": ["informational", "exploitation"], "execute_hydra": ["exploitation", "post_exploitation"], "execute_naabu": ["informational", "exploitation"], "execute_katana": ["informational", "exploitation"], "execute_nuclei": ["informational", "exploitation"], "execute_wpscan": ["informational", "exploitation"], "execute_jsluice": ["informational", "exploitation"], "execute_guarddog": ["informational", "exploitation"], "execute_subfinder": ["informational", "exploitation"], "tradecraft_lookup": ["exploitation", "post_exploitation"], "execute_playwright": ["informational", "exploitation", "post_exploitation"], "metasploit_console": ["exploitation", "post_exploitation"], "execute_osv_scanner": ["informational", "exploitation", "post_exploitation"]}'::jsonb NOT NULL,
    agent_kali_install_enabled boolean DEFAULT false NOT NULL,
    agent_kali_install_allowed_packages text DEFAULT ''::text NOT NULL,
    agent_kali_install_forbidden_packages text DEFAULT ''::text NOT NULL,
    agent_brute_force_max_wordlist_attempts integer DEFAULT 3 NOT NULL,
    agent_bruteforce_speed integer DEFAULT 5 NOT NULL,
    agent_guardrail_enabled boolean DEFAULT true NOT NULL,
    mcp_kali_exec_enabled boolean DEFAULT true NOT NULL,
    fireteam_enabled boolean DEFAULT true NOT NULL,
    fireteam_max_concurrent integer DEFAULT 5 NOT NULL,
    fireteam_max_members integer DEFAULT 5 NOT NULL,
    fireteam_member_max_iterations integer DEFAULT 10 NOT NULL,
    fireteam_timeout_sec integer DEFAULT 7200 NOT NULL,
    fireteam_allowed_phases text[] DEFAULT ARRAY['informational'::text, 'exploitation'::text, 'post_exploitation'::text],
    fireteam_confirmation_timeout_sec integer DEFAULT 600 NOT NULL,
    fireteam_propensity integer DEFAULT 3 NOT NULL,
    agent_lats_enabled boolean DEFAULT false NOT NULL,
    agent_lats_shadow_mode boolean DEFAULT false NOT NULL,
    agent_lats_phase_exploitation boolean DEFAULT true NOT NULL,
    agent_lats_phase_post_expl boolean DEFAULT false NOT NULL,
    agent_lats_min_hypotheses integer DEFAULT 2 NOT NULL,
    agent_lats_branching integer DEFAULT 6 NOT NULL,
    agent_lats_max_depth integer DEFAULT 6 NOT NULL,
    agent_lats_max_rollouts integer DEFAULT 50 NOT NULL,
    agent_lats_max_tree_nodes integer DEFAULT 120 NOT NULL,
    agent_lats_uct_c double precision DEFAULT 1.4 NOT NULL,
    agent_lats_prune_floor double precision DEFAULT 0.15 NOT NULL,
    hydra_enabled boolean DEFAULT true NOT NULL,
    hydra_threads integer DEFAULT 16 NOT NULL,
    hydra_wait_between_connections integer DEFAULT 0 NOT NULL,
    hydra_connection_timeout integer DEFAULT 32 NOT NULL,
    hydra_stop_on_first_found boolean DEFAULT true NOT NULL,
    hydra_extra_checks text DEFAULT 'nsr'::text NOT NULL,
    hydra_verbose boolean DEFAULT true NOT NULL,
    hydra_max_wordlist_attempts integer DEFAULT 3 NOT NULL,
    shodan_enabled boolean DEFAULT true NOT NULL,
    shodan_host_lookup boolean DEFAULT true NOT NULL,
    shodan_reverse_dns boolean DEFAULT true NOT NULL,
    shodan_domain_dns boolean DEFAULT false NOT NULL,
    shodan_passive_cves boolean DEFAULT true NOT NULL,
    shodan_workers integer DEFAULT 5 NOT NULL,
    urlscan_enabled boolean DEFAULT true NOT NULL,
    urlscan_max_results integer DEFAULT 10000 NOT NULL,
    urlscan_max_searches integer DEFAULT 60 NOT NULL,
    urlscan_inject_max_age_days integer DEFAULT 90 NOT NULL,
    urlscan_max_injected_hosts integer DEFAULT 200 NOT NULL,
    urlscan_leaked_links boolean DEFAULT true NOT NULL,
    urlscan_secrets_in_urls boolean DEFAULT true NOT NULL,
    urlscan_sensitive_files boolean DEFAULT true NOT NULL,
    urlscan_document_links boolean DEFAULT true NOT NULL,
    urlscan_redirect_search boolean DEFAULT false NOT NULL,
    urlscan_takeover_pages boolean DEFAULT true NOT NULL,
    urlscan_problem_pages boolean DEFAULT true NOT NULL,
    osint_enrichment_enabled boolean DEFAULT false NOT NULL,
    censys_enabled_recon boolean DEFAULT false NOT NULL,
    fofa_enabled boolean DEFAULT false NOT NULL,
    fofa_max_results integer DEFAULT 1000 NOT NULL,
    otx_enabled boolean DEFAULT true NOT NULL,
    netlas_enabled boolean DEFAULT false NOT NULL,
    virustotal_enabled boolean DEFAULT false NOT NULL,
    zoomeye_enabled boolean DEFAULT false NOT NULL,
    zoomeye_max_results integer DEFAULT 1000 NOT NULL,
    criminalip_enabled boolean DEFAULT false NOT NULL,
    otx_workers integer DEFAULT 5 NOT NULL,
    virustotal_workers integer DEFAULT 3 NOT NULL,
    censys_workers integer DEFAULT 5 NOT NULL,
    criminalip_workers integer DEFAULT 5 NOT NULL,
    fofa_workers integer DEFAULT 5 NOT NULL,
    netlas_workers integer DEFAULT 5 NOT NULL,
    zoomeye_workers integer DEFAULT 5 NOT NULL,
    uncover_enabled boolean DEFAULT false NOT NULL,
    uncover_max_results integer DEFAULT 50000 NOT NULL,
    subdomain_discovery_enabled boolean DEFAULT true NOT NULL,
    domain_recon_ai_txt_hint_enabled boolean DEFAULT true NOT NULL,
    domain_recon_ai_ns_hint_enabled boolean DEFAULT true NOT NULL,
    crtsh_enabled boolean DEFAULT true NOT NULL,
    crtsh_max_results integer DEFAULT 5000 NOT NULL,
    hacker_target_enabled boolean DEFAULT true NOT NULL,
    hacker_target_max_results integer DEFAULT 5000 NOT NULL,
    knockpy_recon_enabled boolean DEFAULT true NOT NULL,
    knockpy_recon_max_results integer DEFAULT 5000 NOT NULL,
    subfinder_enabled boolean DEFAULT true NOT NULL,
    subfinder_max_results integer DEFAULT 5000 NOT NULL,
    amass_enabled boolean DEFAULT false NOT NULL,
    amass_max_results integer DEFAULT 50000 NOT NULL,
    amass_timeout integer DEFAULT 10 NOT NULL,
    amass_active boolean DEFAULT false NOT NULL,
    amass_brute boolean DEFAULT false NOT NULL,
    amass_brute_wordlists jsonb DEFAULT '["default"]'::jsonb NOT NULL,
    puredns_enabled boolean DEFAULT true NOT NULL,
    puredns_threads integer DEFAULT 0 NOT NULL,
    puredns_rate_limit integer DEFAULT 0 NOT NULL,
    puredns_wildcard_batch integer DEFAULT 0 NOT NULL,
    puredns_skip_validation boolean DEFAULT false NOT NULL,
    phishing_smtp_config text DEFAULT ''::text NOT NULL,
    dos_max_duration integer DEFAULT 60 NOT NULL,
    dos_max_attempts integer DEFAULT 3 NOT NULL,
    dos_concurrent_connections integer DEFAULT 1000 NOT NULL,
    dos_assessment_only boolean DEFAULT false NOT NULL,
    sqli_level integer DEFAULT 1 NOT NULL,
    sqli_risk integer DEFAULT 1 NOT NULL,
    sqli_tamper_scripts text DEFAULT ''::text NOT NULL,
    ssrf_oob_callback_enabled boolean DEFAULT true NOT NULL,
    ssrf_cloud_metadata_enabled boolean DEFAULT true NOT NULL,
    ssrf_gopher_enabled boolean DEFAULT true NOT NULL,
    ssrf_dns_rebinding_enabled boolean DEFAULT true NOT NULL,
    ssrf_payload_reference_enabled boolean DEFAULT true NOT NULL,
    ssrf_request_timeout integer DEFAULT 10 NOT NULL,
    ssrf_port_scan_ports text DEFAULT '22,80,443,2375,3306,5432,6379,8080,8500,9200,27017'::text NOT NULL,
    ssrf_internal_ranges text DEFAULT '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16'::text NOT NULL,
    ssrf_oob_provider text DEFAULT 'oast.fun'::text NOT NULL,
    ssrf_cloud_providers text DEFAULT 'aws,gcp,azure,digitalocean,alibaba'::text NOT NULL,
    ssrf_custom_internal_targets text DEFAULT ''::text NOT NULL,
    rce_oob_callback_enabled boolean DEFAULT true NOT NULL,
    rce_deserialization_enabled boolean DEFAULT true NOT NULL,
    rce_aggressive_payloads boolean DEFAULT false NOT NULL,
    rce_heapdump_analysis_enabled boolean DEFAULT false NOT NULL,
    path_traversal_oob_callback_enabled boolean DEFAULT true NOT NULL,
    path_traversal_php_wrappers_enabled boolean DEFAULT true NOT NULL,
    path_traversal_archive_extraction_enabled boolean DEFAULT false NOT NULL,
    path_traversal_payload_reference_enabled boolean DEFAULT true NOT NULL,
    path_traversal_request_timeout integer DEFAULT 10 NOT NULL,
    path_traversal_oob_provider text DEFAULT 'oast.fun'::text NOT NULL,
    path_traversal_git_reconstruct_enabled boolean DEFAULT false NOT NULL,
    path_traversal_validate_secrets_enabled boolean DEFAULT false NOT NULL,
    deserialization_oob_callback_enabled boolean DEFAULT true NOT NULL,
    deserialization_oob_provider text DEFAULT 'oast.fun'::text NOT NULL,
    deserialization_timing_enabled boolean DEFAULT true NOT NULL,
    deserialization_find_sinks_enabled boolean DEFAULT true NOT NULL,
    deserialization_runtimes text DEFAULT 'java,java_typed,python,php,node,ruby,dotnet'::text NOT NULL,
    deserialization_exec_gadgets_enabled boolean DEFAULT false NOT NULL,
    deserialization_phar_enabled boolean DEFAULT false NOT NULL,
    attack_skill_config jsonb DEFAULT '{"user": {}, "builtIn": {"rce": true, "xss": true, "xxe": true, "ssrf": true, "cve_exploit": true, "crypto_attack": true, "sql_injection": true, "access_control": true, "path_traversal": true, "deserialization": false, "denial_of_service": false, "http_request_smuggling": false, "phishing_social_engineering": false, "brute_force_credential_guess": false}}'::jsonb NOT NULL,
    cypherfix_github_token text DEFAULT ''::text NOT NULL,
    cypherfix_default_repo text DEFAULT ''::text NOT NULL,
    cypherfix_default_branch text DEFAULT 'main'::text NOT NULL,
    cypherfix_branch_prefix text DEFAULT 'cypherfix/'::text NOT NULL,
    cypherfix_require_approval boolean DEFAULT true NOT NULL,
    cypherfix_llm_model text DEFAULT ''::text NOT NULL,
    triage_review_budget integer DEFAULT 150 NOT NULL,
    engagement_kind text DEFAULT 'internal'::text NOT NULL,
    engagement_identity_header text DEFAULT ''::text NOT NULL,
    roe_enabled boolean DEFAULT false NOT NULL,
    roe_raw_text text DEFAULT ''::text NOT NULL,
    roe_document_name text DEFAULT ''::text NOT NULL,
    roe_document_data bytea,
    roe_document_mime_type text DEFAULT ''::text NOT NULL,
    roe_parsed_json jsonb,
    roe_client_name text DEFAULT ''::text NOT NULL,
    roe_client_contact_name text DEFAULT ''::text NOT NULL,
    roe_client_contact_email text DEFAULT ''::text NOT NULL,
    roe_client_contact_phone text DEFAULT ''::text NOT NULL,
    roe_emergency_contact text DEFAULT ''::text NOT NULL,
    roe_engagement_start_date text DEFAULT ''::text NOT NULL,
    roe_engagement_end_date text DEFAULT ''::text NOT NULL,
    roe_engagement_type text DEFAULT 'external'::text NOT NULL,
    roe_excluded_hosts text[] DEFAULT ARRAY[]::text[],
    roe_excluded_host_reasons text[] DEFAULT ARRAY[]::text[],
    roe_time_window_enabled boolean DEFAULT false NOT NULL,
    roe_time_window_timezone text DEFAULT 'UTC'::text NOT NULL,
    roe_time_window_days text[] DEFAULT ARRAY['monday'::text, 'tuesday'::text, 'wednesday'::text, 'thursday'::text, 'friday'::text],
    roe_time_window_start_time text DEFAULT '09:00'::text NOT NULL,
    roe_time_window_end_time text DEFAULT '18:00'::text NOT NULL,
    roe_forbidden_tools text[] DEFAULT ARRAY[]::text[],
    roe_forbidden_categories text[] DEFAULT ARRAY[]::text[],
    roe_max_severity_phase text DEFAULT 'post_exploitation'::text NOT NULL,
    roe_allow_dos boolean DEFAULT false NOT NULL,
    roe_allow_social_engineering boolean DEFAULT false NOT NULL,
    roe_allow_physical_access boolean DEFAULT false NOT NULL,
    roe_allow_data_exfiltration boolean DEFAULT false NOT NULL,
    roe_allow_account_lockout boolean DEFAULT false NOT NULL,
    roe_allow_production_testing boolean DEFAULT true NOT NULL,
    roe_global_max_rps integer DEFAULT 0 NOT NULL,
    roe_sensitive_data_handling text DEFAULT 'no_access'::text NOT NULL,
    roe_data_retention_days integer DEFAULT 90 NOT NULL,
    roe_require_data_encryption boolean DEFAULT true NOT NULL,
    roe_status_update_frequency text DEFAULT 'daily'::text NOT NULL,
    roe_critical_finding_notify boolean DEFAULT true NOT NULL,
    roe_incident_procedure text DEFAULT ''::text NOT NULL,
    roe_third_party_providers text[] DEFAULT ARRAY[]::text[],
    roe_compliance_frameworks text[] DEFAULT ARRAY[]::text[],
    roe_notes text DEFAULT ''::text NOT NULL,
    capture_proxy_enabled boolean DEFAULT false NOT NULL,
    activation_state text DEFAULT 'idle'::text NOT NULL,
    activation_started_at timestamp(3) without time zone,
    activation_version_id text
);


--
-- Name: recording_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recording_sessions (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    scope_hosts text[] DEFAULT ARRAY[]::text[],
    started_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at timestamp(3) without time zone NOT NULL,
    stopped_at timestamp(3) without time zone,
    observed_count integer DEFAULT 0 NOT NULL,
    last_error text,
    pending_material jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: remediations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediations (
    id text NOT NULL,
    project_id text NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    severity text DEFAULT 'medium'::text NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    category text DEFAULT 'vulnerability'::text NOT NULL,
    remediation_type text DEFAULT 'code_fix'::text NOT NULL,
    affected_assets jsonb DEFAULT '[]'::jsonb NOT NULL,
    cvss_score double precision,
    cve_ids text[] DEFAULT ARRAY[]::text[],
    cwe_ids text[] DEFAULT ARRAY[]::text[],
    capec_ids text[] DEFAULT ARRAY[]::text[],
    evidence text DEFAULT ''::text NOT NULL,
    attack_chain_path text DEFAULT ''::text NOT NULL,
    exploit_available boolean DEFAULT false NOT NULL,
    cisa_kev boolean DEFAULT false NOT NULL,
    solution text DEFAULT ''::text NOT NULL,
    fix_complexity text DEFAULT 'medium'::text NOT NULL,
    estimated_files integer DEFAULT 0 NOT NULL,
    target_repo text DEFAULT ''::text NOT NULL,
    target_branch text DEFAULT 'main'::text NOT NULL,
    fix_branch text DEFAULT ''::text NOT NULL,
    pr_url text DEFAULT ''::text NOT NULL,
    pr_status text DEFAULT 'none'::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    agent_session_id text DEFAULT ''::text NOT NULL,
    agent_notes text DEFAULT ''::text NOT NULL,
    file_changes jsonb DEFAULT '[]'::jsonb NOT NULL,
    group_key text,
    finding_ids text[] DEFAULT ARRAY[]::text[],
    live_member_count integer DEFAULT 0 NOT NULL,
    priority_score double precision DEFAULT 0 NOT NULL,
    triage_run_id text DEFAULT ''::text NOT NULL,
    still_detected boolean DEFAULT false NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reports (
    id text NOT NULL,
    project_id text NOT NULL,
    title text NOT NULL,
    filename text NOT NULL,
    file_path text NOT NULL,
    file_size integer NOT NULL,
    format text DEFAULT 'html'::text NOT NULL,
    metrics jsonb DEFAULT '{}'::jsonb NOT NULL,
    has_narratives boolean DEFAULT false NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: roe_document_revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roe_document_revisions (
    id text NOT NULL,
    project_id text NOT NULL,
    document_name text NOT NULL,
    mime_type text NOT NULL,
    data bytea,
    bytes_sha256 text NOT NULL,
    text_sha256 text NOT NULL,
    raw_text text NOT NULL,
    parsed_json jsonb,
    applied_at timestamp(3) without time zone,
    superseded_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    superseded_by_id text NOT NULL,
    reason text NOT NULL
);


--
-- Name: scan_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_jobs (
    id text NOT NULL,
    project_id text NOT NULL,
    version_id text,
    kind text DEFAULT 'full_recon'::text NOT NULL,
    run_id text DEFAULT ''::text NOT NULL,
    trigger text DEFAULT 'manual'::text NOT NULL,
    mode text,
    status text DEFAULT 'queued'::text NOT NULL,
    initiated_by_user_id text,
    started_at timestamp(3) without time zone,
    finished_at timestamp(3) without time zone,
    schedule_id text,
    ram_reason text,
    node_count integer,
    settings_hash text,
    authorization_id text,
    targets text[] DEFAULT ARRAY[]::text[],
    degraded_sources integer,
    roe_text_sha256 text,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: scan_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_schedules (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    mode text DEFAULT 'once'::text NOT NULL,
    run_at timestamp(3) without time zone,
    interval_minutes integer,
    cron_expr text,
    scan_mode text DEFAULT 'new'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    next_run_at timestamp(3) without time zone,
    last_run_at timestamp(3) without time zone,
    estimated_envelope_bytes bigint,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: scan_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_versions (
    id text NOT NULL,
    project_id text NOT NULL,
    seq integer NOT NULL,
    label text NOT NULL,
    is_current boolean DEFAULT false NOT NULL,
    pinned boolean DEFAULT false NOT NULL,
    node_count integer,
    link_count integer,
    summary jsonb,
    snapshot bytea,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: supply_chain_batch_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supply_chain_batch_items (
    id text NOT NULL,
    batch_id text NOT NULL,
    repo_full_name text NOT NULL,
    repo_url text NOT NULL,
    ref text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    job_id text,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: supply_chain_batches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supply_chain_batches (
    id text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    org text NOT NULL,
    host text DEFAULT 'github.com'::text NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    total_items integer DEFAULT 0 NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: triage_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.triage_runs (
    id text NOT NULL,
    project_id text NOT NULL,
    actor_user_id text NOT NULL,
    real_actor_user_id text,
    status text DEFAULT 'running'::text NOT NULL,
    started_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    heartbeat_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    finished_at timestamp(3) without time zone,
    model text DEFAULT ''::text NOT NULL,
    score_model_version text DEFAULT ''::text NOT NULL,
    intel_date timestamp(3) without time zone,
    summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    error_class text DEFAULT ''::text NOT NULL,
    trigger text DEFAULT 'app'::text NOT NULL,
    token_id text,
    phase text DEFAULT ''::text NOT NULL,
    progress integer DEFAULT 0 NOT NULL
);


--
-- Name: trufflehog_scan_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trufflehog_scan_profiles (
    id text NOT NULL,
    project_id text NOT NULL,
    source text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: user_attack_skills; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_attack_skills (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    description text,
    content text NOT NULL,
    derived_from_id text,
    lineage_root_id text,
    version integer,
    origin_change_set_id text,
    origin_plugin_id text,
    origin_plugin_version text,
    origin_chain text[] DEFAULT ARRAY[]::text[],
    quarantined_at timestamp(3) without time zone,
    quarantine_reason text,
    quarantined_for text,
    released_for text[] DEFAULT ARRAY[]::text[],
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: user_chat_skills; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_chat_skills (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    description text,
    category text DEFAULT 'general'::text NOT NULL,
    content text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: user_llm_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_llm_providers (
    id text NOT NULL,
    user_id text NOT NULL,
    provider_type text NOT NULL,
    name text NOT NULL,
    api_key text DEFAULT ''::text NOT NULL,
    base_url text DEFAULT ''::text NOT NULL,
    model_identifier text DEFAULT ''::text NOT NULL,
    default_headers jsonb DEFAULT '{}'::jsonb NOT NULL,
    timeout integer DEFAULT 120 NOT NULL,
    temperature double precision DEFAULT 0 NOT NULL,
    max_tokens integer DEFAULT 16384 NOT NULL,
    ssl_verify boolean DEFAULT true NOT NULL,
    reasoning_enabled boolean DEFAULT false NOT NULL,
    reasoning_effort text DEFAULT 'high'::text NOT NULL,
    aws_region text DEFAULT 'us-east-1'::text NOT NULL,
    aws_access_key_id text DEFAULT ''::text NOT NULL,
    aws_secret_key text DEFAULT ''::text NOT NULL,
    aws_bearer_token text DEFAULT ''::text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    created_by_id text,
    updated_by_id text
);


--
-- Name: user_mute_rules_presets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_mute_rules_presets (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    mode text DEFAULT 'denylist'::text NOT NULL,
    rules jsonb NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: user_project_presets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_project_presets (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    settings jsonb NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    created_via text DEFAULT 'ui'::text NOT NULL,
    updated_via text DEFAULT 'ui'::text NOT NULL,
    last_writer_token_prefix text
);


--
-- Name: user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_settings (
    id text NOT NULL,
    user_id text NOT NULL,
    github_access_token text DEFAULT ''::text NOT NULL,
    supply_chain_github_token text DEFAULT ''::text NOT NULL,
    trufflehog_github_token text DEFAULT ''::text NOT NULL,
    trufflehog_gitlab_token text DEFAULT ''::text NOT NULL,
    trufflehog_docker_token text DEFAULT ''::text NOT NULL,
    trufflehog_huggingface_token text DEFAULT ''::text NOT NULL,
    trufflehog_aws_access_key_id text DEFAULT ''::text NOT NULL,
    trufflehog_aws_secret_key text DEFAULT ''::text NOT NULL,
    trufflehog_aws_session_token text DEFAULT ''::text NOT NULL,
    trufflehog_gcp_service_account text DEFAULT ''::text NOT NULL,
    trufflehog_postman_token text DEFAULT ''::text NOT NULL,
    trufflehog_jenkins_username text DEFAULT ''::text NOT NULL,
    trufflehog_jenkins_password text DEFAULT ''::text NOT NULL,
    trufflehog_elastic_username text DEFAULT ''::text NOT NULL,
    trufflehog_elastic_password text DEFAULT ''::text NOT NULL,
    trufflehog_elastic_api_key text DEFAULT ''::text NOT NULL,
    trufflehog_elastic_service_token text DEFAULT ''::text NOT NULL,
    trufflehog_circleci_token text DEFAULT ''::text NOT NULL,
    trufflehog_travisci_token text DEFAULT ''::text NOT NULL,
    trufflehog_git_username text DEFAULT ''::text NOT NULL,
    trufflehog_git_token text DEFAULT ''::text NOT NULL,
    github_enterprise_host text DEFAULT ''::text NOT NULL,
    github_enterprise_token text DEFAULT ''::text NOT NULL,
    tavily_api_key text DEFAULT ''::text NOT NULL,
    shodan_api_key text DEFAULT ''::text NOT NULL,
    serp_api_key text DEFAULT ''::text NOT NULL,
    nvd_api_key text DEFAULT ''::text NOT NULL,
    vulners_api_key text DEFAULT ''::text NOT NULL,
    urlscan_api_key text DEFAULT ''::text NOT NULL,
    censys_api_token text DEFAULT ''::text NOT NULL,
    censys_org_id text DEFAULT ''::text NOT NULL,
    fofa_api_key text DEFAULT ''::text NOT NULL,
    otx_api_key text DEFAULT ''::text NOT NULL,
    netlas_api_key text DEFAULT ''::text NOT NULL,
    virustotal_api_key text DEFAULT ''::text NOT NULL,
    zoomeye_api_key text DEFAULT ''::text NOT NULL,
    criminalip_api_key text DEFAULT ''::text NOT NULL,
    quake_api_key text DEFAULT ''::text NOT NULL,
    hunter_api_key text DEFAULT ''::text NOT NULL,
    publicwww_api_key text DEFAULT ''::text NOT NULL,
    hunterhow_api_key text DEFAULT ''::text NOT NULL,
    google_api_key text DEFAULT ''::text NOT NULL,
    google_api_cx text DEFAULT ''::text NOT NULL,
    onyphe_api_key text DEFAULT ''::text NOT NULL,
    driftnet_api_key text DEFAULT ''::text NOT NULL,
    wpscan_api_token text DEFAULT ''::text NOT NULL,
    pdcp_api_key text DEFAULT ''::text NOT NULL,
    securitytrails_api_key text DEFAULT ''::text NOT NULL,
    viewdns_api_key text DEFAULT ''::text NOT NULL,
    tunnels_enabled boolean DEFAULT false NOT NULL,
    ngrok_authtoken text DEFAULT ''::text NOT NULL,
    chisel_server_url text DEFAULT ''::text NOT NULL,
    chisel_auth text DEFAULT ''::text NOT NULL,
    mcp_servers jsonb DEFAULT '[]'::jsonb NOT NULL,
    capture_proxy_enabled boolean DEFAULT true NOT NULL,
    capture_proxy_port integer DEFAULT 8888 NOT NULL,
    capture_proxy_scope text DEFAULT 'both'::text NOT NULL,
    capture_proxy_store_bodies boolean DEFAULT true NOT NULL,
    capture_proxy_max_body_kb integer DEFAULT 64 NOT NULL,
    capture_proxy_retention_days integer DEFAULT 14 NOT NULL,
    capture_proxy_redact_secrets boolean DEFAULT true NOT NULL,
    capture_proxy_passive_detect boolean DEFAULT true NOT NULL,
    capture_proxy_store_req_bodies boolean DEFAULT true NOT NULL,
    capture_proxy_store_resp_bodies boolean DEFAULT true NOT NULL,
    capture_proxy_max_store_mb integer DEFAULT 5 NOT NULL,
    capture_proxy_body_rules jsonb DEFAULT '{}'::jsonb NOT NULL,
    capture_egress_block_empty_host boolean DEFAULT true NOT NULL,
    capture_egress_block_hard_guardrail boolean DEFAULT true NOT NULL,
    capture_egress_fail_closed boolean DEFAULT true NOT NULL,
    capture_egress_block_unresolvable boolean DEFAULT true NOT NULL,
    capture_egress_block_private boolean DEFAULT true NOT NULL,
    capture_egress_block_loopback boolean DEFAULT true NOT NULL,
    capture_egress_block_link_local boolean DEFAULT true NOT NULL,
    capture_egress_block_cgnat boolean DEFAULT true NOT NULL,
    capture_egress_block_reserved boolean DEFAULT true NOT NULL,
    capture_egress_block_multicast boolean DEFAULT true NOT NULL,
    capture_egress_block_unspecified boolean DEFAULT true NOT NULL,
    sca_intel_ignore_suffixes text DEFAULT 'oastify.com,oast.fun,mburpcollab.com,canarytokens.com,pipedream.net'::text NOT NULL,
    feature_models jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: user_tradecraft_resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_tradecraft_resources (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    url text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    resource_type text DEFAULT 'agentic-crawl'::text NOT NULL,
    summary text DEFAULT ''::text NOT NULL,
    sitemap jsonb DEFAULT '{}'::jsonb NOT NULL,
    crawl_stopped_because text DEFAULT ''::text NOT NULL,
    crawl_stats jsonb DEFAULT '{}'::jsonb NOT NULL,
    llm_model text DEFAULT ''::text NOT NULL,
    github_token_override text DEFAULT ''::text NOT NULL,
    cache_ttl_sec integer DEFAULT 0 NOT NULL,
    last_verified_at timestamp(3) without time zone,
    last_refreshed_at timestamp(3) without time zone,
    last_error text DEFAULT ''::text NOT NULL,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id text NOT NULL,
    name text NOT NULL,
    email text NOT NULL,
    password text DEFAULT ''::text NOT NULL,
    role text DEFAULT 'standard'::text NOT NULL,
    ui_preferences jsonb DEFAULT '{}'::jsonb NOT NULL,
    default_agent_model text,
    default_ai_pipeline_model text,
    created_at timestamp(3) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp(3) without time zone NOT NULL,
    created_by_id text,
    updated_by_id text
);


--
-- Data for Name: act_as_audit; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.act_as_audit (id, admin_id, target_user_id, event, source, created_at) FROM stdin;
\.


--
-- Data for Name: api_key_rotation_configs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.api_key_rotation_configs (id, user_id, tool_name, extra_keys, rotate_every_n, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: api_usage_reports; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.api_usage_reports (id, user_id, schema_version, started_at, finished_at, report, created_at, updated_at, created_by_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.audit_log (id, actor_id, action, target_type, target_id, before, after, source, created_at) FROM stdin;
cmwbat97u0000p86i8o63i86v	\N	system.user_skill_toggles_cutoff	system	\N	\N	\N	system	2026-11-10 23:05:33.931
cmwbat98l0001p86i95ijuqgn	\N	system.user_skill_toggles_backfill	system	\N	\N	{"presets": 0, "projects": 0, "keysWritten": 0}	system	2026-11-10 23:05:33.958
cmwbat9cn0000p877t93t4973	\N	system.jev_provider_selection_cutoff	system	\N	\N	\N	system	2026-11-10 23:05:34.103
cmwbat9cz0001p877mzex0zyt	\N	system.jev_provider_selection_backfill	system	\N	\N	{"owners": 0, "projects": 0, "ambiguousOwners": 0}	system	2026-11-10 23:05:34.116
\.


--
-- Data for Name: captured_http_transactions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.captured_http_transactions (id, project_id, user_id, source, run_id, session_id, member_id, tool, phase, step_id, method, scheme, host, port, path, query, req_headers, req_body, req_body_ref, req_body_size, req_content_type, status_code, resp_headers, resp_body, resp_body_ref, resp_body_size, resp_content_type, req_body_sha256, resp_body_sha256, response_time_ms, target_ip, http_version, is_tls, tls_version, flow_ref, is_replay, origin_id, in_scope, blocked, error_text, redacted, redacted_fields, has_set_cookie, had_auth, reflected_params, security_headers_missing, cookie_flag_issues, labels, finding_id, ioc_incident_id, ioc_incident_url, started_at, created_at) FROM stdin;
\.


--
-- Data for Name: chat_messages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.chat_messages (id, conversation_id, sequence_num, type, data, member_id_key, fireteam_id_key, created_at) FROM stdin;
\.


--
-- Data for Name: checkpoint_blobs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.checkpoint_blobs (thread_id, checkpoint_ns, channel, version, type, blob) FROM stdin;
\.


--
-- Data for Name: checkpoint_migrations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.checkpoint_migrations (v) FROM stdin;
\.


--
-- Data for Name: checkpoint_writes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.checkpoint_writes (thread_id, checkpoint_ns, checkpoint_id, task_id, idx, channel, type, blob, task_path) FROM stdin;
\.


--
-- Data for Name: checkpoints; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.checkpoints (thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, type, checkpoint, metadata) FROM stdin;
\.


--
-- Data for Name: conversations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.conversations (id, project_id, user_id, session_id, title, status, agent_running, current_phase, iteration_count, active_skill_id, created_at, updated_at, created_by_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: engagement_authorization_archive; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.engagement_authorization_archive (id, project_id, document_sha256, document_kind, source_url, program_handle, issued_at, recorded_at, recorded_via, recorded_by_token_id, recorded_by_user_id, summary, archived_at, archived_reason) FROM stdin;
\.


--
-- Data for Name: engagement_authorizations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.engagement_authorizations (id, project_id, document_sha256, document_kind, source_url, program_handle, issued_at, recorded_at, recorded_via, recorded_by_token_id, recorded_by_user_id, summary, idempotency_key) FROM stdin;
\.


--
-- Data for Name: fireteam_members; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fireteam_members (id, fireteam_id, member_id_key, name, task, skills, status, completion_reason, iterations_used, tokens_used, findings_count, wall_clock_seconds, error_message, result_blob, started_at, completed_at) FROM stdin;
\.


--
-- Data for Name: fireteam_settings_audit; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fireteam_settings_audit (id, project_id, user_id, field, old_value, new_value, source, created_at) FROM stdin;
\.


--
-- Data for Name: fireteams; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fireteams (id, parent_conversation_id, parent_session_id, fireteam_id_key, fireteam_number, iteration, status, member_count, plan_rationale, status_counts, wall_clock_seconds, started_at, completed_at) FROM stdin;
\.


--
-- Data for Name: graph_views; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.graph_views (id, project_id, name, description, cypher_query, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: job_queue; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.job_queue (id, project_id, user_id, kind, payload, settings_hash, envelope_bytes, priority, status, attempts, max_attempts, not_before, blocked_code, blocked_reason, run_id, scan_job_id, schedule_id, batch_id, error, enqueued_at, dispatched_at, started_at, finished_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: mcp_access_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mcp_access_tokens (id, user_id, name, token_prefix, token_hash, scopes, profile, last_used_at, expires_at, revoked_at, created_at) FROM stdin;
\.


--
-- Data for Name: node_filter_exemptions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.node_filter_exemptions (id, project_id, label, node_key, created_by, real_actor_user_id, created_at) FROM stdin;
\.


--
-- Data for Name: node_filter_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.node_filter_runs (id, project_id, actor_user_id, real_actor_user_id, status, target, version_id, revision, rules, mode, stats, error, started_at, heartbeat_at, finished_at) FROM stdin;
\.


--
-- Data for Name: plugin_data; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.plugin_data (id, plugin_id, namespace, owner_type, owner_id, user_id, project_id, collection, key, value, size_bytes, expires_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: plugin_installs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.plugin_installs (plugin_id, enabled, status, active_version, previous_version, pending_version, data_version, previous_data_version, granted_permissions, manifest, catalog_entry, installed_by, installed_at, operation_id, operation_kind, operation_args, lease_expires_at, last_error, revoked_reason, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: plugin_overrides; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.plugin_overrides (id, plugin_id, extension_point, scope_type, scope_id, user_id, project_id, target_group, target_key, change_set_id, revision, value, base_sha256, status, note, meta, created_by, decided_by, decided_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: plugin_platform_state; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.plugin_platform_state (key, value, updated_at) FROM stdin;
\.


--
-- Data for Name: project_auth_profiles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.project_auth_profiles (id, project_id, user_id, auth_type, auth_header_name, auth_value, extra_headers, scope_hosts, recon_enabled, agent_enabled, source, status, last_validated_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: project_node_filters; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.project_node_filters (project_id, mode, apply_to_scans, rules, revision, loaded_preset, updated_by, updated_at) FROM stdin;
\.


--
-- Data for Name: projects; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.projects (id, user_id, name, description, created_at, updated_at, created_by_id, updated_by_id, target_domain, subdomain_list, ip_mode, target_ips, domain_batch_mode, domain_batch_hosts, domain_batch_groups, verify_domain_ownership, ownership_token, ownership_txt_prefix, stealth_mode, target_guardrail_enabled, ai_in_pipeline, ai_pipeline_model, jev_provider_id, recon_preset_id, loaded_preset, scan_modules, update_graph_db, use_bruteforce_for_subdomains, whois_enabled, whois_max_retries, dns_enabled, dns_max_retries, dns_max_workers, dns_record_parallelism, github_target_org, github_target_repos, github_scan_members, github_scan_gists, github_scan_commits, github_max_commits, github_output_json, trufflehog_enabled, trufflehog_result_types, trufflehog_no_verification, trufflehog_concurrency, trufflehog_include_detectors, trufflehog_exclude_detectors, trufflehog_filter_entropy, trufflehog_detector_timeout, trufflehog_max_decode_depth, trufflehog_force_skip_binaries, trufflehog_force_skip_archives, trufflehog_archive_max_size, trufflehog_archive_max_depth, trufflehog_archive_timeout, trufflehog_allow_verification_overlap, trufflehog_drop_unverified_jwt, supply_chain_sbom_file, supply_chain_ecosystems, supply_chain_deep_analysis_enabled, supply_chain_input_mode, supply_chain_repo_url, supply_chain_repo_ref, supply_chain_repo_scope, supply_chain_org_name, supply_chain_org_include_forks, supply_chain_org_include_archived, supply_chain_org_max_repos, supply_chain_org_ref, supply_chain_org_deep_analysis_enabled, supply_chain_recon_enabled, supply_chain_recon_ecosystems, supply_chain_recon_deep_analysis_enabled, sca_intel_correlation_enabled, supply_chain_typosquat_enabled, naabu_enabled, naabu_top_ports, naabu_custom_ports, naabu_rate_limit, naabu_threads, naabu_timeout, naabu_retries, naabu_scan_type, naabu_exclude_cdn, naabu_display_cdn, naabu_skip_host_discovery, naabu_verify_ports, naabu_passive_mode, port_scan_ai_port_catalog_enabled, masscan_enabled, masscan_top_ports, masscan_custom_ports, masscan_rate, masscan_banners, masscan_wait, masscan_retries, masscan_exclude_targets, masscan_ai_port_catalog_enabled, nmap_enabled, nmap_version_detection, nmap_script_scan, nmap_timing_template, nmap_timeout, nmap_host_timeout, nmap_parallelism, nmap_ai_version_regex_enabled, httpx_enabled, httpx_threads, httpx_timeout, httpx_retries, httpx_rate_limit, httpx_follow_redirects, httpx_max_redirects, httpx_probe_status_code, httpx_probe_content_length, httpx_probe_content_type, httpx_probe_title, httpx_probe_server, httpx_probe_response_time, httpx_probe_word_count, httpx_probe_line_count, httpx_probe_tech_detect, httpx_probe_ip, httpx_probe_cname, httpx_probe_tls_info, httpx_probe_tls_grab, httpx_probe_favicon, httpx_probe_jarm, httpx_probe_hash, httpx_include_response, httpx_include_response_headers, httpx_jev_page_type, httpx_probe_asn, httpx_probe_cdn, httpx_paths, httpx_custom_headers, httpx_match_codes, httpx_filter_codes, http_probe_ai_header_scan_enabled, http_probe_ai_favicon_hash_enabled, http_probe_ai_title_detection_enabled, http_probe_ai_wappalyzer_enabled, ip_attribution_enabled, ip_attribution_tls_max_probes, wappalyzer_enabled, wappalyzer_min_confidence, wappalyzer_require_html, wappalyzer_auto_update, wappalyzer_npm_version, wappalyzer_cache_ttl_hours, banner_grab_enabled, banner_grab_timeout, banner_grab_threads, banner_grab_max_length, nuclei_enabled, nuclei_severity, nuclei_templates, nuclei_exclude_templates, nuclei_custom_templates, nuclei_selected_custom_templates, nuclei_rate_limit, nuclei_bulk_size, nuclei_concurrency, nuclei_timeout, nuclei_retries, nuclei_max_runtime, nuclei_max_host_error, nuclei_tags, nuclei_exclude_tags, nuclei_dast_mode, nuclei_auto_update_templates, nuclei_new_templates_only, nuclei_headless, nuclei_system_resolvers, nuclei_follow_redirects, nuclei_max_redirects, nuclei_scan_all_ips, nuclei_interactsh, nuclei_ai_tags, nuclei_tags_ai_use_jev, nuclei_ai_response_filter, subdomain_takeover_enabled, subjack_enabled, subjack_threads, subjack_timeout, subjack_ssl, subjack_all, subjack_check_ns, subjack_check_ar, subjack_check_mail, subjack_run_timeout, nuclei_takeovers_enabled, nuclei_takeover_run_timeout, takeover_ai_classifier, takeover_ai_use_jev, takeover_severity, takeover_confidence_threshold, takeover_rate_limit, takeover_manual_review_auto_publish, takeover_cert_validation_enabled, baddns_enabled, baddns_modules, baddns_nameservers, baddns_run_timeout, vhost_sni_enabled, vhost_sni_timeout, vhost_sni_concurrency, vhost_sni_baseline_size_tolerance, vhost_sni_test_l7, vhost_sni_test_l4, vhost_sni_inject_discovered, vhost_sni_use_default_wordlist, vhost_sni_use_graph_candidates, vhost_sni_custom_wordlist, vhost_sni_max_candidates_per_ip, tlsx_enabled, tlsx_scan_mode, tlsx_concurrency, tlsx_timeout, tlsx_run_timeout, tlsx_retries, tlsx_max_injected_hostnames, tlsx_delay, tlsx_include_http_ports, tlsx_inject_hostnames, tlsx_rev_ptr_sni, tlsx_max_hostnames_per_ip, tlsx_probe_jarm, tlsx_version_enum, tlsx_cipher_enum, tlsx_cipher_concurrency, tlsx_max_targets, web_cache_poison_enabled, web_cache_poison_scan_profile, web_cache_poison_timeout, web_cache_poison_timeout_per_req, web_cache_poison_concurrency, web_cache_poison_confirm_workers, web_cache_poison_max_rps_per_host, web_cache_poison_min_confidence, web_cache_poison_allow_framework_packs, web_cache_poison_allow_deception, web_cache_poison_allow_cpdos, web_cache_poison_cross_vantage, web_cache_poison_cache_header, web_cache_poison_cache_buster_param, web_cache_poison_verify_ssl, web_cache_poison_behavioral_oracle, web_cache_poison_behavioral_delay, web_cache_poison_differential, route_exposure_enabled, route_exposure_max_rps, route_exposure_workers, route_exposure_timeout, route_exposure_max_routes_per_host, route_exposure_max_routes_total, route_exposure_seed_paths, route_exposure_vcs_files, route_exposure_backup_files, route_exposure_version_variants, route_exposure_compare_logged_in, route_exposure_pii_detection, route_exposure_siblings, route_exposure_framework_seeds, route_exposure_follow_catalogs, route_exposure_git_walk, route_exposure_cross_host, route_exposure_cors_rider, route_exposure_cache_rider, route_exposure_jev_rank, route_exposure_jev_wall_check, route_exposure_jev_assess, resource_enum_ai_classifier_enabled, resource_enum_ai_path_classifier_enabled, resource_enum_ai_rag_path_flag_enabled, resource_enum_ai_param_injectable_flag_enabled, resource_enum_ai_tool_arg_path_enabled, resource_enum_jev_tool_health, ai_surface_recon_enabled, ai_surface_recon_timeout, ai_surface_recon_max_workers, ai_surface_recon_user_agent, ai_surface_recon_chat_shape_probe_enabled, ai_surface_recon_mcp_handshake_enabled, ai_surface_recon_mcp_list_tools_enabled, ai_surface_recon_mcp_yara_enabled, ai_surface_recon_openapi_discovery_enabled, ai_surface_recon_model_list_enabled, ai_surface_recon_vector_db_read_enabled, ai_surface_recon_julius_probe_pack_enabled, ai_surface_recon_latency_baseline_enabled, ai_surface_recon_cache_enabled, ai_surface_recon_probe_pack_version, katana_enabled, katana_depth, katana_max_urls, katana_rate_limit, katana_timeout, katana_js_crawl, katana_params_only, katana_exclude_patterns, katana_scope, katana_custom_headers, katana_parallelism, katana_concurrency, openapi_enabled, openapi_discovery_paths, openapi_auto_discover, openapi_sources, openapi_timeout, openapi_max_documents, zap_ajax_spider_enabled, zap_ajax_spider_seed_mode, zap_ajax_spider_max_duration, zap_ajax_spider_max_crawl_depth, zap_ajax_spider_max_crawl_states, zap_ajax_spider_number_of_browsers, zap_ajax_spider_browser_id, zap_ajax_spider_event_wait, zap_ajax_spider_reload_wait, zap_ajax_spider_click_default_elems, zap_ajax_spider_click_elems_once, zap_ajax_spider_random_inputs, zap_ajax_spider_logout_avoidance, zap_ajax_spider_scope_check, zap_ajax_spider_custom_headers, zap_ajax_spider_exclude_patterns, zap_ajax_spider_max_urls, zap_ajax_spider_parallelism, zap_ajax_spider_max_seeds, hakrawler_enabled, hakrawler_depth, hakrawler_threads, hakrawler_timeout, hakrawler_max_urls, hakrawler_include_subs, hakrawler_insecure, hakrawler_custom_headers, hakrawler_parallelism, hakrawler_jev_seed_order, jsluice_enabled, jsluice_max_files, jsluice_timeout, jsluice_extract_urls, jsluice_extract_secrets, jsluice_concurrency, jsluice_parallelism, jsluice_verify_urls, jsluice_verify_timeout, jsluice_verify_rate_limit, jsluice_verify_threads, jsluice_verify_accept_status, jsluice_exclude_patterns, js_recon_enabled, js_recon_max_files, js_recon_timeout, js_recon_concurrency, js_recon_validate_keys, js_recon_validation_timeout, js_recon_trufflehog_enabled, js_recon_trufflehog_results, js_recon_extract_endpoints, js_recon_validate_endpoints, js_recon_endpoint_accept_status, js_recon_endpoint_custom_headers, js_recon_endpoint_concurrency, js_recon_regex_patterns, js_recon_source_maps, js_recon_dependency_check, js_recon_dom_sinks, js_recon_framework_detect, js_recon_dev_comments, js_recon_include_chunks, js_recon_include_framework_js, js_recon_include_archived_js, js_recon_min_confidence, js_recon_standalone_crawl_depth, js_recon_standalone_crawl_scope, js_recon_uploaded_files, js_recon_custom_patterns, js_recon_custom_sourcemap_paths, js_recon_custom_packages, js_recon_custom_endpoint_keywords, js_recon_custom_frameworks, serialized_scan_enabled, serialized_scan_jev_rank, js_recon_ai_sdk_detection_enabled, graphql_security_enabled, graphql_introspection_test, graphql_timeout, graphql_rate_limit, graphql_concurrency, graphql_auth_type, graphql_auth_value, graphql_auth_header, graphql_endpoints, graphql_depth_limit, graphql_retry_count, graphql_retry_backoff, graphql_verify_ssl, graphql_cop_enabled, graphql_cop_timeout, graphql_cop_force_scan, graphql_cop_debug, graphql_cop_test_field_suggestions, graphql_cop_test_introspection, graphql_cop_test_graphiql, graphql_cop_test_get_method, graphql_cop_test_alias_overloading, graphql_cop_test_batch_query, graphql_cop_test_trace_mode, graphql_cop_test_directive_overloading, graphql_cop_test_circular_introspection, graphql_cop_test_get_mutation, graphql_cop_test_post_csrf, graphql_cop_test_unhandled_error, ffuf_enabled, ffuf_wordlist, ffuf_threads, ffuf_rate, ffuf_timeout, ffuf_max_time, ffuf_match_codes, ffuf_filter_codes, ffuf_filter_size, ffuf_extensions, ffuf_recursion, ffuf_recursion_depth, ffuf_auto_calibrate, ffuf_follow_redirects, ffuf_custom_headers, ffuf_smart_fuzz, ffuf_smart_fuzz_max_base_paths, ffuf_parallelism, ffuf_ai_extensions, ffuf_ai_use_jev, ffuf_jev_base_paths, arjun_enabled, arjun_threads, arjun_timeout, arjun_scan_timeout, arjun_methods, arjun_max_endpoints, arjun_chunk_size, arjun_rate_limit, arjun_stable, arjun_passive, arjun_disable_redirects, arjun_custom_headers, gau_enabled, gau_providers, gau_max_urls, gau_timeout, gau_threads, gau_blacklist_extensions, gau_year_range, gau_verbose, gau_verify_urls, gau_verify_timeout, gau_verify_rate_limit, gau_verify_threads, gau_verify_accept_status, gau_detect_methods, gau_method_detect_timeout, gau_method_detect_rate_limit, gau_method_detect_threads, gau_filter_dead_endpoints, gau_workers, paramspider_enabled, paramspider_placeholder, paramspider_timeout, paramspider_workers, kiterunner_enabled, kiterunner_wordlists, kiterunner_rate_limit, kiterunner_connections, kiterunner_timeout, kiterunner_scan_timeout, kiterunner_threads, kiterunner_ignore_status, kiterunner_min_content_length, kiterunner_match_status, kiterunner_headers, kiterunner_detect_methods, kiterunner_method_detection_mode, kiterunner_bruteforce_methods, kiterunner_method_detect_timeout, kiterunner_method_detect_rate_limit, kiterunner_method_detect_threads, kiterunner_parallelism, cve_lookup_enabled, cve_lookup_source, cve_lookup_max_cves, cve_lookup_min_cvss, mitre_enabled, mitre_auto_update_db, mitre_include_cwe, mitre_include_capec, mitre_enrich_recon, mitre_enrich_gvm, mitre_cache_ttl_hours, security_check_enabled, security_check_direct_ip_http, security_check_direct_ip_https, security_check_ip_api_exposed, security_check_waf_bypass, waf_ai_classifier, waf_ai_use_jev, security_check_tls_expiring_soon, security_check_tls_expiry_days, security_check_tls_expired, security_check_tls_self_signed, security_check_tls_hostname_mismatch, security_check_tls_weak_version, security_check_tls_weak_cipher, security_check_tls_wildcard_overbroad, security_check_missing_referrer_policy, security_check_missing_permissions_policy, security_check_missing_coop, security_check_missing_corp, security_check_missing_coep, security_check_cache_control_missing, security_check_login_no_https, security_check_session_no_secure, security_check_session_no_httponly, security_check_basic_auth_no_tls, security_check_spf_missing, security_check_dmarc_missing, security_check_dnssec_missing, security_check_zone_transfer, security_check_admin_port_exposed, security_check_database_exposed, security_check_redis_no_auth, security_check_kubernetes_api_exposed, security_check_smtp_open_relay, security_check_csp_unsafe_inline, security_check_insecure_form_action, security_check_no_rate_limiting, security_check_open_consoles, security_check_debug_pages, security_check_unfinished_installers, security_check_dev_servers, security_check_directory_listing, security_check_defaced_pages, security_check_takeover_error_pages, security_check_test_certificates, security_check_timeout, security_check_max_workers, origin_discovery_enabled, origin_discovery_keyless, origin_discovery_scanners, origin_discovery_passive_dns, origin_discovery_urlscan, origin_discovery_max_candidates, origin_discovery_max_search_calls, origin_discovery_threshold, origin_discovery_timeout, origin_discovery_workers, gvm_scan_config, gvm_scan_targets, gvm_port_list, gvm_task_timeout, gvm_poll_interval, gvm_cleanup_after_scan, agent_openai_model, agent_informational_system_prompt, agent_expl_system_prompt, agent_post_expl_system_prompt, agent_activate_post_expl_phase, agent_post_expl_phase_type, agent_lhost, agent_lport, agent_bind_port_on_target, agent_payload_use_https, agent_ngrok_tunnel_enabled, agent_chisel_tunnel_enabled, agent_max_iterations, agent_execution_trace_memory_steps, agent_require_approval_for_exploitation, agent_require_approval_for_post_exploitation, agent_require_tool_confirmation, agent_tool_output_max_chars, agent_plan_max_parallel_tools, agent_cypher_max_retries, agent_llm_parse_max_retries, agent_create_graph_image_on_init, agent_log_max_mb, agent_log_backup_count, agent_tool_phase_map, agent_kali_install_enabled, agent_kali_install_allowed_packages, agent_kali_install_forbidden_packages, agent_brute_force_max_wordlist_attempts, agent_bruteforce_speed, agent_guardrail_enabled, mcp_kali_exec_enabled, fireteam_enabled, fireteam_max_concurrent, fireteam_max_members, fireteam_member_max_iterations, fireteam_timeout_sec, fireteam_allowed_phases, fireteam_confirmation_timeout_sec, fireteam_propensity, agent_lats_enabled, agent_lats_shadow_mode, agent_lats_phase_exploitation, agent_lats_phase_post_expl, agent_lats_min_hypotheses, agent_lats_branching, agent_lats_max_depth, agent_lats_max_rollouts, agent_lats_max_tree_nodes, agent_lats_uct_c, agent_lats_prune_floor, hydra_enabled, hydra_threads, hydra_wait_between_connections, hydra_connection_timeout, hydra_stop_on_first_found, hydra_extra_checks, hydra_verbose, hydra_max_wordlist_attempts, shodan_enabled, shodan_host_lookup, shodan_reverse_dns, shodan_domain_dns, shodan_passive_cves, shodan_workers, urlscan_enabled, urlscan_max_results, urlscan_max_searches, urlscan_inject_max_age_days, urlscan_max_injected_hosts, urlscan_leaked_links, urlscan_secrets_in_urls, urlscan_sensitive_files, urlscan_document_links, urlscan_redirect_search, urlscan_takeover_pages, urlscan_problem_pages, osint_enrichment_enabled, censys_enabled_recon, fofa_enabled, fofa_max_results, otx_enabled, netlas_enabled, virustotal_enabled, zoomeye_enabled, zoomeye_max_results, criminalip_enabled, otx_workers, virustotal_workers, censys_workers, criminalip_workers, fofa_workers, netlas_workers, zoomeye_workers, uncover_enabled, uncover_max_results, subdomain_discovery_enabled, domain_recon_ai_txt_hint_enabled, domain_recon_ai_ns_hint_enabled, crtsh_enabled, crtsh_max_results, hacker_target_enabled, hacker_target_max_results, knockpy_recon_enabled, knockpy_recon_max_results, subfinder_enabled, subfinder_max_results, amass_enabled, amass_max_results, amass_timeout, amass_active, amass_brute, amass_brute_wordlists, puredns_enabled, puredns_threads, puredns_rate_limit, puredns_wildcard_batch, puredns_skip_validation, phishing_smtp_config, dos_max_duration, dos_max_attempts, dos_concurrent_connections, dos_assessment_only, sqli_level, sqli_risk, sqli_tamper_scripts, ssrf_oob_callback_enabled, ssrf_cloud_metadata_enabled, ssrf_gopher_enabled, ssrf_dns_rebinding_enabled, ssrf_payload_reference_enabled, ssrf_request_timeout, ssrf_port_scan_ports, ssrf_internal_ranges, ssrf_oob_provider, ssrf_cloud_providers, ssrf_custom_internal_targets, rce_oob_callback_enabled, rce_deserialization_enabled, rce_aggressive_payloads, rce_heapdump_analysis_enabled, path_traversal_oob_callback_enabled, path_traversal_php_wrappers_enabled, path_traversal_archive_extraction_enabled, path_traversal_payload_reference_enabled, path_traversal_request_timeout, path_traversal_oob_provider, path_traversal_git_reconstruct_enabled, path_traversal_validate_secrets_enabled, deserialization_oob_callback_enabled, deserialization_oob_provider, deserialization_timing_enabled, deserialization_find_sinks_enabled, deserialization_runtimes, deserialization_exec_gadgets_enabled, deserialization_phar_enabled, attack_skill_config, cypherfix_github_token, cypherfix_default_repo, cypherfix_default_branch, cypherfix_branch_prefix, cypherfix_require_approval, cypherfix_llm_model, triage_review_budget, engagement_kind, engagement_identity_header, roe_enabled, roe_raw_text, roe_document_name, roe_document_data, roe_document_mime_type, roe_parsed_json, roe_client_name, roe_client_contact_name, roe_client_contact_email, roe_client_contact_phone, roe_emergency_contact, roe_engagement_start_date, roe_engagement_end_date, roe_engagement_type, roe_excluded_hosts, roe_excluded_host_reasons, roe_time_window_enabled, roe_time_window_timezone, roe_time_window_days, roe_time_window_start_time, roe_time_window_end_time, roe_forbidden_tools, roe_forbidden_categories, roe_max_severity_phase, roe_allow_dos, roe_allow_social_engineering, roe_allow_physical_access, roe_allow_data_exfiltration, roe_allow_account_lockout, roe_allow_production_testing, roe_global_max_rps, roe_sensitive_data_handling, roe_data_retention_days, roe_require_data_encryption, roe_status_update_frequency, roe_critical_finding_notify, roe_incident_procedure, roe_third_party_providers, roe_compliance_frameworks, roe_notes, capture_proxy_enabled, activation_state, activation_started_at, activation_version_id) FROM stdin;
upg-p-a	upg-member-a	upg-PA	\N	2026-03-03 09:00:00	2026-03-03 09:00:00	\N	\N	upg-a.test	{}	f	{}	f	{}	\N	f	your-secret-token-here	_redamon-verify	f	t	f	claude-opus-4-6	\N	\N	\N	{domain_discovery,port_scan,http_probe,resource_enum,vuln_scan}	t	f	t	6	t	3	80	t			f	t	t	100	t	f	verified,unverified,unknown	f	8					5	f	f		0		f	f		npm,PyPI,Go,Maven,crates.io,Packagist,RubyGems,NuGet	f	upload					f	f	50		f	f	npm	f	t	f	t	1000		1000	25	10000	1	s	f	t	t	t	f	t	f	1000		1000	f	10	1		t	t	t	t	T3	600	300	5	t	t	50	10	2	50	t	10	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	sha256	t	t	f	t	t	{}	{"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36","Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8","Accept-Language: en-US,en;q=0.9","Accept-Encoding: gzip, deflate","Connection: keep-alive","Upgrade-Insecure-Requests: 1","Sec-Fetch-Dest: document","Sec-Fetch-Mode: navigate","Sec-Fetch-Site: none","Sec-Fetch-User: ?1","Cache-Control: max-age=0"}	{}	{}	t	t	t	t	t	500	t	50	t	t	6.10.56	24	t	5	20	1000	t	{critical,high,medium,low}	{}	{}	{}	{}	100	25	25	10	1	86400	30	{cve,xss,sqli,rce,lfi,ssrf,xxe,ssti}	{dos,fuzz}	f	t	f	f	t	t	10	f	t	f	f	f	f	t	10	30	t	f	f	f	f	900	t	1800	f	f	{critical,high,medium}	60	50	f	t	f	{cname,ns,mx,txt,spf}	{}	1800	f	3	20	50	t	t	t	t	t		2000	t	auto	50	5	900	1	200		f	t	f	1	f	f	f	10	2000	f	safe-confirm	1800	10	10	6	0	0.8	t	t	f	f		rdmncb	t	t	1.1	t	f	5	4	10	300	3000	t	t	t	t	t	t	t	t	t	t	f	t	t	f	f	f	t	t	t	t	t	f	t	10	5	RedAmon-AISurfaceRecon/1.0	t	t	t	t	t	t	t	t	t	t	latest	t	2	300000	50	3600	t	f	{/_next/image,/_next/static,/_next/data,/__nextjs,/_nuxt/,/__nuxt,/runtime.,/polyfills.,/vendor.,/webpack,/chunk.,.chunk.js,.bundle.js,hot-update,/static/,/public/,/dist/,/build/,/lib/,/vendor/,/node_modules/,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.avif,.bmp,.tiff,.tif,.heic,.heif,.raw,/images/,/img/,/image/,/pics/,/pictures/,/thumbnails/,/thumb/,/thumbs/,.css,.scss,.sass,.less,.styl,.css.map,/css/,/styles/,/style/,/stylesheet/,.js.map,.min.js,/js/lib/,/js/vendor/,/js/plugins/,jquery,bootstrap.js,popper.js,.woff,.woff2,.ttf,.eot,.otf,/fonts/,/font/,/webfonts/,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.rtf,.odt,.ods,.odp,.zip,.rar,.7z,.tar,.gz,.bz2,.mp3,.mp4,.avi,.mov,.wmv,.flv,.webm,.mkv,.wav,.ogg,.aac,.m4a,.flac,/video/,/videos/,/audio/,/music/,/sounds/,/wp-content/uploads/,/wp-content/themes/,/wp-includes/,/sites/default/files/,/core/assets/,/pub/static/,/pub/media/,/storage/,/staticfiles/,/packs/,cdn.,cdnjs.,cloudflare.,akamai.,fastly.,googleapis.com,gstatic.com,cloudfront.net,unpkg.com,jsdelivr.net,bootstrapcdn.com,google-analytics,googletagmanager,gtag/,facebook.com/tr,facebook.net,analytics.,tracking.,pixel.,hotjar.,mouseflow.,clarity.,googlesyndication,doubleclick,adservice,platform.twitter,connect.facebook,platform.linkedin,maps.google,maps.googleapis,openstreetmap,mapbox,recaptcha,hcaptcha,captcha,manifest.json,sw.js,service-worker,browserconfig.xml,robots.txt,sitemap.xml,.well-known/,favicon,apple-touch-icon,android-chrome,/icons/,/icon/}	dn	{"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36","Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","Accept-Language: en-US,en;q=0.9"}	8	15	t	{/openapi.json,/openapi.yaml,/swagger.json,/swagger.yaml,/v3/api-docs,/v2/api-docs,/swagger/v1/swagger.json,/swagger-ui/index.html,/swagger-ui.html,/docs,/api-docs,/api-docs/}	f	[]	10	50	f	base_urls	10	5	0	1	firefox-headless	1000	1000	t	t	f	t	Strict	{}	{}	1000	3	250	t	2	5	30	50000	t	t	{}	5	f	t	10000	300	t	t	5	5	t	5	50	50	{200,201,301,302,307,308,401,403}	{/_next/image,/_next/static,/_next/data,/__nextjs,/_nuxt/,/__nuxt,/runtime.,/polyfills.,/vendor.,/webpack,/chunk.,.chunk.js,.bundle.js,hot-update,/static/,/public/,/dist/,/build/,/lib/,/vendor/,/node_modules/,.js,.mjs,.map,.css,.scss,.sass,.less,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.avif,.woff,.woff2,.ttf,.eot,.otf,.mp3,.mp4,.avi,.mov,.wmv,.flv,.webm,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip,.rar,.7z,.tar,.gz,/rxjs/,/react/,/angular/,/lodash/,/zone.js/}	f	10000	900	10	t	5	t	{verified,unknown,unverified}	t	f	{200,201,204,301,302,307,308,401,403,405}	{}	10	t	t	t	t	t	t	t	t	t	low	3	subdomain	{}						f	f	t	f	t	30	10	5					10	3	2	t	f	120	f	f	t	f	t	t	t	t	t	t	t	t	t	t	f	/usr/share/seclists/Discovery/Web-Content/common.txt	40	0	10	1800	{200,201,204,301,302,307,308,401,403,405}	{}		{}	f	2	t	f	{}	t	20	20	f	f	f	t	2	15	600	{GET,POST}	50000	500	0	f	f	f	{}	f	{wayback,commoncrawl,otx,urlscan}	50000	60	5	{png,jpg,jpeg,gif,svg,ico,webp,avif,css,woff,woff2,ttf,eot,otf,mp3,mp4,avi,mov,wmv,flv,webm}	{}	f	t	5	100	50	{200,201,301,302,307,308,401,403}	t	5	50	25	t	10	f	FUZZ	120	8	f	{routes-large}	100	100	10	1000	50	{}	0	{200,201,204,301,302,401,403,405}	{}	t	bruteforce	{POST,PUT,DELETE,PATCH}	5	50	25	3	t	nvd	20	0	t	t	t	t	t	t	24	t	t	t	t	t	f	f	t	30	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	10	10	f	t	t	t	t	25	50	60	10	10	Full and fast	both	All TCP and Nmap top 100 UDP	14400	30	t	claude-opus-4-6				t	statefull		\N	\N	f	f	f	100	100	t	t	t	40000	10	3	3	f	10	5	{"shodan": ["informational", "exploitation", "post_exploitation"], "cve_intel": ["informational", "exploitation", "post_exploitation"], "kali_shell": ["informational", "exploitation", "post_exploitation"], "web_search": ["informational", "exploitation", "post_exploitation"], "execute_gau": ["informational", "exploitation"], "google_dork": ["informational"], "msf_restart": ["exploitation", "post_exploitation"], "proxy_brain": ["informational", "exploitation", "post_exploitation"], "query_graph": ["informational", "exploitation", "post_exploitation"], "execute_code": ["informational", "exploitation", "post_exploitation"], "execute_curl": ["informational", "exploitation", "post_exploitation"], "execute_ffuf": ["informational", "exploitation"], "execute_nmap": ["informational", "exploitation", "post_exploitation"], "execute_amass": ["informational", "exploitation"], "execute_arjun": ["informational", "exploitation"], "execute_httpx": ["informational", "exploitation"], "execute_hydra": ["exploitation", "post_exploitation"], "execute_naabu": ["informational", "exploitation"], "execute_katana": ["informational", "exploitation"], "execute_nuclei": ["informational", "exploitation"], "execute_wpscan": ["informational", "exploitation"], "execute_jsluice": ["informational", "exploitation"], "execute_guarddog": ["informational", "exploitation"], "execute_subfinder": ["informational", "exploitation"], "tradecraft_lookup": ["exploitation", "post_exploitation"], "execute_playwright": ["informational", "exploitation", "post_exploitation"], "metasploit_console": ["exploitation", "post_exploitation"], "execute_osv_scanner": ["informational", "exploitation", "post_exploitation"]}	f			3	5	t	t	t	5	5	10	7200	{informational,exploitation,post_exploitation}	600	3	f	f	t	f	2	6	6	50	120	1.4	0.15	t	16	0	32	t	nsr	t	3	t	t	t	f	t	5	t	10000	60	90	200	t	t	t	t	f	t	t	f	f	f	1000	t	f	f	f	1000	f	5	3	5	5	5	5	5	f	50000	t	t	t	t	5000	t	5000	t	5000	t	5000	f	50000	10	f	f	["default"]	t	0	0	0	f		60	3	1000	f	1	1		t	t	t	t	t	10	22,80,443,2375,3306,5432,6379,8080,8500,9200,27017	127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16	oast.fun	aws,gcp,azure,digitalocean,alibaba		t	t	f	f	t	t	f	t	10	oast.fun	f	f	t	oast.fun	t	t	java,java_typed,python,php,node,ruby,dotnet	f	f	{"user": {}, "builtIn": {"rce": true, "xss": true, "xxe": true, "ssrf": true, "cve_exploit": true, "crypto_attack": true, "sql_injection": true, "access_control": true, "path_traversal": true, "deserialization": false, "denial_of_service": false, "http_request_smuggling": false, "phishing_social_engineering": false, "brute_force_credential_guess": false}}			main	cypherfix/	t		150	internal		f			\N		\N								external	{}	{}	f	UTC	{monday,tuesday,wednesday,thursday,friday}	09:00	18:00	{}	{}	post_exploitation	f	f	f	f	f	t	0	no_access	90	t	daily	t		{}	{}		f	idle	\N	\N
\.


--
-- Data for Name: recording_sessions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.recording_sessions (id, project_id, user_id, state, scope_hosts, started_at, expires_at, stopped_at, observed_count, last_error, pending_material) FROM stdin;
\.


--
-- Data for Name: remediations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.remediations (id, project_id, title, description, severity, priority, category, remediation_type, affected_assets, cvss_score, cve_ids, cwe_ids, capec_ids, evidence, attack_chain_path, exploit_available, cisa_kev, solution, fix_complexity, estimated_files, target_repo, target_branch, fix_branch, pr_url, pr_status, status, agent_session_id, agent_notes, file_changes, group_key, finding_ids, live_member_count, priority_score, triage_run_id, still_detected, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: reports; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.reports (id, project_id, title, filename, file_path, file_size, format, metrics, has_narratives, created_at) FROM stdin;
\.


--
-- Data for Name: roe_document_revisions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.roe_document_revisions (id, project_id, document_name, mime_type, data, bytes_sha256, text_sha256, raw_text, parsed_json, applied_at, superseded_at, superseded_by_id, reason) FROM stdin;
\.


--
-- Data for Name: scan_jobs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.scan_jobs (id, project_id, version_id, kind, run_id, trigger, mode, status, initiated_by_user_id, started_at, finished_at, schedule_id, ram_reason, node_count, settings_hash, authorization_id, targets, degraded_sources, roe_text_sha256, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: scan_schedules; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.scan_schedules (id, project_id, user_id, label, mode, run_at, interval_minutes, cron_expr, scan_mode, enabled, next_run_at, last_run_at, estimated_envelope_bytes, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: scan_versions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.scan_versions (id, project_id, seq, label, is_current, pinned, node_count, link_count, summary, snapshot, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: supply_chain_batch_items; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.supply_chain_batch_items (id, batch_id, repo_full_name, repo_url, ref, status, job_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: supply_chain_batches; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.supply_chain_batches (id, project_id, user_id, org, host, status, total_items, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: triage_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.triage_runs (id, project_id, actor_user_id, real_actor_user_id, status, started_at, heartbeat_at, finished_at, model, score_model_version, intel_date, summary, error_class, trigger, token_id, phase, progress) FROM stdin;
\.


--
-- Data for Name: trufflehog_scan_profiles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.trufflehog_scan_profiles (id, project_id, source, label, config, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user_attack_skills; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_attack_skills (id, user_id, name, description, content, derived_from_id, lineage_root_id, version, origin_change_set_id, origin_plugin_id, origin_plugin_version, origin_chain, quarantined_at, quarantine_reason, quarantined_for, released_for, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user_chat_skills; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_chat_skills (id, user_id, name, description, category, content, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user_llm_providers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_llm_providers (id, user_id, provider_type, name, api_key, base_url, model_identifier, default_headers, timeout, temperature, max_tokens, ssl_verify, reasoning_enabled, reasoning_effort, aws_region, aws_access_key_id, aws_secret_key, aws_bearer_token, created_at, updated_at, created_by_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: user_mute_rules_presets; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_mute_rules_presets (id, user_id, name, description, mode, rules, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user_project_presets; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_project_presets (id, user_id, name, description, settings, created_at, updated_at, created_via, updated_via, last_writer_token_prefix) FROM stdin;
\.


--
-- Data for Name: user_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_settings (id, user_id, github_access_token, supply_chain_github_token, trufflehog_github_token, trufflehog_gitlab_token, trufflehog_docker_token, trufflehog_huggingface_token, trufflehog_aws_access_key_id, trufflehog_aws_secret_key, trufflehog_aws_session_token, trufflehog_gcp_service_account, trufflehog_postman_token, trufflehog_jenkins_username, trufflehog_jenkins_password, trufflehog_elastic_username, trufflehog_elastic_password, trufflehog_elastic_api_key, trufflehog_elastic_service_token, trufflehog_circleci_token, trufflehog_travisci_token, trufflehog_git_username, trufflehog_git_token, github_enterprise_host, github_enterprise_token, tavily_api_key, shodan_api_key, serp_api_key, nvd_api_key, vulners_api_key, urlscan_api_key, censys_api_token, censys_org_id, fofa_api_key, otx_api_key, netlas_api_key, virustotal_api_key, zoomeye_api_key, criminalip_api_key, quake_api_key, hunter_api_key, publicwww_api_key, hunterhow_api_key, google_api_key, google_api_cx, onyphe_api_key, driftnet_api_key, wpscan_api_token, pdcp_api_key, securitytrails_api_key, viewdns_api_key, tunnels_enabled, ngrok_authtoken, chisel_server_url, chisel_auth, mcp_servers, capture_proxy_enabled, capture_proxy_port, capture_proxy_scope, capture_proxy_store_bodies, capture_proxy_max_body_kb, capture_proxy_retention_days, capture_proxy_redact_secrets, capture_proxy_passive_detect, capture_proxy_store_req_bodies, capture_proxy_store_resp_bodies, capture_proxy_max_store_mb, capture_proxy_body_rules, capture_egress_block_empty_host, capture_egress_block_hard_guardrail, capture_egress_fail_closed, capture_egress_block_unresolvable, capture_egress_block_private, capture_egress_block_loopback, capture_egress_block_link_local, capture_egress_block_cgnat, capture_egress_block_reserved, capture_egress_block_multicast, capture_egress_block_unspecified, sca_intel_ignore_suffixes, feature_models, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user_tradecraft_resources; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_tradecraft_resources (id, user_id, name, slug, url, enabled, resource_type, summary, sitemap, crawl_stopped_because, crawl_stats, llm_model, github_token_override, cache_ttl_sec, last_verified_at, last_refreshed_at, last_error, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (id, name, email, password, role, ui_preferences, default_agent_model, default_ai_pipeline_model, created_at, updated_at, created_by_id, updated_by_id) FROM stdin;
upg-admin-a	Upg Admin A	upg-admin-a@e2e.local		admin	{}	\N	\N	2026-01-05 09:00:00	2026-01-05 09:00:00	\N	\N
upg-admin-b	Upg Admin B	upg-admin-b@e2e.local		admin	{}	\N	\N	2026-02-10 09:00:00	2026-02-10 09:00:00	\N	\N
upg-member-a	Upg Member A	upg-member-a@e2e.local	$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42	standard	{}	\N	\N	2026-03-01 09:00:00	2026-03-01 09:00:00	\N	\N
upg-member-b	Upg Member B	upg-member-b@e2e.local		standard	{}	\N	\N	2026-03-02 09:00:00	2026-03-02 09:00:00	\N	\N
\.


--
-- Name: act_as_audit act_as_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.act_as_audit
    ADD CONSTRAINT act_as_audit_pkey PRIMARY KEY (id);


--
-- Name: api_key_rotation_configs api_key_rotation_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_key_rotation_configs
    ADD CONSTRAINT api_key_rotation_configs_pkey PRIMARY KEY (id);


--
-- Name: api_usage_reports api_usage_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_usage_reports
    ADD CONSTRAINT api_usage_reports_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: captured_http_transactions captured_http_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.captured_http_transactions
    ADD CONSTRAINT captured_http_transactions_pkey PRIMARY KEY (id);


--
-- Name: chat_messages chat_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_pkey PRIMARY KEY (id);


--
-- Name: checkpoint_blobs checkpoint_blobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoint_blobs
    ADD CONSTRAINT checkpoint_blobs_pkey PRIMARY KEY (thread_id, checkpoint_ns, channel, version);


--
-- Name: checkpoint_migrations checkpoint_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoint_migrations
    ADD CONSTRAINT checkpoint_migrations_pkey PRIMARY KEY (v);


--
-- Name: checkpoint_writes checkpoint_writes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoint_writes
    ADD CONSTRAINT checkpoint_writes_pkey PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id, task_id, idx);


--
-- Name: checkpoints checkpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoints
    ADD CONSTRAINT checkpoints_pkey PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id);


--
-- Name: conversations conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_pkey PRIMARY KEY (id);


--
-- Name: engagement_authorization_archive engagement_authorization_archive_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.engagement_authorization_archive
    ADD CONSTRAINT engagement_authorization_archive_pkey PRIMARY KEY (id);


--
-- Name: engagement_authorizations engagement_authorizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.engagement_authorizations
    ADD CONSTRAINT engagement_authorizations_pkey PRIMARY KEY (id);


--
-- Name: fireteam_members fireteam_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fireteam_members
    ADD CONSTRAINT fireteam_members_pkey PRIMARY KEY (id);


--
-- Name: fireteam_settings_audit fireteam_settings_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fireteam_settings_audit
    ADD CONSTRAINT fireteam_settings_audit_pkey PRIMARY KEY (id);


--
-- Name: fireteams fireteams_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fireteams
    ADD CONSTRAINT fireteams_pkey PRIMARY KEY (id);


--
-- Name: graph_views graph_views_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.graph_views
    ADD CONSTRAINT graph_views_pkey PRIMARY KEY (id);


--
-- Name: job_queue job_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_queue
    ADD CONSTRAINT job_queue_pkey PRIMARY KEY (id);


--
-- Name: mcp_access_tokens mcp_access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_access_tokens
    ADD CONSTRAINT mcp_access_tokens_pkey PRIMARY KEY (id);


--
-- Name: node_filter_exemptions node_filter_exemptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_filter_exemptions
    ADD CONSTRAINT node_filter_exemptions_pkey PRIMARY KEY (id);


--
-- Name: node_filter_runs node_filter_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_filter_runs
    ADD CONSTRAINT node_filter_runs_pkey PRIMARY KEY (id);


--
-- Name: plugin_data plugin_data_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_data
    ADD CONSTRAINT plugin_data_pkey PRIMARY KEY (id);


--
-- Name: plugin_installs plugin_installs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_installs
    ADD CONSTRAINT plugin_installs_pkey PRIMARY KEY (plugin_id);


--
-- Name: plugin_overrides plugin_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_overrides
    ADD CONSTRAINT plugin_overrides_pkey PRIMARY KEY (id);


--
-- Name: plugin_platform_state plugin_platform_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_platform_state
    ADD CONSTRAINT plugin_platform_state_pkey PRIMARY KEY (key);


--
-- Name: project_auth_profiles project_auth_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_auth_profiles
    ADD CONSTRAINT project_auth_profiles_pkey PRIMARY KEY (id);


--
-- Name: project_node_filters project_node_filters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_node_filters
    ADD CONSTRAINT project_node_filters_pkey PRIMARY KEY (project_id);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: recording_sessions recording_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recording_sessions
    ADD CONSTRAINT recording_sessions_pkey PRIMARY KEY (id);


--
-- Name: remediations remediations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediations
    ADD CONSTRAINT remediations_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: roe_document_revisions roe_document_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roe_document_revisions
    ADD CONSTRAINT roe_document_revisions_pkey PRIMARY KEY (id);


--
-- Name: scan_jobs scan_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_pkey PRIMARY KEY (id);


--
-- Name: scan_schedules scan_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_schedules
    ADD CONSTRAINT scan_schedules_pkey PRIMARY KEY (id);


--
-- Name: scan_versions scan_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_versions
    ADD CONSTRAINT scan_versions_pkey PRIMARY KEY (id);


--
-- Name: supply_chain_batch_items supply_chain_batch_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supply_chain_batch_items
    ADD CONSTRAINT supply_chain_batch_items_pkey PRIMARY KEY (id);


--
-- Name: supply_chain_batches supply_chain_batches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supply_chain_batches
    ADD CONSTRAINT supply_chain_batches_pkey PRIMARY KEY (id);


--
-- Name: triage_runs triage_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.triage_runs
    ADD CONSTRAINT triage_runs_pkey PRIMARY KEY (id);


--
-- Name: trufflehog_scan_profiles trufflehog_scan_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trufflehog_scan_profiles
    ADD CONSTRAINT trufflehog_scan_profiles_pkey PRIMARY KEY (id);


--
-- Name: user_attack_skills user_attack_skills_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_attack_skills
    ADD CONSTRAINT user_attack_skills_pkey PRIMARY KEY (id);


--
-- Name: user_chat_skills user_chat_skills_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_chat_skills
    ADD CONSTRAINT user_chat_skills_pkey PRIMARY KEY (id);


--
-- Name: user_llm_providers user_llm_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_llm_providers
    ADD CONSTRAINT user_llm_providers_pkey PRIMARY KEY (id);


--
-- Name: user_mute_rules_presets user_mute_rules_presets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_mute_rules_presets
    ADD CONSTRAINT user_mute_rules_presets_pkey PRIMARY KEY (id);


--
-- Name: user_project_presets user_project_presets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_project_presets
    ADD CONSTRAINT user_project_presets_pkey PRIMARY KEY (id);


--
-- Name: user_settings user_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_pkey PRIMARY KEY (id);


--
-- Name: user_tradecraft_resources user_tradecraft_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_tradecraft_resources
    ADD CONSTRAINT user_tradecraft_resources_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: act_as_audit_admin_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX act_as_audit_admin_id_created_at_idx ON public.act_as_audit USING btree (admin_id, created_at);


--
-- Name: act_as_audit_target_user_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX act_as_audit_target_user_id_created_at_idx ON public.act_as_audit USING btree (target_user_id, created_at);


--
-- Name: api_key_rotation_configs_user_id_tool_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX api_key_rotation_configs_user_id_tool_name_key ON public.api_key_rotation_configs USING btree (user_id, tool_name);


--
-- Name: api_usage_reports_user_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX api_usage_reports_user_id_key ON public.api_usage_reports USING btree (user_id);


--
-- Name: audit_log_actor_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_actor_id_created_at_idx ON public.audit_log USING btree (actor_id, created_at);


--
-- Name: audit_log_target_type_target_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_target_type_target_id_created_at_idx ON public.audit_log USING btree (target_type, target_id, created_at);


--
-- Name: captured_http_transactions_project_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_created_at_idx ON public.captured_http_transactions USING btree (project_id, created_at);


--
-- Name: captured_http_transactions_project_id_host_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_host_idx ON public.captured_http_transactions USING btree (project_id, host);


--
-- Name: captured_http_transactions_project_id_in_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_in_scope_idx ON public.captured_http_transactions USING btree (project_id, in_scope);


--
-- Name: captured_http_transactions_project_id_ioc_incident_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_ioc_incident_id_idx ON public.captured_http_transactions USING btree (project_id, ioc_incident_id);


--
-- Name: captured_http_transactions_project_id_is_replay_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_is_replay_idx ON public.captured_http_transactions USING btree (project_id, is_replay);


--
-- Name: captured_http_transactions_project_id_run_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_run_id_idx ON public.captured_http_transactions USING btree (project_id, run_id);


--
-- Name: captured_http_transactions_project_id_session_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_session_id_idx ON public.captured_http_transactions USING btree (project_id, session_id);


--
-- Name: captured_http_transactions_project_id_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_source_idx ON public.captured_http_transactions USING btree (project_id, source);


--
-- Name: captured_http_transactions_project_id_status_code_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_status_code_idx ON public.captured_http_transactions USING btree (project_id, status_code);


--
-- Name: captured_http_transactions_project_id_tool_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_tool_idx ON public.captured_http_transactions USING btree (project_id, tool);


--
-- Name: captured_http_transactions_project_id_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX captured_http_transactions_project_id_user_id_idx ON public.captured_http_transactions USING btree (project_id, user_id);


--
-- Name: chat_messages_conversation_id_sequence_num_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_messages_conversation_id_sequence_num_idx ON public.chat_messages USING btree (conversation_id, sequence_num);


--
-- Name: chat_messages_fireteam_id_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_messages_fireteam_id_key_idx ON public.chat_messages USING btree (fireteam_id_key);


--
-- Name: chat_messages_member_id_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_messages_member_id_key_idx ON public.chat_messages USING btree (member_id_key);


--
-- Name: conversations_project_id_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX conversations_project_id_user_id_idx ON public.conversations USING btree (project_id, user_id);


--
-- Name: conversations_session_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX conversations_session_id_key ON public.conversations USING btree (session_id);


--
-- Name: engagement_authorization_archive_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX engagement_authorization_archive_project_id_idx ON public.engagement_authorization_archive USING btree (project_id);


--
-- Name: engagement_authorization_archive_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX engagement_authorization_archive_project_idx ON public.engagement_authorization_archive USING btree (project_id);


--
-- Name: engagement_authorizations_document_sha256_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX engagement_authorizations_document_sha256_idx ON public.engagement_authorizations USING btree (document_sha256);


--
-- Name: engagement_authorizations_idempotency_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX engagement_authorizations_idempotency_key_key ON public.engagement_authorizations USING btree (idempotency_key);


--
-- Name: engagement_authorizations_project_id_recorded_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX engagement_authorizations_project_id_recorded_at_idx ON public.engagement_authorizations USING btree (project_id, recorded_at);


--
-- Name: fireteam_members_fireteam_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX fireteam_members_fireteam_id_idx ON public.fireteam_members USING btree (fireteam_id);


--
-- Name: fireteam_members_member_id_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX fireteam_members_member_id_key_key ON public.fireteam_members USING btree (member_id_key);


--
-- Name: fireteam_settings_audit_field_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX fireteam_settings_audit_field_idx ON public.fireteam_settings_audit USING btree (field);


--
-- Name: fireteam_settings_audit_project_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX fireteam_settings_audit_project_id_created_at_idx ON public.fireteam_settings_audit USING btree (project_id, created_at);


--
-- Name: fireteams_fireteam_id_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX fireteams_fireteam_id_key_key ON public.fireteams USING btree (fireteam_id_key);


--
-- Name: fireteams_parent_conversation_id_fireteam_number_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX fireteams_parent_conversation_id_fireteam_number_idx ON public.fireteams USING btree (parent_conversation_id, fireteam_number);


--
-- Name: fireteams_parent_session_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX fireteams_parent_session_id_idx ON public.fireteams USING btree (parent_session_id);


--
-- Name: graph_views_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX graph_views_project_id_idx ON public.graph_views USING btree (project_id);


--
-- Name: job_queue_project_id_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX job_queue_project_id_status_idx ON public.job_queue USING btree (project_id, status);


--
-- Name: job_queue_status_priority_enqueued_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX job_queue_status_priority_enqueued_at_idx ON public.job_queue USING btree (status, priority, enqueued_at);


--
-- Name: job_queue_user_id_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX job_queue_user_id_status_idx ON public.job_queue USING btree (user_id, status);


--
-- Name: mcp_access_tokens_token_hash_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mcp_access_tokens_token_hash_key ON public.mcp_access_tokens USING btree (token_hash);


--
-- Name: mcp_access_tokens_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_access_tokens_user_id_idx ON public.mcp_access_tokens USING btree (user_id);


--
-- Name: node_filter_exemptions_project_id_label_node_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX node_filter_exemptions_project_id_label_node_key_key ON public.node_filter_exemptions USING btree (project_id, label, node_key);


--
-- Name: node_filter_runs_project_id_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_filter_runs_project_id_status_idx ON public.node_filter_runs USING btree (project_id, status);


--
-- Name: plugin_data_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_data_expires_at_idx ON public.plugin_data USING btree (expires_at);


--
-- Name: plugin_data_plugin_id_namespace_collection_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_data_plugin_id_namespace_collection_idx ON public.plugin_data USING btree (plugin_id, namespace, collection);


--
-- Name: plugin_data_plugin_id_namespace_owner_type_owner_id_collect_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX plugin_data_plugin_id_namespace_owner_type_owner_id_collect_key ON public.plugin_data USING btree (plugin_id, namespace, owner_type, owner_id, collection, key);


--
-- Name: plugin_data_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_data_project_id_idx ON public.plugin_data USING btree (project_id);


--
-- Name: plugin_data_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_data_user_id_idx ON public.plugin_data USING btree (user_id);


--
-- Name: plugin_overrides_change_set_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_overrides_change_set_id_idx ON public.plugin_overrides USING btree (change_set_id);


--
-- Name: plugin_overrides_extension_point_scope_type_scope_id_target_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_overrides_extension_point_scope_type_scope_id_target_idx ON public.plugin_overrides USING btree (extension_point, scope_type, scope_id, target_group, status);


--
-- Name: plugin_overrides_one_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX plugin_overrides_one_active ON public.plugin_overrides USING btree (extension_point, scope_type, scope_id, target_key) WHERE (status = 'active'::text);


--
-- Name: plugin_overrides_plugin_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_overrides_plugin_id_idx ON public.plugin_overrides USING btree (plugin_id);


--
-- Name: plugin_overrides_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_overrides_project_id_idx ON public.plugin_overrides USING btree (project_id);


--
-- Name: plugin_overrides_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX plugin_overrides_user_id_idx ON public.plugin_overrides USING btree (user_id);


--
-- Name: project_auth_profiles_project_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX project_auth_profiles_project_id_key ON public.project_auth_profiles USING btree (project_id);


--
-- Name: project_auth_profiles_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_auth_profiles_user_id_idx ON public.project_auth_profiles USING btree (user_id);


--
-- Name: projects_jev_provider_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX projects_jev_provider_id_idx ON public.projects USING btree (jev_provider_id);


--
-- Name: recording_sessions_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX recording_sessions_project_id_idx ON public.recording_sessions USING btree (project_id);


--
-- Name: recording_sessions_state_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX recording_sessions_state_expires_at_idx ON public.recording_sessions USING btree (state, expires_at);


--
-- Name: remediations_project_id_group_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX remediations_project_id_group_key_key ON public.remediations USING btree (project_id, group_key);


--
-- Name: remediations_project_id_priority_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX remediations_project_id_priority_idx ON public.remediations USING btree (project_id, priority);


--
-- Name: remediations_project_id_severity_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX remediations_project_id_severity_idx ON public.remediations USING btree (project_id, severity);


--
-- Name: remediations_project_id_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX remediations_project_id_status_idx ON public.remediations USING btree (project_id, status);


--
-- Name: reports_project_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX reports_project_id_created_at_idx ON public.reports USING btree (project_id, created_at);


--
-- Name: roe_document_revisions_project_id_superseded_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX roe_document_revisions_project_id_superseded_at_idx ON public.roe_document_revisions USING btree (project_id, superseded_at);


--
-- Name: scan_jobs_project_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scan_jobs_project_id_created_at_idx ON public.scan_jobs USING btree (project_id, created_at);


--
-- Name: scan_jobs_project_id_kind_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scan_jobs_project_id_kind_status_idx ON public.scan_jobs USING btree (project_id, kind, status);


--
-- Name: scan_jobs_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scan_jobs_status_idx ON public.scan_jobs USING btree (status);


--
-- Name: scan_schedules_enabled_next_run_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scan_schedules_enabled_next_run_at_idx ON public.scan_schedules USING btree (enabled, next_run_at);


--
-- Name: scan_schedules_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scan_schedules_project_id_idx ON public.scan_schedules USING btree (project_id);


--
-- Name: scan_versions_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scan_versions_project_id_idx ON public.scan_versions USING btree (project_id);


--
-- Name: scan_versions_project_id_seq_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX scan_versions_project_id_seq_key ON public.scan_versions USING btree (project_id, seq);


--
-- Name: supply_chain_batch_items_batch_id_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supply_chain_batch_items_batch_id_status_idx ON public.supply_chain_batch_items USING btree (batch_id, status);


--
-- Name: supply_chain_batches_project_id_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supply_chain_batches_project_id_status_idx ON public.supply_chain_batches USING btree (project_id, status);


--
-- Name: supply_chain_batches_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supply_chain_batches_user_id_idx ON public.supply_chain_batches USING btree (user_id);


--
-- Name: triage_runs_project_id_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX triage_runs_project_id_status_idx ON public.triage_runs USING btree (project_id, status);


--
-- Name: triage_runs_project_id_trigger_started_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX triage_runs_project_id_trigger_started_at_idx ON public.triage_runs USING btree (project_id, trigger, started_at);


--
-- Name: trufflehog_scan_profiles_project_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trufflehog_scan_profiles_project_id_idx ON public.trufflehog_scan_profiles USING btree (project_id);


--
-- Name: trufflehog_scan_profiles_project_id_source_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX trufflehog_scan_profiles_project_id_source_key ON public.trufflehog_scan_profiles USING btree (project_id, source);


--
-- Name: user_attack_skills_origin_change_set_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_attack_skills_origin_change_set_id_key ON public.user_attack_skills USING btree (origin_change_set_id);


--
-- Name: user_attack_skills_origin_plugin_id_origin_plugin_version_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_attack_skills_origin_plugin_id_origin_plugin_version_idx ON public.user_attack_skills USING btree (origin_plugin_id, origin_plugin_version);


--
-- Name: user_attack_skills_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_attack_skills_user_id_idx ON public.user_attack_skills USING btree (user_id);


--
-- Name: user_chat_skills_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_chat_skills_user_id_idx ON public.user_chat_skills USING btree (user_id);


--
-- Name: user_llm_providers_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_llm_providers_user_id_idx ON public.user_llm_providers USING btree (user_id);


--
-- Name: user_mute_rules_presets_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_mute_rules_presets_user_id_idx ON public.user_mute_rules_presets USING btree (user_id);


--
-- Name: user_project_presets_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_project_presets_user_id_idx ON public.user_project_presets USING btree (user_id);


--
-- Name: user_settings_user_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_settings_user_id_key ON public.user_settings USING btree (user_id);


--
-- Name: user_tradecraft_resources_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_tradecraft_resources_user_id_idx ON public.user_tradecraft_resources USING btree (user_id);


--
-- Name: user_tradecraft_resources_user_id_slug_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_tradecraft_resources_user_id_slug_key ON public.user_tradecraft_resources USING btree (user_id, slug);


--
-- Name: user_tradecraft_resources_user_id_url_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_tradecraft_resources_user_id_url_key ON public.user_tradecraft_resources USING btree (user_id, url);


--
-- Name: users_email_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_email_key ON public.users USING btree (email);


--
-- Name: engagement_authorizations engagement_authorizations_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER engagement_authorizations_append_only BEFORE DELETE OR UPDATE ON public.engagement_authorizations FOR EACH ROW EXECUTE FUNCTION public.redamon_engagement_authorizations_append_only();


--
-- Name: api_usage_reports api_usage_reports_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_usage_reports
    ADD CONSTRAINT api_usage_reports_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: captured_http_transactions captured_http_transactions_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.captured_http_transactions
    ADD CONSTRAINT captured_http_transactions_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: captured_http_transactions captured_http_transactions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.captured_http_transactions
    ADD CONSTRAINT captured_http_transactions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: chat_messages chat_messages_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: conversations conversations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: conversations conversations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: engagement_authorizations engagement_authorizations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.engagement_authorizations
    ADD CONSTRAINT engagement_authorizations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: fireteam_members fireteam_members_fireteam_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fireteam_members
    ADD CONSTRAINT fireteam_members_fireteam_id_fkey FOREIGN KEY (fireteam_id) REFERENCES public.fireteams(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: fireteams fireteams_parent_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fireteams
    ADD CONSTRAINT fireteams_parent_conversation_id_fkey FOREIGN KEY (parent_conversation_id) REFERENCES public.conversations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: graph_views graph_views_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.graph_views
    ADD CONSTRAINT graph_views_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: job_queue job_queue_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_queue
    ADD CONSTRAINT job_queue_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: mcp_access_tokens mcp_access_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_access_tokens
    ADD CONSTRAINT mcp_access_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: node_filter_exemptions node_filter_exemptions_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_filter_exemptions
    ADD CONSTRAINT node_filter_exemptions_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: node_filter_runs node_filter_runs_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_filter_runs
    ADD CONSTRAINT node_filter_runs_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: plugin_data plugin_data_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_data
    ADD CONSTRAINT plugin_data_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.plugin_installs(plugin_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: plugin_data plugin_data_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_data
    ADD CONSTRAINT plugin_data_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: plugin_data plugin_data_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_data
    ADD CONSTRAINT plugin_data_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: plugin_overrides plugin_overrides_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_overrides
    ADD CONSTRAINT plugin_overrides_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.plugin_installs(plugin_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: plugin_overrides plugin_overrides_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_overrides
    ADD CONSTRAINT plugin_overrides_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: plugin_overrides plugin_overrides_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plugin_overrides
    ADD CONSTRAINT plugin_overrides_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: project_auth_profiles project_auth_profiles_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_auth_profiles
    ADD CONSTRAINT project_auth_profiles_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: project_node_filters project_node_filters_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_node_filters
    ADD CONSTRAINT project_node_filters_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: projects projects_jev_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_jev_provider_id_fkey FOREIGN KEY (jev_provider_id) REFERENCES public.user_llm_providers(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: projects projects_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: recording_sessions recording_sessions_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recording_sessions
    ADD CONSTRAINT recording_sessions_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: remediations remediations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediations
    ADD CONSTRAINT remediations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: reports reports_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: roe_document_revisions roe_document_revisions_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roe_document_revisions
    ADD CONSTRAINT roe_document_revisions_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: scan_jobs scan_jobs_authorization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_authorization_id_fkey FOREIGN KEY (authorization_id) REFERENCES public.engagement_authorizations(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: scan_jobs scan_jobs_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: scan_jobs scan_jobs_schedule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES public.scan_schedules(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: scan_jobs scan_jobs_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_version_id_fkey FOREIGN KEY (version_id) REFERENCES public.scan_versions(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: scan_schedules scan_schedules_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_schedules
    ADD CONSTRAINT scan_schedules_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: scan_versions scan_versions_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_versions
    ADD CONSTRAINT scan_versions_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: supply_chain_batch_items supply_chain_batch_items_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supply_chain_batch_items
    ADD CONSTRAINT supply_chain_batch_items_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.supply_chain_batches(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: supply_chain_batches supply_chain_batches_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supply_chain_batches
    ADD CONSTRAINT supply_chain_batches_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: triage_runs triage_runs_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.triage_runs
    ADD CONSTRAINT triage_runs_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: trufflehog_scan_profiles trufflehog_scan_profiles_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trufflehog_scan_profiles
    ADD CONSTRAINT trufflehog_scan_profiles_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_attack_skills user_attack_skills_derived_from_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_attack_skills
    ADD CONSTRAINT user_attack_skills_derived_from_id_fkey FOREIGN KEY (derived_from_id) REFERENCES public.user_attack_skills(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: user_attack_skills user_attack_skills_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_attack_skills
    ADD CONSTRAINT user_attack_skills_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_chat_skills user_chat_skills_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_chat_skills
    ADD CONSTRAINT user_chat_skills_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_llm_providers user_llm_providers_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_llm_providers
    ADD CONSTRAINT user_llm_providers_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_mute_rules_presets user_mute_rules_presets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_mute_rules_presets
    ADD CONSTRAINT user_mute_rules_presets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_project_presets user_project_presets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_project_presets
    ADD CONSTRAINT user_project_presets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_settings user_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_tradecraft_resources user_tradecraft_resources_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_tradecraft_resources
    ADD CONSTRAINT user_tradecraft_resources_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict 267p1R7KiyNeBe6mcSo6n35IlNf9y7chN9u8vwEYUDdKtIyDVh1XpoVhf8KdfmU

