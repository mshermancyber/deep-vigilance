-- ============================================================
-- Enterprise Scanning Capabilities — Schema Migration
-- SAST expansion, DAST enterprise, API Client, SBOM, Supply Chain
-- ============================================================

BEGIN;

-- ==========================================
-- SAST Rule Library (M5a, M5f)
-- ==========================================
CREATE TABLE sast_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    rule_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    languages TEXT[] DEFAULT ARRAY[]::TEXT[],
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    cvss_score NUMERIC(3,1) DEFAULT 0.0,
    cvss_vector VARCHAR(255),
    patterns JSONB NOT NULL DEFAULT '[]'::jsonb,
    pattern_type VARCHAR(50) NOT NULL DEFAULT 'regex' CHECK (pattern_type IN ('regex','semgrep','codeql','ast','dataflow','custom')),
    source_repo VARCHAR(255),
    source_license VARCHAR(100),
    source_version VARCHAR(50),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    precision_score NUMERIC(5,2),
    recall_score NUMERIC(5,2),
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,
    avg_scan_time_ms INTEGER,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, rule_id)
);

CREATE INDEX idx_sast_rules_org ON sast_rules(org_id);
CREATE INDEX idx_sast_rules_category ON sast_rules(category);
CREATE INDEX idx_sast_rules_severity ON sast_rules(severity);
CREATE INDEX idx_sast_rules_cwe ON sast_rules(cwe_id);
CREATE INDEX idx_sast_rules_language ON sast_rules USING GIN(languages);
CREATE INDEX idx_sast_rules_enabled ON sast_rules(enabled);

-- SAST Rule Overrides (per-org, per-project, per-rule)
CREATE TABLE sast_rule_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    rule_id UUID NOT NULL REFERENCES sast_rules(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id),
    severity_override VARCHAR(20) CHECK (severity_override IN ('critical','high','medium','low','info','suppress')),
    enabled_override BOOLEAN,
    exclude_patterns TEXT[] DEFAULT ARRAY[]::TEXT[],
    justification TEXT,
    approved_by UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, rule_id, project_id)
);

-- SAST Scan Index (incremental scanning cache) (M5e)
CREATE TABLE sast_scan_index (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    language VARCHAR(50),
    ast_hash VARCHAR(64),
    rules_evaluated TEXT[] DEFAULT ARRAY[]::TEXT[],
    findings_count INTEGER DEFAULT 0,
    scan_duration_ms INTEGER,
    last_scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(review_id, file_path)
);

CREATE INDEX idx_sast_scan_index_review ON sast_scan_index(review_id);
CREATE INDEX idx_sast_scan_index_hash ON sast_scan_index(file_hash);

-- Dataflow Analysis Results (M5d)
CREATE TABLE dataflow_paths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES code_review_findings(id) ON DELETE CASCADE,
    source_type VARCHAR(100) NOT NULL,
    source_location TEXT,
    sink_type VARCHAR(100) NOT NULL,
    sink_location TEXT,
    path_nodes JSONB NOT NULL DEFAULT '[]'::jsonb,
    sanitizers_encountered TEXT[] DEFAULT ARRAY[]::TEXT[],
    taint_broken BOOLEAN DEFAULT FALSE,
    path_length INTEGER DEFAULT 0,
    reachability_score NUMERIC(3,2) DEFAULT 1.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dataflow_paths_finding ON dataflow_paths(finding_id);

-- ==========================================
-- Container Image Scanning (M5h)
-- ==========================================
CREATE TABLE container_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    image_name VARCHAR(500) NOT NULL,
    image_digest VARCHAR(128),
    registry VARCHAR(255),
    tag VARCHAR(255),
    layers_count INTEGER DEFAULT 0,
    total_packages INTEGER DEFAULT 0,
    vulnerable_packages INTEGER DEFAULT 0,
    critical_cves INTEGER DEFAULT 0,
    high_cves INTEGER DEFAULT 0,
    medium_cves INTEGER DEFAULT 0,
    low_cves INTEGER DEFAULT 0,
    base_image VARCHAR(500),
    base_image_cves INTEGER DEFAULT 0,
    dockerfile_path TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'queued',
    scan_duration_ms BIGINT,
    sbom_generated BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,
    started_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_container_scans_org ON container_scans(org_id);
CREATE INDEX idx_container_scans_image ON container_scans(image_name);

CREATE TABLE container_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES container_scans(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),
    cve_id VARCHAR(20),
    severity VARCHAR(20) NOT NULL,
    cvss_score NUMERIC(3,1),
    package_name VARCHAR(255),
    installed_version VARCHAR(100),
    fixed_version VARCHAR(100),
    layer_idx INTEGER,
    title VARCHAR(500),
    description TEXT,
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_container_findings_scan ON container_findings(scan_id);
CREATE INDEX idx_container_findings_cve ON container_findings(cve_id);

-- ==========================================
-- Binary & Mobile Scanning (M5i)
-- ==========================================
CREATE TABLE binary_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    artifact_type VARCHAR(50) NOT NULL CHECK (artifact_type IN ('jar','war','ear','aar','dll','exe','elf','macho','wasm','apk','ipa')),
    artifact_path TEXT NOT NULL,
    artifact_hash VARCHAR(128),
    decompile_status VARCHAR(30) DEFAULT 'pending',
    languages_detected TEXT[],
    total_findings INTEGER DEFAULT 0,
    status VARCHAR(30) NOT NULL DEFAULT 'queued',
    metadata JSONB DEFAULT '{}'::jsonb,
    started_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_binary_scans_org ON binary_scans(org_id);

CREATE TABLE binary_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES binary_scans(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),
    finding_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500),
    description TEXT,
    cwe_id VARCHAR(20),
    cvss_score NUMERIC(3,1),
    file_path TEXT,
    class_name VARCHAR(255),
    method_name VARCHAR(255),
    code_snippet TEXT,
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_binary_findings_scan ON binary_findings(scan_id);

-- ==========================================
-- SBOM & Supply Chain (M5j)
-- ==========================================
CREATE TABLE sbom_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    scan_id UUID,
    format VARCHAR(20) NOT NULL CHECK (format IN ('cyclonedx','spdx')),
    version VARCHAR(20) NOT NULL DEFAULT '1.5',
    file_path TEXT NOT NULL,
    file_size_bytes BIGINT,
    component_count INTEGER DEFAULT 0,
    vulnerability_count INTEGER DEFAULT 0,
    signed BOOLEAN DEFAULT FALSE,
    signature_key_id VARCHAR(255),
    slsa_level VARCHAR(10),
    generated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sbom_exports_org ON sbom_exports(org_id);

CREATE TABLE license_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    license_type VARCHAR(100) NOT NULL,
    license_text TEXT,
    is_compatible BOOLEAN,
    policy_violation BOOLEAN DEFAULT FALSE,
    policy_rule VARCHAR(255),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_license_audit_org ON license_audit(org_id);

-- ==========================================
-- DAST Enterprise (M6a-M6g)
-- ==========================================
CREATE TABLE dast_auth_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    name VARCHAR(255) NOT NULL,
    auth_type VARCHAR(50) NOT NULL CHECK (auth_type IN ('form','basic','digest','ntlm','oauth2','oidc','jwt','apikey','mtls','saml')),
    login_url TEXT,
    login_macro JSONB,
    credentials_encrypted TEXT,
    oauth_config JSONB,
    mfa_config JSONB,
    cookie_jar JSONB,
    token_refresh_url TEXT,
    session_validation_url TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dast_auth_profiles_org ON dast_auth_profiles(org_id);

CREATE TABLE dast_crawl_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    method VARCHAR(10),
    status_code INTEGER,
    content_type VARCHAR(255),
    response_time_ms INTEGER,
    page_title TEXT,
    form_count INTEGER DEFAULT 0,
    link_count INTEGER DEFAULT 0,
    js_rendered BOOLEAN DEFAULT FALSE,
    screenshot_path TEXT,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dast_crawl_scan ON dast_crawl_results(scan_id);

CREATE TABLE dast_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    screenshot_path TEXT,
    request_har JSONB,
    response_har JSONB,
    curl_command TEXT,
    poc_script TEXT,
    video_path TEXT,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dast_evidence_finding ON dast_evidence(finding_id);

CREATE TABLE dast_waf_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    target_host TEXT NOT NULL,
    waf_detected VARCHAR(100),
    waf_mode VARCHAR(50),
    evasion_techniques TEXT[],
    rate_limit_threshold INTEGER,
    rate_limit_window_seconds INTEGER,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==========================================
-- API Client Enterprise (M7a-M7e)
-- ==========================================
CREATE TABLE api_workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    visibility VARCHAR(20) NOT NULL DEFAULT 'private' CHECK (visibility IN ('private','team','public')),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_workspaces_org ON api_workspaces(org_id);

CREATE TABLE api_workspace_members (
    workspace_id UUID NOT NULL REFERENCES api_workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','editor','viewer')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE api_variables (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('global','collection','environment','data','local')),
    scope_id UUID,
    key VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    secret BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_variables_scope ON api_variables(scope, scope_id);

CREATE TABLE api_collection_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    collection_id UUID NOT NULL REFERENCES api_collections(id) ON DELETE CASCADE,
    environment_id UUID,
    data_file_path TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'queued',
    total_requests INTEGER DEFAULT 0,
    passed INTEGER DEFAULT 0,
    failed INTEGER DEFAULT 0,
    skipped INTEGER DEFAULT 0,
    duration_ms BIGINT,
    results_json JSONB,
    started_by UUID REFERENCES users(id),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_collection_runs_collection ON api_collection_runs(collection_id);

CREATE TABLE api_mock_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    collection_id UUID NOT NULL REFERENCES api_collections(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    base_url TEXT NOT NULL,
    config JSONB DEFAULT '{}'::jsonb,
    enabled BOOLEAN DEFAULT TRUE,
    request_count INTEGER DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_mock_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mock_server_id UUID NOT NULL REFERENCES api_mock_servers(id) ON DELETE CASCADE,
    request_id UUID REFERENCES api_requests(id),
    method VARCHAR(10) NOT NULL,
    path_pattern TEXT NOT NULL,
    match_headers JSONB,
    match_body JSONB,
    response_status INTEGER NOT NULL DEFAULT 200,
    response_headers JSONB DEFAULT '{}'::jsonb,
    response_body TEXT,
    latency_ms INTEGER DEFAULT 0,
    error_probability NUMERIC(5,2) DEFAULT 0.0,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_monitors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    collection_id UUID NOT NULL REFERENCES api_collections(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    schedule VARCHAR(20) NOT NULL CHECK (schedule IN ('5m','15m','1h','daily','cron')),
    cron_expression VARCHAR(100),
    enabled BOOLEAN DEFAULT TRUE,
    alert_on_failure BOOLEAN DEFAULT TRUE,
    alert_on_timeout BOOLEAN DEFAULT TRUE,
    alert_channels TEXT[],
    last_run_at TIMESTAMPTZ,
    last_status VARCHAR(30),
    uptime_pct NUMERIC(5,2),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==========================================
-- Code Review Enterprise (M14a-M14e)
-- ==========================================
CREATE TABLE code_review_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    review_id UUID NOT NULL REFERENCES code_reviews(id),
    file_path TEXT NOT NULL,
    baseline_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    committed_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_baselines_project ON code_review_baselines(project_id);

CREATE TABLE finding_sla_tracking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES code_review_findings(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,
    sla_deadline TIMESTAMPTZ NOT NULL,
    sla_breached BOOLEAN DEFAULT FALSE,
    escalated_at TIMESTAMPTZ,
    escalated_to UUID REFERENCES users(id),
    resolved_at TIMESTAMPTZ,
    time_to_resolve_hours NUMERIC(8,2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sla_finding ON finding_sla_tracking(finding_id);
CREATE INDEX idx_sla_breached ON finding_sla_tracking(sla_breached) WHERE sla_breached = TRUE;

CREATE TABLE remediation_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    target_cwe TEXT[],
    target_severity TEXT[],
    target_teams UUID[],
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ,
    total_findings INTEGER DEFAULT 0,
    findings_fixed INTEGER DEFAULT 0,
    status VARCHAR(30) DEFAULT 'active',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE security_debt_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    debt_score INTEGER NOT NULL,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    avg_age_days NUMERIC(8,2),
    mttf_hours NUMERIC(8,2),
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    UNIQUE(org_id, project_id, snapshot_date)
);

-- ==========================================
-- Code Review Hotspots (M14e)
-- ==========================================
CREATE TABLE security_hotspots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    function_name VARCHAR(255),
    hotspot_category VARCHAR(100) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    description TEXT,
    requires_manual_review BOOLEAN DEFAULT TRUE,
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_hotspots_review ON security_hotspots(review_id);
CREATE INDEX idx_hotspots_category ON security_hotspots(hotspot_category);

-- ==========================================
-- Rule Sync Tracking (M18, M19)
-- ==========================================
CREATE TABLE rule_sync_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    source_name VARCHAR(100) NOT NULL,
    source_url TEXT NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    last_synced_at TIMESTAMPTZ,
    last_commit_hash VARCHAR(64),
    rules_count INTEGER DEFAULT 0,
    sync_enabled BOOLEAN DEFAULT TRUE,
    sync_schedule VARCHAR(20) DEFAULT 'daily',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, source_name)
);

CREATE TABLE rule_sync_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES rule_sync_sources(id) ON DELETE CASCADE,
    rules_added INTEGER DEFAULT 0,
    rules_updated INTEGER DEFAULT 0,
    rules_removed INTEGER DEFAULT 0,
    rules_deprecated INTEGER DEFAULT 0,
    conflicts INTEGER DEFAULT 0,
    sync_duration_ms BIGINT,
    status VARCHAR(30) NOT NULL,
    error_message TEXT,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==========================================
-- Collections Collaboration (M7e)
-- ==========================================
CREATE TABLE collection_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id UUID NOT NULL REFERENCES api_collections(id) ON DELETE CASCADE,
    version_tag VARCHAR(50),
    snapshot JSONB NOT NULL,
    change_description TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_collection_versions_coll ON collection_versions(collection_id);

COMMIT;
