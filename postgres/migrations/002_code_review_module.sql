-- ============================================================
-- Code Review & Secure Fuzz Analysis Module — Schema Migration
-- Version: 2.0.0
-- ============================================================

BEGIN;

-- Git Repository Connections
CREATE TABLE git_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL CHECK (provider IN ('github', 'gitlab', 'bitbucket', 'azure', 'gitea', 'generic')),
    repository_url TEXT NOT NULL,
    clone_url TEXT NOT NULL,
    default_branch VARCHAR(255) DEFAULT 'main',
    auth_type VARCHAR(50) NOT NULL DEFAULT 'token' CHECK (auth_type IN ('token', 'ssh', 'oauth', 'app', 'none')),
    auth_credentials TEXT,
    webhook_secret TEXT,
    webhook_id VARCHAR(255),
    last_synced_at TIMESTAMPTZ,
    last_commit_hash VARCHAR(64),
    sync_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_git_connections_org ON git_connections(org_id);
CREATE INDEX idx_git_connections_project ON git_connections(project_id);

-- Code Review Scans
CREATE TABLE code_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    git_connection_id UUID REFERENCES git_connections(id),
    name VARCHAR(255) NOT NULL,
    review_type VARCHAR(50) NOT NULL CHECK (review_type IN (
        'full', 'semantic', 'security', 'dependency', 'fuzz', 'health', 'incremental'
    )),
    target_type VARCHAR(30) NOT NULL CHECK (target_type IN (
        'repository', 'upload', 'folder', 'file', 'monorepo', 'iac', 'cicd'
    )),
    target_path TEXT,
    branch VARCHAR(255),
    commit_hash VARCHAR(64),
    base_commit_hash VARCHAR(64),
    status VARCHAR(30) NOT NULL DEFAULT 'queued' CHECK (status IN (
        'queued', 'cloning', 'indexing', 'analyzing', 'reviewing', 'fuzzing',
        'completed', 'failed', 'cancelled', 'partial'
    )),
    options JSONB DEFAULT '{}'::jsonb,
    languages_detected TEXT[] DEFAULT ARRAY[]::TEXT[],
    files_scanned INTEGER DEFAULT 0,
    lines_scanned BIGINT DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    false_positive_rate NUMERIC(5,2),
    scan_duration_ms BIGINT,
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    started_by UUID REFERENCES users(id),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_code_reviews_org ON code_reviews(org_id);
CREATE INDEX idx_code_reviews_project ON code_reviews(project_id);
CREATE INDEX idx_code_reviews_status ON code_reviews(status);
CREATE INDEX idx_code_reviews_type ON code_reviews(review_type);

-- Code Review Findings (semantic, security, quality)
CREATE TABLE code_review_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id),

    -- Finding identification
    finding_type VARCHAR(50) NOT NULL CHECK (finding_type IN (
        'semantic', 'security', 'quality', 'performance', 'logic',
        'dependency', 'fuzz', 'style', 'architecture', 'configuration',
        'license', 'supply_chain', 'iac', 'cicd'
    )),
    category VARCHAR(100) NOT NULL,
    rule_id VARCHAR(100) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,

    -- Severity & scoring
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    severity_rank INTEGER NOT NULL DEFAULT 3,
    confidence_score NUMERIC(5,2) DEFAULT 0.0,
    false_positive_probability NUMERIC(5,2) DEFAULT 0.0,
    exploitability_score NUMERIC(5,2),

    -- Location
    file_path TEXT,
    line_number INTEGER,
    line_range VARCHAR(50),
    column_number INTEGER,
    function_name VARCHAR(255),
    class_name VARCHAR(255),
    code_snippet TEXT,
    context_snippet TEXT,

    -- AI Analysis
    ai_summary TEXT,
    root_cause TEXT,
    security_impact TEXT,
    business_impact TEXT,
    exploitability_assessment TEXT,
    recommended_fix TEXT,
    secure_code_example TEXT,
    alternative_mitigations TEXT[],
    ai_confidence_score NUMERIC(5,2),

    -- Standards mapping
    cwe_id VARCHAR(20),
    cve_id VARCHAR(20),
    owasp_category VARCHAR(100),
    cvss_score NUMERIC(3,1) DEFAULT 0.0,
    cvss_vector VARCHAR(255),
    epss_score NUMERIC(5,4) DEFAULT 0.0,
    kev_match BOOLEAN DEFAULT FALSE,

    -- Remediation
    recommendation TEXT,
    references_data JSONB DEFAULT '[]'::jsonb,
    evidence JSONB DEFAULT '{}'::jsonb,

    -- Status tracking
    status VARCHAR(30) NOT NULL DEFAULT 'open' CHECK (status IN (
        'open', 'acknowledged', 'in_progress', 'fixed', 'wont_fix',
        'false_positive', 'accepted_risk', 'remediated', 'verified'
    )),
    assigned_to UUID REFERENCES users(id),
    resolved_at TIMESTAMPTZ,

    -- Metadata
    language VARCHAR(50),
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_crf_review ON code_review_findings(review_id);
CREATE INDEX idx_crf_org ON code_review_findings(org_id);
CREATE INDEX idx_crf_type ON code_review_findings(finding_type);
CREATE INDEX idx_crf_severity ON code_review_findings(severity);
CREATE INDEX idx_crf_status ON code_review_findings(status);
CREATE INDEX idx_crf_cwe ON code_review_findings(cwe_id);
CREATE INDEX idx_crf_language ON code_review_findings(language);
CREATE INDEX idx_crf_category ON code_review_findings(category);

-- Automated Fix Suggestions
CREATE TABLE code_fixes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES code_review_findings(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),

    original_code TEXT NOT NULL,
    suggested_code TEXT NOT NULL,
    patch_diff TEXT,
    explanation TEXT NOT NULL,
    security_benefit TEXT,
    potential_side_effects TEXT,
    confidence_level NUMERIC(5,2) NOT NULL DEFAULT 0.0,
    fix_type VARCHAR(50) NOT NULL CHECK (fix_type IN (
        'replace', 'insert', 'delete', 'refactor', 'configure', 'dependency_upgrade'
    )),
    language VARCHAR(50),
    applied BOOLEAN NOT NULL DEFAULT FALSE,
    applied_by UUID REFERENCES users(id),
    applied_at TIMESTAMPTZ,
    exported_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_code_fixes_finding ON code_fixes(finding_id);
CREATE INDEX idx_code_fixes_org ON code_fixes(org_id);

-- Fuzz Test Configurations
CREATE TABLE fuzz_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    review_id UUID REFERENCES code_reviews(id),
    name VARCHAR(255) NOT NULL,
    target_type VARCHAR(50) NOT NULL CHECK (target_type IN (
        'rest_api', 'graphql', 'soap', 'json_parser', 'xml_parser',
        'file_parser', 'cli_parser', 'config_parser', 'serialization',
        'deserialization', 'regex', 'input_validation', 'auth_workflow',
        'custom'
    )),
    target_spec TEXT,
    target_url TEXT,
    target_file TEXT,
    target_function VARCHAR(255),

    -- Fuzz configuration
    fuzz_strategies TEXT[] DEFAULT ARRAY[]::TEXT[],
    mutation_count INTEGER DEFAULT 1000,
    timeout_seconds INTEGER DEFAULT 300,
    max_input_size_bytes INTEGER DEFAULT 1048576,
    seed_corpus TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Status
    status VARCHAR(30) NOT NULL DEFAULT 'queued' CHECK (status IN (
        'queued', 'running', 'generating', 'executing', 'completed', 'failed', 'cancelled'
    )),
    total_iterations INTEGER DEFAULT 0,
    crash_count INTEGER DEFAULT 0,
    exception_count INTEGER DEFAULT 0,
    timeout_count INTEGER DEFAULT 0,
    unique_crashes INTEGER DEFAULT 0,
    code_coverage_pct NUMERIC(5,2),
    duration_ms BIGINT,

    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    started_by UUID REFERENCES users(id),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fuzz_tests_org ON fuzz_tests(org_id);
CREATE INDEX idx_fuzz_tests_review ON fuzz_tests(review_id);

-- Fuzz Test Cases
CREATE TABLE fuzz_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fuzz_test_id UUID NOT NULL REFERENCES fuzz_tests(id) ON DELETE CASCADE,
    iteration INTEGER NOT NULL,
    input_data TEXT NOT NULL,
    input_size INTEGER,
    strategy VARCHAR(100),
    mutated_from VARCHAR(255),
    execution_time_ms INTEGER,
    exit_code INTEGER,
    signal_number INTEGER,
    crash_detected BOOLEAN DEFAULT FALSE,
    exception_detected BOOLEAN DEFAULT FALSE,
    timeout_detected BOOLEAN DEFAULT FALSE,
    output_data TEXT,
    error_output TEXT,
    stack_trace TEXT,
    memory_usage_bytes BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fuzz_cases_test ON fuzz_cases(fuzz_test_id);
CREATE INDEX idx_fuzz_cases_crash ON fuzz_cases(crash_detected) WHERE crash_detected = TRUE;

-- Fuzz Crashes (deterministic reproduction)
CREATE TABLE fuzz_crashes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fuzz_test_id UUID NOT NULL REFERENCES fuzz_tests(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),
    crash_type VARCHAR(100) NOT NULL CHECK (crash_type IN (
        'segfault', 'panic', 'exception', 'stack_overflow', 'memory_exhaustion',
        'timeout', 'resource_exhaustion', 'unhandled_error', 'abort', 'assertion_failure'
    )),
    severity VARCHAR(20) NOT NULL DEFAULT 'high' CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    crash_signature VARCHAR(500) NOT NULL,
    reproducible BOOLEAN NOT NULL DEFAULT FALSE,
    reproduction_input TEXT,
    reproduction_steps TEXT,
    crash_output TEXT,
    stack_trace TEXT,
    register_state TEXT,
    memory_dump TEXT,
    affected_function VARCHAR(255),
    affected_file TEXT,
    line_number INTEGER,
    root_cause_analysis TEXT,
    cwe_id VARCHAR(20),
    cvss_score NUMERIC(3,1),
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fuzz_crashes_test ON fuzz_crashes(fuzz_test_id);
CREATE INDEX idx_fuzz_crashes_org ON fuzz_crashes(org_id);
CREATE INDEX idx_fuzz_crashes_type ON fuzz_crashes(crash_type);

-- Dependency Scans (SCA)
CREATE TABLE dependency_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    review_id UUID REFERENCES code_reviews(id),
    name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL CHECK (ecosystem IN (
        'npm', 'pip', 'maven', 'gradle', 'nuget', 'cargo',
        'composer', 'go_modules', 'rubygems', 'other'
    )),
    manifest_file TEXT,
    lock_file TEXT,
    total_packages INTEGER DEFAULT 0,
    vulnerable_packages INTEGER DEFAULT 0,
    deprecated_packages INTEGER DEFAULT 0,
    end_of_life_packages INTEGER DEFAULT 0,
    license_issues INTEGER DEFAULT 0,
    supply_chain_risks INTEGER DEFAULT 0,
    status VARCHAR(30) NOT NULL DEFAULT 'queued' CHECK (status IN (
        'queued', 'parsing', 'resolving', 'scanning', 'completed', 'failed'
    )),
    scan_duration_ms BIGINT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dependency_scans_org ON dependency_scans(org_id);
CREATE INDEX idx_dependency_scans_review ON dependency_scans(review_id);

-- Dependency Findings
CREATE TABLE dependency_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES dependency_scans(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    vulnerability_type VARCHAR(50) NOT NULL CHECK (vulnerability_type IN (
        'cve', 'deprecated', 'end_of_life', 'license', 'supply_chain',
        'typosquatting', 'dependency_confusion', 'unmaintained', 'malicious'
    )),
    cve_id VARCHAR(20),
    cwe_id VARCHAR(20),
    cvss_score NUMERIC(3,1),
    epss_score NUMERIC(5,4),
    kev_match BOOLEAN DEFAULT FALSE,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    fixed_in_version VARCHAR(100),
    recommendation TEXT,
    references_data JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dep_findings_scan ON dependency_findings(scan_id);
CREATE INDEX idx_dep_findings_cve ON dependency_findings(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_dep_findings_severity ON dependency_findings(severity);

-- Repository Health Metrics
CREATE TABLE repo_health_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    project_id UUID REFERENCES projects(id),
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,

    -- Core metrics
    total_files INTEGER DEFAULT 0,
    total_lines BIGINT DEFAULT 0,
    code_lines BIGINT DEFAULT 0,
    comment_lines BIGINT DEFAULT 0,
    blank_lines BIGINT DEFAULT 0,
    total_functions INTEGER DEFAULT 0,
    total_classes INTEGER DEFAULT 0,

    -- Complexity
    cyclomatic_complexity_avg NUMERIC(7,2),
    cyclomatic_complexity_max INTEGER,
    cognitive_complexity_avg NUMERIC(7,2),

    -- Maintainability
    maintainability_index NUMERIC(5,2),
    technical_debt_ratio NUMERIC(5,2),
    technical_debt_minutes BIGINT,
    duplication_pct NUMERIC(5,2),
    duplicated_blocks INTEGER DEFAULT 0,
    duplicated_lines INTEGER DEFAULT 0,

    -- Code quality
    code_churn_pct NUMERIC(5,2),
    comment_density_pct NUMERIC(5,2),
    unused_code_pct NUMERIC(5,2),
    dead_code_pct NUMERIC(5,2),
    security_density NUMERIC(5,2),

    -- Method/Class analysis
    complex_methods_count INTEGER DEFAULT 0,
    large_classes_count INTEGER DEFAULT 0,
    long_methods_count INTEGER DEFAULT 0,
    too_many_params_count INTEGER DEFAULT 0,

    -- Architecture
    architecture_smells JSONB DEFAULT '[]'::jsonb,
    dependency_graph JSONB,
    call_graph JSONB,
    package_graph JSONB,

    -- Risk
    risk_score INTEGER DEFAULT 0,
    risk_heatmap JSONB,

    -- Trend
    previous_review_id UUID REFERENCES code_reviews(id),
    metrics_delta JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_repo_health_review ON repo_health_metrics(review_id);

-- SARIF Export History
CREATE TABLE sarif_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_size_bytes BIGINT,
    sarif_version VARCHAR(20) DEFAULT '2.1.0',
    finding_count INTEGER DEFAULT 0,
    exported_by UUID REFERENCES users(id),
    exported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sarif_exports_review ON sarif_exports(review_id);

-- Code Index (for fast incremental rescan)
CREATE TABLE code_index (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    language VARCHAR(50),
    file_size_bytes INTEGER,
    line_count INTEGER,
    function_names TEXT[] DEFAULT ARRAY[]::TEXT[],
    class_names TEXT[] DEFAULT ARRAY[]::TEXT[],
    imports TEXT[] DEFAULT ARRAY[]::TEXT[],
    ast_hash VARCHAR(64),
    last_indexed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(review_id, file_path)
);

CREATE INDEX idx_code_index_review ON code_index(review_id);
CREATE INDEX idx_code_index_hash ON code_index(file_hash);
CREATE INDEX idx_code_index_language ON code_index(language);

-- Review Comments (collaboration)
CREATE TABLE review_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES code_review_findings(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    comment TEXT NOT NULL,
    line_number INTEGER,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_review_comments_finding ON review_comments(finding_id);

-- Notification preferences for code review events
CREATE TABLE code_review_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,
    events TEXT[] DEFAULT ARRAY['review.completed', 'finding.critical', 'fuzz.crash']::TEXT[],
    notify_email BOOLEAN DEFAULT TRUE,
    notify_webhook BOOLEAN DEFAULT FALSE,
    notify_ui BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, review_id)
);

COMMIT;
