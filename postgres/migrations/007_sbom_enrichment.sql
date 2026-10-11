-- Add SBOM visualizer enrichment columns
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS enrichment JSONB;
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS graph_html TEXT;
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS enrichment_status VARCHAR(20) NOT NULL DEFAULT 'pending';
