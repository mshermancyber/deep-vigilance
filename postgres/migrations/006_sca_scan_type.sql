-- Add 'sca' scan type to scans and findings tables
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_scan_type_check;
ALTER TABLE scans ADD CONSTRAINT scans_scan_type_check
  CHECK (scan_type::text = ANY (ARRAY['sast','dast','api','sca','full']::text[]));

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_type_check
  CHECK (type::text = ANY (ARRAY['sast','dast','api','sca','manual']::text[]));
