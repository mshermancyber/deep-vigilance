// Platform initialization — creates default admin, applies migrations, seeds data
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { query } from './core/db/pool.js';
import { logger } from './core/logging/logger.js';

export async function initializePlatform(): Promise<void> {
  logger.info('Initializing platform...');

  // Check if organizations exist
  const orgCount = await query('SELECT COUNT(*) as count FROM organizations');
  if (parseInt((orgCount.rows[0] as Record<string,unknown>).count as string, 10) > 0) {
    logger.info('Platform already initialized — skipping');
    return;
  }

  logger.info('First run detected — creating default organization and admin user');

  // Create default organization
  const orgId = uuidv4();
  await query(`INSERT INTO organizations (id, name, settings, created_at, updated_at) VALUES ($1, 'Default Organization', '{"defaultRole":"viewer","mfaRequired":false}'::jsonb, NOW(), NOW())`, [orgId]);

  // Create super admin user
  const userId = uuidv4();
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!@#ChangeMe';
  const passwordHash = await bcrypt.hash(adminPassword, 14);

  await query(`INSERT INTO users (id, org_id, email, password_hash, name, role, created_at, updated_at)
    VALUES ($1, $2, $3, $4, 'System Administrator', 'super_admin', NOW(), NOW())`, [userId, orgId, adminEmail, passwordHash]);

  // Create default team
  const teamId = uuidv4();
  await query(`INSERT INTO teams (id, org_id, name, description, created_at, updated_at)
    VALUES ($1, $2, 'Security Team', 'Default security team', NOW(), NOW())`, [teamId, orgId]);
  await query(`INSERT INTO user_teams (user_id, team_id) VALUES ($1, $2)`, [userId, teamId]);

  // Seed rule sync sources (25 golden sources)
  const sources = [
    ['semgrep-rules','https://github.com/semgrep/semgrep-rules','sast','daily'],
    ['codeql','https://github.com/github/codeql','sast','daily'],
    ['gitlab-sast-rules','https://gitlab.com/gitlab-org/security-products/sast-rules','sast','daily'],
    ['gosec','https://github.com/securego/gosec','sast','weekly'],
    ['bandit','https://github.com/PyCQA/bandit','sast','weekly'],
    ['spotbugs','https://github.com/spotbugs/spotbugs','sast','weekly'],
    ['pmd','https://github.com/pmd/pmd','sast','weekly'],
    ['nuclei-templates','https://github.com/projectdiscovery/nuclei-templates','dast','daily'],
    ['fuzzdb','https://github.com/fuzzdb-project/fuzzdb','fuzz','weekly'],
    ['PayloadsAllTheThings','https://github.com/swisskyrepo/PayloadsAllTheThings','fuzz','weekly'],
    ['SecLists','https://github.com/danielmiessler/SecLists','fuzz','weekly'],
    ['gitleaks','https://github.com/gitleaks/gitleaks','secret','daily'],
    ['trufflehog','https://github.com/trufflesecurity/trufflehog','secret','daily'],
    ['checkov','https://github.com/bridgecrewio/checkov','iac','daily'],
    ['trivy','https://github.com/aquasecurity/trivy','container','daily'],
    ['grype','https://github.com/anchore/grype','vulndb','daily'],
    ['MobSF','https://github.com/MobSF/Mobile-Security-Framework-MobSF','mobile','weekly'],
    ['OWASP-ASVS','https://github.com/OWASP/ASVS','sast','weekly'],
    ['OWASP-MSTG','https://github.com/OWASP/owasp-mastg','mobile','weekly'],
    ['OWASP-wstg','https://github.com/OWASP/wstg','dast','weekly'],
    ['CIS-Benchmarks','https://www.cisecurity.org/cis-benchmarks','iac','monthly'],
  ];
  for (const [name, url, type, schedule] of sources) {
    await query(`INSERT INTO rule_sync_sources (id, org_id, source_name, source_url, source_type, sync_enabled, sync_schedule, created_at)
      VALUES ($1, $2, $3, $4, $5, true, $6, NOW())`, [uuidv4(), orgId, name, url, type, schedule]);
  }

  // Create default API workspace
  const wsId = uuidv4();
  await query(`INSERT INTO api_workspaces (id, org_id, name, description, visibility, created_by, created_at, updated_at)
    VALUES ($1, $2, 'Default Workspace', 'Default API workspace', 'private', $3, NOW(), NOW())`, [wsId, orgId, userId]);

  logger.info({ orgId, userId, adminEmail }, 'Platform initialization complete');
}
