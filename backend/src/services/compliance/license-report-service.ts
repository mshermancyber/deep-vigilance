import { query } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LicenseCategory =
  | 'permissive'
  | 'copyleft'
  | 'weak-copyleft'
  | 'restricted'
  | 'proprietary'
  | 'unknown';

export interface LicenseObligation {
  attribution: boolean;
  sourceDisclosure: boolean;
  sameLicense: boolean;
  stateChanges: boolean;
  includeNotice: boolean;
}

export interface DependencyEntry {
  name: string;
  version: string;
  filePath: string;
}

export interface LicenseGroup {
  licenseId: string;
  licenseName: string;
  category: LicenseCategory;
  dependencies: DependencyEntry[];
  obligations: LicenseObligation;
  compatibilityWarnings: string[];
}

export interface ActionItem {
  priority: 'critical' | 'high' | 'medium' | 'low';
  licenseId: string;
  licenseName: string;
  category: LicenseCategory;
  action: string;
  affectedDependencies: string[];
}

export interface LicenseComplianceReport {
  projectId: string;
  generatedAt: string;
  executiveSummary: string;
  totalDependencies: number;
  totalLicenses: number;
  categoryBreakdown: Record<LicenseCategory, number>;
  licenseGroups: LicenseGroup[];
  obligationMatrix: Array<{
    licenseId: string;
    licenseName: string;
    category: LicenseCategory;
    dependencyCount: number;
    attribution: boolean;
    sourceDisclosure: boolean;
    sameLicense: boolean;
  }>;
  actionItems: ActionItem[];
}

// ---------------------------------------------------------------------------
// License Obligation Definitions
// ---------------------------------------------------------------------------

const LICENSE_OBLIGATIONS: Record<string, LicenseObligation> = {
  // Permissive
  'MIT':             { attribution: true,  sourceDisclosure: false, sameLicense: false, stateChanges: false, includeNotice: true  },
  'Apache-2.0':     { attribution: true,  sourceDisclosure: false, sameLicense: false, stateChanges: true,  includeNotice: true  },
  'BSD-2-Clause':   { attribution: true,  sourceDisclosure: false, sameLicense: false, stateChanges: false, includeNotice: true  },
  'BSD-3-Clause':   { attribution: true,  sourceDisclosure: false, sameLicense: false, stateChanges: false, includeNotice: true  },
  'ISC':            { attribution: true,  sourceDisclosure: false, sameLicense: false, stateChanges: false, includeNotice: true  },
  'Unlicense':      { attribution: false, sourceDisclosure: false, sameLicense: false, stateChanges: false, includeNotice: false },
  'CC0-1.0':        { attribution: false, sourceDisclosure: false, sameLicense: false, stateChanges: false, includeNotice: false },
  'Zlib':           { attribution: true,  sourceDisclosure: false, sameLicense: false, stateChanges: true,  includeNotice: false },

  // Copyleft
  'GPL-2.0':        { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },
  'GPL-2.0-only':   { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },
  'GPL-3.0':        { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },
  'GPL-3.0-only':   { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },
  'AGPL-3.0':       { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },
  'AGPL-3.0-only':  { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },

  // Weak-copyleft
  'LGPL-2.1':       { attribution: true,  sourceDisclosure: true,  sameLicense: false, stateChanges: true,  includeNotice: true  },
  'LGPL-2.1-only':  { attribution: true,  sourceDisclosure: true,  sameLicense: false, stateChanges: true,  includeNotice: true  },
  'LGPL-3.0':       { attribution: true,  sourceDisclosure: true,  sameLicense: false, stateChanges: true,  includeNotice: true  },
  'LGPL-3.0-only':  { attribution: true,  sourceDisclosure: true,  sameLicense: false, stateChanges: true,  includeNotice: true  },
  'MPL-2.0':        { attribution: true,  sourceDisclosure: true,  sameLicense: false, stateChanges: true,  includeNotice: true  },
  'EPL-1.0':        { attribution: true,  sourceDisclosure: true,  sameLicense: false, stateChanges: true,  includeNotice: true  },
  'EPL-2.0':        { attribution: true,  sourceDisclosure: true,  sameLicense: false, stateChanges: true,  includeNotice: true  },

  // Restricted
  'SSPL-1.0':       { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },
  'EUPL-1.2':       { attribution: true,  sourceDisclosure: true,  sameLicense: true,  stateChanges: true,  includeNotice: true  },
  'BSL-1.0':        { attribution: true,  sourceDisclosure: false, sameLicense: false, stateChanges: false, includeNotice: true  },
};

const CATEGORY_MAP: Record<string, LicenseCategory> = {
  'MIT': 'permissive',
  'Apache-2.0': 'permissive',
  'BSD-2-Clause': 'permissive',
  'BSD-3-Clause': 'permissive',
  'ISC': 'permissive',
  'Unlicense': 'permissive',
  'CC0-1.0': 'permissive',
  'Zlib': 'permissive',
  'GPL-2.0': 'copyleft',
  'GPL-2.0-only': 'copyleft',
  'GPL-3.0': 'copyleft',
  'GPL-3.0-only': 'copyleft',
  'AGPL-3.0': 'copyleft',
  'AGPL-3.0-only': 'copyleft',
  'LGPL-2.1': 'weak-copyleft',
  'LGPL-2.1-only': 'weak-copyleft',
  'LGPL-3.0': 'weak-copyleft',
  'LGPL-3.0-only': 'weak-copyleft',
  'MPL-2.0': 'weak-copyleft',
  'EPL-1.0': 'weak-copyleft',
  'EPL-2.0': 'weak-copyleft',
  'SSPL-1.0': 'restricted',
  'EUPL-1.2': 'restricted',
  'BSL-1.0': 'restricted',
};

// ---------------------------------------------------------------------------
// Compatibility Warnings
// ---------------------------------------------------------------------------

function getCompatibilityWarnings(licenseId: string, category: LicenseCategory): string[] {
  const warnings: string[] = [];

  if (category === 'copyleft') {
    warnings.push(
      `${licenseId} is a copyleft license. Any software linked with ${licenseId}-licensed code must also be distributed under ${licenseId} or a compatible license.`,
    );
    if (licenseId.startsWith('AGPL')) {
      warnings.push(
        `${licenseId} extends copyleft to network use. Providing the software as a service (SaaS) triggers source disclosure obligations.`,
      );
    }
  }

  if (category === 'weak-copyleft') {
    warnings.push(
      `${licenseId} requires source disclosure for modifications to the library itself, but does not extend to the larger work when dynamically linked.`,
    );
  }

  if (category === 'restricted') {
    warnings.push(
      `${licenseId} has restrictive terms that may limit commercial use or impose additional obligations. Legal review is recommended.`,
    );
  }

  if (category === 'proprietary') {
    warnings.push(
      'Proprietary license detected. Verify that the license terms permit the intended use, distribution, and modification.',
    );
  }

  if (category === 'unknown') {
    warnings.push(
      'License could not be identified. This dependency may be using a custom or non-standard license. Manual review required.',
    );
  }

  // Cross-compatibility warnings
  if (licenseId === 'GPL-2.0' || licenseId === 'GPL-2.0-only') {
    warnings.push(
      'GPL-2.0 is not compatible with Apache-2.0. If your project uses Apache-2.0, you cannot include GPL-2.0 dependencies.',
    );
  }

  return warnings;
}

// ---------------------------------------------------------------------------
// Core Service
// ---------------------------------------------------------------------------

/**
 * Generate a License Compliance Report for a given project.
 *
 * Reads license findings from the DB, groups them by license type,
 * computes obligations for each license, and produces a structured
 * report with an executive summary, obligation matrix, and action items.
 */
export async function generateLicenseReport(
  projectId: string,
  orgId: string,
): Promise<LicenseComplianceReport> {
  // Fetch license-related findings for the project
  const result = await query(
    `SELECT f.id, f.rule_id, f.title, f.description, f.severity,
            f.file_path, f.line_number, f.metadata
     FROM findings f
     JOIN scans s ON s.id = f.scan_id
     WHERE s.project_id = $1
       AND s.org_id = $2
       AND f.rule_id LIKE 'LIC-%'
     ORDER BY f.severity_rank ASC, f.created_at DESC`,
    [projectId, orgId],
  );

  const rows = result.rows as Array<Record<string, unknown>>;

  logger.info(
    { projectId, licenseFindings: rows.length },
    'Fetched license findings for compliance report',
  );

  // Extract dependency and license information from findings
  const licenseMap = new Map<string, {
    licenseName: string;
    category: LicenseCategory;
    dependencies: DependencyEntry[];
  }>();

  for (const row of rows) {
    const metadata = (row.metadata ?? {}) as Record<string, unknown>;
    const licenseId = (metadata.license_id as string) ?? extractLicenseId(row.title as string);
    const licenseName = (metadata.license_name as string) ?? licenseId;
    const depName = (metadata.dependency_name as string) ?? extractDependencyName(row.title as string);
    const depVersion = (metadata.dependency_version as string) ?? '';
    const category = determineLicenseCategory(licenseId);

    if (!licenseMap.has(licenseId)) {
      licenseMap.set(licenseId, {
        licenseName,
        category,
        dependencies: [],
      });
    }

    const entry = licenseMap.get(licenseId)!;
    // Avoid duplicate dependencies
    const alreadyListed = entry.dependencies.some(
      d => d.name === depName && d.version === depVersion,
    );
    if (!alreadyListed) {
      entry.dependencies.push({
        name: depName,
        version: depVersion,
        filePath: (row.file_path as string) ?? '',
      });
    }
  }

  // Build license groups with obligations and compatibility warnings
  const licenseGroups: LicenseGroup[] = [];
  const categoryBreakdown: Record<LicenseCategory, number> = {
    permissive: 0,
    copyleft: 0,
    'weak-copyleft': 0,
    restricted: 0,
    proprietary: 0,
    unknown: 0,
  };

  let totalDependencies = 0;

  for (const [licenseId, data] of licenseMap) {
    const obligations = LICENSE_OBLIGATIONS[licenseId] ?? {
      attribution: true,
      sourceDisclosure: false,
      sameLicense: false,
      stateChanges: false,
      includeNotice: true,
    };

    const compatibilityWarnings = getCompatibilityWarnings(licenseId, data.category);

    licenseGroups.push({
      licenseId,
      licenseName: data.licenseName,
      category: data.category,
      dependencies: data.dependencies,
      obligations,
      compatibilityWarnings,
    });

    categoryBreakdown[data.category] += data.dependencies.length;
    totalDependencies += data.dependencies.length;
  }

  // Sort groups: restricted/copyleft first, then weak-copyleft, then permissive, then unknown
  const categoryOrder: Record<LicenseCategory, number> = {
    restricted: 0,
    copyleft: 1,
    'weak-copyleft': 2,
    proprietary: 3,
    unknown: 4,
    permissive: 5,
  };

  licenseGroups.sort((a, b) => categoryOrder[a.category] - categoryOrder[b.category]);

  // Build obligation matrix
  const obligationMatrix = licenseGroups.map(g => ({
    licenseId: g.licenseId,
    licenseName: g.licenseName,
    category: g.category,
    dependencyCount: g.dependencies.length,
    attribution: g.obligations.attribution,
    sourceDisclosure: g.obligations.sourceDisclosure,
    sameLicense: g.obligations.sameLicense,
  }));

  // Generate action items
  const actionItems = buildActionItems(licenseGroups);

  // Generate executive summary
  const executiveSummary = buildExecutiveSummary(
    totalDependencies,
    licenseGroups.length,
    categoryBreakdown,
    actionItems,
  );

  return {
    projectId,
    generatedAt: new Date().toISOString(),
    executiveSummary,
    totalDependencies,
    totalLicenses: licenseGroups.length,
    categoryBreakdown,
    licenseGroups,
    obligationMatrix,
    actionItems,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function determineLicenseCategory(licenseId: string): LicenseCategory {
  if (!licenseId) return 'unknown';
  return CATEGORY_MAP[licenseId] ?? 'unknown';
}

function extractLicenseId(title: string): string {
  if (!title) return 'unknown';
  // Try to extract license identifier from finding title
  // e.g., "Copyleft license detected: GPL-3.0" → "GPL-3.0"
  const match = title.match(/:\s*([A-Za-z0-9._-]+)\s*$/);
  if (match?.[1]) return match[1];

  // Try to find SPDX-style identifiers in the title
  const spdxMatch = title.match(/(MIT|Apache-2\.0|GPL-[23]\.0(?:-only)?|LGPL-[23]\.[01](?:-only)?|AGPL-3\.0(?:-only)?|MPL-2\.0|BSD-[23]-Clause|ISC|Unlicense|CC0-1\.0)/i);
  if (spdxMatch?.[1]) return spdxMatch[1];

  return 'unknown';
}

function extractDependencyName(title: string): string {
  if (!title) return 'unknown';
  // Try to extract dependency name from finding title
  // e.g., "License issue in express@4.18.2" → "express"
  const match = title.match(/in\s+([^\s@]+)/);
  if (match?.[1]) return match[1];
  return 'unknown';
}

function buildActionItems(licenseGroups: LicenseGroup[]): ActionItem[] {
  const items: ActionItem[] = [];

  for (const group of licenseGroups) {
    const depNames = group.dependencies.map(d => d.name);

    if (group.category === 'restricted') {
      items.push({
        priority: 'critical',
        licenseId: group.licenseId,
        licenseName: group.licenseName,
        category: group.category,
        action: `Review and evaluate restricted license ${group.licenseId}. Determine if the license terms are compatible with your project's distribution model. Consider replacing these dependencies with permissively-licensed alternatives.`,
        affectedDependencies: depNames,
      });
    }

    if (group.category === 'copyleft') {
      items.push({
        priority: 'high',
        licenseId: group.licenseId,
        licenseName: group.licenseName,
        category: group.category,
        action: `Copyleft license ${group.licenseId} requires source disclosure and same-license distribution. Verify that your distribution model complies with these obligations. If distributing as proprietary software, consider replacing these dependencies.`,
        affectedDependencies: depNames,
      });
    }

    if (group.category === 'weak-copyleft') {
      items.push({
        priority: 'medium',
        licenseId: group.licenseId,
        licenseName: group.licenseName,
        category: group.category,
        action: `Weak-copyleft license ${group.licenseId} requires source disclosure for modifications to the library. Ensure any modifications are tracked and disclosed. Dynamic linking is generally permitted without additional obligations.`,
        affectedDependencies: depNames,
      });
    }

    if (group.category === 'unknown') {
      items.push({
        priority: 'high',
        licenseId: group.licenseId,
        licenseName: group.licenseName,
        category: group.category,
        action: `License for ${group.dependencies.length} dependencies could not be identified. Manually verify the license terms for these packages before use in production.`,
        affectedDependencies: depNames,
      });
    }

    if (group.category === 'proprietary') {
      items.push({
        priority: 'high',
        licenseId: group.licenseId,
        licenseName: group.licenseName,
        category: group.category,
        action: `Proprietary license detected. Confirm that a valid commercial license or agreement is in place for all listed dependencies.`,
        affectedDependencies: depNames,
      });
    }

    // Attribution action for all non-public-domain licenses
    if (group.obligations.attribution && group.category === 'permissive') {
      items.push({
        priority: 'low',
        licenseId: group.licenseId,
        licenseName: group.licenseName,
        category: group.category,
        action: `Include license notice and attribution for ${group.licenseId}-licensed dependencies in your NOTICE or LICENSES file.`,
        affectedDependencies: depNames,
      });
    }
  }

  // Sort by priority
  const priorityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  items.sort((a, b) => (priorityOrder[a.priority] ?? 99) - (priorityOrder[b.priority] ?? 99));

  return items;
}

function buildExecutiveSummary(
  totalDependencies: number,
  totalLicenses: number,
  categoryBreakdown: Record<LicenseCategory, number>,
  actionItems: ActionItem[],
): string {
  const parts: string[] = [];

  parts.push(
    `License compliance analysis complete. ${totalDependencies} dependencies analyzed across ${totalLicenses} distinct license types.`,
  );

  // Category breakdown
  const breakdownParts: string[] = [];
  if (categoryBreakdown.permissive > 0) breakdownParts.push(`${categoryBreakdown.permissive} permissive`);
  if (categoryBreakdown.copyleft > 0) breakdownParts.push(`${categoryBreakdown.copyleft} copyleft`);
  if (categoryBreakdown['weak-copyleft'] > 0) breakdownParts.push(`${categoryBreakdown['weak-copyleft']} weak-copyleft`);
  if (categoryBreakdown.restricted > 0) breakdownParts.push(`${categoryBreakdown.restricted} restricted`);
  if (categoryBreakdown.proprietary > 0) breakdownParts.push(`${categoryBreakdown.proprietary} proprietary`);
  if (categoryBreakdown.unknown > 0) breakdownParts.push(`${categoryBreakdown.unknown} unknown`);

  if (breakdownParts.length > 0) {
    parts.push(`Distribution: ${breakdownParts.join(', ')}.`);
  }

  // Risk assessment
  const criticalItems = actionItems.filter(i => i.priority === 'critical').length;
  const highItems = actionItems.filter(i => i.priority === 'high').length;

  if (criticalItems > 0) {
    parts.push(`${criticalItems} critical action item(s) requiring immediate attention (restricted licenses detected).`);
  }
  if (highItems > 0) {
    parts.push(`${highItems} high-priority action item(s) for review (copyleft, proprietary, or unidentified licenses).`);
  }
  if (criticalItems === 0 && highItems === 0) {
    parts.push('No critical or high-priority license issues detected. Standard attribution obligations apply for permissive licenses.');
  }

  return parts.join(' ');
}
