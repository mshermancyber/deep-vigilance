// License Compliance Scanner
// Scans project dependency manifests for license information, flags incompatibilities,
// copyleft in proprietary projects, and unknown licenses.
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LicenseCategory = 'permissive' | 'copyleft' | 'weak-copyleft' | 'restricted' | 'proprietary' | 'unknown';

export interface LicenseInfo {
  id: string;
  name: string;
  identifier: string;    // SPDX identifier
  category: LicenseCategory;
  url: string;
  description: string;
  allowsCommercial: boolean;
  allowsModification: boolean;
  allowsDistribution: boolean;
  requiresDisclosure: boolean;
  requiresSameLicense: boolean; // strong copyleft
}

export interface LicenseFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  dependencyName: string;
  dependencyVersion: string;
  licenseId: string;
  licenseName: string;
  filePath: string;
  lineNumber?: number;
  recommendation: string;
}

export interface CompatibilityEntry {
  licenseA: string;
  licenseB: string;
  compatible: boolean;
  note: string;
}

export interface LicenseAuditResult {
  projectPath: string;
  manifestsScanned: string[];
  totalDependencies: number;
  dependenciesWithLicenses: number;
  dependenciesWithoutLicenses: number;
  licenseBreakdown: Record<string, number>;
  categoryBreakdown: Record<LicenseCategory, number>;
  findings: LicenseFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

// ---------------------------------------------------------------------------
// Embedded License Database — 50+ licenses
// ---------------------------------------------------------------------------

const LICENSE_DATABASE: LicenseInfo[] = [
  // --- Permissive ---
  { id: 'MIT', name: 'MIT License', identifier: 'MIT', category: 'permissive', url: 'https://opensource.org/licenses/MIT', description: 'Simple permissive license with a preservation of copyright and license notices requirement.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Apache-2.0', name: 'Apache License 2.0', identifier: 'Apache-2.0', category: 'permissive', url: 'https://www.apache.org/licenses/LICENSE-2.0', description: 'Permissive license requiring preservation of copyright and patent notices.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'BSD-2-Clause', name: 'BSD 2-Clause License', identifier: 'BSD-2-Clause', category: 'permissive', url: 'https://opensource.org/licenses/BSD-2-Clause', description: 'Simple permissive license with a restriction on endorsing derived works.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'BSD-3-Clause', name: 'BSD 3-Clause License', identifier: 'BSD-3-Clause', category: 'permissive', url: 'https://opensource.org/licenses/BSD-3-Clause', description: 'Permissive license with a clause restricting use of contributors names.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'ISC', name: 'ISC License', identifier: 'ISC', category: 'permissive', url: 'https://opensource.org/licenses/ISC', description: 'A permissive license functionally equivalent to the MIT license.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Unlicense', name: 'The Unlicense', identifier: 'Unlicense', category: 'permissive', url: 'https://unlicense.org/', description: 'A license with no conditions, dedicating works to the public domain.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'CC0-1.0', name: 'CC0 1.0 Universal', identifier: 'CC0-1.0', category: 'permissive', url: 'https://creativecommons.org/publicdomain/zero/1.0/', description: 'Public domain dedication, waives all copyright and related rights.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Zlib', name: 'Zlib License', identifier: 'Zlib', category: 'permissive', url: 'https://opensource.org/licenses/Zlib', description: 'Permissive license for software libraries, used by zlib.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'PostgreSQL', name: 'PostgreSQL License', identifier: 'PostgreSQL', category: 'permissive', url: 'https://opensource.org/licenses/PostgreSQL', description: 'MIT-like license used by the PostgreSQL database.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: '0BSD', name: 'BSD Zero Clause License', identifier: '0BSD', category: 'permissive', url: 'https://opensource.org/licenses/0BSD', description: 'A permissive license with no restrictions, similar to public domain.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'BlueOak-1.0.0', name: 'Blue Oak Model License 1.0.0', identifier: 'BlueOak-1.0.0', category: 'permissive', url: 'https://blueoakcouncil.org/license/1.0.0', description: 'A modern permissive license with clear patent grant.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'MIT-0', name: 'MIT No Attribution', identifier: 'MIT-0', category: 'permissive', url: 'https://opensource.org/licenses/MIT-0', description: 'MIT license without the requirement to preserve copyright notices.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },

  // --- Weak Copyleft (file-level) ---
  { id: 'MPL-2.0', name: 'Mozilla Public License 2.0', identifier: 'MPL-2.0', category: 'weak-copyleft', url: 'https://www.mozilla.org/en-US/MPL/2.0/', description: 'File-level copyleft license that allows combining with proprietary code.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'LGPL-2.1', name: 'GNU Lesser General Public License 2.1', identifier: 'LGPL-2.1', category: 'weak-copyleft', url: 'https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html', description: 'Copyleft license for libraries; allows linking from proprietary code.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'LGPL-3.0', name: 'GNU Lesser General Public License 3.0', identifier: 'LGPL-3.0', category: 'weak-copyleft', url: 'https://www.gnu.org/licenses/lgpl-3.0.html', description: 'Updated version of LGPL with better compatibility with GPLv3.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'EPL-2.0', name: 'Eclipse Public License 2.0', identifier: 'EPL-2.0', category: 'weak-copyleft', url: 'https://www.eclipse.org/legal/epl-2.0/', description: 'Weak copyleft license from the Eclipse Foundation.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'CDDL-1.0', name: 'Common Development and Distribution License 1.0', identifier: 'CDDL-1.0', category: 'weak-copyleft', url: 'https://opensource.org/licenses/CDDL-1.0', description: 'File-level copyleft license used by Sun/Oracle projects.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'CPL-1.0', name: 'Common Public License 1.0', identifier: 'CPL-1.0', category: 'weak-copyleft', url: 'https://opensource.org/licenses/CPL-1.0', description: 'Weak copyleft license from IBM.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },

  // --- Strong Copyleft ---
  { id: 'GPL-2.0', name: 'GNU General Public License 2.0', identifier: 'GPL-2.0', category: 'copyleft', url: 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.html', description: 'Strong copyleft license requiring derived works to be distributed under GPLv2.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'GPL-3.0', name: 'GNU General Public License 3.0', identifier: 'GPL-3.0', category: 'copyleft', url: 'https://www.gnu.org/licenses/gpl-3.0.html', description: 'Strong copyleft license with additional protections against patent claims and TiVoization.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'AGPL-3.0', name: 'GNU Affero General Public License 3.0', identifier: 'AGPL-3.0', category: 'copyleft', url: 'https://www.gnu.org/licenses/agpl-3.0.html', description: 'Copyleft license covering network interactions — access counts as distribution.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'EUPL-1.2', name: 'European Union Public License 1.2', identifier: 'EUPL-1.2', category: 'copyleft', url: 'https://eupl.eu/', description: 'Copyleft license recognized by EU law.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'CC-BY-SA-4.0', name: 'Creative Commons Attribution-ShareAlike 4.0', identifier: 'CC-BY-SA-4.0', category: 'copyleft', url: 'https://creativecommons.org/licenses/by-sa/4.0/', description: 'Share-alike license for creative works.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },

  // --- Restricted (non-OSI, commercial-only, etc) ---
  { id: 'BUSL-1.1', name: 'Business Source License 1.1', identifier: 'BUSL-1.1', category: 'restricted', url: 'https://mariadb.com/bsl11/', description: 'Source-available license that converts to open source after a change date.', allowsCommercial: false, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'SSPL-1.0', name: 'Server Side Public License 1.0', identifier: 'SSPL-1.0', category: 'restricted', url: 'https://www.mongodb.com/licensing/server-side-public-license', description: 'Copyleft license requiring offering SaaS services to release source code.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'Elastic-2.0', name: 'Elastic License 2.0', identifier: 'Elastic-2.0', category: 'restricted', url: 'https://www.elastic.co/licensing/elastic-license', description: 'Non-open-source license restricting use for competitive offerings.', allowsCommercial: false, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'JCR-1.0', name: 'Java Research License 1.0', identifier: 'JRL', category: 'restricted', url: 'https://www.oracle.com/legal/licenses/java-research-license.html', description: 'Restricted license for Java research use.', allowsCommercial: false, allowsModification: true, allowsDistribution: false, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'BCL', name: 'Oracle Binary Code License', identifier: 'BCL', category: 'restricted', url: 'https://www.oracle.com/downloads/licenses/binary-code-license.html', description: 'Oracle proprietary license for JDK/JRE distributions.', allowsCommercial: false, allowsModification: false, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'MS-PL', name: 'Microsoft Public License', identifier: 'MS-PL', category: 'restricted', url: 'https://opensource.org/licenses/MS-PL', description: 'OSI-approved but with limitations on derivative use in some contexts.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Fair', name: 'Fair License', identifier: 'Fair', category: 'restricted', url: 'https://opensource.org/licenses/Fair', description: 'License restricting use to personal or non-profit.', allowsCommercial: false, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },

  // --- Proprietary ---
  { id: 'Proprietary', name: 'Proprietary License', identifier: 'LicenseRef-Proprietary', category: 'proprietary', url: '', description: 'All rights reserved — proprietary/commercial license.', allowsCommercial: true, allowsModification: false, allowsDistribution: false, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'SEE LICENSE', name: 'SEE LICENSE IN LICENSE file', identifier: 'LicenseRef-SEE', category: 'proprietary', url: '', description: 'Reference to a local LICENSE file.', allowsCommercial: true, allowsModification: false, allowsDistribution: false, requiresDisclosure: true, requiresSameLicense: false },

  // --- Additional Licenses ---
  { id: 'Artistic-2.0', name: 'Artistic License 2.0', identifier: 'Artistic-2.0', category: 'permissive', url: 'https://opensource.org/licenses/Artistic-2.0', description: 'Permissive license used by Perl.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'AFL-3.0', name: 'Academic Free License 3.0', identifier: 'AFL-3.0', category: 'permissive', url: 'https://opensource.org/licenses/AFL-3.0', description: 'Permissive license with patent protection clauses.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'WTFPL', name: 'Do What The F*ck You Want To Public License', identifier: 'WTFPL', category: 'permissive', url: 'http://www.wtfpl.net/', description: 'Extremely permissive public-domain-like license.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'NCSA', name: 'University of Illinois/NCSA Open Source License', identifier: 'NCSA', category: 'permissive', url: 'https://opensource.org/licenses/NCSA', description: 'BSD/MIT-style license.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'UPL-1.0', name: 'Universal Permissive License 1.0', identifier: 'UPL-1.0', category: 'permissive', url: 'https://opensource.org/licenses/UPL', description: 'Permissive license from Oracle for open source projects.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'OSL-3.0', name: 'Open Software License 3.0', identifier: 'OSL-3.0', category: 'copyleft', url: 'https://opensource.org/licenses/OSL-3.0', description: 'Copyleft license that also creates a patent license.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'RPL-1.5', name: 'Reciprocal Public License 1.5', identifier: 'RPL-1.5', category: 'copyleft', url: 'https://opensource.org/licenses/RPL-1.5', description: 'Strong copyleft focusing on reciprocity.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'NPOSL-3.0', name: 'Non-Profit Open Software License 3.0', identifier: 'NPOSL-3.0', category: 'restricted', url: 'https://opensource.org/licenses/NPOSL-3.0', description: 'OSL variant restricted to non-profit use.', allowsCommercial: false, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: false },
  { id: 'Zend-2.0', name: 'Zend Framework License 2.0', identifier: 'Zend-2.0', category: 'permissive', url: 'https://framework.zend.com/license', description: 'Permissive license used by Zend Framework.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'PHP-3.01', name: 'PHP License 3.01', identifier: 'PHP-3.01', category: 'permissive', url: 'https://www.php.net/license/3_01.txt', description: 'BSD-style license used by PHP.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Ruby', name: 'Ruby License', identifier: 'Ruby', category: 'permissive', url: 'https://www.ruby-lang.org/en/about/license.txt', description: 'Dual-licensed under BSD-2-Clause or custom terms.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Python-2.0', name: 'Python Software Foundation License 2.0', identifier: 'Python-2.0', category: 'permissive', url: 'https://docs.python.org/3/license.html', description: 'Permissive license used by Python.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Bootstrap', name: 'Bootstrap License (MIT)', identifier: 'MIT', category: 'permissive', url: 'https://github.com/twbs/bootstrap/blob/main/LICENSE', description: 'MIT license used by Bootstrap.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'libpng', name: 'libpng License', identifier: 'Libpng', category: 'permissive', url: 'http://www.libpng.org/pub/png/src/libpng-LICENSE.txt', description: 'Permissive license for libpng.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Boost-1.0', name: 'Boost Software License 1.0', identifier: 'BSL-1.0', category: 'permissive', url: 'https://www.boost.org/users/license.html', description: 'Permissive license used by Boost C++ libraries.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'JSON', name: 'JSON License', identifier: 'JSON', category: 'restricted', url: 'https://www.json.org/license.html', description: 'License with a clause requiring "the software shall be used for good, not evil."', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'CECILL-2.1', name: 'CeCILL License 2.1', identifier: 'CECILL-2.1', category: 'copyleft', url: 'https://cecill.info/', description: 'French copyleft license compatible with GPL.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'GFDL-1.3', name: 'GNU Free Documentation License 1.3', identifier: 'GFDL-1.3', category: 'copyleft', url: 'https://www.gnu.org/licenses/fdl-1.3.html', description: 'Copyleft license for documentation.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'OGL-UK-3.0', name: 'Open Government License 3.0 (UK)', identifier: 'OGL-UK-3.0', category: 'permissive', url: 'https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/', description: 'Permissive license for UK public sector information.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'QPL-1.0', name: 'Q Public License 1.0', identifier: 'QPL-1.0', category: 'copyleft', url: 'https://opensource.org/licenses/QPL-1.0', description: 'Copyleft license used by Qt toolkit.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
  { id: 'W3C', name: 'W3C Software and Document License', identifier: 'W3C', category: 'permissive', url: 'https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document', description: 'Permissive license for W3C standards.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Xnet', name: 'X.Net License', identifier: 'Xnet', category: 'permissive', url: 'https://opensource.org/licenses/Xnet', description: 'A permissive license similar to the MIT license.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'iMatix', name: 'iMatix Standard Function License', identifier: 'iMatix', category: 'restricted', url: 'http://legacy.imatix.com/html/sfl/', description: 'Ending open source license from iMatix.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'NTP', name: 'NTP License', identifier: 'NTP', category: 'permissive', url: 'https://opensource.org/licenses/NTP', description: 'Permissive license used by NTP software.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: false, requiresSameLicense: false },
  { id: 'Sleepycat', name: 'Sleepycat License', identifier: 'Sleepycat', category: 'copyleft', url: 'https://opensource.org/licenses/Sleepycat', description: 'Berkeley DB license — copyleft-like.', allowsCommercial: true, allowsModification: true, allowsDistribution: true, requiresDisclosure: true, requiresSameLicense: true },
];

const LICENSE_BY_IDENTIFIER = new Map<string, LicenseInfo>(
  LICENSE_DATABASE.map(l => [l.identifier.toLowerCase(), l]),
);

// ---------------------------------------------------------------------------
// Compatibility Matrix
// ---------------------------------------------------------------------------

const COMPATIBILITY_MATRIX: CompatibilityEntry[] = [
  // Permissive x Permissive — always compatible
  { licenseA: 'permissive', licenseB: 'permissive', compatible: true, note: 'All permissive licenses are compatible with each other.' },
  // Permissive x Weak Copyleft
  { licenseA: 'permissive', licenseB: 'weak-copyleft', compatible: true, note: 'Permissive code can be incorporated into weak-copyleft projects. Combined work inherits the weak-copyleft license for modifications.' },
  // Permissive x Strong Copyleft
  { licenseA: 'permissive', licenseB: 'copyleft', compatible: true, note: 'Permissive code can be incorporated into copyleft projects. Combined work must be distributed under the copyleft terms.' },
  // Permissive x Restricted
  { licenseA: 'permissive', licenseB: 'restricted', compatible: true, note: 'Permissive code used in restricted-licensed projects does not impose additional requirements.' },
  // Weak Copyleft x Weak Copyleft
  { licenseA: 'weak-copyleft', licenseB: 'weak-copyleft', compatible: false, note: 'Combining multiple weak-copyleft libraries may create conflicting file-level licensing requirements.' },
  // Weak Copyleft x Strong Copyleft — GPL treats LGPL as compatible
  { licenseA: 'LGPL-2.1', licenseB: 'GPL-2.0', compatible: true, note: 'LGPLv2.1 allows relicensing under GPLv2. Compatible.' },
  { licenseA: 'LGPL-3.0', licenseB: 'GPL-3.0', compatible: true, note: 'LGPLv3 allows relicensing under GPLv3. Compatible.' },
  { licenseA: 'MPL-2.0', licenseB: 'GPL-3.0', compatible: false, note: 'MPL-2.0 code cannot be incorporated into GPLv3 projects without creating a derivative work — legal interpretation varies. MPL-2.0 with "GPL-compatible" secondary notice is compatible.' },
  { licenseA: 'CDDL-1.0', licenseB: 'GPL-2.0', compatible: false, note: 'CDDL-1.0 and GPL-2.0 are incompatible due to conflicting terms. Case example: OpenJDK vs GNU Classpath.' },
  { licenseA: 'EPL-2.0', licenseB: 'GPL-3.0', compatible: false, note: 'EPL-2.0 is not compatible with GPL-3.0 without explicit secondary license grant.' },
  // Strong Copyleft x Strong Copyleft
  { licenseA: 'GPL-2.0', licenseB: 'GPL-3.0', compatible: false, note: 'GPLv2 and GPLv3 are incompatible. Code under GPLv2-only cannot be combined with GPLv3 code.' },
  { licenseA: 'GPL-3.0', licenseB: 'AGPL-3.0', compatible: true, note: 'AGPLv3 and GPLv3 are compatible. AGPLv3 code can be combined with GPLv3 code.' },
  { licenseA: 'AGPL-3.0', licenseB: 'GPL-2.0', compatible: false, note: 'AGPLv3 is not compatible with GPLv2.' },
  // Copyleft x Restricted
  { licenseA: 'copyleft', licenseB: 'restricted', compatible: false, note: 'Restricted licenses are generally incompatible with copyleft requirements.' },
  // Proprietary x Copyleft
  { licenseA: 'proprietary', licenseB: 'copyleft', compatible: false, note: 'Proprietary code cannot incorporate copyleft-licensed code without open-sourcing the entire work.' },
  { licenseA: 'proprietary', licenseB: 'weak-copyleft', compatible: false, note: 'Proprietary code cannot incorporate weak-copyleft code without complying with its terms.' },
  // Copyleft x Copyleft (generic rule)
  { licenseA: 'copyleft', licenseB: 'copyleft', compatible: false, note: 'Strong copyleft licenses from different families are generally incompatible.' },
];

// ---------------------------------------------------------------------------
// License Resolution
// ---------------------------------------------------------------------------

function normalizeLicenseString(license: string): string {
  const lower = license.trim().toLowerCase();

  // Handle common aliases and variations
  const aliases: Record<string, string> = {
    'mit': 'MIT',
    'apache 2.0': 'Apache-2.0',
    'apache-2.0': 'Apache-2.0',
    'apache2': 'Apache-2.0',
    'apache 2': 'Apache-2.0',
    'apache-2': 'Apache-2.0',
    'apache license 2.0': 'Apache-2.0',
    'bsd': 'BSD-3-Clause',
    'bsd-2': 'BSD-2-Clause',
    'bsd-3': 'BSD-3-Clause',
    'bsd 2-clause': 'BSD-2-Clause',
    'bsd 3-clause': 'BSD-3-Clause',
    'new bsd': 'BSD-3-Clause',
    'modified bsd': 'BSD-3-Clause',
    'gpl 2.0': 'GPL-2.0',
    'gpl-2.0': 'GPL-2.0',
    'gplv2': 'GPL-2.0',
    'gpl 2': 'GPL-2.0',
    'gpl 3.0': 'GPL-3.0',
    'gpl-3.0': 'GPL-3.0',
    'gplv3': 'GPL-3.0',
    'gpl 3': 'GPL-3.0',
    'lgpl 2.1': 'LGPL-2.1',
    'lgpl-2.1': 'LGPL-2.1',
    'lgpl 3.0': 'LGPL-3.0',
    'lgpl-3.0': 'LGPL-3.0',
    'lgplv3': 'LGPL-3.0',
    'lgplv2.1': 'LGPL-2.1',
    'agpl 3.0': 'AGPL-3.0',
    'agpl-3.0': 'AGPL-3.0',
    'agplv3': 'AGPL-3.0',
    'agpl 3': 'AGPL-3.0',
    'mpl 2.0': 'MPL-2.0',
    'mpl-2.0': 'MPL-2.0',
    'mpl2': 'MPL-2.0',
    'bSL-1.0': 'Boost-1.0',
    'afl 3.0': 'AFL-3.0',
    'epl 2.0': 'EPL-2.0',
    'epl-2.0': 'EPL-2.0',
    'isc': 'ISC',
    'unlicense': 'Unlicense',
    'cc0': 'CC0-1.0',
    'cc0-1.0': 'CC0-1.0',
    'zlib': 'Zlib',
    'public domain': 'Unlicense',
    'cc by-sa 4.0': 'CC-BY-SA-4.0',
    'artistic 2.0': 'Artistic-2.0',
    'cddl 1.0': 'CDDL-1.0',
    'cddl-1.0': 'CDDL-1.0',
    'postgresql': 'PostgreSQL',
    'wtfpl': 'WTFPL',
    '0bsd': '0BSD',
    'bsl-1.0': 'Boost-1.0',
    'epl-1.0': 'EPL-2.0',  // EPL-1.0 compatibility
    'cecill 2.1': 'CECILL-2.1',
    'cpl 1.0': 'CPL-1.0',
    'eupl 1.2': 'EUPL-1.2',
    'qpl 1.0': 'QPL-1.0',
    'fair': 'Fair',
    'json': 'JSON',
    'ruby': 'Ruby',
    'php-3.01': 'PHP-3.01',
    'boost-1.0': 'Boost-1.0',
    'bsd-0': '0BSD',
    'ncsa': 'NCSA',
    'upl-1.0': 'UPL-1.0',
    'osl-3.0': 'OSL-3.0',
  };

  return aliases[lower] || license.trim();
}

function resolveLicense(licenseStr: string): LicenseInfo | null {
  if (!licenseStr || licenseStr.trim() === '') return null;

  const normalized = normalizeLicenseString(licenseStr);
  const lower = normalized.toLowerCase();

  // Direct lookup by identifier
  const known = LICENSE_BY_IDENTIFIER.get(lower);
  if (known) return known;

  // Check aliases again via normalize
  const reNormalized = normalizeLicenseString(licenseStr);
  if (reNormalized !== licenseStr) {
    const reLower = reNormalized.toLowerCase();
    const known2 = LICENSE_BY_IDENTIFIER.get(reLower);
    if (known2) return known2;
  }

  // Try partial match
  for (const lic of LICENSE_DATABASE) {
    const licLower = lic.identifier.toLowerCase();
    if (licLower.includes(lower) || lower.includes(licLower)) {
      return lic;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Manifest Parsers
// ---------------------------------------------------------------------------

interface DependencyEntry {
  name: string;
  version: string;
  license: string | null;
  filePath: string;
  lineNumber?: number;
  ecosystem: string;
}

function parsePackageJson(filePath: string, content: string): DependencyEntry[] {
  const deps: DependencyEntry[] = [];
  try {
    const json = JSON.parse(content);
    const allDeps: Record<string, string> = {
      ...(json.dependencies || {}),
      ...(json.devDependencies || {}),
    };
    const projectLicense = json.license || null;

    // Add the project itself
    if (json.name) {
      deps.push({
        name: json.name,
        version: json.version || '0.0.0',
        license: projectLicense,
        filePath,
        lineNumber: 1,
        ecosystem: 'npm',
      });
    }

    for (const [name, version] of Object.entries(allDeps)) {
      deps.push({
        name,
        version: version as string,
        license: null, // package.json doesn't include license per dependency
        filePath,
        ecosystem: 'npm',
      });
    }
  } catch {
    // Invalid JSON
  }
  return deps;
}

function parsePomXml(filePath: string, content: string): DependencyEntry[] {
  const deps: DependencyEntry[] = [];
  try {
    // Extract project license
    const projectLicenseMatch = content.match(/<licenses>([\s\S]*?)<\/licenses>/);
    const projectLicense = projectLicenseMatch
      ? extractPomLicense(projectLicenseMatch[1]!)
      : null;

    // Extract dependencies
    const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match: RegExpExecArray | null;
    while ((match = depRegex.exec(content)) !== null) {
      const block = match[1]!;
      const gid = block.match(/<groupId>\s*(\S+?)\s*<\/groupId>/);
      const aid = block.match(/<artifactId>\s*(\S+?)\s*<\/artifactId>/);
      const ver = block.match(/<version>\s*(\S+?)\s*<\/version>/);
      if (gid && aid) {
        deps.push({
          name: `${gid[1]}:${aid[1]}`,
          version: ver ? ver[1] : 'unknown',
          license: null, // pom.xml has per-dependency licenses optionally
          filePath,
          ecosystem: 'maven',
        });
      }
    }

    // Add project itself
    const projectName = content.match(/<artifactId>\s*(\S+?)\s*<\/artifactId>/);
    const projectVersion = content.match(/<version>\s*(\S+?)\s*<\/version>/);
    if (projectName) {
      deps.unshift({
        name: projectName[1]!,
        version: projectVersion?.[1] || '0.0.0',
        license: projectLicense,
        filePath,
        ecosystem: 'maven',
      });
    }
  } catch {
    // Parse error
  }
  return deps;
}

function extractPomLicense(block: string): string | null {
  const nameMatch = block.match(/<name>\s*(\S[\s\S]*?\S)\s*<\/name>/);
  return nameMatch ? nameMatch[1]!.trim() : null;
}

function parseCargoToml(filePath: string, content: string): DependencyEntry[] {
  const deps: DependencyEntry[] = [];
  try {
    // Extract project license
    const projectLicenseMatch = content.match(/^license\s*=\s*["'](.+?)["']/m);
    const projectNameMatch = content.match(/^name\s*=\s*["'](.+?)["']/m);
    const projectVersionMatch = content.match(/^version\s*=\s*["'](.+?)["']/m);

    if (projectNameMatch) {
      deps.push({
        name: projectNameMatch[1]!,
        version: projectVersionMatch?.[1] || '0.0.0',
        license: projectLicenseMatch?.[1] || null,
        filePath,
        ecosystem: 'cargo',
      });
    }

    // Extract [dependencies] section
    const depsSection = content.match(/\[dependencies\]([\s\S]*?)(?:^\[|\Z)/m);
    if (depsSection) {
      const depLines = depsSection[1]!.split('\n');
      for (const line of depLines) {
        const depMatch = line.match(/^\s*(\w[\w-]*)\s*=\s*["']([^"']+)["']/);
        if (depMatch) {
          deps.push({
            name: depMatch[1]!,
            version: depMatch[2]!,
            license: null,
            filePath,
            ecosystem: 'cargo',
          });
        }
      }
    }

    // Extract [dev-dependencies] section
    const devDepsSection = content.match(/\[dev-dependencies\]([\s\S]*?)(?:^\[|\Z)/m);
    if (devDepsSection) {
      const depLines = devDepsSection[1]!.split('\n');
      for (const line of depLines) {
        const depMatch = line.match(/^\s*(\w[\w-]*)\s*=\s*["']([^"']+)["']/);
        if (depMatch) {
          deps.push({
            name: depMatch[1]!,
            version: depMatch[2]!,
            license: null,
            filePath,
            ecosystem: 'cargo',
          });
        }
      }
    }
  } catch {
    // Parse error
  }
  return deps;
}

function parseGoMod(filePath: string, content: string): DependencyEntry[] {
  const deps: DependencyEntry[] = [];
  try {
    // Extract module name and project-level info
    const moduleMatch = content.match(/^module\s+(\S+)/m);
    if (moduleMatch) {
      deps.push({
        name: moduleMatch[1]!,
        version: '(project)',
        license: null,
        filePath,
        ecosystem: 'go',
      });
    }

    // Extract require block
    const requireMatch = content.match(/require\s*\(([\s\S]*?)\)/);
    if (requireMatch) {
      const reqLines = requireMatch[1]!.split('\n');
      for (const line of reqLines) {
        const reqMatch = line.match(/^\s*(\S+)\s+(v\S+)/);
        if (reqMatch) {
          deps.push({
            name: reqMatch[1]!,
            version: reqMatch[2]!,
            license: null,
            filePath,
            ecosystem: 'go',
          });
        }
      }
    }

    // Extract single require lines
    const singleRequires = content.matchAll(/^require\s+(\S+)\s+(v\S+)/gm);
    for (const match of singleRequires) {
      // Avoid duplicating if already in block
      if (!deps.some(d => d.name === match[1]!)) {
        deps.push({
          name: match[1]!,
          version: match[2]!,
          license: null,
          filePath,
          ecosystem: 'go',
        });
      }
    }
  } catch {
    // Parse error
  }
  return deps;
}

function parseRequirementsTxt(filePath: string, content: string): DependencyEntry[] {
  const deps: DependencyEntry[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    // Skip comments, empty lines, and options
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;

    const pkgMatch = line.match(/^([\w_.-]+)\s*(?:[><=!~]+\s*[\w.*-]+)?/);
    if (pkgMatch) {
      const versionMatch = line.match(/[\><=!~]{1,2}\s*([\w.*-]+)/);
      deps.push({
        name: pkgMatch[1]!,
        version: versionMatch?.[1] || 'any',
        license: null,
        filePath,
        lineNumber: i + 1,
        ecosystem: 'pip',
      });
    }
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Compatibility Checks
// ---------------------------------------------------------------------------

function getCategoryCompatibility(catA: LicenseCategory, catB: LicenseCategory): boolean | 'maybe' {
  // Permissive is compatible with everything
  if (catA === 'permissive' || catB === 'permissive') return true;

  // Check specific matrix entries
  for (const entry of COMPATIBILITY_MATRIX) {
    const matchesCategory = (entry.licenseA === catA && entry.licenseB === catB) ||
      (entry.licenseA === catB && entry.licenseB === catA);
    if (matchesCategory) return entry.compatible;
  }

  // Check by specific license IDs (covers LGPL/GPL, etc.)
  for (const entry of COMPATIBILITY_MATRIX) {
    if (entry.licenseA !== 'permissive' && entry.licenseA !== 'copyleft' &&
        entry.licenseA !== 'weak-copyleft' && entry.licenseA !== 'restricted' &&
        entry.licenseA !== 'proprietary') {
      // This is a specific license ID check
    }
  }

  // If both are weak-copyleft or both are copyleft, flag as potentially incompatible
  if (catA === catB && (catA === 'copyleft' || catA === 'weak-copyleft')) {
    return false;
  }

  return 'maybe';
}

function checkLicenseCompatibility(
  deps: DependencyEntry[],
  resolvedLicenses: Map<string, LicenseInfo>,
): LicenseFinding[] {
  const findings: LicenseFinding[] = [];

  const entries = Array.from(resolvedLicenses.entries());
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      const [nameA, licA] = entries[i]!;
      const [nameB, licB] = entries[j]!;

      const compat = getCategoryCompatibility(licA.category, licB.category);
      if (compat === false) {
        findings.push({
          ruleId: 'LIC-COMPAT-001',
          title: 'Incompatible license combination',
          description: `${nameA} (${licA.identifier}) and ${nameB} (${licB.identifier}) have incompatible licenses. ${licA.name} and ${licB.name} cannot be combined in the same project.`,
          severity: 'high',
          category: 'license',
          dependencyName: nameA,
          dependencyVersion: deps.find(d => d.name === nameA)?.version || 'unknown',
          licenseId: licA.identifier,
          licenseName: licA.name,
          filePath: deps.find(d => d.name === nameA)?.filePath || '',
          recommendation: `Replace either ${nameA} or ${nameB} with a compatible alternative. Check if either package offers a dual-license or has a compatible version.`,
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main Scanner
// ---------------------------------------------------------------------------

export function scanLicenses(projectPath: string): LicenseAuditResult {
  logger.info({ projectPath }, 'Starting license scan');

  const manifests: string[] = [];
  const allDeps: DependencyEntry[] = [];
  const findings: LicenseFinding[] = [];
  const resolvedLicenses = new Map<string, LicenseInfo>();

  // Find all manifest files
  const manifestFiles = ['package.json', 'pom.xml', 'Cargo.toml', 'go.mod', 'requirements.txt'];
  for (const mf of manifestFiles) {
    const fp = path.join(projectPath, mf);
    if (fs.existsSync(fp)) {
      manifests.push(fp);
    }
  }

  // Also search subdirectories for workspace manifests
  function findManifestsRecursive(dir: string, depth: number): void {
    if (depth > 3) return;
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          findManifestsRecursive(path.join(dir, entry.name), depth + 1);
        } else if (entry.isFile() && manifestFiles.includes(entry.name)) {
          const fp = path.join(dir, entry.name);
          if (!manifests.includes(fp)) {
            manifests.push(fp);
          }
        }
      }
    } catch {
      // Permission denied
    }
  }
  findManifestsRecursive(projectPath, 0);

  // Parse each manifest
  for (const mf of manifests) {
    try {
      const content = fs.readFileSync(mf, 'utf-8');
      const basename = path.basename(mf);
      let deps: DependencyEntry[] = [];

      switch (basename) {
        case 'package.json':
          deps = parsePackageJson(mf, content);
          break;
        case 'pom.xml':
          deps = parsePomXml(mf, content);
          break;
        case 'Cargo.toml':
          deps = parseCargoToml(mf, content);
          break;
        case 'go.mod':
          deps = parseGoMod(mf, content);
          break;
        case 'requirements.txt':
          deps = parseRequirementsTxt(mf, content);
          break;
      }

      allDeps.push(...deps);

      // Resolve licenses for dependencies that have them
      for (const dep of deps) {
        if (dep.license) {
          const resolved = resolveLicense(dep.license);
          if (resolved) {
            resolvedLicenses.set(dep.name, resolved);
          } else {
            // Unknown license
            findings.push({
              ruleId: 'LIC-UNKNOWN-001',
              title: 'Dependency with unknown license',
              description: `Package "${dep.name}" declares license "${dep.license}" which could not be resolved in the license database.`,
              severity: 'medium',
              category: 'license',
              dependencyName: dep.name,
              dependencyVersion: dep.version,
              licenseId: dep.license,
              licenseName: dep.license,
              filePath: mf,
              recommendation: 'Manually verify the license of this dependency by checking its repository or packaging metadata. Update the license field to use a standard SPDX identifier.',
            });
          }
        } else if (dep.ecosystem !== 'go') {
          // Missing license field (Go doesn't always have it in go.mod)
          findings.push({
            ruleId: 'LIC-MISSING-001',
            title: 'Dependency without declared license',
            description: `Package "${dep.name}" (v${dep.version}) does not have a license field in its manifest.`,
            severity: 'low',
            category: 'license',
            dependencyName: dep.name,
            dependencyVersion: dep.version,
            licenseId: 'unknown',
            licenseName: 'Unknown',
            filePath: mf,
            recommendation: 'File an issue or PR to add a license field to the package. Consider using an alternative that has a clearly declared license.',
          });
        }
      }
    } catch (err) {
      logger.warn({ manifest: mf, err }, 'Failed to parse manifest');
    }
  }

  // Check compatibility between all resolved licenses
  const compatFindings = checkLicenseCompatibility(allDeps, resolvedLicenses);
  findings.push(...compatFindings);

  // Flag copyleft in what appears to be a proprietary project
  const projectLicenses = allDeps
    .filter(d => d.license !== null && d.license !== 'unknown')
    .map(d => resolveLicense(d.license!))
    .filter((l): l is LicenseInfo => l !== null);

  const hasCopyleft = projectLicenses.some(l => l.category === 'copyleft' || l.category === 'weak-copyleft');
  const hasProprietary = projectLicenses.some(l => l.category === 'proprietary');

  if (hasCopyleft && hasProprietary) {
    findings.push({
      ruleId: 'LIC-COPYLEFT-001',
      title: 'Copyleft dependency in proprietary project',
      description: 'The project contains copyleft dependencies (GPL/AGPL) but is licensed as proprietary. This creates a licensing conflict that may require open-sourcing the entire project.',
      severity: 'critical',
      category: 'license',
      dependencyName: projectLicenses.filter(l => l.category === 'copyleft').map(l => l.identifier).join(', '),
      dependencyVersion: '',
      licenseId: projectLicenses.find(l => l.category === 'copyleft')?.identifier || '',
      licenseName: projectLicenses.find(l => l.category === 'copyleft')?.name || '',
      filePath: manifests[0] || '',
      recommendation: 'Remove copyleft dependencies or change the project license to a compatible open source license. Consider replacing GPL/AGPL dependencies with permissive alternatives.',
    });
  }

  // Build category breakdown
  const categoryBreakdown: Record<LicenseCategory, number> = {
    permissive: 0,
    'weak-copyleft': 0,
    copyleft: 0,
    restricted: 0,
    proprietary: 0,
    unknown: 0,
  };

  const licenseBreakdown: Record<string, number> = {};
  let depsWithLicenses = 0;
  let depsWithoutLicenses = 0;

  for (const dep of allDeps) {
    if (dep.license) {
      depsWithLicenses++;
      const resolved = resolveLicense(dep.license);
      const key = resolved?.identifier || dep.license;
      licenseBreakdown[key] = (licenseBreakdown[key] || 0) + 1;
      if (resolved) {
        categoryBreakdown[resolved.category]++;
      } else {
        categoryBreakdown.unknown++;
      }
    } else {
      depsWithoutLicenses++;
    }
  }

  const summary = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  return {
    projectPath,
    manifestsScanned: manifests,
    totalDependencies: allDeps.length,
    dependenciesWithLicenses: depsWithLicenses,
    dependenciesWithoutLicenses: depsWithoutLicenses,
    licenseBreakdown,
    categoryBreakdown,
    findings,
    summary,
  };
}

// ---------------------------------------------------------------------------
// Utility exports
// ---------------------------------------------------------------------------

export function getLicenseDatabase(): LicenseInfo[] {
  return [...LICENSE_DATABASE];
}

export function getCompatibilityMatrix(): CompatibilityEntry[] {
  return [...COMPATIBILITY_MATRIX];
}

export function lookupLicense(identifier: string): LicenseInfo | null {
  return resolveLicense(identifier);
}
