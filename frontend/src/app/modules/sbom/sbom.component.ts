import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTabsModule } from '@angular/material/tabs';
import { MatTableModule } from '@angular/material/table';
import { MatChipsModule } from '@angular/material/chips';
import { MatBadgeModule } from '@angular/material/badge';
import { NotificationService } from '../../core/services/notification.service';
import { environment } from '../../../environments/environment';
import { openSafeDownloadUrl } from '../../core/utils/safe-url';

interface SBOMComponentItem {
  id: string;
  name: string;
  version: string;
  purl: string;
  type?: string;
  license?: string;
}

interface SBOMExport {
  id: string;
  format: string;
  spdx_version?: string;
  spec_version?: string;
  component_count: number;
  vulnerability_count: number;
  signed: boolean;
  file_size: number;
  created_at: string;
  components?: SBOMComponentItem[];
}

interface LicenseAudit {
  id: string;
  package_name: string;
  package_version: string;
  ecosystem: string;
  license_type: string;
  is_compatible: boolean;
  policy_violation: boolean;
  policy_rule: string | null;
}

interface EnrichmentVuln {
  id: string;
  cveId?: string;
  description?: string;
  cvss?: { score: number; severity: string; version?: string; vector?: string };
  cwes?: string[];
  fixed?: string[];
  kev?: boolean;
  epss?: { score: number; percentile: number };
  published?: string;
}

interface EnrichmentFinding {
  componentIndex: number;
  componentName?: string;
  vulns: EnrichmentVuln[];
}

interface RemediationItem {
  componentIndex: number;
  name: string;
  currentVersion: string;
  target: string;
  cvesResolved: number;
  kevCount: number;
}

interface EnrichmentData {
  findings: EnrichmentFinding[];
  summary: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; NONE: number; UNKNOWN: number; total: number; scanned: number; affected: number } | null;
  assessment: {
    verdict: { status: string; reasons: string[]; policy: string };
    risk: { score: number; grade: string; pct: number };
    summary: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; NONE: number; UNKNOWN: number; total: number; scanned: number; affected: number };
    remediation?: RemediationItem[];
    noFix?: Array<{ componentIndex: number; name: string; vulnCount: number }>;
    topCwes?: Array<{ id: string; name: string; count: number }>;
    kevCount?: number;
    maliciousCount?: number;
  } | null;
  graphHtml: string | null;
  status: string;
}

@Component({
  selector: 'app-sbom',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatButtonModule,
    MatIconModule,
    MatCardModule,
    MatSelectModule,
    MatFormFieldModule,
    MatProgressSpinnerModule,
    MatTabsModule,
    MatTableModule,
    MatChipsModule,
    MatBadgeModule,
  ],
  template: `
    <div class="page-container fade-in">
      <!-- Header -->
      <div class="page-header">
        <h1>SBOM & Supply Chain</h1>
        <div class="header-actions">
          <mat-form-field appearance="outline" class="format-select">
            <mat-label>Format</mat-label>
            <mat-select [(ngModel)]="selectedFormat">
              <mat-option value="cyclonedx">CycloneDX</mat-option>
              <mat-option value="spdx">SPDX</mat-option>
            </mat-select>
          </mat-form-field>
          <button
            mat-flat-button
            color="primary"
            (click)="generateSBOM()"
            [disabled]="generating()"
          >
            @if (generating()) {
              <mat-icon>
                <mat-spinner diameter="16" strokeWidth="2"></mat-spinner>
              </mat-icon>
            } @else {
              <mat-icon>add</mat-icon>
            }
            Generate SBOM
          </button>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid-3" style="margin-bottom: 24px">
        <div class="stat-card">
          <div class="stat-value" [style.color]="'var(--accent-primary)'">
            {{ totalSBOMs() }}
          </div>
          <div class="stat-label">SBOMs Generated</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" [style.color]="'var(--accent-success)'">
            {{ totalComponents() | number }}
          </div>
          <div class="stat-label">Components Tracked</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" [style.color]="'var(--accent-warning)'">
            {{ licenseIssuesCount() }}
          </div>
          <div class="stat-label">License Issues Found</div>
        </div>
      </div>

      <!-- Loading state -->
      @if (loading()) {
        <div class="spinner"></div>
      }

      <!-- SBOM Exports Table -->
      @if (!loading() && exports().length) {
        <table class="data-table exports-table">
          <thead>
            <tr>
              <th>Format</th>
              <th>Version</th>
              <th>Components</th>
              <th>Vulnerabilities</th>
              <th>Signed</th>
              <th>File Size</th>
              <th>Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            @for (e of exports(); track e.id) {
              <!-- Main row -->
              <tr
                class="export-row"
                [class.expanded]="expandedRow() === e.id"
                (click)="toggleRow(e.id)"
              >
                <td>
                  <span class="severity-badge info">
                    {{ e.format === 'cyclonedx' ? 'CycloneDX' : 'SPDX' }}
                  </span>
                </td>
                <td>
                  <span class="version-tag">
                    {{ e.format === 'cyclonedx' ? (e.spec_version || '1.4') : (e.spdx_version || '2.3') }}
                  </span>
                </td>
                <td>{{ e.component_count || 0 }}</td>
                <td>
                  <span
                    class="severity-badge"
                    [class]="(e.vulnerability_count || 0) > 0 ? 'critical' : 'low'"
                  >
                    {{ e.vulnerability_count || 0 }}
                  </span>
                </td>
                <td>
                  <span class="signed-badge" [class.unsigned]="!e.signed">
                    {{ e.signed ? 'Signed' : 'Unsigned' }}
                  </span>
                </td>
                <td class="mono">{{ formatFileSize(e.file_size) }}</td>
                <td>{{ e.created_at | date : 'medium' }}</td>
                <td (click)="$event.stopPropagation()">
                  <button
                    mat-icon-button
                    (click)="downloadSBOM(e.id)"
                    matTooltip="Download SBOM"
                    aria-label="Download SBOM"
                  >
                    <mat-icon>download</mat-icon>
                  </button>
                  <button
                    mat-icon-button
                    (click)="loadEnrichment(e.id)"
                    matTooltip="Analyze with SBOM Visualizer"
                    aria-label="Analyze SBOM"
                  >
                    <mat-icon>security</mat-icon>
                  </button>
                </td>
              </tr>

              <!-- Expanded row: components list -->
              @if (expandedRow() === e.id) {
                <tr class="expanded-row">
                  <td colspan="8">
                    <div class="expanded-content">
                      <div class="expanded-header">
                        <mat-icon>inventory_2</mat-icon>
                        <strong>Components ({{ (e.components || []).length }})</strong>
                        @if (loadingComponents()) {
                          <mat-spinner diameter="16" strokeWidth="2" class="inline-spinner"></mat-spinner>
                        }
                      </div>
                      @if (e.components && e.components.length) {
                        <table class="sub-table">
                          <thead>
                            <tr>
                              <th>Name</th>
                              <th>Version</th>
                              <th>Type</th>
                              <th>PURL</th>
                              <th>License</th>
                            </tr>
                          </thead>
                          <tbody>
                            @for (c of e.components; track c.id) {
                              <tr>
                                <td class="component-name">{{ c.name }}</td>
                                <td class="mono">{{ c.version }}</td>
                                <td>
                                  <span class="type-tag">{{ c.type || 'library' }}</span>
                                </td>
                                <td>
                                  <code class="purl-text">{{ c.purl }}</code>
                                </td>
                                <td>{{ c.license || 'Unknown' }}</td>
                              </tr>
                            }
                          </tbody>
                        </table>
                      } @else {
                        <div class="empty-sub">
                          <mat-icon>info</mat-icon>
                          <span>No component details available.</span>
                        </div>
                      }
                    </div>
                  </td>
                </tr>
              }
            }
          </tbody>
        </table>
      } @else if (!loading()) {
        <div class="empty-state">
          <mat-icon>description</mat-icon>
          <h3>No SBOMs generated</h3>
          <p>
            Generate a Software Bill of Materials (CycloneDX or SPDX) to track
            dependencies and license compliance across your projects.
          </p>
        </div>
      }

      <!-- Enrichment Panel -->
      @if (selectedExportId() && enrichment()) {
        <div class="enrichment-panel card" style="margin: 24px 0;">
          <div class="enrichment-header">
            <h2><mat-icon>security</mat-icon> SBOM Visualizer Analysis</h2>
            <span class="enrichment-status" [class.failed]="enrichment()?.status === 'failed'">
              {{ enrichment()?.status === 'completed' ? '✓ Complete' : '⚠ Enrichment failed' }}
            </span>
          </div>

          <!-- Summary bar -->
          @if (enrichment()?.assessment) {
            <div class="assessment-bar">
              <div class="verdict" [class]="enrichment()!.assessment!.verdict.status.toLowerCase()">
                {{ enrichment()!.assessment!.verdict.status }}
              </div>
              <div class="risk-grade">Risk: {{ enrichment()!.assessment!.risk.grade }} ({{ enrichment()!.assessment!.risk.pct }}%)</div>
              <div class="kev-count">KEV: {{ enrichment()!.assessment!.kevCount || 0 }}</div>
            </div>
          }

          <!-- Tab nav -->
          <div class="tab-nav">
            <button [class.active]="activeTab() === 'vulns'" (click)="activeTab.set('vulns')">Vulnerabilities</button>
            <button [class.active]="activeTab() === 'remediation'" (click)="activeTab.set('remediation')">Remediation</button>
            <button [class.active]="activeTab() === 'graph'" (click)="activeTab.set('graph')">Dependency Map</button>
          </div>

          <!-- Vulns tab -->
          @if (activeTab() === 'vulns') {
            <table class="data-table vuln-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Component</th>
                  <th>KEV</th>
                  <th>EPSS</th>
                </tr>
              </thead>
              <tbody>
                @for (finding of enrichment()!.findings || []; track finding.componentIndex) {
                  @for (vuln of finding.vulns; track vuln.id) {
                    <tr>
                      <td class="mono">{{ vuln.cveId || vuln.id }}</td>
                      <td>
                        <span class="severity-badge" [class]="(vuln.cvss?.severity || 'UNKNOWN').toLowerCase()">
                          {{ vuln.cvss?.severity || 'N/A' }}
                        </span>
                      </td>
                      <td class="mono">{{ vuln.cvss?.score || '-' }}</td>
                      <td>{{ finding.componentName || 'Component #' + finding.componentIndex }}</td>
                      <td>
                        @if (vuln.kev) {
                          <span class="kev-badge">KEV</span>
                        }
                      </td>
                      <td class="mono">{{ vuln.epss ? (vuln.epss.score | percent : '1.0-2') : '-' }}</td>
                    </tr>
                  }
                }
              </tbody>
            </table>
            @if (!enrichment()?.findings?.length) {
              <p class="no-issues">No vulnerability findings.</p>
            }
          }

          <!-- Remediation tab -->
          @if (activeTab() === 'remediation') {
            @if (enrichment()?.assessment?.remediation?.length) {
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Current Version</th>
                    <th>Target Version</th>
                    <th>CVEs Resolved</th>
                  </tr>
                </thead>
                <tbody>
                  @for (rem of enrichment()!.assessment!.remediation!; track rem.componentIndex) {
                    <tr>
                      <td class="component-name">{{ rem.name }}</td>
                      <td class="mono">{{ rem.currentVersion }}</td>
                      <td class="mono"><strong>{{ rem.target }}</strong></td>
                      <td>{{ rem.cvesResolved }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            } @else {
              <p class="no-issues">No remediation recommendations available.</p>
            }
          }

          <!-- Graph tab -->
          @if (activeTab() === 'graph') {
            @if (safeGraphHtml()) {
              <iframe class="graph-frame" [srcdoc]="safeGraphHtml()" sandbox="allow-scripts" style="width:100%;height:600px;border:1px solid var(--border-primary);border-radius:8px;"></iframe>
            } @else {
              <p class="no-issues">Dependency graph not available.</p>
            }
          }
        </div>
      }

      @if (selectedExportId() && enrichmentLoading()) {
        <div class="spinner" style="margin: 24px 0;"></div>
      }

      <!-- License Audit Section -->
      <div class="section-divider"></div>
      <div class="section-header">
        <h2>
          <mat-icon>gavel</mat-icon>
          License Audit
        </h2>
        @if (licenseIssuesCount() > 0) {
          <span class="issue-count">{{ licenseIssuesCount() }} issue(s)</span>
        }
      </div>

      @if (licenseIssues().length) {
        <table class="data-table license-table">
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Ecosystem</th>
              <th>License</th>
              <th>Compatible</th>
              <th>Policy Violation</th>
            </tr>
          </thead>
          <tbody>
            @for (l of licenseIssues(); track l.id) {
              <tr>
                <td class="package-cell">
                  <mat-icon class="package-icon">package</mat-icon>
                  {{ l.package_name }}
                </td>
                <td class="mono">{{ l.package_version }}</td>
                <td>
                  <span class="ecosystem-tag">{{ l.ecosystem }}</span>
                </td>
                <td>
                  <span
                    class="license-badge"
                    [class.restricted]="!l.is_compatible"
                  >
                    {{ l.license_type }}
                  </span>
                </td>
                <td>
                  @if (l.is_compatible) {
                    <span class="compat-yes">&#10003; Compatible</span>
                  } @else {
                    <span class="compat-no">&#10007; Incompatible</span>
                  }
                </td>
                <td>
                  @if (l.policy_violation) {
                    <span class="violation-badge">
                      <mat-icon>warning_amber</mat-icon>
                      {{ l.policy_rule || 'Policy violation' }}
                    </span>
                  } @else {
                    <span class="no-violation">None</span>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      } @else {
        <p class="no-issues">No license issues detected across all SBOMs.</p>
      }
    </div>
  `,
  styles: [
    `
      /* Header */
      .header-actions {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .format-select {
        width: 160px;
        margin-bottom: 0;
      }

      /* Export table row cursor */
      .export-row {
        cursor: pointer;
      }
      .export-row.expanded {
        background: var(--bg-hover);
      }

      /* Version tag */
      .version-tag {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        font-family: var(--font-mono);
      }

      /* Signed / Unsigned badge */
      .signed-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        background: rgba(34, 197, 94, 0.15);
        color: var(--accent-success);
      }
      .signed-badge.unsigned {
        background: rgba(239, 68, 68, 0.15);
        color: var(--accent-danger);
      }

      /* Mono text */
      .mono {
        font-family: var(--font-mono);
        font-size: 12px;
      }

      /* Expanded row */
      .expanded-row td {
        padding: 0;
        background: var(--bg-secondary);
        border-bottom: 2px solid var(--border-primary);
      }
      .expanded-content {
        padding: 16px 24px 16px 48px;
      }
      .expanded-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 12px;
        font-size: 14px;
        color: var(--text-secondary);
      }
      .expanded-header mat-icon {
        font-size: 20px;
        width: 20px;
        height: 20px;
      }
      .inline-spinner {
        display: inline-block;
        margin-left: 8px;
      }

      /* Sub-table inside expanded row */
      .sub-table {
        width: 100%;
        border-collapse: collapse;
      }
      .sub-table th {
        text-align: left;
        padding: 8px 12px;
        font-size: 11px;
        font-weight: 600;
        color: var(--text-tertiary);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        border-bottom: 1px solid var(--border-primary);
      }
      .sub-table td {
        padding: 8px 12px;
        font-size: 12px;
        border-bottom: 1px solid var(--border-secondary);
      }
      .sub-table tr:last-child td {
        border-bottom: none;
      }
      .component-name {
        font-weight: 500;
        color: var(--text-primary);
      }

      /* PURL text */
      .purl-text {
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--accent-primary);
        word-break: break-all;
      }

      /* Type tag */
      .type-tag {
        display: inline-block;
        padding: 1px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 500;
        background: var(--bg-tertiary);
        color: var(--text-secondary);
      }

      /* Empty sub-state */
      .empty-sub {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 16px 0;
        color: var(--text-tertiary);
        font-size: 13px;
      }

      /* Section divider */
      .section-divider {
        height: 1px;
        background: var(--border-primary);
        margin: 32px 0 24px;
      }

      /* Section header */
      .section-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 16px;
      }
      .section-header h2 {
        display: flex;
        align-items: center;
        gap: 8px;
        margin: 0;
        font-size: 18px;
      }
      .section-header h2 mat-icon {
        font-size: 22px;
        width: 22px;
        height: 22px;
        color: var(--accent-primary);
      }
      .issue-count {
        font-size: 12px;
        font-weight: 600;
        padding: 2px 10px;
        border-radius: 12px;
        background: rgba(245, 158, 11, 0.15);
        color: var(--accent-warning);
      }

      /* License table */
      .license-table td {
        vertical-align: middle;
      }
      .package-cell {
        display: flex;
        align-items: center;
        gap: 8px;
        font-weight: 500;
      }
      .package-icon {
        font-size: 18px;
        width: 18px;
        height: 18px;
        color: var(--text-tertiary);
      }

      /* Ecosystem tag */
      .ecosystem-tag {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        background: var(--bg-tertiary);
        color: var(--accent-info);
        font-family: var(--font-mono);
        text-transform: uppercase;
      }

      /* License badge */
      .license-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        background: rgba(34, 197, 94, 0.12);
        color: var(--accent-success);
      }
      .license-badge.restricted {
        background: rgba(239, 68, 68, 0.12);
        color: var(--accent-danger);
      }

      /* Compatibility status */
      .compat-yes {
        font-size: 12px;
        font-weight: 600;
        color: var(--accent-success);
      }
      .compat-no {
        font-size: 12px;
        font-weight: 600;
        color: var(--accent-danger);
      }

      /* Violation badge */
      .violation-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 12px;
        font-weight: 600;
        color: var(--accent-warning);
      }
      .violation-badge mat-icon {
        font-size: 16px;
        width: 16px;
        height: 16px;
      }
      .no-violation {
        font-size: 12px;
        color: var(--text-tertiary);
      }
      a {
        text-decoration: none;
        color: inherit;
      }

      /* No issues message */
      .no-issues {
        padding: 20px 16px;
        color: var(--text-secondary);
        font-size: 14px;
        background: var(--bg-card);
        border: 1px solid var(--border-primary);
        border-radius: var(--radius-lg);
      }

      /* Spinner override for inline */
      ::ng-deep .mat-mdc-progress-spinner {
        --mdc-circular-progress-active-indicator-color: var(--accent-primary);
      }

      @media (max-width: 768px) {
        .header-actions {
          flex-direction: column;
          align-items: stretch;
        }
        .format-select {
          width: 100%;
        }
      }

      /* Enrichment panel */
      .enrichment-panel {
        padding: 24px;
      }
      .enrichment-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 16px;
      }
      .enrichment-header h2 {
        display: flex;
        align-items: center;
        gap: 8px;
        margin: 0;
        font-size: 18px;
      }
      .enrichment-status {
        font-size: 12px;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 12px;
        background: rgba(34,197,94,0.12);
        color: var(--accent-success);
      }
      .enrichment-status.failed {
        background: rgba(239,68,68,0.12);
        color: var(--accent-danger);
      }
      .assessment-bar {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 16px;
        background: var(--bg-secondary);
        border-radius: 8px;
        margin-bottom: 16px;
        font-size: 14px;
      }
      .verdict {
        font-weight: 700;
        padding: 2px 12px;
        border-radius: 4px;
        font-size: 12px;
        text-transform: uppercase;
      }
      .verdict.pass { background: rgba(34,197,94,0.15); color: var(--accent-success); }
      .verdict.fail { background: rgba(239,68,68,0.15); color: var(--accent-danger); }
      .verdict.warn { background: rgba(245,158,11,0.15); color: var(--accent-warning); }
      .verdict.review { background: rgba(59,130,246,0.15); color: var(--accent-info); }
      .tab-nav {
        display: flex;
        gap: 4px;
        margin-bottom: 16px;
        border-bottom: 2px solid var(--border-primary);
      }
      .tab-nav button {
        padding: 8px 20px;
        border: none;
        background: transparent;
        color: var(--text-secondary);
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        margin-bottom: -2px;
        transition: all 0.15s;
      }
      .tab-nav button.active {
        color: var(--accent-primary);
        border-bottom-color: var(--accent-primary);
      }
      .tab-nav button:hover { color: var(--text-primary); }
      .kev-badge {
        display: inline-block;
        padding: 1px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        background: rgba(239,68,68,0.15);
        color: var(--accent-danger);
      }
      .vuln-table td { vertical-align: middle; font-size: 12px; }
      .graph-frame { width: 100%; height: 600px; border: 1px solid var(--border-primary); border-radius: var(--radius-lg); }
    `,
  ],
})
export class SBOMComponent implements OnInit {
  private http = inject(HttpClient);
  private notify = inject(NotificationService);
  private sanitizer = inject(DomSanitizer);

  exports = signal<SBOMExport[]>([]);
  licenseIssues = signal<LicenseAudit[]>([]);
  loading = signal(false);
  generating = signal(false);
  selectedFormat = signal('cyclonedx');
  expandedRow = signal<string | null>(null);
  loadingComponents = signal(false);

  selectedExportId = signal<string | null>(null);
  enrichment = signal<EnrichmentData | null>(null);
  enrichmentLoading = signal(false);
  safeGraphHtml = signal<SafeHtml | null>(null);
  activeTab = signal<'vulns' | 'remediation' | 'graph'>('vulns');

  totalSBOMs = signal(0);
  totalComponents = signal(0);
  licenseIssuesCount = signal(0);

  ngOnInit(): void {
    this.loadData();
  }

  loadData(): void {
    this.loading.set(true);

    this.http
      .get<{ data: SBOMExport[] }>(`${environment.apiUrl}/sbom/exports`)
      .subscribe({
        next: (res) => {
          const data = res.data || [];
          this.exports.set(data);
          this.totalSBOMs.set(data.length);
          this.totalComponents.set(
            data.reduce((sum, e) => sum + (e.component_count || 0), 0)
          );
          this.loading.set(false);
        },
        error: (err) => {
          this.notify.error(err.error?.error || 'Failed to load SBOM exports');
          this.loading.set(false);
        },
      });

    this.http
      .get<{ data: LicenseAudit[] }>(`${environment.apiUrl}/sbom/license-audit`)
      .subscribe({
        next: (res) => {
          const data = res.data || [];
          this.licenseIssues.set(data);
          this.licenseIssuesCount.set(data.length);
        },
        error: (err) =>
          this.notify.error(
            err.error?.error || 'Failed to load license audit data'
          ),
      });
  }

  generateSBOM(): void {
    this.generating.set(true);

    this.http
      .post(`${environment.apiUrl}/sbom/generate`, {
        format: this.selectedFormat(),
      })
      .subscribe({
        next: () => {
          this.notify.success(
            `SBOM (${this.selectedFormat()}) generated successfully`
          );
          this.generating.set(false);
          this.loadData();
        },
        error: (err) => {
          this.notify.error(err.error?.error || 'Failed to generate SBOM');
          this.generating.set(false);
        },
      });
  }

  downloadSBOM(id: string): void {
    openSafeDownloadUrl(`${environment.apiUrl}/sbom/exports/${id}/download`);
  }

  toggleRow(id: string): void {
    if (this.expandedRow() === id) {
      this.expandedRow.set(null);
      return;
    }

    const exp = this.exports().find((e) => e.id === id);
    if (exp?.components) {
      this.expandedRow.set(id);
      return;
    }

    this.loadingComponents.set(true);

    this.http
      .get<{ data: SBOMComponentItem[] }>(
        `${environment.apiUrl}/sbom/exports/${id}/components`
      )
      .subscribe({
        next: (res) => {
          const comps = res.data || [];
          this.exports.update((list) =>
            list.map((e) =>
              e.id === id ? { ...e, components: comps } : e
            )
          );
          this.expandedRow.set(id);
          this.loadingComponents.set(false);
        },
        error: (err) => {
          this.notify.error(
            err.error?.error || 'Failed to load components for this SBOM'
          );
          this.loadingComponents.set(false);
        },
      });
  }

  formatFileSize(bytes: number): string {
    if (!bytes && bytes !== 0) return 'N/A';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let size = bytes;
    while (size >= 1024 && i < units.length - 1) {
      size /= 1024;
      i++;
    }
    return `${size.toFixed(1)} ${units[i]}`;
  }

  loadEnrichment(id: string): void {
    this.selectedExportId.set(id);
    this.enrichmentLoading.set(true);
    this.http.get<EnrichmentData>(`${environment.apiUrl}/sbom/exports/${id}/enrichment`)
      .subscribe({
        next: (res) => {
          this.enrichment.set(res);
          if (res.graphHtml) {
            this.safeGraphHtml.set(this.sanitizer.bypassSecurityTrustHtml(res.graphHtml));
          }
          this.enrichmentLoading.set(false);
        },
        error: (err) => {
          this.notify.error(err.error?.error || 'Failed to load enrichment data');
          this.enrichmentLoading.set(false);
        },
      });
  }
}
