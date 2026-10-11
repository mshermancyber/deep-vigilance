import { Component, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDividerModule } from '@angular/material/divider';
import { ApiService } from '../../core/services/api.service';
import { NotificationService } from '../../core/services/notification.service';
import { openSafeDownloadUrl } from '../../core/utils/safe-url';

@Component({
  selector: 'app-container-scan',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatButtonModule, MatIconModule, MatCardModule,
    MatFormFieldModule, MatInputModule, MatSelectModule,
    MatTooltipModule, MatDividerModule,
  ],
  template: `
    <div class="page-container fade-in">
      <!-- Header -->
      <div class="page-header">
        <h1>Container & Image Scanning</h1>
        <div class="header-actions">
          <span class="exporting-hint" [class.active]="exporting()">
            <mat-icon>sync</mat-icon> Exporting...
          </span>
        </div>
      </div>

      <!-- Scan Launch Form -->
      <div class="scan-form card">
        <div class="scan-form-header">
          <mat-icon>radar</mat-icon>
          <h3>Launch New Scan</h3>
        </div>
        <div class="scan-form-fields">
          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Image Name *</mat-label>
            <input matInput [(ngModel)]="imageName" placeholder="alpine" autocomplete="off">
            <mat-hint>Repository name without tag</mat-hint>
          </mat-form-field>

          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Registry</mat-label>
            <mat-select [(ngModel)]="registry">
              <mat-option value="">Docker Hub</mat-option>
              <mat-option value="ecr">AWS ECR</mat-option>
              <mat-option value="gcr">GCP GCR</mat-option>
              <mat-option value="acr">Azure ACR</mat-option>
              <mat-option value="ghcr">GHCR</mat-option>
              <mat-option value="harbor">Harbor</mat-option>
              <mat-option value="quay">Quay</mat-option>
              <mat-option value="self-hosted">Self-Hosted</mat-option>
            </mat-select>
          </mat-form-field>

          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Tag</mat-label>
            <input matInput [(ngModel)]="imageTag" placeholder="latest" autocomplete="off">
          </mat-form-field>

          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Priority</mat-label>
            <mat-select [(ngModel)]="priority">
              <mat-option value="low">Low</mat-option>
              <mat-option value="normal">Normal</mat-option>
              <mat-option value="high">High</mat-option>
              <mat-option value="critical">Critical</mat-option>
            </mat-select>
          </mat-form-field>

          <button
            mat-flat-button
            color="primary"
            class="launch-btn"
            (click)="launchScan()"
            [disabled]="!imageName.trim() || scanning()"
          >
            @if (scanning()) {
              <mat-icon class="spin">sync</mat-icon>
              <span>Scanning...</span>
            } @else {
              <mat-icon>play_arrow</mat-icon>
              <span>Scan Image</span>
            }
          </button>
        </div>
      </div>

      <!-- Summary Stats -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value severity-critical-color">{{ totalCritical() }}</div>
          <div class="stat-label">Critical CVEs</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-high-color">{{ totalHigh() }}</div>
          <div class="stat-label">High CVEs</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-medium-color">{{ totalMedium() }}</div>
          <div class="stat-label">Medium CVEs</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{{ totalScans() }}</div>
          <div class="stat-label">Total Scans</div>
        </div>
      </div>

      <!-- Scans Table -->
      @if (scans().length) {
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th class="col-expand"></th>
                <th class="col-image">Image</th>
                <th class="col-registry">Registry</th>
                <th class="col-tag">Tag</th>
                <th class="col-critical">Critical</th>
                <th class="col-high">High</th>
                <th class="col-medium">Medium</th>
                <th class="col-low">Low</th>
                <th class="col-packages">Packages</th>
                <th class="col-base">Base Image</th>
                <th class="col-status">Status</th>
                <th class="col-date">Date</th>
                <th class="col-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (s of scans(); track s.id) {
                <!-- Main scan row -->
                <tr
                  class="scan-row"
                  (click)="toggleExpand(s.id)"
                  [class.expanded]="expandedId() === s.id"
                  [class.queued]="s.status === 'queued'"
                  [class.scanning]="s.status === 'scanning' || s.status === 'in_progress'"
                  [class.completed]="s.status === 'completed'"
                  [class.failed]="s.status === 'failed'"
                >
                  <td class="col-expand">
                    <mat-icon class="expand-icon">
                      {{ expandedId() === s.id ? 'expand_less' : 'expand_more' }}
                    </mat-icon>
                  </td>
                  <td class="col-image">
                    <div class="cell-image-name">
                      <span class="image-name-text">{{ s.image_name }}</span>
                    </div>
                  </td>
                  <td class="col-registry">
                    <span class="registry-label">{{ registryLabel(s.registry) }}</span>
                  </td>
                  <td class="col-tag">
                    <code class="tag-value">{{ s.tag || 'latest' }}</code>
                  </td>
                  <td class="col-critical">
                    <span class="severity-badge critical">{{ s.critical_cves ?? 0 }}</span>
                  </td>
                  <td class="col-high">
                    <span class="severity-badge high">{{ s.high_cves ?? 0 }}</span>
                  </td>
                  <td class="col-medium">
                    <span class="severity-badge medium">{{ s.medium_cves ?? 0 }}</span>
                  </td>
                  <td class="col-low">
                    <span class="severity-badge low">{{ s.low_cves ?? 0 }}</span>
                  </td>
                  <td class="col-packages">{{ s.total_packages ?? 0 }}</td>
                  <td class="col-base">
                    <span class="base-image-text" [title]="s.base_image">{{ s.base_image || '-' }}</span>
                  </td>
                  <td class="col-status">
                    <span class="status-badge" [class]="s.status">
                      @if (s.status === 'scanning' || s.status === 'in_progress') {
                        <span class="status-dot pulse"></span>
                      }
                      {{ statusLabel(s.status) }}
                    </span>
                  </td>
                  <td class="col-date">{{ s.created_at | date:'short' }}</td>
                  <td class="col-actions">
                    <div class="action-buttons" (click)="$event.stopPropagation()">
                      <button
                        mat-icon-button
                        [matTooltip]="'Export SBOM'"
                        matTooltipPosition="above"
                        (click)="exportSbom(s.id)"
                        [disabled]="exporting()"
                      >
                        <mat-icon>inventory_2</mat-icon>
                      </button>
                      <button
                        mat-icon-button
                        [matTooltip]="expandedId() === s.id ? 'Collapse' : 'View Details'"
                        matTooltipPosition="above"
                        (click)="toggleExpand(s.id)"
                      >
                        <mat-icon>{{ expandedId() === s.id ? 'visibility_off' : 'visibility' }}</mat-icon>
                      </button>
                    </div>
                  </td>
                </tr>

                <!-- Expanded findings row -->
                @if (expandedId() === s.id) {
                  <tr class="expanded-row">
                    <td colspan="13" class="expanded-cell">
                      <div class="findings-container">
                        <div class="findings-header">
                          <div class="findings-header-left">
                            <mat-icon>bug_report</mat-icon>
                            <h4>Vulnerability Findings</h4>
                          </div>
                          <div class="findings-header-right">
                            @if (findings().length) {
                              <span class="findings-count">Total: {{ findings().length }} findings</span>
                            }
                            <button
                              mat-stroked-button
                              size="small"
                              (click)="$event.stopPropagation(); loadFindings(s.id)"
                              [disabled]="findingsLoading()"
                            >
                              <mat-icon>refresh</mat-icon>
                              Refresh
                            </button>
                          </div>
                        </div>

                        @if (findingsLoading()) {
                          <div class="findings-loading">
                            <div class="spinner"></div>
                            <span>Loading findings...</span>
                          </div>
                        } @else if (findings().length) {
                          <div class="findings-table-wrapper">
                            <table class="findings-table">
                              <thead>
                                <tr>
                                  <th class="f-cve">CVE ID</th>
                                  <th class="f-severity">Severity</th>
                                  <th class="f-cvss">CVSS</th>
                                  <th class="f-package">Package</th>
                                  <th class="f-installed">Installed</th>
                                  <th class="f-fixed">Fixed Version</th>
                                  <th class="f-layer">Layer</th>
                                  <th class="f-recommendation">Recommendation</th>
                                </tr>
                              </thead>
                              <tbody>
                                @for (f of findings(); track f.cve_id + '_' + f.affected_package) {
                                  <tr class="finding-row" [class]="'severity-' + (f.severity || 'unknown').toLowerCase()">
                                    <td class="f-cve">
                                      <a [href]="'https://nvd.nist.gov/vuln/detail/' + f.cve_id" target="_blank" rel="noopener" (click)="$event.stopPropagation()">
                                        <code>{{ f.cve_id }}</code>
                                      </a>
                                    </td>
                                    <td class="f-severity">
                                      <span class="severity-badge" [class]="(f.severity || 'unknown').toLowerCase()">
                                        {{ f.severity || 'UNKNOWN' }}
                                      </span>
                                    </td>
                                    <td class="f-cvss">
                                      @if (f.cvss_score) {
                                        <span class="cvss-score" [class]="cvssLevel(f.cvss_score)">
                                          {{ f.cvss_score }}
                                        </span>
                                      } @else {
                                        <span class="text-muted">-</span>
                                      }
                                    </td>
                                    <td class="f-package">
                                      <code>{{ f.affected_package }}</code>
                                    </td>
                                    <td class="f-installed">
                                      <code>{{ f.installed_version }}</code>
                                    </td>
                                    <td class="f-fixed">
                                      @if (f.fixed_version) {
                                        <code class="fixed-version">{{ f.fixed_version }}</code>
                                      } @else {
                                        <span class="text-muted">No fix available</span>
                                      }
                                    </td>
                                    <td class="f-layer">{{ f.layer_index !== null && f.layer_index !== undefined ? f.layer_index : '-' }}</td>
                                    <td class="f-recommendation">
                                      <span class="recommendation-text" [title]="f.recommendation">
                                        {{ f.recommendation || '-' }}
                                      </span>
                                    </td>
                                  </tr>
                                }
                              </tbody>
                            </table>
                          </div>
                        } @else {
                          <div class="no-findings">
                            <mat-icon>verified</mat-icon>
                            <span>No vulnerabilities found for this image.</span>
                          </div>
                        }
                      </div>
                    </td>
                  </tr>
                }
              }
            </tbody>
          </table>
        </div>
      } @else {
        <div class="empty-state">
          <mat-icon class="empty-icon">inventory_2</mat-icon>
          <h3>No container scans</h3>
          <p>Scan a container image for CVEs, vulnerabilities, and best practice violations. Use the form above to launch your first scan.</p>
        </div>
      }
    </div>
  `,
  styles: [`
    /* ============================================
       Scan Launch Form
       ============================================ */
    .scan-form {
      margin-bottom: 20px;
    }
    .scan-form-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 16px;
    }
    .scan-form-header mat-icon {
      color: var(--accent-secondary);
      font-size: 22px;
      width: 22px;
      height: 22px;
    }
    .scan-form-header h3 {
      margin: 0;
      font-size: 15px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .scan-form-fields {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: flex-start;
    }
    .scan-form-fields mat-form-field {
      flex: 1 1 180px;
      min-width: 140px;
    }
    .scan-form-fields mat-form-field:first-child {
      flex: 2 1 260px;
    }
    .launch-btn {
      height: 48px;
      align-self: flex-start;
      margin-top: 2px;
      padding: 0 24px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .launch-btn mat-icon {
      font-size: 20px;
      width: 20px;
      height: 20px;
    }

    /* Header actions */
    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .exporting-hint {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--text-tertiary);
      opacity: 0;
      transition: opacity 0.2s;
    }
    .exporting-hint.active {
      opacity: 1;
      color: var(--accent-primary);
    }
    .exporting-hint mat-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
    }

    /* ============================================
       Stats Grid
       ============================================ */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 20px;
    }
    .severity-critical-color { color: var(--severity-critical) !important; }
    .severity-high-color { color: var(--severity-high) !important; }
    .severity-medium-color { color: var(--severity-medium) !important; }

    /* ============================================
       Scans Table
       ============================================ */
    .table-wrapper {
      overflow-x: auto;
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-lg);
      background: var(--bg-card);
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    .data-table thead th {
      background: var(--bg-secondary);
      padding: 10px 12px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 2px solid var(--border-primary);
      white-space: nowrap;
      position: sticky;
      top: 0;
      z-index: 1;
    }
    .data-table tbody td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border-secondary);
      font-size: 13px;
      vertical-align: middle;
    }

    /* Column widths */
    .col-expand { width: 36px; min-width: 36px; }
    .col-image { width: 16%; }
    .col-registry { width: 11%; }
    .col-tag { width: 9%; }
    .col-critical { width: 7%; }
    .col-high { width: 7%; }
    .col-medium { width: 8%; }
    .col-low { width: 6%; }
    .col-packages { width: 8%; }
    .col-base { width: 13%; }
    .col-status { width: 9%; }
    .col-date { width: 11%; }
    .col-actions { width: 70px; min-width: 70px; }

    /* Scan row hover/state */
    .scan-row {
      cursor: pointer;
      transition: background 0.15s;
    }
    .scan-row:hover td {
      background: var(--bg-hover);
    }
    .scan-row.expanded td {
      background: rgba(59, 130, 246, 0.04);
    }
    .scan-row.queued td { opacity: 0.7; }
    .scan-row.failed td {
      border-left: 3px solid var(--severity-critical);
    }

    /* Expand icon */
    .expand-icon {
      font-size: 18px;
      width: 18px;
      height: 18px;
      color: var(--text-tertiary);
      transition: transform 0.2s;
      vertical-align: middle;
    }

    /* Cell content */
    .cell-image-name {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .image-name-text {
      font-weight: 500;
      color: var(--text-primary);
    }
    .registry-label {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-weight: 500;
    }
    .tag-value {
      font-family: var(--font-mono);
      font-size: 12px;
      padding: 1px 6px;
      border-radius: 3px;
      background: var(--bg-tertiary);
      color: var(--text-secondary);
    }
    .base-image-text {
      display: block;
      max-width: 140px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text-secondary);
      font-size: 12px;
    }
    .text-muted {
      color: var(--text-tertiary);
      font-style: italic;
    }

    /* Status badges */
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      text-transform: capitalize;
    }
    .status-badge.completed {
      background: rgba(34, 197, 94, 0.12);
      color: var(--accent-success);
    }
    .status-badge.queued {
      background: rgba(139, 92, 246, 0.12);
      color: var(--accent-info);
    }
    .status-badge.scanning, .status-badge.in_progress {
      background: rgba(59, 130, 246, 0.12);
      color: var(--accent-primary);
    }
    .status-badge.failed {
      background: rgba(239, 68, 68, 0.12);
      color: var(--severity-critical);
    }
    .status-badge.completed_no_issues {
      background: rgba(34, 197, 94, 0.12);
      color: var(--accent-success);
    }
    .status-badge.partial {
      background: rgba(245, 158, 11, 0.12);
      color: var(--accent-warning);
    }

    /* Status dot animation */
    .status-dot {
      display: inline-block;
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
    }
    .status-dot.pulse {
      animation: statusPulse 1.2s ease-in-out infinite;
    }
    @keyframes statusPulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }

    /* Action buttons */
    .action-buttons {
      display: flex;
      gap: 2px;
      opacity: 0.5;
      transition: opacity 0.15s;
    }
    tr:hover .action-buttons {
      opacity: 1;
    }
    .action-buttons button {
      width: 30px;
      height: 30px;
      line-height: 30px;
    }
    .action-buttons button mat-icon {
      font-size: 17px;
      width: 17px;
      height: 17px;
      line-height: 17px;
    }

    /* ============================================
       Expanded Row / Findings Section
       ============================================ */
    .expanded-row td {
      padding: 0 !important;
      background: var(--bg-primary);
      border-bottom: 2px solid var(--border-primary);
    }
    .expanded-cell {
      padding: 0 !important;
    }
    .findings-container {
      padding: 16px 20px 20px 20px;
    }
    .findings-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
    }
    .findings-header-left {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .findings-header-left mat-icon {
      font-size: 18px;
      width: 18px;
      height: 18px;
      color: var(--accent-warning);
    }
    .findings-header-left h4 {
      margin: 0;
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .findings-header-right {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .findings-count {
      font-size: 12px;
      color: var(--text-secondary);
    }
    .findings-header-right button {
      height: 32px;
      font-size: 12px;
      padding: 0 12px;
    }
    .findings-header-right button mat-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
      margin-right: 2px;
    }

    /* Findings loading */
    .findings-loading {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
      padding: 32px;
      color: var(--text-secondary);
      font-size: 13px;
    }

    /* Findings table */
    .findings-table-wrapper {
      overflow-x: auto;
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-md);
    }
    .findings-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    .findings-table thead th {
      background: var(--bg-secondary);
      padding: 8px 12px;
      font-size: 10px;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border-primary);
      white-space: nowrap;
      text-align: left;
    }
    .findings-table tbody td {
      padding: 8px 12px;
      border-bottom: 1px solid var(--border-secondary);
      vertical-align: middle;
    }
    .finding-row:hover td {
      background: var(--bg-hover);
    }
    .finding-row.severity-critical td { border-left: 3px solid var(--severity-critical); }
    .finding-row.severity-high td { border-left: 3px solid var(--severity-high); }
    .finding-row.severity-medium td { border-left: 3px solid var(--severity-medium); }
    .finding-row.severity-low td { border-left: 3px solid var(--severity-low); }

    /* Findings column widths */
    .f-cve { min-width: 140px; }
    .f-severity { min-width: 90px; }
    .f-cvss { min-width: 60px; }
    .f-package { min-width: 130px; }
    .f-installed { min-width: 100px; }
    .f-fixed { min-width: 100px; }
    .f-layer { min-width: 55px; width: 55px; }
    .f-recommendation { min-width: 200px; }

    /* CVSS score colors */
    .cvss-score {
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 12px;
    }
    .cvss-score.critical { color: var(--severity-critical); }
    .cvss-score.high { color: var(--severity-high); }
    .cvss-score.medium { color: var(--severity-medium); }
    .cvss-score.low { color: var(--severity-low); }
    .cvss-score.none { color: var(--text-tertiary); }

    /* Recommendation text */
    .recommendation-text {
      display: block;
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text-secondary);
    }
    .finding-row:hover .recommendation-text {
      white-space: normal;
      overflow: visible;
      background: var(--bg-tooltip);
      padding: 4px 8px;
      border-radius: var(--radius-sm);
      position: relative;
      z-index: 2;
    }

    /* Fixed version highlight */
    .fixed-version {
      color: var(--accent-success);
    }

    /* No findings state */
    .no-findings {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 24px;
      color: var(--text-secondary);
      font-size: 13px;
    }
    .no-findings mat-icon {
      color: var(--accent-success);
    }

    /* ============================================
       Empty state
       ============================================ */
    .empty-icon {
      font-size: 52px !important;
      width: 52px !important;
      height: 52px !important;
      color: var(--text-tertiary);
      margin-bottom: 8px;
    }

    /* Spin animation */
    .spin {
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    /* ============================================
       Responsive
       ============================================ */
    @media (max-width: 1100px) {
      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
      .col-base, .col-date { display: none; }
      .data-table td.col-base, .data-table td.col-date,
      .data-table th.col-base, .data-table th.col-date {
        display: none;
      }
    }
    @media (max-width: 768px) {
      .scan-form-fields {
        flex-direction: column;
      }
      .scan-form-fields mat-form-field {
        flex: 1 1 auto;
        width: 100%;
        min-width: 0;
      }
      .launch-btn {
        width: 100%;
      }
      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
        gap: 10px;
      }
      .col-registry, .col-tag, .col-low, .col-packages {
        display: none;
      }
      .data-table td.col-registry, .data-table td.col-tag,
      .data-table td.col-low, .data-table td.col-packages,
      .data-table th.col-registry, .data-table th.col-tag,
      .data-table th.col-low, .data-table th.col-packages {
        display: none;
      }
    }
  `],
})
export class ContainerScanComponent implements OnInit {
  private api = inject(ApiService);
  private notification = inject(NotificationService);

  /** Reactive state */
  scans = signal<any[]>([]);
  findings = signal<any[]>([]);

  /** Form fields */
  imageName = '';
  registry = '';
  imageTag = 'latest';
  priority = 'normal';

  /** Loading states */
  scanning = signal(false);
  findingsLoading = signal(false);
  expandedId = signal<string | null>(null);
  exporting = signal(false);

  /** Computed aggregates from scans */
  totalCritical = computed(() =>
    this.scans().reduce((sum, s) => sum + (s.critical_cves ?? 0), 0)
  );
  totalHigh = computed(() =>
    this.scans().reduce((sum, s) => sum + (s.high_cves ?? 0), 0)
  );
  totalMedium = computed(() =>
    this.scans().reduce((sum, s) => sum + (s.medium_cves ?? 0), 0)
  );
  totalScans = computed(() => this.scans().length);

  /** Registry display labels */
  private registryLabels: Record<string, string> = {
    '': 'Docker Hub',
    'docker-hub': 'Docker Hub',
    ecr: 'AWS ECR',
    gcr: 'GCP GCR',
    acr: 'Azure ACR',
    ghcr: 'GHCR',
    harbor: 'Harbor',
    quay: 'Quay',
    'self-hosted': 'Self-Hosted',
  };

  /** Status display labels */
  private statusLabels: Record<string, string> = {
    completed: 'Completed',
    completed_no_issues: 'Clean',
    queued: 'Queued',
    scanning: 'Scanning',
    in_progress: 'In Progress',
    failed: 'Failed',
    partial: 'Partial',
    cancelled: 'Cancelled',
  };

  // ==================================================================
  // Lifecycle
  // ==================================================================

  ngOnInit(): void {
    this.loadScans();
  }

  // ==================================================================
  // Data Loading
  // ==================================================================

  /** Fetch all container scans from the API */
  loadScans(): void {
    this.api.get<{ data: any[] }>('/container-scan/scans').subscribe({
      next: (res) => {
        this.scans.set(res.data ?? []);
      },
      error: () => {
        this.notification.error('Failed to load container scans. Please try again.');
      },
    });
  }

  /** Fetch findings for a specific scan */
  loadFindings(scanId: string): void {
    this.findingsLoading.set(true);
    this.findings.set([]);

    this.api.get<{ data: any[] }>(`/container-scan/scans/${scanId}/findings`).subscribe({
      next: (res) => {
        this.findings.set(res.data ?? []);
        this.findingsLoading.set(false);
      },
      error: () => {
        this.findingsLoading.set(false);
        this.notification.error('Failed to load vulnerability findings.');
      },
    });
  }

  // ==================================================================
  // Actions
  // ==================================================================

  /** Launch a new container scan */
  launchScan(): void {
    const name = this.imageName.trim();
    if (!name) {
      this.notification.warning('Image name is required.');
      return;
    }

    this.scanning.set(true);

    this.api.post('/container-scan/scans', {
      imageName: name,
      registry: this.registry || undefined,
      tag: this.imageTag?.trim() || 'latest',
      priority: this.priority,
    }).subscribe({
      next: () => {
        this.scanning.set(false);
        this.notification.success(`Scan launched for ${name}`);
        // Reset form
        this.imageName = '';
        this.imageTag = 'latest';
        this.priority = 'normal';
        this.loadScans();
      },
      error: () => {
        this.scanning.set(false);
        this.notification.error('Failed to launch scan. Check the image name and registry.');
      },
    });
  }

  /** Toggle the expanded findings row for a scan */
  toggleExpand(scanId: string): void {
    if (this.expandedId() === scanId) {
      this.expandedId.set(null);
      this.findings.set([]);
    } else {
      this.expandedId.set(scanId);
      this.loadFindings(scanId);
    }
  }

  /** Export SBOM for a completed scan */
  exportSbom(scanId: string): void {
    this.exporting.set(true);

    this.api.get(`/container-scan/scans/${scanId}/sbom`).subscribe({
      next: () => {
        this.exporting.set(false);
        this.notification.success('SBOM generation queued. It will be available in the reports section shortly.');
      },
      error: () => {
        this.exporting.set(false);
        this.notification.error('Failed to export SBOM for this image.');
      },
    });
  }

  // ==================================================================
  // Helpers
  // ==================================================================

  registryLabel(registry: string): string {
    return this.registryLabels[registry] || registry || 'Docker Hub';
  }

  statusLabel(status: string): string {
    return this.statusLabels[status] || status || 'Unknown';
  }

  cvssLevel(score: number): string {
    if (score === null || score === undefined) return 'none';
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score > 0) return 'low';
    return 'none';
  }
}
