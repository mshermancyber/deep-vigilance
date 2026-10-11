import { Component, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDividerModule } from '@angular/material/divider';
import { ApiService } from '../../core/services/api.service';
import { NotificationService } from '../../core/services/notification.service';

interface LaunchForm {
  artifactPath: string;
  artifactType: string;
  projectId: string;
  priority: string;
  enableDecompilation: boolean;
  secretsScan: boolean;
}

@Component({
  selector: 'app-binary-scan',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatButtonModule, MatIconModule, MatCardModule,
    MatFormFieldModule, MatInputModule, MatSelectModule,
    MatCheckboxModule, MatTooltipModule, MatDividerModule,
  ],
  template: `
    <div class="page-container fade-in">
      <!-- Header -->
      <div class="page-header">
        <h1>Binary & Mobile Scan</h1>
        <div class="header-actions">
          @if (projects().length) {
            <mat-form-field appearance="outline" subscriptSizing="dynamic" class="project-filter">
              <mat-label>Filter by Project</mat-label>
              <mat-select [(ngModel)]="filterProjectId" (selectionChange)="loadScans()">
                <mat-option value="">All Projects</mat-option>
                @for (p of projects(); track p.id) {
                  <mat-option [value]="p.id">{{ p.name }}</mat-option>
                }
              </mat-select>
            </mat-form-field>
          }
        </div>
      </div>

      <!-- Scan Launch Form -->
      <div class="scan-form card">
        <div class="scan-form-header">
          <mat-icon>radar</mat-icon>
          <h3>Launch New Binary / Mobile Scan</h3>
        </div>
        <div class="scan-form-fields">
          <mat-form-field appearance="outline" subscriptSizing="dynamic" class="field-path">
            <mat-label>Artifact Path *</mat-label>
            <input
              matInput
              [(ngModel)]="launchForm.artifactPath"
              placeholder="/path/to/app.apk or my-app.jar"
              autocomplete="off"
            >
            <mat-hint>Absolute path to the binary artifact on disk or a download URL</mat-hint>
          </mat-form-field>

          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Artifact Type</mat-label>
            <mat-select [(ngModel)]="launchForm.artifactType">
              <mat-option value="">Auto-detect</mat-option>
              <mat-option value="jar">JAR</mat-option>
              <mat-option value="war">WAR</mat-option>
              <mat-option value="ear">EAR</mat-option>
              <mat-option value="aar">AAR</mat-option>
              <mat-option value="dll">DLL</mat-option>
              <mat-option value="exe">EXE</mat-option>
              <mat-option value="elf">ELF</mat-option>
              <mat-option value="macho">Mach-O</mat-option>
              <mat-option value="wasm">WASM</mat-option>
              <mat-option value="apk">APK</mat-option>
              <mat-option value="ipa">IPA</mat-option>
            </mat-select>
          </mat-form-field>

          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Priority</mat-label>
            <mat-select [(ngModel)]="launchForm.priority">
              <mat-option value="low">Low</mat-option>
              <mat-option value="normal">Normal</mat-option>
              <mat-option value="high">High</mat-option>
              <mat-option value="critical">Critical</mat-option>
            </mat-select>
          </mat-form-field>

          <mat-form-field appearance="outline" subscriptSizing="dynamic" class="field-project">
            <mat-label>Project</mat-label>
            <mat-select [(ngModel)]="launchForm.projectId">
              <mat-option value="">No Project</mat-option>
              @for (p of projects(); track p.id) {
                <mat-option [value]="p.id">{{ p.name }}</mat-option>
              }
            </mat-select>
          </mat-form-field>
        </div>

        <div class="scan-form-options">
          <mat-checkbox [(ngModel)]="launchForm.enableDecompilation" color="primary">
            Enable decompilation
          </mat-checkbox>
          <mat-checkbox [(ngModel)]="launchForm.secretsScan" color="primary">
            Secrets scan
          </mat-checkbox>
        </div>

        <div class="scan-form-actions">
          <button
            mat-flat-button
            color="primary"
            class="launch-btn"
            (click)="launchScan()"
            [disabled]="!launchForm.artifactPath.trim() || scanning()"
          >
            @if (scanning()) {
              <mat-icon class="spin">sync</mat-icon>
              <span>Submitting...</span>
            } @else {
              <mat-icon>play_arrow</mat-icon>
              <span>Launch Scan</span>
            }
          </button>
        </div>
      </div>

      <!-- Summary Stats -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">{{ totalScans() }}</div>
          <div class="stat-label">Total Scans</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-critical-color">{{ totalCritical() }}</div>
          <div class="stat-label">Critical Findings</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-high-color">{{ totalHigh() }}</div>
          <div class="stat-label">High Findings</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-medium-color">{{ totalMedium() }}</div>
          <div class="stat-label">Medium Findings</div>
        </div>
      </div>

      <!-- Scans Table -->
      @if (scans().length) {
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th class="col-expand"></th>
                <th class="col-artifact">Artifact Path</th>
                <th class="col-type">Type</th>
                <th class="col-status">Status</th>
                <th class="col-findings">Findings</th>
                <th class="col-critical">Critical</th>
                <th class="col-high">High</th>
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
                  <td class="col-artifact">
                    <div class="cell-artifact-name">
                      <span class="artifact-name-text" [title]="s.artifact_path">{{ s.artifact_path }}</span>
                    </div>
                  </td>
                  <td class="col-type">
                    <span class="type-label">{{ s.artifact_type || '-' }}</span>
                  </td>
                  <td class="col-status">
                    <span class="status-badge" [class]="s.status">
                      @if (s.status === 'scanning' || s.status === 'in_progress') {
                        <span class="status-dot pulse"></span>
                      }
                      {{ statusLabel(s.status) }}
                    </span>
                  </td>
                  <td class="col-findings">{{ s.findings_count ?? 0 }}</td>
                  <td class="col-critical">
                    <span class="severity-badge critical">{{ s.critical_findings ?? 0 }}</span>
                  </td>
                  <td class="col-high">
                    <span class="severity-badge high">{{ s.high_findings ?? 0 }}</span>
                  </td>
                  <td class="col-date">{{ s.created_at | date: 'short' }}</td>
                  <td class="col-actions">
                    <div class="action-buttons" (click)="$event.stopPropagation()">
                      <button
                        mat-icon-button
                        [matTooltip]="expandedId() === s.id ? 'Collapse' : 'View Findings'"
                        matTooltipPosition="above"
                        (click)="toggleExpand(s.id)"
                      >
                        <mat-icon>{{ expandedId() === s.id ? 'visibility_off' : 'visibility' }}</mat-icon>
                      </button>
                      <button
                        mat-icon-button
                        [matTooltip]="'Rescan'"
                        matTooltipPosition="above"
                        (click)="rescan(s.id)"
                        [disabled]="scanning()"
                      >
                        <mat-icon>refresh</mat-icon>
                      </button>
                      <button
                        mat-icon-button
                        [matTooltip]="'Delete Scan'"
                        matTooltipPosition="above"
                        (click)="deleteScan(s.id)"
                      >
                        <mat-icon>delete</mat-icon>
                      </button>
                    </div>
                  </td>
                </tr>

                <!-- Expanded findings row -->
                @if (expandedId() === s.id) {
                  <tr class="expanded-row">
                    <td colspan="9" class="expanded-cell">
                      <div class="findings-container">
                        <div class="findings-header">
                          <div class="findings-header-left">
                            <mat-icon>bug_report</mat-icon>
                            <h4>Binary Scan Findings</h4>
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
                                  <th class="f-type">Type</th>
                                  <th class="f-severity">Severity</th>
                                  <th class="f-cwe">CWE</th>
                                  <th class="f-cvss">CVSS</th>
                                  <th class="f-class">Class / Method</th>
                                  <th class="f-title">Title</th>
                                  <th class="f-recommendation">Recommendation</th>
                                </tr>
                              </thead>
                              <tbody>
                                @for (f of findings(); track f.id) {
                                  <tr class="finding-row" [class]="'severity-' + (f.severity || 'unknown').toLowerCase()">
                                    <td class="f-type">
                                      <span class="finding-type-label">{{ f.finding_type || '-' }}</span>
                                    </td>
                                    <td class="f-severity">
                                      <span class="severity-badge" [class]="(f.severity || 'unknown').toLowerCase()">
                                        {{ f.severity || 'UNKNOWN' }}
                                      </span>
                                    </td>
                                    <td class="f-cwe">
                                      @if (f.cwe_id) {
                                        <a
                                          [href]="'https://cwe.mitre.org/data/definitions/' + f.cwe_id.replace('CWE-', '') + '.html'"
                                          target="_blank"
                                          rel="noopener"
                                          (click)="$event.stopPropagation()"
                                        >
                                          <code>{{ f.cwe_id }}</code>
                                        </a>
                                      } @else {
                                        <span class="text-muted">-</span>
                                      }
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
                                    <td class="f-class">
                                      <div class="class-method-info">
                                        @if (f.class_name) {
                                          <div class="class-name" [title]="f.class_name">
                                            <code>{{ f.class_name }}</code>
                                          </div>
                                        }
                                        @if (f.method_name) {
                                          <div class="method-name" [title]="f.method_name">
                                            <code>{{ f.method_name }}</code>
                                          </div>
                                        }
                                        @if (!f.class_name && !f.method_name) {
                                          <span class="text-muted">-</span>
                                        }
                                      </div>
                                    </td>
                                    <td class="f-title">
                                      <span class="title-text" [title]="f.title">{{ f.title }}</span>
                                    </td>
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
                            <span>No findings for this binary artifact.</span>
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
          <mat-icon class="empty-icon">memory</mat-icon>
          <h3>No binary scans</h3>
          <p>Analyze binary artifacts such as JAR, WAR, APK, IPA, DLL, EXE, ELF, Mach-O, and WASM for security vulnerabilities, hardcoded secrets, and code-level issues.</p>
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
      flex: 1 1 160px;
      min-width: 130px;
    }
    .scan-form-fields .field-path {
      flex: 3 1 340px;
      min-width: 200px;
    }
    .scan-form-fields .field-project {
      flex: 1 1 180px;
      min-width: 140px;
    }
    .scan-form-options {
      display: flex;
      flex-wrap: wrap;
      gap: 20px;
      margin: 14px 0 0;
      padding: 12px 0 0;
      border-top: 1px solid var(--border-secondary);
    }
    .scan-form-options mat-checkbox {
      font-size: 13px;
      color: var(--text-secondary);
    }
    .scan-form-actions {
      margin-top: 16px;
      display: flex;
    }
    .launch-btn {
      height: 44px;
      padding: 0 28px;
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
    .project-filter {
      width: 220px;
      margin-bottom: 0;
    }
    .project-filter ::ng-deep .mat-mdc-form-field-subscript-wrapper {
      display: none;
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
    .col-artifact { width: 24%; }
    .col-type { width: 9%; }
    .col-status { width: 10%; }
    .col-findings { width: 9%; }
    .col-critical { width: 7%; }
    .col-high { width: 7%; }
    .col-date { width: 13%; }
    .col-actions { width: 100px; min-width: 100px; }

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
    .cell-artifact-name {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .artifact-name-text {
      font-weight: 500;
      color: var(--text-primary);
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 300px;
    }
    .type-label {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-weight: 500;
      text-transform: uppercase;
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
    .status-badge.cancelled {
      background: rgba(100, 116, 139, 0.12);
      color: var(--text-tertiary);
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
    .f-type { min-width: 90px; width: 10%; }
    .f-severity { min-width: 90px; width: 9%; }
    .f-cwe { min-width: 100px; width: 10%; }
    .f-cvss { min-width: 60px; width: 6%; }
    .f-class { min-width: 150px; width: 18%; }
    .f-title { min-width: 180px; width: 22%; }
    .f-recommendation { min-width: 200px; width: 25%; }

    /* Finding type label */
    .finding-type-label {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-weight: 500;
    }

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

    /* Class / method info */
    .class-method-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .class-name code,
    .method-name code {
      font-size: 11px;
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 200px;
    }
    .class-name code {
      color: var(--accent-primary);
    }
    .method-name code {
      color: var(--accent-secondary);
      font-size: 10px;
    }

    /* CWE link */
    .f-cwe a code {
      color: var(--accent-primary);
      font-size: 12px;
    }
    .f-cwe a:hover code {
      color: var(--accent-primary-hover);
      text-decoration: underline;
    }

    /* Title text */
    .title-text {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 250px;
      color: var(--text-primary);
      font-weight: 500;
    }
    .finding-row:hover .title-text {
      white-space: normal;
      overflow: visible;
      background: var(--bg-tooltip);
      padding: 4px 8px;
      border-radius: var(--radius-sm);
      position: relative;
      z-index: 2;
    }

    /* Recommendation text */
    .recommendation-text {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 260px;
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
      .col-date { display: none; }
      .data-table td.col-date,
      .data-table th.col-date {
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
      .col-type, .col-findings, .col-critical, .col-high {
        display: none;
      }
      .data-table td.col-type, .data-table td.col-findings,
      .data-table td.col-critical, .data-table td.col-high,
      .data-table th.col-type, .data-table th.col-findings,
      .data-table th.col-critical, .data-table th.col-high {
        display: none;
      }
      .header-actions .project-filter {
        width: 140px;
      }
    }
  `],
})
export class BinaryScanComponent implements OnInit {
  private api = inject(ApiService);
  private notification = inject(NotificationService);

  /** Reactive state */
  scans = signal<any[]>([]);
  findings = signal<any[]>([]);
  projects = signal<any[]>([]);

  /** Launch form */
  launchForm: LaunchForm = {
    artifactPath: '',
    artifactType: '',
    projectId: '',
    priority: 'normal',
    enableDecompilation: false,
    secretsScan: false,
  };

  /** Filter */
  filterProjectId = '';

  /** Loading states */
  scanning = signal(false);
  findingsLoading = signal(false);
  expandedId = signal<string | null>(null);

  /** Computed aggregates from scans */
  totalScans = computed(() => this.scans().length);

  totalCritical = computed(() =>
    this.scans().reduce((sum, s) => sum + (s.critical_findings ?? 0), 0)
  );

  totalHigh = computed(() =>
    this.scans().reduce((sum, s) => sum + (s.high_findings ?? 0), 0)
  );

  totalMedium = computed(() =>
    this.scans().reduce((sum, s) => sum + (s.medium_findings ?? 0), 0)
  );

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
    this.loadProjects();
  }

  // ==================================================================
  // Data Loading
  // ==================================================================

  /** Fetch all binary scans from the API */
  loadScans(): void {
    const params: Record<string, string | number | boolean> = { limit: 50 };
    if (this.filterProjectId) {
      params['projectId'] = this.filterProjectId;
    }

    this.api.get<{ data: any[] }>('/advanced-scan/binary-scans', params).subscribe({
      next: (res) => {
        this.scans.set(res.data ?? []);
      },
      error: () => {
        this.notification.error('Failed to load binary scans. Please try again.');
      },
    });
  }

  /** Fetch findings for a specific scan */
  loadFindings(scanId: string): void {
    this.findingsLoading.set(true);
    this.findings.set([]);

    this.api.get<{ data: any[] }>(`/advanced-scan/binary-scans/${scanId}/findings`).subscribe({
      next: (res) => {
        this.findings.set(res.data ?? []);
        this.findingsLoading.set(false);
      },
      error: () => {
        this.findingsLoading.set(false);
        this.notification.error('Failed to load findings for this binary scan.');
      },
    });
  }

  /** Fetch available projects for the selector */
  loadProjects(): void {
    this.api.get<{ data: any[] }>('/projects', { limit: 100 }).subscribe({
      next: (res) => {
        this.projects.set(res.data ?? []);
      },
      // Silently fail — projects are optional enrichment
      error: () => {},
    });
  }

  // ==================================================================
  // Actions
  // ==================================================================

  /** Launch a new binary/mobile scan */
  launchScan(): void {
    const path = this.launchForm.artifactPath.trim();
    if (!path) {
      this.notification.warning('Artifact path is required.');
      return;
    }

    this.scanning.set(true);

    const payload: Record<string, unknown> = {
      artifactPath: path,
      artifactType: this.launchForm.artifactType || undefined,
      priority: this.launchForm.priority,
      options: {},
    };

    if (this.launchForm.projectId) {
      payload['projectId'] = this.launchForm.projectId;
    }

    if (this.launchForm['enableDecompilation']) {
      (payload['options'] as Record<string, boolean>)['enableDecompilation'] = true;
    }

    if (this.launchForm['secretsScan']) {
      (payload['options'] as Record<string, boolean>)['secretsScan'] = true;
    }

    this.api.post('/advanced-scan/binary-scans', payload).subscribe({
      next: () => {
        this.scanning.set(false);
        this.notification.success(`Binary scan launched for ${path}`);

        // Reset form
        this.launchForm.artifactPath = '';
        this.launchForm.artifactType = '';
        this.launchForm.projectId = '';
        this.launchForm.priority = 'normal';
        this.launchForm['enableDecompilation'] = false;
        this.launchForm['secretsScan'] = false;

        this.loadScans();
      },
      error: () => {
        this.scanning.set(false);
        this.notification.error('Failed to launch binary scan. Check the artifact path and type.');
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

  /** Rescan an existing artifact */
  rescan(scanId: string): void {
    this.scanning.set(true);

    this.api.post(`/advanced-scan/binary-scans/${scanId}/rescan`, {}).subscribe({
      next: () => {
        this.scanning.set(false);
        this.notification.success('Rescan initiated successfully.');
        this.loadScans();
      },
      error: () => {
        this.scanning.set(false);
        this.notification.error('Failed to initiate rescan.');
      },
    });
  }

  /** Delete a binary scan */
  deleteScan(scanId: string): void {
    this.notification.confirm(
      'Delete Scan',
      'Are you sure you want to delete this scan and all its findings?'
    ).then((confirmed) => {
      if (!confirmed) return;

      this.api.delete(`/advanced-scan/binary-scans/${scanId}`).subscribe({
        next: () => {
          this.notification.success('Scan deleted successfully.');

          if (this.expandedId() === scanId) {
            this.expandedId.set(null);
            this.findings.set([]);
          }

          this.loadScans();
        },
        error: () => {
          this.notification.error('Failed to delete scan.');
        },
      });
    });
  }

  // ==================================================================
  // Helpers
  // ==================================================================

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
