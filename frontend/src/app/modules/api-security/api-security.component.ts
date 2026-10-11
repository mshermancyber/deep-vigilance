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

@Component({
  selector: 'app-api-security',
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
        <h1>API Security</h1>
        <div class="header-actions">
          <span class="refresh-hint">Auto-refresh on action</span>
        </div>
      </div>

      <!-- Scan Launch Form -->
      <div class="scan-form card">
        <div class="scan-form-header">
          <mat-icon>security</mat-icon>
          <h3>Launch API Scan</h3>
        </div>
        <div class="scan-form-fields">
          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Project *</mat-label>
            <mat-select [(ngModel)]="selectedProjectId">
              @for (p of projects(); track p.id) {
                <mat-option [value]="p.id">{{ p.name }}</mat-option>
              }
            </mat-select>
          </mat-form-field>

          <mat-form-field appearance="outline" subscriptSizing="dynamic">
            <mat-label>Target URL *</mat-label>
            <input matInput [(ngModel)]="targetUrl" placeholder="https://api.example.com" autocomplete="off">
            <mat-hint>The base URL of the API to scan</mat-hint>
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

          <mat-form-field appearance="outline" subscriptSizing="dynamic" class="swagger-field">
            <mat-label>OpenAPI Spec (JSON, optional)</mat-label>
            <textarea
              matInput
              [(ngModel)]="swaggerSpecText"
              placeholder='{"openapi":"3.0.0","info":{"title":"My API","version":"1.0"},"paths":{}}'
              rows="3"
            ></textarea>
            <mat-hint>Paste your OpenAPI/Swagger spec JSON to guide the scan</mat-hint>
          </mat-form-field>

          <button
            mat-flat-button
            color="primary"
            class="launch-btn"
            (click)="launchScan()"
            [disabled]="!targetUrl.trim() || !selectedProjectId || scanning()"
          >
            @if (scanning()) {
              <mat-icon class="spin">sync</mat-icon>
              <span>Scanning...</span>
            } @else {
              <mat-icon>play_arrow</mat-icon>
              <span>Scan API</span>
            }
          </button>
        </div>
      </div>

      <!-- Summary Stats -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">{{ totalScans() }}</div>
          <div class="stat-label">Total API Scans</div>
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
                <th class="col-name">Name</th>
                <th class="col-project">Project</th>
                <th class="col-status">Status</th>
                <th class="col-findings">Findings</th>
                <th class="col-risk">Risk Score</th>
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
                  [class.scanning]="s.status === 'scanning' || s.status === 'running' || s.status === 'in_progress'"
                  [class.completed]="s.status === 'completed'"
                  [class.failed]="s.status === 'failed'"
                >
                  <td class="col-expand">
                    <mat-icon class="expand-icon">
                      {{ expandedId() === s.id ? 'expand_less' : 'expand_more' }}
                    </mat-icon>
                  </td>
                  <td class="col-name">
                    <div class="cell-name">
                      <span class="name-text">{{ s.name }}</span>
                    </div>
                  </td>
                  <td class="col-project">
                    <span class="project-label">{{ s.project_name }}</span>
                  </td>
                  <td class="col-status">
                    <span class="status-badge" [class]="s.status">
                      @if (s.status === 'scanning' || s.status === 'running' || s.status === 'in_progress') {
                        <span class="status-dot pulse"></span>
                      }
                      {{ statusLabel(s.status) }}
                    </span>
                  </td>
                  <td class="col-findings">
                    <span>{{ s.findings_count ?? 0 }}</span>
                  </td>
                  <td class="col-risk">
                    @if (s.options?.riskScore !== undefined && s.options?.riskScore !== null) {
                      <span class="risk-score" [class]="riskLevel(s.options.riskScore)">
                        {{ s.options.riskScore }}
                      </span>
                    } @else {
                      <span class="text-muted">-</span>
                    }
                  </td>
                  <td class="col-date">{{ s.created_at | date:'short' }}</td>
                  <td class="col-actions">
                    <div class="action-buttons" (click)="$event.stopPropagation()">
                      <button
                        mat-icon-button
                        [matTooltip]="'Refresh Findings'"
                        matTooltipPosition="above"
                        (click)="loadFindings(s.id)"
                        [disabled]="findingsLoading()"
                      >
                        <mat-icon>refresh</mat-icon>
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
                    <td colspan="8" class="expanded-cell">
                      <div class="findings-container">
                        <div class="findings-header">
                          <div class="findings-header-left">
                            <mat-icon>bug_report</mat-icon>
                            <h4>API Vulnerability Findings</h4>
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
                                  <th class="f-severity">Severity</th>
                                  <th class="f-title">Title</th>
                                  <th class="f-endpoint">Endpoint</th>
                                  <th class="f-method">Method</th>
                                  <th class="f-parameter">Parameter</th>
                                  <th class="f-anomaly">Anomaly Type</th>
                                  <th class="f-statuscode">Status Code</th>
                                  <th class="f-evidence">Evidence</th>
                                </tr>
                              </thead>
                              <tbody>
                                @for (f of findings(); track f.id) {
                                  <tr class="finding-row" [class]="'severity-' + (f.severity || 'unknown').toLowerCase()">
                                    <td class="f-severity">
                                      <span class="severity-badge" [class]="(f.severity || 'unknown').toLowerCase()">
                                        {{ f.severity || 'UNKNOWN' }}
                                      </span>
                                    </td>
                                    <td class="f-title">
                                      <span class="finding-title" [title]="f.title">{{ f.title }}</span>
                                    </td>
                                    <td class="f-endpoint">
                                      <code>{{ f.metadata?.endpoint || '-' }}</code>
                                    </td>
                                    <td class="f-method">
                                      @if (f.metadata?.method) {
                                        <span class="method-badge" [class]="f.metadata.method.toLowerCase()">
                                          {{ f.metadata.method }}
                                        </span>
                                      } @else {
                                        <span class="text-muted">-</span>
                                      }
                                    </td>
                                    <td class="f-parameter">
                                      <code>{{ f.metadata?.parameter || '-' }}</code>
                                    </td>
                                    <td class="f-anomaly">
                                      <span>{{ f.metadata?.anomalyType || '-' }}</span>
                                    </td>
                                    <td class="f-statuscode">
                                      @if (f.metadata?.statusCode) {
                                        <span class="status-code" [class]="statusCodeClass(f.metadata.statusCode)">
                                          {{ f.metadata.statusCode }}
                                        </span>
                                      } @else {
                                        <span class="text-muted">-</span>
                                      }
                                    </td>
                                    <td class="f-evidence">
                                      <span class="evidence-text" [title]="f.metadata?.evidence || ''">
                                        {{ f.metadata?.evidence || '-' }}
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
                            <span>No findings for this scan.</span>
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
          <mat-icon class="empty-icon">security</mat-icon>
          <h3>No API scans</h3>
          <p>Scan your APIs for vulnerabilities, misconfigurations, and OWASP Top 10 issues. Use the form above to launch your first API security scan.</p>
        </div>
      }
    </div>
  `,
  styles: [`
    /* ============================================
       Header
       ============================================ */
    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .refresh-hint {
      font-size: 12px;
      color: var(--text-tertiary);
    }

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
      flex: 1 1 200px;
    }
    .swagger-field {
      flex: 2 1 340px !important;
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
      table-layout: auto;
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
    .col-name { min-width: 160px; }
    .col-project { min-width: 120px; }
    .col-status { min-width: 110px; }
    .col-findings { min-width: 80px; text-align: center; }
    .col-risk { min-width: 90px; text-align: center; }
    .col-date { min-width: 130px; }
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
    .cell-name {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .name-text {
      font-weight: 500;
      color: var(--text-primary);
    }
    .project-label {
      font-size: 12px;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-weight: 500;
    }
    .text-muted {
      color: var(--text-tertiary);
      font-style: italic;
    }

    /* Risk score */
    .risk-score {
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 13px;
    }
    .risk-score.critical { color: var(--severity-critical); }
    .risk-score.high { color: var(--severity-high); }
    .risk-score.medium { color: var(--severity-medium); }
    .risk-score.low { color: var(--severity-low); }
    .risk-score.none { color: var(--text-tertiary); }

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
    .status-badge.scanning, .status-badge.running, .status-badge.in_progress {
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
      background: rgba(156, 163, 175, 0.12);
      color: var(--text-secondary);
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
    .f-severity { min-width: 85px; }
    .f-title { min-width: 160px; }
    .f-endpoint { min-width: 140px; }
    .f-method { min-width: 70px; }
    .f-parameter { min-width: 100px; }
    .f-anomaly { min-width: 110px; }
    .f-statuscode { min-width: 90px; }
    .f-evidence { min-width: 180px; }

    /* Finding title truncation */
    .finding-title {
      display: block;
      max-width: 200px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text-primary);
    }

    /* Evidence text */
    .evidence-text {
      display: block;
      max-width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 11px;
    }
    .finding-row:hover .evidence-text {
      white-space: normal;
      overflow: visible;
      background: var(--bg-tooltip);
      padding: 4px 8px;
      border-radius: var(--radius-sm);
      position: relative;
      z-index: 2;
    }

    /* HTTP method badge */
    .method-badge {
      display: inline-block;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 10px;
      font-weight: 700;
      font-family: var(--font-mono);
      text-transform: uppercase;
    }
    .method-badge.get { background: rgba(34, 197, 94, 0.12); color: var(--accent-success); }
    .method-badge.post { background: rgba(59, 130, 246, 0.12); color: var(--accent-primary); }
    .method-badge.put { background: rgba(245, 158, 11, 0.12); color: var(--accent-warning); }
    .method-badge.patch { background: rgba(139, 92, 246, 0.12); color: var(--accent-info); }
    .method-badge.delete { background: rgba(239, 68, 68, 0.12); color: var(--severity-critical); }
    .method-badge.options { background: rgba(156, 163, 175, 0.12); color: var(--text-secondary); }
    .method-badge.head { background: rgba(156, 163, 175, 0.12); color: var(--text-secondary); }

    /* Status code colors */
    .status-code {
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 12px;
    }
    .status-code.code-2xx { color: var(--accent-success); }
    .status-code.code-3xx { color: var(--accent-primary); }
    .status-code.code-4xx { color: var(--accent-warning); }
    .status-code.code-5xx { color: var(--severity-critical); }

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

    /* Spinner */
    .spinner {
      width: 32px;
      height: 32px;
      border: 3px solid var(--border-primary);
      border-top-color: var(--accent-primary);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    /* ============================================
       Severity badges (findings)
       ============================================ */
    .severity-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: capitalize;
    }
    .severity-badge.critical { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .severity-badge.high { background: var(--severity-high-bg); color: var(--severity-high); }
    .severity-badge.medium { background: var(--severity-medium-bg); color: var(--severity-medium); }
    .severity-badge.low { background: var(--severity-low-bg); color: var(--severity-low); }
    .severity-badge.info { background: rgba(59, 130, 246, 0.1); color: var(--accent-primary); }
    .severity-badge.unknown { background: var(--bg-tertiary); color: var(--text-secondary); }

    /* ============================================
       Responsive
       ============================================ */
    @media (max-width: 1100px) {
      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
      .col-risk { display: none; }
      .data-table td.col-risk, .data-table th.col-risk {
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
      .col-project, .col-date, .col-risk {
        display: none;
      }
      .data-table td.col-project, .data-table td.col-date, .data-table td.col-risk,
      .data-table th.col-project, .data-table th.col-date, .data-table th.col-risk {
        display: none;
      }
    }
  `],
})
export class ApiSecurityComponent implements OnInit {
  private api = inject(ApiService);
  private notification = inject(NotificationService);

  /** Reactive state */
  scans = signal<any[]>([]);
  findings = signal<any[]>([]);
  projects = signal<any[]>([]);
  /** API finding severity totals from /dashboard/summary apiStats */
  apiStats = signal<{ api_critical?: number; api_high?: number; api_medium?: number; api_low?: number; total_api_findings?: number } | null>(null);

  /** Form fields */
  selectedProjectId = '';
  targetUrl = '';
  priority = 'normal';
  swaggerSpecText = '';

  /** Loading states */
  scanning = signal(false);
  findingsLoading = signal(false);
  expandedId = signal<string | null>(null);

  /** Computed aggregates */
  totalScans = computed(() => this.scans().length);

  // Severity totals come from the backend apiStats aggregate — the scans list
  // only carries findings_count, not a per-severity breakdown.
  totalCritical = computed(() => Number(this.apiStats()?.api_critical ?? 0));
  totalHigh = computed(() => Number(this.apiStats()?.api_high ?? 0));
  totalMedium = computed(() => Number(this.apiStats()?.api_medium ?? 0));

  /** Status display labels */
  private statusLabels: Record<string, string> = {
    completed: 'Completed',
    completed_no_issues: 'Clean',
    queued: 'Queued',
    scanning: 'Scanning',
    running: 'Running',
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
    this.loadApiStats();
  }

  /** Fetch API finding severity totals from the dashboard summary */
  loadApiStats(): void {
    this.api.get<{ apiStats?: any }>('/dashboard/summary').subscribe({
      next: (res) => this.apiStats.set(res.apiStats ?? null),
      error: () => { /* stats card falls back to 0 */ },
    });
  }

  // ==================================================================
  // Data Loading
  // ==================================================================

  /** Fetch API scans from the backend */
  loadScans(): void {
    this.api.get<{ data: any[]; pagination: { page: number; limit: number; total: number; pages: number } }>(
      '/scans',
      { scanType: 'api', limit: 50 },
    ).subscribe({
      next: (res) => {
        this.scans.set(res.data ?? []);
      },
      error: () => {
        this.notification.error('Failed to load API scans. Please try again.');
      },
    });
  }

  /** Fetch projects for the launch dropdown */
  loadProjects(): void {
    this.api.get<{ data: any[] }>('/projects', { limit: 100 }).subscribe({
      next: (res) => {
        const list = res.data ?? [];
        this.projects.set(list);
        if (list.length && !this.selectedProjectId) {
          this.selectedProjectId = list[0].id;
        }
      },
      error: () => {
        this.notification.error('Failed to load projects.');
      },
    });
  }

  /** Fetch findings for a specific scan */
  loadFindings(scanId: string): void {
    this.findingsLoading.set(true);
    this.findings.set([]);

    this.api.get<{ data: any[]; total: number }>(`/scans/${scanId}/findings`).subscribe({
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

  /** Launch a new API scan */
  launchScan(): void {
    const url = this.targetUrl.trim();
    if (!url) {
      this.notification.warning('Target URL is required.');
      return;
    }
    if (!this.selectedProjectId) {
      this.notification.warning('Please select a project.');
      return;
    }

    const options: any = { targetUrl: url };

    // Parse optional OpenAPI spec
    const specText = this.swaggerSpecText.trim();
    if (specText) {
      try {
        options.swaggerDoc = JSON.parse(specText);
      } catch {
        this.notification.error('Invalid JSON in OpenAPI spec.');
        return;
      }
    }

    this.scanning.set(true);

    this.api.post('/scans/launch', {
      projectId: this.selectedProjectId,
      name: 'API Scan',
      scanType: 'api',
      options,
      priority: this.priority,
    }).subscribe({
      next: () => {
        this.scanning.set(false);
        this.notification.success(`API scan launched for ${url}`);
        // Reset form
        this.targetUrl = '';
        this.swaggerSpecText = '';
        this.priority = 'normal';
        this.loadScans();
        this.loadApiStats();
      },
      error: (err) => {
        this.scanning.set(false);
        const msg = err?.error?.error || err?.error?.message || 'Failed to launch API scan.';
        this.notification.error(msg);
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

  // ==================================================================
  // Helpers
  // ==================================================================

  statusLabel(status: string): string {
    return this.statusLabels[status] || status || 'Unknown';
  }

  riskLevel(score: number): string {
    if (score === null || score === undefined) return 'none';
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score > 0) return 'low';
    return 'none';
  }

  statusCodeClass(code: number): string {
    if (code >= 200 && code < 300) return 'code-2xx';
    if (code >= 300 && code < 400) return 'code-3xx';
    if (code >= 400 && code < 500) return 'code-4xx';
    if (code >= 500) return 'code-5xx';
    return '';
  }
}
