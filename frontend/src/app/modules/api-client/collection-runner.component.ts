import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { MatCardModule } from '@angular/material/card';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatChipsModule } from '@angular/material/chips';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatExpansionModule } from '@angular/material/expansion';
import { environment } from '../../../environments/environment';
import { ApiService } from '../../core/services/api.service';
import { NotificationService } from '../../core/services/notification.service';
import { ScriptExecutorService } from './script-executor.service';
import { lastValueFrom } from 'rxjs';

export interface CollectionRequest {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: string;
  body: string;
  pre_script: string;
  post_script: string;
  sort_order: number;
}

export interface Collection {
  id: string;
  name: string;
  description: string;
  request_count: number;
  requests: CollectionRequest[];
  variables: Record<string, unknown>;
}

export interface RunnerResult {
  requestId: string;
  requestName: string;
  method: string;
  url: string;
  status: number;
  statusText: string;
  timing: number;
  passed: boolean;
  testResults: Array<{ name: string; passed: boolean; error: string | null }>;
  logs: string[];
  error: string | null;
  iteration: number;
  body: string;
}

export interface CsvDataSet {
  [column: string]: string;
}

@Component({
  selector: 'app-collection-runner',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatButtonModule, MatIconModule, MatFormFieldModule,
    MatSelectModule, MatInputModule, MatCardModule,
    MatProgressBarModule, MatChipsModule, MatDividerModule,
    MatTooltipModule, MatCheckboxModule, MatExpansionModule,
  ],
  template: `
    <div class="runner-container">
      <!-- Header -->
      <div class="runner-header">
        <div style="display:flex;align-items:center;gap:12px">
          <mat-icon>play_circle</mat-icon>
          <h3>Collection Runner</h3>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <mat-form-field appearance="outline" style="width:200px">
            <mat-label>Iterations</mat-label>
            <mat-select [(ngModel)]="iterations" (ngModelChange)="clearResults()">
              <mat-option [value]="1">1</mat-option>
              <mat-option [value]="5">5</mat-option>
              <mat-option [value]="10">10</mat-option>
              <mat-option [value]="25">25</mat-option>
              <mat-option [value]="50">50</mat-option>
              <mat-option [value]="100">100</mat-option>
            </mat-select>
          </mat-form-field>
          <mat-form-field appearance="outline" style="width:180px">
            <mat-label>Delay (ms)</mat-label>
            <mat-select [(ngModel)]="delayMs">
              <mat-option [value]="0">None</mat-option>
              <mat-option [value]="100">100ms</mat-option>
              <mat-option [value]="500">500ms</mat-option>
              <mat-option [value]="1000">1s</mat-option>
              <mat-option [value]="3000">3s</mat-option>
            </mat-select>
          </mat-form-field>
          <button mat-flat-button color="primary" (click)="selectCsv()" [disabled]="running()">
            <mat-icon>table_chart</mat-icon> CSV
          </button>
          <input #csvInput type="file" accept=".csv" (change)="loadCsv($event)" style="display:none">
          <button mat-flat-button color="accent" (click)="runCollection()" [disabled]="running() || !collection()">
            <mat-icon>play_arrow</mat-icon> {{ running() ? 'Running...' : 'Run All' }}
          </button>
          <button mat-stroked-button (click)="stopRun()" [disabled]="!running()">
            <mat-icon>stop</mat-icon> Stop
          </button>
        </div>
      </div>

      <!-- CSV info -->
      @if (csvData().length > 0) {
        <div class="csv-info">
          <mat-icon>table_chart</mat-icon>
          <span>Loaded {{ csvData().length }} data rows with {{ csvColumns().length }} columns: {{ csvColumns().join(', ') }}</span>
          <button mat-icon-button (click)="clearCsv()"><mat-icon>close</mat-icon></button>
        </div>
      }

      <!-- Progress -->
      @if (running()) {
        <div class="progress-section">
          <div class="progress-header">
            <span>Running {{ currentRequestName() }}</span>
            <span>{{ completedRequests() }} / {{ totalRequests() }} requests ({{ completedIterations() }}/{{ iterations }} iterations)</span>
          </div>
          <mat-progress-bar mode="determinate" [value]="progressPercent()"></mat-progress-bar>
          <div class="progress-stats">
            <span class="pass">Passed: {{ passCount() }}</span>
            <span class="fail">Failed: {{ failCount() }}</span>
            <span>Avg time: {{ avgTime() }}ms</span>
          </div>
        </div>
      }

      <!-- Collection selection -->
      <div class="collection-select" *ngIf="collections().length > 0 && !collection()">
        <h4>Select a Collection</h4>
        <div class="coll-grid">
          @for (c of collections(); track c.id) {
            <div class="coll-card" (click)="loadCollection(c.id)">
              <mat-icon>folder_open</mat-icon>
              <strong>{{ c.name }}</strong>
              <span class="req-count">{{ c.request_count || 0 }} requests</span>
            </div>
          }
          @if (collections().length === 0) {
            <div class="empty-state">
              <mat-icon>folder_off</mat-icon>
              <p>Create a collection first</p>
            </div>
          }
        </div>
      </div>

      <!-- Collection requests overview -->
      @if (collection(); as coll) {
        <div class="collection-banner">
          <div style="display:flex;align-items:center;gap:8px">
            <mat-icon>folder</mat-icon>
            <strong>{{ coll.name }}</strong>
            <span class="req-count-chip">{{ coll.requests?.length || 0 }} requests</span>
            @if (coll.variables && Object.keys(coll.variables).length > 0) {
              <span class="var-indicator" [matTooltip]="formatVars(coll.variables)">
                <mat-icon>settings</mat-icon> {{ Object.keys(coll.variables).length }} vars
              </span>
            }
          </div>
          <button mat-button (click)="collection.set(null); clearResults()">
            <mat-icon>close</mat-icon> Change
          </button>
        </div>

        <!-- Request list -->
        <div class="request-list">
          @for (req of coll.requests; track req.id; let idx = $index) {
            <div class="request-item" [class.active]="selectedRequestId() === req.id">
              <span class="method-badge" [class]="req.method.toLowerCase()">{{ req.method }}</span>
              <span class="req-name">{{ req.name || req.url }}</span>
              <span class="req-url-preview">{{ truncateUrl(req.url) }}</span>
              @if (hasScripts(req)) {
                <span class="script-badge" matTooltip="Has pre-request and/or test scripts">
                  <mat-icon>code</mat-icon>
                </span>
              }
              <span class="req-index">{{ idx + 1 }}</span>
            </div>
          }
        </div>
      }

      <!-- Results -->
      @if (results().length > 0) {
        <div class="results-section">
          <h4>Results ({{ results().length }} requests)</h4>

          <!-- Summary -->
          <div class="summary-bar">
            <div class="summary-stat total" [matTooltip]="'Total: ' + results().length">
              <span class="stat-value">{{ results().length }}</span>
              <span class="stat-label">Total</span>
            </div>
            <div class="summary-stat pass" [matTooltip]="'Passed: ' + passCount()">
              <span class="stat-value">{{ passCount() }}</span>
              <span class="stat-label">Passed</span>
            </div>
            <div class="summary-stat fail" [matTooltip]="'Failed: ' + failCount()">
              <span class="stat-value">{{ failCount() }}</span>
              <span class="stat-label">Failed</span>
            </div>
            <div class="summary-stat">
              <span class="stat-value">{{ avgTime() }}ms</span>
              <span class="stat-label">Avg Time</span>
            </div>
            <div class="summary-stat">
              <span class="stat-value">{{ totalTime() }}ms</span>
              <span class="stat-label">Total Time</span>
            </div>
          </div>

          <!-- Results table -->
          <div class="results-table-wrap">
            <table class="data-table results-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Method</th>
                  <th>Request</th>
                  <th>Status</th>
                  <th>Time</th>
                  <th>Tests</th>
                  <th>Result</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (r of results(); track r.requestId + '-' + r.iteration) {
                  <tr [class.result-fail]="!r.passed" [class.result-pass]="r.passed"
                      (click)="toggleDetail(r.requestId + '-' + r.iteration)">
                    <td>{{ $index + 1 }}</td>
                    <td><span class="method-badge" [class]="r.method.toLowerCase()">{{ r.method }}</span></td>
                    <td class="req-cell">
                      <span class="req-title">{{ r.requestName }}</span>
                      <span class="req-iteration" *ngIf="iterations > 1">Iteration {{ r.iteration + 1 }}</span>
                    </td>
                    <td>
                      <span class="status-code" [class.success]="r.status < 400" [class.redirect]="r.status >= 300 && r.status < 400" [class.error]="r.status >= 400">
                        {{ r.status || 'ERR' }}
                      </span>
                    </td>
                    <td class="timing-cell">{{ r.timing }}ms</td>
                    <td>
                      @if (r.testResults.length > 0) {
                        <span class="test-summary">
                          <span class="pass-count">{{ passedCount(r) }}</span>/<span class="fail-count">{{ failedCount(r) }}</span>
                        </span>
                      } @else {
                        <span style="color:var(--text-tertiary)">—</span>
                      }
                    </td>
                    <td>
                      @if (r.passed) {
                        <span class="result-badge pass"><mat-icon>check_circle</mat-icon> Pass</span>
                      } @else {
                        <span class="result-badge fail"><mat-icon>cancel</mat-icon> Fail</span>
                      }
                    </td>
                    <td>
                      <button mat-icon-button>
                        <mat-icon>{{ expandedDetail() === (r.requestId + '-' + r.iteration) ? 'expand_less' : 'expand_more' }}</mat-icon>
                      </button>
                    </td>
                  </tr>
                  @if (expandedDetail() === (r.requestId + '-' + r.iteration)) {
                    <tr class="detail-row">
                      <td colspan="8">
                        <div class="detail-panel">
                          <div class="detail-grid">
                            <div class="detail-section">
                              <h5><mat-icon>info</mat-icon> Response</h5>
                              <div class="detail-field"><label>Status:</label> <span [style.color]="r.status < 400 ? 'var(--accent-success)' : 'var(--severity-critical)'">{{ r.status }} {{ r.statusText }}</span></div>
                              <div class="detail-field"><label>Time:</label> <span>{{ r.timing }}ms</span></div>
                              <pre class="detail-body">{{ truncateBody(r.body, 2000) }}</pre>
                            </div>
                            @if (r.testResults.length > 0) {
                              <div class="detail-section">
                                <h5><mat-icon>fact_check</mat-icon> Test Results</h5>
                                @for (t of r.testResults; track t.name) {
                                  <div class="test-row" [class.test-pass]="t.passed" [class.test-fail]="!t.passed">
                                    <mat-icon>{{ t.passed ? 'check_circle' : 'cancel' }}</mat-icon>
                                    <span>{{ t.name }}</span>
                                    @if (t.error) { <span class="test-error">{{ t.error }}</span> }
                                  </div>
                                }
                              </div>
                            }
                            @if (r.logs.length > 0) {
                              <div class="detail-section">
                                <h5><mat-icon>terminal</mat-icon> Script Logs</h5>
                                @for (l of r.logs; track l) {
                                  <div class="log-line">{{ l }}</div>
                                }
                              </div>
                            }
                            @if (r.error) {
                              <div class="detail-section error-section">
                                <h5><mat-icon>error</mat-icon> Error</h5>
                                <div class="error-msg">{{ r.error }}</div>
                              </div>
                            }
                          </div>
                        </div>
                      </td>
                    </tr>
                  }
                }
              </tbody>
            </table>
          </div>

          <!-- Export -->
          <div class="export-bar">
            <button mat-stroked-button (click)="exportResults()">
              <mat-icon>download</mat-icon> Export Results (JSON)
            </button>
            <button mat-stroked-button (click)="clearResults()">
              <mat-icon>delete_sweep</mat-icon> Clear Results
            </button>
          </div>
        </div>
      }

      <!-- Empty state -->
      @if (results().length === 0 && !running() && !collection()) {
        <div class="empty-state" style="margin-top:40px">
          <mat-icon>playlist_play</mat-icon>
          <h3>No collection selected</h3>
          <p>Select a collection from the list above, then click "Run All" to start executing requests sequentially.</p>
        </div>
      }
    </div>
  `,
  styles: [`
    .runner-container { padding: 16px; }
    .runner-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; flex-wrap: wrap; gap: 12px; }
    .runner-header h3 { display: flex; align-items: center; gap: 8px; margin: 0; }
    .csv-info { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: rgba(139, 92, 246, 0.12); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: var(--radius-md); margin-bottom: 12px; font-size: 13px; }
    .csv-info mat-icon { color: var(--accent-info); }
    .csv-info button { margin-left: auto; }
    .progress-section { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 16px; margin-bottom: 16px; }
    .progress-header { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 8px; }
    .progress-stats { display: flex; gap: 16px; margin-top: 8px; font-size: 12px; }
    .progress-stats .pass { color: var(--accent-success); }
    .progress-stats .fail { color: var(--severity-critical); }
    .collection-select { margin-bottom: 16px; }
    .coll-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-top: 12px; }
    .coll-card { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 16px; cursor: pointer; display: flex; flex-direction: column; gap: 6px; align-items: center; text-align: center; transition: border-color 0.2s; }
    .coll-card:hover { border-color: var(--accent-primary); }
    .coll-card mat-icon { font-size: 32px; width: 32px; height: 32px; color: var(--accent-primary); }
    .req-count { font-size: 12px; color: var(--text-tertiary); }
    .collection-banner { display: flex; align-items: center; justify-content: space-between; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 12px 16px; margin-bottom: 12px; }
    .req-count-chip { font-size: 11px; background: var(--bg-tertiary); color: var(--text-secondary); padding: 2px 8px; border-radius: 10px; }
    .var-indicator { display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--accent-info); cursor: help; }
    .var-indicator mat-icon { font-size: 14px; width: 14px; height: 14px; }
    .request-list { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); overflow: hidden; margin-bottom: 16px; }
    .request-item { display: flex; align-items: center; gap: 12px; padding: 10px 16px; border-bottom: 1px solid var(--border-secondary); font-size: 13px; cursor: default; }
    .request-item:last-child { border-bottom: none; }
    .request-item.active { background: rgba(59, 130, 246, 0.08); }
    .method-badge { font-family: var(--font-mono); font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; min-width: 44px; text-align: center; }
    .method-badge.get { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
    .method-badge.post { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
    .method-badge.put { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
    .method-badge.patch { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
    .method-badge.delete { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .method-badge.options { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }
    .method-badge.head { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }
    .req-name { font-weight: 500; }
    .req-url-preview { color: var(--text-tertiary); font-size: 12px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .script-badge { display: flex; align-items: center; color: var(--accent-secondary); }
    .script-badge mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .req-index { font-size: 11px; color: var(--text-tertiary); }
    .results-section { margin-top: 16px; }
    .summary-bar { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
    .summary-stat { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 12px 20px; text-align: center; min-width: 100px; cursor: help; }
    .summary-stat .stat-value { font-size: 22px; font-weight: 700; display: block; }
    .summary-stat .stat-label { font-size: 11px; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: 0.5px; }
    .summary-stat.total .stat-value { color: var(--text-primary); }
    .summary-stat.pass .stat-value { color: var(--accent-success); }
    .summary-stat.fail .stat-value { color: var(--severity-critical); }
    .results-table-wrap { overflow-x: auto; }
    .results-table { font-size: 13px; }
    .results-table th { white-space: nowrap; }
    .results-table tr.result-fail { background: rgba(239, 68, 68, 0.04); }
    .results-table tr.result-pass { }
    .results-table tbody tr { cursor: pointer; }
    .req-cell { display: flex; flex-direction: column; }
    .req-title { font-weight: 500; }
    .req-iteration { font-size: 11px; color: var(--accent-info); }
    .status-code { font-family: var(--font-mono); font-weight: 600; font-size: 12px; }
    .status-code.success { color: var(--accent-success); }
    .status-code.redirect { color: var(--accent-warning); }
    .status-code.error { color: var(--severity-critical); }
    .timing-cell { font-family: var(--font-mono); font-size: 12px; }
    .test-summary { font-family: var(--font-mono); font-size: 12px; }
    .pass-count { color: var(--accent-success); }
    .fail-count { color: var(--severity-critical); }
    .result-badge { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; font-weight: 600; }
    .result-badge.pass { color: var(--accent-success); }
    .result-badge.fail { color: var(--severity-critical); }
    .result-badge mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .detail-row td { padding: 0 !important; }
    .detail-panel { background: var(--bg-secondary); border-top: 1px solid var(--border-primary); padding: 20px; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    @media (max-width: 900px) { .detail-grid { grid-template-columns: 1fr; } }
    .detail-section { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); padding: 12px; }
    .detail-section h5 { display: flex; align-items: center; gap: 6px; font-size: 13px; margin-bottom: 8px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
    .detail-section h5 mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .detail-field { display: flex; gap: 8px; font-size: 13px; margin-bottom: 4px; }
    .detail-field label { color: var(--text-tertiary); min-width: 50px; }
    .detail-body { background: var(--bg-input); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); padding: 8px; font-family: var(--font-mono); font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow: auto; margin-top: 8px; }
    .test-row { display: flex; align-items: flex-start; gap: 6px; font-size: 12px; padding: 4px 0; }
    .test-row mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .test-pass mat-icon { color: var(--accent-success); }
    .test-pass { color: var(--text-primary); }
    .test-fail mat-icon { color: var(--severity-critical); }
    .test-fail { color: var(--severity-critical); }
    .test-error { display: block; font-size: 11px; color: var(--text-tertiary); margin-left: 22px; }
    .log-line { font-family: var(--font-mono); font-size: 11px; padding: 2px 0; color: var(--text-secondary); border-bottom: 1px solid var(--border-secondary); }
    .error-section { border-color: rgba(239, 68, 68, 0.3); }
    .error-msg { color: var(--severity-critical); font-size: 13px; }
    .export-bar { display: flex; gap: 8px; margin-top: 16px; justify-content: flex-end; }
  `],
})
export class CollectionRunnerComponent {
  private http = inject(HttpClient);
  private api = inject(ApiService);

  // Template helpers (Angular templates don't allow arrow functions).
  passedCount(r: RunnerResult): number { return r.testResults.filter((t) => t.passed).length; }
  failedCount(r: RunnerResult): number { return r.testResults.filter((t) => !t.passed).length; }
  private notify = inject(NotificationService);
  private scriptExecutor = inject(ScriptExecutorService);

  Object = Object;

  // State
  collections = signal<any[]>([]);
  collection = signal<Collection | null>(null);
  results = signal<RunnerResult[]>([]);
  running = signal(false);
  stopFlag = false;

  // Config
  iterations = 1;
  delayMs = 0;

  // Progress
  currentRequestName = signal('');
  completedRequests = signal(0);
  totalRequests = signal(0);
  completedIterations = signal(0);
  selectedRequestId = signal<string | null>(null);
  expandedDetail = signal<string | null>(null);

  // CSV
  csvData = signal<CsvDataSet[]>([]);
  csvColumns = signal<string[]>([]);

  // Computed
  get progressPercent(): () => number {
    return () => {
      const total = this.totalRequests();
      if (total === 0) return 0;
      return Math.round((this.completedRequests() / total) * 100);
    };
  }

  get passCount(): () => number {
    return () => this.results().filter(r => r.passed).length;
  }

  get failCount(): () => number {
    return () => this.results().filter(r => !r.passed).length;
  }

  get avgTime(): () => number {
    return () => {
      const r = this.results();
      if (r.length === 0) return 0;
      return Math.round(r.reduce((sum, x) => sum + x.timing, 0) / r.length);
    };
  }

  get totalTime(): () => number {
    return () => {
      const r = this.results();
      if (r.length === 0) return 0;
      return r.reduce((sum, x) => sum + x.timing, 0);
    };
  }

  ngOnInit() {
    this.loadCollections();
  }

  private loadCollections() {
    this.api.get<any>('/api-client/collections').subscribe({
      next: (res) => this.collections.set(res.data || []),
      error: () => this.collections.set([]),
    });
  }

  loadCollection(id: string) {
    this.api.get<any>(`/api-client/collections/${id}`).subscribe({
      next: (res) => {
        const coll: Collection = {
          id: res.id,
          name: res.name,
          description: res.description || '',
          request_count: res.request_count || 0,
          requests: (res.requests || []).sort((a: CollectionRequest, b: CollectionRequest) => (a.sort_order || 0) - (b.sort_order || 0)),
          variables: res.variables || {},
        };
        this.collection.set(coll);
        this.clearResults();
      },
      error: (err) => this.notify.error('Failed to load collection: ' + (err.message || 'Unknown error')),
    });
  }

  selectCsv() {
    // Trigger file input
    const input = document.querySelector<HTMLInputElement>('input[type="file"]');
    input?.click();
  }

  loadCsv(event: Event) {
    const input = event.target as HTMLInputElement;
    if (!input.files || input.files.length === 0) return;

    const file = input.files[0];
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      this.parseCsv(text);
    };
    reader.readAsText(file);
    input.value = '';
  }

  private parseCsv(text: string) {
    try {
      const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
      if (lines.length < 2) {
        this.notify.warning('CSV must have a header row and at least one data row');
        return;
      }

      const headers = this.parseCsvRow(lines[0]);
      const data: CsvDataSet[] = [];

      for (let i = 1; i < lines.length; i++) {
        const values = this.parseCsvRow(lines[i]);
        if (values.length === 0) continue;
        const row: CsvDataSet = {};
        headers.forEach((h, idx) => {
          row[h] = values[idx] || '';
        });
        data.push(row);
      }

      this.csvColumns.set(headers);
      this.csvData.set(data);
      this.notify.success(`Loaded ${data.length} CSV data rows`);
    } catch (err) {
      this.notify.error('Failed to parse CSV file');
    }
  }

  private parseCsvRow(line: string): string[] {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        result.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    result.push(current.trim());
    return result;
  }

  clearCsv() {
    this.csvData.set([]);
    this.csvColumns.set([]);
  }

  async runCollection() {
    const coll = this.collection();
    if (!coll || !coll.requests || coll.requests.length === 0) {
      this.notify.warning('Collection has no requests');
      return;
    }

    this.running.set(true);
    this.stopFlag = false;
    this.clearResults();

    const allRequests = coll.requests;
    const totalIterations = this.iterations;
    const totalReqs = allRequests.length * totalIterations;
    this.totalRequests.set(totalReqs);
    this.completedRequests.set(0);
    this.completedIterations.set(0);

    const environmentVars: Record<string, unknown> = { ...(coll.variables || {}) };
    const collectionVars: Record<string, unknown> = { ...(coll.variables || {}) };
    const results: RunnerResult[] = [];

    for (let iter = 0; iter < totalIterations; iter++) {
      if (this.stopFlag) break;

      const iterationData: Record<string, unknown> = {};
      if (this.csvData().length > 0) {
        const csvRow = this.csvData()[iter % this.csvData().length];
        Object.assign(iterationData, csvRow);
        // Also make CSV columns available as variables
        Object.assign(environmentVars, csvRow);
      }

      for (const req of allRequests) {
        if (this.stopFlag) break;

        this.currentRequestName.set(req.name || req.url);
        this.selectedRequestId.set(req.id);

        // Variable substitution in URL using {{var}} syntax
        let resolvedUrl = req.url;
        const allVars = { ...environmentVars, ...collectionVars, ...iterationData };
        resolvedUrl = resolvedUrl.replace(/\{\{(\w+)\}\}/g, (_, key) => {
          const val = allVars[key];
          return val !== undefined ? String(val) : '{{' + key + '}}';
        });

        // Resolve headers with variables
        let resolvedHeaders: Record<string, string> = {};
        try {
          const rawHeaders = JSON.parse(req.headers || '{}');
          for (const [k, v] of Object.entries(rawHeaders)) {
            resolvedHeaders[k] = String(v).replace(/\{\{(\w+)\}\}/g, (_, key) => {
              const val = allVars[key];
              return val !== undefined ? String(val) : '{{' + key + '}}';
            });
          }
        } catch { /* ignore */ }

        // Resolve body with variables
        let resolvedBody = req.body;
        if (resolvedBody && typeof resolvedBody === 'string') {
          resolvedBody = resolvedBody.replace(/\{\{(\w+)\}\}/g, (_, key) => {
            const val = allVars[key];
            return val !== undefined ? String(val) : '{{' + key + '}}';
          });
        }

        // Execute pre-request script
        let preScriptLog: string[] = [];
        if (req.pre_script && req.pre_script.trim()) {
          const preResult = this.scriptExecutor.execute(req.pre_script, {
            variables: allVars,
            environment: environmentVars,
            collectionVariables: collectionVars,
            globals: {},
            request: { method: req.method, url: resolvedUrl, headers: resolvedHeaders, body: resolvedBody },
            iterationData,
          });
          preScriptLog = preResult.logs;
          // Collect variables set during pre-script
          // The sandbox modifies copies, so we capture the request.headers mutation indirectly
          // via the pm.request.addHeader calls. Those updates were applied to the local
          // requestHeaders in the sandbox, but we track them through the result.
        }

        // Send the actual HTTP request
        const startTime = performance.now();
        let responseStatus = 0;
        let responseStatusText = '';
        let responseBody = '';
        let responseHeaders: Record<string, string> = {};
        let requestError: string | null = null;

        try {
          let httpParams = new HttpParams();
          let parsedBody: unknown = undefined;

          if (resolvedBody) {
            try { parsedBody = JSON.parse(resolvedBody); }
            catch { parsedBody = resolvedBody; }
          }

          const httpHeaders = new HttpHeaders(resolvedHeaders);

          const resp = await lastValueFrom(
            this.http.request(req.method, resolvedUrl, {
              body: ['GET', 'HEAD'].includes(req.method.toUpperCase()) ? undefined : parsedBody,
              headers: httpHeaders,
              params: httpParams,
              observe: 'response',
              responseType: 'json',
            })
          );

          responseStatus = resp.status;
          responseStatusText = resp.statusText || '';
          responseBody = typeof resp.body === 'string' ? resp.body : JSON.stringify(resp.body, null, 2);
          // Extract response headers
          resp.headers.keys().forEach(k => {
            const v = resp.headers.get(k);
            if (v) responseHeaders[k] = v;
          });
        } catch (err: any) {
          responseStatus = err.status || 0;
          responseStatusText = err.statusText || 'Error';
          responseBody = err.error ? (typeof err.error === 'string' ? err.error : JSON.stringify(err.error, null, 2)) : (err.message || 'Request failed');
          requestError = err.message || 'Request failed';
        }

        const timing = Math.round(performance.now() - startTime);

        // Execute post-response script
        let postTestResults: Array<{ name: string; passed: boolean; error: string | null }> = [];
        let postLogs: string[] = [...preScriptLog];
        let scriptError: string | null = null;

        if (req.post_script && req.post_script.trim()) {
          const postResult = this.scriptExecutor.execute(req.post_script, {
            variables: allVars,
            environment: environmentVars,
            collectionVariables: collectionVars,
            globals: {},
            request: { method: req.method, url: resolvedUrl, headers: resolvedHeaders, body: resolvedBody },
            response: {
              status: responseStatus,
              statusText: responseStatusText,
              body: responseBody,
              headers: responseHeaders,
              responseTime: timing,
            },
            iterationData,
          });
          postTestResults = postResult.tests;
          postLogs = [...postLogs, ...postResult.logs];
          scriptError = postResult.error;
        }

        // Determine overall pass/fail
        const allTestsPassed = postTestResults.length === 0 || postTestResults.every(t => t.passed);
        const noError = !requestError && !scriptError;
        const passed = allTestsPassed && noError;

        results.push({
          requestId: req.id,
          requestName: req.name || req.url,
          method: req.method,
          url: resolvedUrl,
          status: responseStatus,
          statusText: responseStatusText,
          timing,
          passed,
          testResults: postTestResults,
          logs: postLogs,
          error: requestError || scriptError,
          iteration: iter,
          body: responseBody,
        });

        this.completedRequests.update(n => n + 1);

        // Apply delay between requests
        if (this.delayMs > 0 && !this.stopFlag) {
          await this.sleep(this.delayMs);
        }
      }

      this.completedIterations.update(n => n + 1);
    }

    this.results.set(results);
    this.running.set(false);
    this.currentRequestName.set('');

    const passed = results.filter(r => r.passed).length;
    const failed = results.filter(r => !r.passed).length;
    this.notify.info(`Run complete: ${passed} passed, ${failed} failed, ${results.length} total`);
  }

  stopRun() {
    this.stopFlag = true;
    this.running.set(false);
  }

  toggleDetail(id: string) {
    this.expandedDetail.update(current => current === id ? null : id);
  }

  clearResults() {
    this.results.set([]);
    this.expandedDetail.set(null);
    this.completedRequests.set(0);
    this.completedIterations.set(0);
  }

  exportResults() {
    const data = this.results();
    if (data.length === 0) {
      this.notify.warning('No results to export');
      return;
    }

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `collection-runner-${new Date().toISOString().slice(0, 19)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    this.notify.success('Results exported');
  }

  hasScripts(req: CollectionRequest): boolean {
    return !!(req.pre_script?.trim() || req.post_script?.trim());
  }

  truncateUrl(url: string): string {
    try {
      const u = new URL(url);
      return u.pathname + u.search;
    } catch {
      return url.length > 50 ? url.substring(0, 50) + '...' : url;
    }
  }

  truncateBody(body: string, max: number): string {
    return body.length > max ? body.substring(0, max) + '\n... (truncated)' : body;
  }

  formatVars(vars: Record<string, unknown>): string {
    return Object.entries(vars).map(([k, v]) => `${k}: ${v}`).join('\n');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
