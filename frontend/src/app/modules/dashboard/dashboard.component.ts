import { Component, OnInit, OnDestroy, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { RouterModule } from '@angular/router';
import { interval, Subscription } from 'rxjs';
import { switchMap, startWith } from 'rxjs/operators';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-dashboard', standalone: true,
  imports: [CommonModule, RouterModule, MatCardModule, MatIconModule, MatButtonModule, MatProgressBarModule],
  template: `
    <div class="page-container fade-in">
      <div class="page-header"><h1>Security Dashboard</h1><span class="refresh-hint">Auto-refresh 30s · {{ lastUpdated() }}</span></div>
      <div class="grid-4 stat-row">
        @for (s of severity(); track s.label) { <div class="stat-card" [style.borderLeft]="'3px solid '+s.color"><div class="stat-value" [style.color]="s.color">{{ s.count }}</div><div class="stat-label">{{ s.label }}</div></div> }
      </div>
      <div class="dash-grid">
        <mat-card class="dash-card"><mat-card-header><mat-card-title><mat-icon>radar</mat-icon>Recent Scans</mat-card-title><a mat-button color="primary" routerLink="/scans">View All</a></mat-card-header><mat-card-content>
          @if (scans().length) { <table class="data-table"><thead><tr><th>Name</th><th>Project</th><th>Type</th><th>Status</th><th>Findings</th></tr></thead><tbody>
            @for (s of scans(); track s.id) { <tr><td>{{ s.name }}</td><td>{{ s.project_name }}</td><td><span class="severity-badge info">{{ s.scan_type }}</span></td><td><span class="status-badge" [class]="s.status">{{ s.status }}</span></td><td>{{ s.finding_count || 0 }}</td></tr> }
          </tbody></table> } @else { <div class="empty-state"><mat-icon>radar</mat-icon><h3>No scans</h3></div> }
        </mat-card-content></mat-card>

        <mat-card class="dash-card"><mat-card-header><mat-card-title><mat-icon>api</mat-icon>API Security</mat-card-title><a mat-button color="primary" routerLink="/api-security">View Details</a></mat-card-header><mat-card-content>
          @if (apiStats()) { <div class="api-stats-grid"><div class="api-stat"><span class="api-stat-value">{{ apiStats().total_api_scans || 0 }}</span><span class="api-stat-label">Total Scans</span></div><div class="api-stat"><span class="api-stat-value severity-critical-color">{{ apiStats().api_critical || 0 }}</span><span class="api-stat-label">Critical</span></div><div class="api-stat"><span class="api-stat-value severity-high-color">{{ apiStats().api_high || 0 }}</span><span class="api-stat-label">High</span></div><div class="api-stat"><span class="api-stat-value severity-medium-color">{{ apiStats().api_medium || 0 }}</span><span class="api-stat-label">Medium</span></div><div class="api-stat"><span class="api-stat-value">{{ apiStats().api_low || 0 }}</span><span class="api-stat-label">Low</span></div></div><div class="api-scans-breakdown"><span class="api-breakdown-label">Scan Status:</span><span class="api-breakdown-item completed">{{ apiStats().completed_api_scans || 0 }} completed</span><span class="api-breakdown-item running">{{ apiStats().running_api_scans || 0 }} running</span><span class="api-breakdown-item queued">{{ apiStats().queued_api_scans || 0 }} queued</span></div> } @else { <div class="empty-state"><mat-icon>api</mat-icon><h3>No API scans</h3></div> }
        </mat-card-content></mat-card>

        <mat-card class="dash-card"><mat-card-header><mat-card-title><mat-icon>bug_report</mat-icon>Top Vulnerable Apps</mat-card-title></mat-card-header><mat-card-content>
          @if (topApps().length) { @for (a of topApps(); track a.id) { <div class="app-row"><div class="app-info"><strong>{{ a.name }}</strong><span>{{ a.open_findings || 0 }} open</span></div><div class="app-bar"><div class="bar critical" [style.width.%]="(a.critical||0)*5"></div><div class="bar high" [style.width.%]="(a.high||0)*5"></div></div></div> } } @else { <div class="empty-state"><mat-icon>shield</mat-icon><h3>No vulnerabilities</h3></div> }
        </mat-card-content></mat-card>

        <mat-card class="dash-card"><mat-card-header><mat-card-title><mat-icon>dns</mat-icon>Queue Status</mat-card-title></mat-card-header><mat-card-content>
          @if (queues()) { @for (q of queues() | keyvalue; track q.key) { <div class="queue-row"><span class="q-name">{{ q.key }}</span><span class="q-count">{{ q.value.waiting }}w / {{ q.value.active }}a</span><mat-progress-bar mode="determinate" [value]="q.value.active+q.value.waiting>0?(q.value.active/(q.value.active+q.value.waiting+1))*100:0"></mat-progress-bar></div> } } @else { <div class="empty-state"><mat-icon>hourglass_empty</mat-icon><h3>Idle</h3></div> }
        </mat-card-content></mat-card>

        <mat-card class="dash-card"><mat-card-header><mat-card-title><mat-icon>trending_up</mat-icon>30-Day Trend</mat-card-title></mat-card-header><mat-card-content>
          @if (trend().length) { <div class="trend-chart">@for (d of trend(); track d.date) { <div class="trend-bar" [style.height.px]="(d.critical||0)*3+10" [title]="d.date+': '+d.critical+' critical'"></div> }</div> } @else { <div class="empty-state"><mat-icon>show_chart</mat-icon><h3>No data</h3></div> }
        </mat-card-content></mat-card>
      </div>
    </div>
  `,
  styles: [`.refresh-hint{color:var(--text-tertiary);font-size:12px}.stat-row{margin-bottom:24px}.dash-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.dash-card{background:var(--bg-card);border:1px solid var(--border-primary)}.dash-card mat-card-title{display:flex;align-items:center;gap:8px;font-size:16px}.status-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}.status-badge.completed{background:rgba(34,197,94,.15);color:var(--accent-success)}.status-badge.running{background:rgba(59,130,246,.15);color:var(--accent-primary)}.status-badge.failed{background:var(--severity-critical-bg);color:var(--severity-critical)}.app-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-secondary)}.app-bar{display:flex;gap:3px}.bar{height:6px;border-radius:3px}.bar.critical{background:var(--severity-critical)}.bar.high{background:var(--severity-high)}.queue-row{margin-bottom:8px}.q-name{font-size:12px;font-weight:600;text-transform:uppercase}.q-count{font-size:11px;color:var(--text-secondary);margin-left:8px}.trend-chart{display:flex;align-items:flex-end;gap:2px;height:80px}.trend-bar{width:8px;background:var(--accent-primary);border-radius:2px 2px 0 0;min-height:2px}.api-stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:12px}.api-stat{text-align:center;padding:8px 4px;border-radius:6px;background:var(--bg-secondary)}.api-stat-value{display:block;font-size:22px;font-weight:700;line-height:1.2}.api-stat-label{display:block;font-size:10px;color:var(--text-secondary);margin-top:2px;text-transform:uppercase;letter-spacing:.3px}.api-scans-breakdown{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:11px}.api-breakdown-label{color:var(--text-secondary);font-weight:600}.api-breakdown-item{padding:1px 8px;border-radius:10px;font-weight:500}.api-breakdown-item.completed{background:rgba(34,197,94,.12);color:var(--accent-success)}.api-breakdown-item.running{background:rgba(59,130,246,.12);color:var(--accent-primary)}.api-breakdown-item.queued{background:rgba(139,92,246,.12);color:var(--accent-info)}@media(max-width:1024px){.dash-grid{grid-template-columns:1fr}}`],
})
export class DashboardComponent implements OnInit, OnDestroy {
  private http = inject(HttpClient); private sub?: Subscription;
  severity = signal<Array<{label:string;count:number;color:string}>>([{label:'Critical',count:0,color:'var(--severity-critical)'},{label:'High',count:0,color:'var(--severity-high)'},{label:'Medium',count:0,color:'var(--severity-medium)'},{label:'Low',count:0,color:'var(--severity-low)'}]);
  scans = signal<any[]>([]); topApps = signal<any[]>([]); queues = signal<Record<string, { waiting: number; active: number }> | null>(null); trend = signal<any[]>([]); lastUpdated = signal('');
  apiStats = signal<any>(null);
  ngOnInit(): void {
    this.sub = interval(30000).pipe(startWith(0), switchMap(() => this.http.get<any>(`${environment.apiUrl}/dashboard/summary`))).subscribe({ next: (d) => { if(d?.findings){const f=d.findings;this.severity.set([{label:'Critical',count:f.critical||0,color:'var(--severity-critical)'},{label:'High',count:f.high||0,color:'var(--severity-high)'},{label:'Medium',count:f.medium||0,color:'var(--severity-medium)'},{label:'Low',count:f.low||0,color:'var(--severity-low)'}]);} if(d?.recentScans)this.scans.set(d.recentScans); if(d?.topVulnerableApps)this.topApps.set(d.topVulnerableApps); if(d?.apiStats)this.apiStats.set(d.apiStats); this.lastUpdated.set(new Date().toLocaleTimeString()); }});
    this.http.get<any>(`${environment.apiUrl}/dashboard/queue-stats`).subscribe({ next: (d) => this.queues.set(d) });
    this.http.get<any>(`${environment.apiUrl}/dashboard/trend`).subscribe({ next: (d) => this.trend.set(d?.data||[]) });
  }
  ngOnDestroy(): void { this.sub?.unsubscribe(); }
}
