import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatMenuModule } from '@angular/material/menu';
import { NotificationService } from '../../core/services/notification.service';
import { environment } from '../../../environments/environment';

@Component({selector:'app-findings',standalone:true,imports:[CommonModule,FormsModule,MatButtonModule,MatIconModule,MatFormFieldModule,MatSelectModule,MatMenuModule],
  template:`<div class="page-container fade-in">

  <!-- ============ TARGETS VIEW (default) ============ -->
  @if(!scanId){
    <div class="page-header"><h1>Findings</h1><span class="sub">Select a scan target to drill into its findings</span></div>
    @if(targets().length){<table class="data-table"><thead><tr><th>Target / Asset</th><th>Scan</th><th>Type</th><th>Status</th><th>Findings</th><th>Date</th><th>Actions</th></tr></thead><tbody>
      @for(t of targets();track t.id){<tr class="row" (click)="openTarget(t)">
        <td class="mono tcell" [title]="targetOf(t)">{{targetOf(t)}}</td><td>{{t.name}}</td>
        <td><span class="severity-badge info">{{t.scan_type}}</span></td>
        <td><span class="status-badge" [class]="t.status">{{t.status}}</span></td>
        <td>{{t.finding_count||0}}</td><td>{{t.created_at|date:'short'}}</td>
        <td (click)="$event.stopPropagation()">
          <button mat-icon-button (click)="openTarget(t)" title="View findings"><mat-icon>visibility</mat-icon></button>
          <button mat-icon-button [matMenuTriggerFor]="em" title="Export"><mat-icon>download</mat-icon></button>
          <mat-menu #em><button mat-menu-item (click)="exportJson(t)"><mat-icon>data_object</mat-icon>Export JSON</button><button mat-menu-item (click)="exportPdf(t)"><mat-icon>picture_as_pdf</mat-icon>Export PDF</button></mat-menu>
        </td></tr>}
    </tbody></table>}@else{<div class="empty-state"><mat-icon>radar</mat-icon><h3>No scans yet</h3><p>Launch a scan to see targets and findings here.</p></div>}
  }

  <!-- ============ FINDINGS VIEW (drill-down) ============ -->
  @if(scanId){
    <div class="page-header">
      <div class="hgroup"><button mat-icon-button (click)="back()" title="Back to targets"><mat-icon>arrow_back</mat-icon></button>
        <div><h1>Findings</h1><span class="sub mono">{{currentTarget||'scan '+scanId.slice(0,8)}}</span></div></div>
      <div class="filters">
        <button mat-stroked-button (click)="exportJson(null)"><mat-icon>data_object</mat-icon>JSON</button>
        <button mat-stroked-button (click)="exportPdf(null)"><mat-icon>picture_as_pdf</mat-icon>PDF</button>
        <mat-form-field appearance="outline" class="f"><mat-label>Severity</mat-label><mat-select [(ngModel)]="sevFilter" (selectionChange)="load()"><mat-option value="">All</mat-option><mat-option value="critical">Critical</mat-option><mat-option value="high">High</mat-option><mat-option value="medium">Medium</mat-option><mat-option value="low">Low</mat-option><mat-option value="info">Info</mat-option></mat-select></mat-form-field>
        <mat-form-field appearance="outline" class="f"><mat-label>Status</mat-label><mat-select [(ngModel)]="statusFilter" (selectionChange)="load()"><mat-option value="">All</mat-option><mat-option value="open">Open</mat-option><mat-option value="in_progress">In Progress</mat-option><mat-option value="resolved">Resolved</mat-option><mat-option value="false_positive">False Positive</mat-option></mat-select></mat-form-field>
      </div>
    </div>
    @if(findings().length){<table class="data-table"><thead><tr><th></th><th>Title</th><th>Target / Asset</th><th>Severity</th><th>Type</th><th>CWE</th><th>CVSS</th><th>Status</th><th>Actions</th></tr></thead><tbody>
      @for(f of findings();track f.id){
        <tr class="row" (click)="toggle(f)"><td><mat-icon class="chev">{{selected()?.id===f.id?'expand_more':'chevron_right'}}</mat-icon></td><td>{{f.title}}</td><td class="mono tcell">{{f.file_path||f.endpoint||'—'}}</td><td><span class="severity-badge" [class]="f.severity">{{f.severity}}</span></td><td>{{f.type}}</td><td>{{f.cwe_id||'N/A'}}</td><td>{{f.cvss_score||'N/A'}}</td><td>{{f.status}}</td><td (click)="$event.stopPropagation()"><button mat-icon-button [matMenuTriggerFor]="m"><mat-icon>more_vert</mat-icon></button><mat-menu #m><button mat-menu-item (click)="updateStatus(f.id,'in_progress')">In Progress</button><button mat-menu-item (click)="updateStatus(f.id,'resolved')">Resolved</button><button mat-menu-item (click)="updateStatus(f.id,'false_positive')">False Positive</button></mat-menu></td></tr>
        @if(selected()?.id===f.id){<tr class="detail-row"><td colspan="9"><div class="detail">
          <div class="d-grid">
            <div><label>Location</label><span class="mono">{{f.file_path||f.endpoint||'—'}}{{f.line_number?(':'+f.line_number):''}}</span></div>
            <div><label>Rule</label><span>{{f.rule_name||f.rule_id||'—'}}</span></div>
            <div><label>OWASP</label><span>{{f.owasp_category||'—'}}</span></div>
            <div><label>CVSS</label><span class="mono">{{f.cvss_score||'N/A'}} {{f.cvss_vector||''}}</span></div>
            <div><label>Confidence</label><span>{{f.confidence||'—'}}</span></div>
            <div><label>Method</label><span>{{f.http_method||'—'}}</span></div>
          </div>
          @if(f.description){<div class="block"><label>Description</label><p>{{f.description}}</p></div>}
          @if(f.recommendation){<div class="block"><label>Recommendation</label><p>{{f.recommendation}}</p></div>}
          @if(f.code_snippet){<div class="block"><label>Evidence</label><pre>{{f.code_snippet}}</pre></div>}
        </div></td></tr>}
      }
    </tbody></table>}@else{<div class="empty-state"><mat-icon>shield</mat-icon><h3>No findings for this scan</h3><p>This scan reported no issues at the current filters.</p></div>}
  }
  </div>`,
  styles:[`.sub{color:var(--text-secondary);font-size:13px}.hgroup{display:flex;align-items:center;gap:8px}.filters{display:flex;gap:12px;align-items:center}.f{width:150px}
  .data-table{table-layout:auto}
  .data-table th,.data-table td{padding:12px 22px;vertical-align:middle;white-space:nowrap}
  .data-table th{text-align:left}
  .row{cursor:pointer}.row:hover td{background:var(--bg-hover)}.chev{vertical-align:middle;color:var(--text-tertiary)}
  .severity-badge,.status-badge{display:inline-block}
  .tcell{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .status-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}.status-badge.completed{background:rgba(34,197,94,.15);color:var(--accent-success)}.status-badge.running{background:rgba(34,211,238,.15);color:var(--accent-primary)}.status-badge.failed{background:var(--severity-critical-bg);color:var(--severity-critical)}.status-badge.queued,.status-badge.cancelled{background:rgba(148,163,184,.15);color:var(--text-secondary)}
  .detail-row td{background:var(--bg-secondary);padding:0;white-space:normal}
  .detail{padding:16px 20px;border-left:3px solid var(--brand-cyan)}
  .d-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px 24px;margin-bottom:12px}
  .d-grid label,.block label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--text-tertiary);margin-bottom:2px}
  .block{margin-bottom:12px}.block p{color:var(--text-secondary);line-height:1.5;margin:0}
  .mono{font-family:var(--font-mono);font-size:12px;word-break:break-all}
  pre{background:var(--bg-primary);border:1px solid var(--border-primary);border-radius:6px;padding:10px;overflow:auto;font-size:12px;color:var(--text-secondary)}`],
})
export class FindingsComponent implements OnInit {
  private http=inject(HttpClient);private route=inject(ActivatedRoute);private router=inject(Router);private notify=inject(NotificationService);
  targets=signal<any[]>([]);findings=signal<any[]>([]);selected=signal<any>(null);
  sevFilter='';statusFilter='';scanId='';currentTarget='';currentProjectId='';

  ngOnInit(){this.route.queryParams.subscribe(p=>{this.scanId=p['scanId']||'';this.selected.set(null);if(this.scanId)this.load();else this.loadTargets();});}

  // ---- targets ----
  loadTargets(){this.http.get<{data:any[]}>(`${environment.apiUrl}/scans?limit=100`).subscribe({next:(r)=>this.targets.set(r.data||[])});}
  targetOf(t:any){return t?.options?.targetUrl||t?.options?.targetPath||t?.target_url||'—';}
  openTarget(t:any){this.currentTarget=this.targetOf(t);this.currentProjectId=t.project_id;this.router.navigate([],{queryParams:{scanId:t.id}});}
  back(){this.router.navigate([],{queryParams:{}});}

  // ---- findings ----
  load(){let u=`${environment.apiUrl}/findings?limit=200&scanId=${this.scanId}`;if(this.sevFilter)u+=`&severity=${this.sevFilter}`;if(this.statusFilter)u+=`&status=${this.statusFilter}`;
    this.http.get<{data:any[]}>(u).subscribe({next:(r)=>{this.findings.set(r.data||[]);const f=(r.data||[])[0];if(f){if(!this.currentProjectId)this.currentProjectId=f.project_id;}}});}
  toggle(f:any){this.selected.set(this.selected()?.id===f.id?null:f);}
  updateStatus(id:string,status:string){this.http.patch(`${environment.apiUrl}/findings/${id}`,{status}).subscribe({next:()=>this.load(),error:()=>this.notify.error('Failed to update status')});}

  // ---- export ----
  private download(blob:Blob,filename:string){const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename;a.click();URL.revokeObjectURL(url);}
  exportJson(t:any){const sid=t?t.id:this.scanId;const label=t?this.targetOf(t):(this.currentTarget||sid);
    // Paginate (API max 200/page) so the export includes ALL findings, not just 200.
    const all:any[]=[];
    const fetchPage=(page:number)=>{
      this.http.get<{data:any[]}>(`${environment.apiUrl}/findings?scanId=${sid}&limit=200&page=${page}`).subscribe({
        next:(r)=>{const d=r.data||[];all.push(...d);
          if(d.length===200 && page<100){fetchPage(page+1);}
          else{const payload={target:label,scanId:sid,exportedAt:new Date().toISOString(),count:all.length,findings:all};
            this.download(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),`findings-${sid.slice(0,8)}.json`);
            this.notify.success(`JSON exported (${all.length} findings)`);}},
        error:()=>this.notify.error('JSON export failed')});
    };
    fetchPage(1);}
  exportPdf(t:any){const projectId=t?t.project_id:this.currentProjectId;const name=`Findings report ${(t?this.targetOf(t):this.currentTarget)||''}`.slice(0,180);
    if(!projectId){this.notify.error('No project for this scan');return;}
    this.notify.info('Generating PDF report…');
    this.http.post<any>(`${environment.apiUrl}/reports/generate`,{name,projectId,templateType:'summary',format:'pdf',filters:{}}).subscribe({
      next:(rep)=>this.pollReport(rep.id,0),error:(e)=>this.notify.error(e.error?.error||'PDF request failed')});}
  private pollReport(id:string,tries:number){this.http.get<any>(`${environment.apiUrl}/reports/${id}`).subscribe({next:(rep)=>{
    if(rep.status==='completed'){this.http.get(`${environment.apiUrl}/reports/${id}/download`,{responseType:'blob'}).subscribe({next:(b)=>{this.download(b,`report-${id.slice(0,8)}.pdf`);this.notify.success('PDF downloaded');},error:()=>this.notify.error('PDF download failed')});}
    else if(rep.status==='failed'){this.notify.error('PDF generation failed');}
    else if(tries<40){setTimeout(()=>this.pollReport(id,tries+1),2000);}
    else{this.notify.error('PDF generation timed out');}
  },error:()=>this.notify.error('PDF status check failed')});}
}
