import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { NotificationService } from '../../core/services/notification.service';
import { environment } from '../../../environments/environment';
import { openSafeDownloadUrl } from '../../core/utils/safe-url';

@Component({selector:'app-reports',standalone:true,imports:[CommonModule,FormsModule,MatButtonModule,MatIconModule,MatFormFieldModule,MatSelectModule,MatInputModule],
  template:`<div class="page-container fade-in"><div class="page-header"><h1>Reports</h1><button mat-flat-button color="primary" (click)="showForm=true"><mat-icon>add</mat-icon>Generate Report</button></div>
  @if(showForm){<div class="launch-panel"><mat-form-field appearance="outline"><mat-label>Name</mat-label><input matInput [(ngModel)]="form.name"></mat-form-field>
    <mat-form-field appearance="outline"><mat-label>Format</mat-label><mat-select [(ngModel)]="form.format"><mat-option value="pdf">PDF</mat-option><mat-option value="html">HTML</mat-option><mat-option value="json">JSON</mat-option><mat-option value="csv">CSV</mat-option><mat-option value="markdown">Markdown</mat-option></mat-select></mat-form-field>
    <mat-form-field appearance="outline"><mat-label>Template</mat-label><mat-select [(ngModel)]="form.template"><mat-option value="executive">Executive</mat-option><mat-option value="developer">Developer</mat-option><mat-option value="compliance">Compliance</mat-option><mat-option value="owasp">OWASP</mat-option><mat-option value="summary">Summary</mat-option></mat-select></mat-form-field>
    <button mat-flat-button color="primary" (click)="generate()">Generate</button><button mat-button (click)="showForm=false">Cancel</button></div>}
  @if(reports().length){<table class="data-table"><thead><tr><th>Name</th><th>Project</th><th>Template</th><th>Format</th><th>Status</th><th>Date</th><th>Download</th></tr></thead><tbody>
    @for(r of reports();track r.id){<tr><td>{{r.name}}</td><td>{{r.project_name}}</td><td>{{r.template_type}}</td><td>{{r.format}}</td><td><span class="status-badge" [class]="r.status==='completed'?'completed':'running'">{{r.status}}</span></td><td>{{r.created_at|date:'short'}}</td><td><button mat-icon-button (click)="download(r.id)"><mat-icon>download</mat-icon></button></td></tr>}
  </tbody></table>}@else{<div class="empty-state"><mat-icon>description</mat-icon><h3>No reports</h3><p>Generate your first security report.</p></div>}</div>`,
  styles:[`.launch-panel{display:flex;gap:12px;align-items:center;margin-bottom:20px;padding:16px;background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-lg);flex-wrap:wrap}.status-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}.status-badge.completed{background:rgba(34,197,94,.15);color:var(--accent-success)}.status-badge.running{background:rgba(59,130,246,.15);color:var(--accent-primary)}`],
})
export class ReportsComponent implements OnInit {
  private http=inject(HttpClient);private notify=inject(NotificationService);
  reports=signal<any[]>([]);showForm=false;form={name:'',format:'pdf',template:'executive'};
  ngOnInit(){this.load();}
  load(){this.http.get<{data:any[]}>(`${environment.apiUrl}/reports?limit=50`).subscribe({next:(r)=>this.reports.set(r.data||[])});}
  generate(){this.http.post(`${environment.apiUrl}/reports/generate`,{...this.form,projectId:null}).subscribe({next:()=>{this.notify.success('Report queued');this.showForm=false;this.load();},error:(e)=>this.notify.error(e.error?.error||'Failed')});}
  download(id:string){openSafeDownloadUrl(`${environment.apiUrl}/reports/${id}/download`);}
}
