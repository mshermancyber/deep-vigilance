import { Component, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpParams } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatMenuModule } from '@angular/material/menu';
import { RouterLink } from '@angular/router';
import { NotificationService } from '../../core/services/notification.service';
import { environment } from '../../../environments/environment';

interface ScanPagination { page: number; limit: number; total: number; pages: number; }

@Component({selector:'app-scans',standalone:true,imports:[CommonModule,FormsModule,MatButtonModule,MatIconModule,MatFormFieldModule,MatInputModule,MatSelectModule,MatMenuModule,RouterLink],
  template:`<div class="page-container fade-in"><div class="page-header"><h1>Scans</h1><button mat-flat-button color="primary" (click)="showLaunch=true"><mat-icon>play_arrow</mat-icon>Launch Scan</button></div>
  @if(showLaunch){<div class="launch-panel">
    @if(projects().length){
      <mat-form-field appearance="outline"><mat-label>Project</mat-label><mat-select [(ngModel)]="launchForm.projectId">@for(p of projects();track p.id){<mat-option [value]="p.id">{{p.name}}</mat-option>}</mat-select></mat-form-field>
      <mat-form-field appearance="outline"><mat-label>Scan Type</mat-label><mat-select [(ngModel)]="launchForm.scanType"><mat-option value="sast">SAST</mat-option><mat-option value="sca">SCA</mat-option><mat-option value="secret">Secrets</mat-option><mat-option value="dast">DAST</mat-option><mat-option value="api">API</mat-option><mat-option value="full">Full</mat-option></mat-select></mat-form-field>
      <mat-form-field appearance="outline"><mat-label>{{['sast','sca','secret'].includes(launchForm.scanType)?'Git repo URL or local path (/scan/…)':'Target URL'}}</mat-label><input matInput [(ngModel)]="launchForm.target" [placeholder]="['sast','sca','secret'].includes(launchForm.scanType)?'https://github.com/org/repo.git or /scan/myapp':'https://app.example.com'"></mat-form-field>
      @if(['sast','sca','secret'].includes(launchForm.scanType)){
        <mat-form-field appearance="outline" class="narrow"><mat-label>Branch (optional)</mat-label><input matInput [(ngModel)]="launchForm.branch" placeholder="main"></mat-form-field>
        <mat-form-field appearance="outline" class="narrow"><mat-label>Git token (private repos)</mat-label><input matInput type="password" [(ngModel)]="launchForm.gitToken" autocomplete="off"></mat-form-field>
      }
      @if(launchForm.scanType==='api'){
        <mat-form-field appearance="outline" class="wide"><mat-label>OpenAPI/Swagger Spec (JSON, optional)</mat-label><textarea matInput [(ngModel)]="launchForm.swaggerSpec" placeholder='{"openapi":"3.0.0","info":{"title":"My API","version":"1.0"},"paths":{}}' rows="4"></textarea></mat-form-field>
      }
      <button mat-flat-button color="primary" (click)="launchScan()" [disabled]="launching">Launch</button><button mat-button (click)="showLaunch=false">Cancel</button>
    }@else{
      <span class="hint">No projects yet — create one to scan:</span>
      <mat-form-field appearance="outline"><mat-label>Project name</mat-label><input matInput [(ngModel)]="newProjectName" placeholder="My Application"></mat-form-field>
      <button mat-flat-button color="primary" (click)="createProject()" [disabled]="creating">Create Project</button><button mat-button (click)="showLaunch=false">Cancel</button>
    }
  </div>}
  <div class="filter-bar">
    <mat-form-field appearance="outline" subscriptSizing="dynamic" class="filter-type">
      <mat-label>Scan Type</mat-label>
      <mat-select [(ngModel)]="scanTypeFilter" (ngModelChange)="onFilterChange()">
        <mat-option value="">All Types</mat-option>
        <mat-option value="sast">SAST</mat-option>
        <mat-option value="dast">DAST</mat-option>
        <mat-option value="api">API</mat-option>
        <mat-option value="sca">SCA</mat-option>
        <mat-option value="full">Full</mat-option>
      </mat-select>
    </mat-form-field>
  </div>
  @if(scans().length){<table class="data-table"><thead><tr><th>Name</th><th>Project</th><th>Type</th><th>Status</th><th>Findings</th><th>Date</th><th>Actions</th></tr></thead><tbody>
    @for(s of scans();track s.id){<tr><td>{{s.name}}</td><td>{{s.project_name}}</td><td><span class="severity-badge info">{{s.scan_type}}</span></td><td><span class="status-badge" [class]="s.status">{{s.status}}</span></td><td>{{s.findings_count||0}}</td><td>{{s.created_at|date:'short'}}</td><td><button mat-icon-button [matMenuTriggerFor]="m"><mat-icon>more_vert</mat-icon></button><mat-menu #m><button mat-menu-item>Cancel</button><button mat-menu-item [routerLink]="['/findings']" [queryParams]="{scanId:s.id}">Findings</button></mat-menu></td></tr>}
  </tbody></table>
  <div class="pagination-bar">
    <span class="pagination-info">Showing {{paginationFrom()}}&ndash;{{paginationTo()}} of {{totalScans()}} scans</span>
    <div class="pagination-buttons">
      <button mat-icon-button (click)="prevPage()" [disabled]="currentPage()<=1"><mat-icon>chevron_left</mat-icon></button>
      <span class="page-indicator">Page {{currentPage()}} of {{totalPages() || 1}}</span>
      <button mat-icon-button (click)="nextPage()" [disabled]="currentPage()>=totalPages()"><mat-icon>chevron_right</mat-icon></button>
    </div>
  </div>
  }@else{<div class="empty-state"><mat-icon>radar</mat-icon><h3>No scans</h3><p>Launch your first security scan.</p></div>}</div>`,
  styles:[`.launch-panel{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:20px;padding:16px;background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-lg)}.hint{color:var(--text-secondary);font-size:13px}.filter-bar{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}.filter-type{min-width:180px}.pagination-bar{display:flex;align-items:center;justify-content:space-between;margin-top:16px;padding:8px 0;flex-wrap:wrap;gap:8px}.pagination-info{font-size:13px;color:var(--text-secondary)}.pagination-buttons{display:flex;align-items:center;gap:4px}.page-indicator{font-size:13px;color:var(--text-secondary);margin:0 8px}.status-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}.status-badge.completed{background:rgba(34,197,94,.15);color:var(--accent-success)}.status-badge.running{background:rgba(34,211,238,.15);color:var(--accent-primary)}.status-badge.failed{background:var(--severity-critical-bg);color:var(--severity-critical)}.status-badge.queued{background:rgba(20,184,166,.15);color:var(--accent-secondary)}`],
})
export class ScansComponent implements OnInit {
  private http=inject(HttpClient);private notify=inject(NotificationService);
  scans=signal<any[]>([]);projects=signal<any[]>([]);showLaunch=false;launching=false;creating=false;
  launchForm={projectId:'',scanType:'full',target:'',branch:'',gitToken:'',swaggerSpec:''};
  newProjectName='';

  /** Filter & pagination state */
  scanTypeFilter = '';
  currentPage = signal(1);
  pageSize = signal(20);
  totalScans = signal(0);
  totalPages = signal(0);

  /** Computed pagination display values */
  paginationFrom = computed(() => this.totalScans() === 0 ? 0 : (this.currentPage() - 1) * this.pageSize() + 1);
  paginationTo = computed(() => Math.min(this.currentPage() * this.pageSize(), this.totalScans()));

  ngOnInit(){this.loadScans();this.loadProjects();}

  loadScans(){
    let params = new HttpParams()
      .set('page', String(this.currentPage()))
      .set('limit', String(this.pageSize()));
    if (this.scanTypeFilter) params = params.set('scanType', this.scanTypeFilter);
    this.http.get<{data:any[];pagination:ScanPagination}>(`${environment.apiUrl}/scans`, {params})
      .subscribe({next:(r)=>{
        this.scans.set(r.data||[]);
        if (r.pagination) {
          this.totalScans.set(r.pagination.total);
          this.totalPages.set(r.pagination.pages);
        }
      }});
  }

  onFilterChange(){
    this.currentPage.set(1);
    this.loadScans();
  }

  prevPage(){
    if (this.currentPage() > 1) {
      this.currentPage.set(this.currentPage() - 1);
      this.loadScans();
    }
  }

  nextPage(){
    if (this.currentPage() < this.totalPages()) {
      this.currentPage.set(this.currentPage() + 1);
      this.loadScans();
    }
  }

  loadProjects(){this.http.get<{data:any[]}>(`${environment.apiUrl}/projects?limit=100`).subscribe({next:(r)=>{const list=r.data||[];this.projects.set(list);if(list.length&&!this.launchForm.projectId)this.launchForm.projectId=list[0].id;}});}
  createProject(){const name=this.newProjectName.trim();if(!name)return;this.creating=true;
    this.http.post<any>(`${environment.apiUrl}/projects`,{name}).subscribe({next:()=>{this.creating=false;this.newProjectName='';this.notify.success('Project created');this.loadProjects();},error:(e)=>{this.creating=false;this.notify.error(e.error?.error||'Failed to create project');}});
  }
  launchScan(){
    if(!this.launchForm.projectId){this.notify.error('Select a project first');return;}
    if(!this.launchForm.target.trim()){this.notify.error('Enter a target');return;}
    const target=this.launchForm.target.trim();
    const isUrl=/^https?:\/\//i.test(target);
    const options:any={};
    if(['sast','sca','secret'].includes(this.launchForm.scanType)){
      // Repo-based scans (SAST/SCA/Secrets): a Git repo URL (cloned & scanned) or a local path under /scan.
      if(isUrl){options.repoUrl=target; if(this.launchForm.branch.trim())options.branch=this.launchForm.branch.trim(); if(this.launchForm.gitToken.trim())options.gitToken=this.launchForm.gitToken.trim();}
      else options.targetPath=target;
    } else if(this.launchForm.scanType==='api'){
      if(isUrl)options.targetUrl=target;else options.targetPath=target;
      if(this.launchForm.swaggerSpec.trim()){
        try{options.swaggerDoc=JSON.parse(this.launchForm.swaggerSpec.trim());}
        catch{this.notify.error('Invalid JSON in OpenAPI/Swagger spec');return;}
      }
    } else {
      if(isUrl)options.targetUrl=target;else options.targetPath=target;
    }
    const payload:any={projectId:this.launchForm.projectId,name:`${this.launchForm.scanType.toUpperCase()} Scan`,scanType:this.launchForm.scanType,options};
    this.launching=true;
    this.http.post(`${environment.apiUrl}/scans/launch`,payload).subscribe({next:()=>{this.launching=false;this.notify.success('Scan launched');this.showLaunch=false;this.launchForm.target='';this.loadScans();},error:(e)=>{this.launching=false;this.notify.error(e.error?.error||e.error?.message||'Failed');}});
  }
}
