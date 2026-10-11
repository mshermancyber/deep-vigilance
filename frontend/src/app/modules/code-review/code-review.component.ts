import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormsModule, ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { MatTabsModule } from '@angular/material/tabs';
import { MatChipsModule } from '@angular/material/chips';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatMenuModule } from '@angular/material/menu';
import { MatExpansionModule } from '@angular/material/expansion';
import { environment } from '../../../environments/environment';
import { NotificationService } from '../../core/services/notification.service';

@Component({selector:'app-code-review',standalone:true,imports:[CommonModule,FormsModule,ReactiveFormsModule,MatButtonModule,MatIconModule,MatCardModule,MatFormFieldModule,MatSelectModule,MatInputModule,MatTabsModule,MatChipsModule,MatProgressBarModule,MatSlideToggleModule,MatTooltipModule,MatMenuModule,MatExpansionModule],
  template:`<div class="cr-container"><div class="cr-header"><div class="cr-title"><mat-icon class="cr-logo">code_review</mat-icon><div><h1>Code Review & Fuzz</h1><span class="cr-sub">Regex Semantic Analysis &middot; Dependency SCA &middot; Repo Health</span></div></div><div class="cr-actions"><button mat-stroked-button (click)="tab.set('launch')"><mat-icon>add</mat-icon>New Review</button><button mat-flat-button color="primary" (click)="tab.set('reviews');loadReviews()"><mat-icon>list</mat-icon>Reviews</button></div></div>
  <div class="cr-tabs"><button [class.active]="tab()==='reviews'" (click)="tab.set('reviews');loadReviews()"><mat-icon>reviews</mat-icon>Reviews</button><button [class.active]="tab()==='findings'" (click)="tab.set('findings');loadFindings()"><mat-icon>bug_report</mat-icon>Findings</button><button [class.active]="tab()==='deps'" (click)="tab.set('deps');loadDepScans()"><mat-icon>inventory_2</mat-icon>Dependencies</button><button [class.active]="tab()==='health'" (click)="tab.set('health');loadHealth()"><mat-icon>monitoring</mat-icon>Health</button><button [class.active]="tab()==='launch'" (click)="tab.set('launch')"><mat-icon>rocket_launch</mat-icon>Launch</button></div>

  @if(tab()==='reviews'){<div class="tab-content"><div class="filter-bar"><mat-form-field appearance="outline" class="f"><mat-label>Type</mat-label><mat-select [(ngModel)]="reviewTypeFilter" (selectionChange)="loadReviews()"><mat-option value="">All</mat-option><mat-option value="full">Full</mat-option><mat-option value="semantic">Semantic</mat-option><mat-option value="security">Security</mat-option><mat-option value="dependency">Dependency</mat-option><mat-option value="health">Health</mat-option></mat-select></mat-form-field></div>
  @if(reviews().length){<table class="data-table"><thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Critical</th><th>High</th><th>Medium</th><th>Files</th><th>Date</th></tr></thead><tbody>
    @for(r of reviews();track r.id){<tr [class.failed]="r.status==='failed'"><td class="link" (click)="viewReview(r.id)">{{r.name}}</td><td><span class="severity-badge info">{{r.review_type}}</span></td><td><span class="status-badge" [class]="r.status">{{r.status}}</span></td><td><span class="severity-badge critical">{{r.critical_count||0}}</span></td><td><span class="severity-badge high">{{r.high_count||0}}</span></td><td><span class="severity-badge medium">{{r.medium_count||0}}</span></td><td>{{r.files_scanned||0}}</td><td>{{r.created_at|date:'short'}}</td></tr>}
  </tbody></table>}@else{<div class="empty-state"><mat-icon>code</mat-icon><h3>No reviews</h3><p>Launch a code review to analyze your repositories.</p></div>}</div>}

  @if(tab()==='findings'){<div class="tab-content"><div class="findings-layout"><div class="findings-list"><div class="filter-bar"><mat-form-field appearance="outline" class="f"><mat-label>Severity</mat-label><mat-select [(ngModel)]="findingSevFilter" (selectionChange)="loadFindings()"><mat-option value="">All</mat-option><mat-option value="critical">Critical</mat-option><mat-option value="high">High</mat-option><mat-option value="medium">Medium</mat-option></mat-select></mat-form-field><mat-form-field appearance="outline" class="f"><mat-label>Type</mat-label><mat-select [(ngModel)]="findingTypeFilter" (selectionChange)="loadFindings()"><mat-option value="">All</mat-option><mat-option value="security">Security</mat-option><mat-option value="semantic">Semantic</mat-option><mat-option value="logic">Logic</mat-option><mat-option value="quality">Quality</mat-option><mat-option value="architecture">Architecture</mat-option><mat-option value="dependency">Dependency</mat-option></mat-select></mat-form-field></div>
  @for(f of findings();track f.id){<div class="finding-card" [class.selected]="selected()?.id===f.id" (click)="selected.set(f)"><div class="f-header"><span class="severity-badge" [class]="f.severity">{{f.severity}}</span><span class="f-type">{{f.finding_type}}</span><span class="f-conf" [style.color]="f.confidence_score>0.7?'var(--accent-success)':'var(--accent-warning)'">{{((f.confidence_score||0)*100)|number:'1.0-0'}}%</span></div><div class="f-title">{{f.title}}</div><div class="f-loc"><mat-icon>insert_drive_file</mat-icon>{{shortPath(f.file_path)}}:{{f.line_number||'?'}}</div></div>}</div>
  <div class="finding-detail">@if(selected();as f){<div class="detail-header"><h3>{{f.title}}</h3><div class="detail-meta"><span class="severity-badge" [class]="f.severity">{{f.severity}}</span><span class="f-type">{{f.finding_type}}</span><span>{{f.rule_id}}</span>@if(f.cwe_id){<span>{{f.cwe_id}}</span>}@if(f.cvss_score){<span>CVSS {{f.cvss_score}}</span>}</div></div><mat-tab-group><mat-tab label="Overview"><div class="detail-section"><p><strong>Description:</strong> {{f.description}}</p><p><strong>Root Cause:</strong> {{f.root_cause||'N/A'}}</p><p><strong>Security Impact:</strong> {{f.security_impact||'N/A'}}</p><p><strong>Recommendation:</strong> {{f.recommendation||'N/A'}}</p></div></mat-tab><mat-tab label="Code"><div class="detail-section"><pre class="code-block"><code>{{f.code_snippet||'No snippet'}}</code></pre>@if(f.context_snippet){<h4>Context</h4><pre class="code-block"><code>{{f.context_snippet}}</code></pre>}</div></mat-tab><mat-tab label="Secure Fix"><div class="detail-section">@if(f.secure_code_example){<h4>Secure Alternative</h4><pre class="code-block secure"><code>{{f.secure_code_example}}</code></pre>}@if(f.ai_summary){<div class="ai-card"><mat-icon>psychology</mat-icon><p>{{f.ai_summary}}</p></div>}</div></mat-tab></mat-tab-group>}@else{<div class="empty-state"><mat-icon>touch_app</mat-icon><h3>Select a finding</h3></div>}</div></div></div>}

  @if(tab()==='deps'){<div class="tab-content">
  @if(depScans().length){<table class="data-table"><thead><tr><th></th><th>Ecosystem</th><th>Total Pkgs</th><th>Vulnerable</th><th>Deprecated</th><th>Supply Chain</th><th>License Issues</th><th>Date</th></tr></thead><tbody>
    @for(d of depScans();track d.id){<tr class="scan-row" style="cursor:pointer" (click)="toggleDepScan(d.id)" [class.expanded]="expandedDepId()===d.id"><td><mat-icon style="font-size:18px">{{expandedDepId()===d.id?'expand_less':'expand_more'}}</mat-icon></td><td><span class="severity-badge info">{{d.ecosystem}}</span></td><td>{{d.total_packages}}</td><td><span class="severity-badge" [class]="d.vulnerable_packages>0?'critical':'low'">{{d.vulnerable_packages}}</span></td><td>{{d.deprecated_packages}}</td><td><span class="severity-badge" [class]="d.supply_chain_risks>0?'high':'low'">{{d.supply_chain_risks}}</span></td><td>{{d.license_issues}}</td><td>{{d.created_at|date:'short'}}</td></tr>
    @if(expandedDepId()===d.id){<tr><td colspan="8" style="padding:0"><div style="padding:12px 16px;background:var(--bg-input)">
      @if(depFindingsLoading()){<div style="padding:20px;text-align:center;color:var(--text-secondary)">Loading findings...</div>}
      @else if(depFindings().length){<table class="data-table" style="margin:0"><thead><tr><th>Package</th><th>Version</th><th>Type</th><th>Severity</th><th>CVSS</th><th>CVE</th><th>Title</th><th>Fixed In</th><th>Recommendation</th></tr></thead><tbody>
        @for(f of depFindings();track f.id){<tr><td><strong>{{f.package_name}}</strong></td><td><code>{{f.package_version}}</code></td><td>{{f.vulnerability_type}}</td><td><span class="severity-badge" [class]="(f.severity||'').toLowerCase()">{{f.severity}}</span></td><td>{{f.cvss_score||'-'}}</td><td>@if(f.cve_id){<a [href]="'https://nvd.nist.gov/vuln/detail/'+f.cve_id" target="_blank" rel="noopener"><code>{{f.cve_id}}</code></a>}@else{<span>-</span>}</td><td>{{f.title}}</td><td>{{f.fixed_in_version||'-'}}</td><td style="max-width:300px;font-size:12px">{{f.recommendation||'-'}}</td></tr>}
      </tbody></table>}
      @else{<div style="padding:20px;text-align:center;color:var(--text-secondary)">No vulnerability findings for this ecosystem scan.</div>}
    </div></td></tr>}}
  </tbody></table>}@else{<div class="empty-state"><mat-icon>inventory_2</mat-icon><h3>No dependency scans</h3><p>Run a full or dependency code review to generate dependency analysis.</p></div>}</div>}

  @if(tab()==='health'){<div class="tab-content">
  @if(healthData()){<div class="health-grid">
    <mat-card class="metric-card"><mat-card-header><mat-card-title>Maintainability</mat-card-title></mat-card-header><mat-card-content><div class="metric-value" [class]="healthData().maintainability_index>70?'good':healthData().maintainability_index>40?'warn':'bad'">{{healthData().maintainability_index|number:'1.0-0'}}</div><span class="metric-label">Maintainability Index</span></mat-card-content></mat-card>
    <mat-card class="metric-card"><mat-card-header><mat-card-title>Complexity</mat-card-title></mat-card-header><mat-card-content><div class="metric-value">{{healthData().cyclomatic_complexity_avg|number:'1.1-1'}}</div><span class="metric-label">Avg Cyclomatic / Max: {{healthData().cyclomatic_complexity_max}}</span></mat-card-content></mat-card>
    <mat-card class="metric-card"><mat-card-header><mat-card-title>Tech Debt</mat-card-title></mat-card-header><mat-card-content><div class="metric-value warn">{{healthData().technical_debt_ratio|number:'1.1-1'}}%</div><span class="metric-label">Debt Ratio ({{healthData().technical_debt_minutes}} min)</span></mat-card-content></mat-card>
    <mat-card class="metric-card"><mat-card-header><mat-card-title>Duplication</mat-card-title></mat-card-header><mat-card-content><div class="metric-value" [class]="healthData().duplication_pct>10?'bad':'good'">{{healthData().duplication_pct|number:'1.1-1'}}%</div><span class="metric-label">{{healthData().duplicated_blocks}} blocks / {{healthData().duplicated_lines}} lines</span></mat-card-content></mat-card>
    <mat-card class="metric-card"><mat-card-header><mat-card-title>Code Smells</mat-card-title></mat-card-header><mat-card-content><div class="metric-value">{{healthData().complex_methods_count}}</div><span class="metric-label">Complex methods · {{healthData().large_classes_count}} large classes · {{healthData().long_methods_count}} long methods</span></mat-card-content></mat-card>
    <mat-card class="metric-card"><mat-card-header><mat-card-title>Risk Score</mat-card-title></mat-card-header><mat-card-content><div class="metric-value" [class]="healthData().risk_score>70?'bad':healthData().risk_score>40?'warn':'good'">{{healthData().risk_score|number:'1.0-0'}}</div><span class="metric-label">Overall Risk Score</span></mat-card-content></mat-card>
  </div>}@else{<div class="empty-state"><mat-icon>monitoring</mat-icon><h3>No health data</h3><p>Run a full or health code review, then select a review to see metrics.</p></div>}</div>}

  @if(tab()==='launch'){<div class="tab-content"><mat-card class="launch-card"><mat-card-header><mat-card-title>Launch Code Review</mat-card-title></mat-card-header><mat-card-content><form [formGroup]="launchForm" (ngSubmit)="launchReview()"><div class="launch-grid"><mat-form-field appearance="outline"><mat-label>Name</mat-label><input matInput formControlName="name" placeholder="My Review"></mat-form-field>
    <mat-form-field appearance="outline"><mat-label>Review Type</mat-label><mat-select formControlName="reviewType"><mat-option value="full">Full</mat-option><mat-option value="semantic">Semantic</mat-option><mat-option value="security">Security</mat-option><mat-option value="dependency">Dependency</mat-option><mat-option value="health">Health</mat-option></mat-select></mat-form-field>
    <mat-form-field appearance="outline"><mat-label>Target Type</mat-label><mat-select formControlName="targetType" (selectionChange)="onTargetTypeChange()"><mat-option value="repository">Git Repository</mat-option><mat-option value="folder">Local Folder (/scan mount)</mat-option></mat-select></mat-form-field>
    @if(launchForm.get('targetType')?.value==='repository'){<mat-form-field appearance="outline" class="full-width"><mat-label>Repository URL</mat-label><input matInput formControlName="repoUrl" placeholder="https://github.com/org/repo"></mat-form-field>}
    @if(launchForm.get('targetType')?.value==='folder'){<mat-form-field appearance="outline" class="full-width"><mat-label>Path (inside /scan)</mat-label><input matInput formControlName="targetPath" placeholder="my-project"></mat-form-field>}
    </div><button mat-flat-button color="primary" type="submit" [disabled]="launchForm.invalid||launching()"><mat-icon>rocket_launch</mat-icon>{{launching()?'Launching...':'Launch Review'}}</button></form></mat-card-content></mat-card></div>}</div>`,
  styles:[`.cr-container{height:calc(100vh - 56px);display:flex;flex-direction:column;background:var(--bg-primary)}.cr-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px 0}.cr-logo{font-size:36px;width:36px;height:36px;color:var(--accent-primary)}.cr-sub{font-size:13px;color:var(--text-secondary)}.cr-tabs{display:flex;gap:4px;padding:16px 24px;border-bottom:1px solid var(--border-primary)}.cr-tabs button{display:flex;align-items:center;gap:6px;padding:8px 16px;border:none;background:0 0;color:var(--text-secondary);cursor:pointer;border-radius:var(--radius-md);font-size:13px;font-weight:500}.cr-tabs button.active,.cr-tabs button:hover{background:rgba(59,130,246,.15);color:var(--accent-primary)}.tab-content{flex:1;overflow:auto;padding:20px 24px}.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}.f{width:180px}.link{color:var(--accent-primary);cursor:pointer;font-weight:500}.link:hover{text-decoration:underline}.status-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}.status-badge.completed{background:rgba(34,197,94,.15);color:var(--accent-success)}.status-badge.running,.status-badge.analyzing,.status-badge.queued{background:rgba(59,130,246,.15);color:var(--accent-primary)}.status-badge.failed{background:var(--severity-critical-bg);color:var(--severity-critical)}.findings-layout{display:grid;grid-template-columns:400px 1fr;gap:20px;height:100%}.findings-list{overflow:auto}.finding-card{background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-md);padding:12px;margin-bottom:8px;cursor:pointer}.finding-card:hover,.finding-card.selected{border-color:var(--accent-primary)}.finding-card.selected{background:rgba(59,130,246,.08)}.f-header{display:flex;align-items:center;gap:8px;margin-bottom:6px}.f-type{font-size:11px;color:var(--text-secondary);text-transform:uppercase}.f-conf{font-size:11px;margin-left:auto}.f-title{font-size:13px;font-weight:500;margin-bottom:4px}.f-loc{font-size:12px;color:var(--text-secondary);display:flex;align-items:center;gap:4px}.f-loc mat-icon{font-size:14px;width:14px;height:14px}.finding-detail{overflow:auto;background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-lg)}.detail-header{padding:16px 20px 0}.detail-meta{display:flex;gap:8px;align-items:center;margin-top:8px;font-size:12px;color:var(--text-secondary)}.detail-section{padding:16px 20px}.detail-section p{margin-bottom:8px;font-size:13px;line-height:1.6}.detail-section h4{margin:12px 0 6px;font-size:13px}.code-block{background:var(--bg-input);border:1px solid var(--border-primary);border-radius:var(--radius-md);padding:12px;font-family:var(--font-mono);font-size:12px;overflow:auto;white-space:pre-wrap}.code-block.secure{border-left:3px solid var(--accent-success)}.ai-card{display:flex;gap:12px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.3);border-radius:var(--radius-md);padding:16px;margin-top:16px}.launch-card{background:var(--bg-card);border:1px solid var(--border-primary);max-width:700px}.launch-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.full-width{grid-column:1/-1}.cr-actions{display:flex;gap:8px}.cr-title{display:flex;align-items:center;gap:12px}.health-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}.metric-card{background:var(--bg-card);border:1px solid var(--border-primary)}.metric-value{font-size:36px;font-weight:700;color:var(--accent-primary)}.metric-value.good{color:var(--accent-success)}.metric-value.warn{color:var(--accent-warning)}.metric-value.bad{color:var(--severity-critical)}.metric-label{font-size:12px;color:var(--text-secondary);margin-top:4px}tr.failed{opacity:.6}@media(max-width:1024px){.findings-layout{grid-template-columns:1fr}.launch-grid{grid-template-columns:1fr}.health-grid{grid-template-columns:1fr}}`],
})
export class CodeReviewComponent implements OnInit {
  private http=inject(HttpClient);private fb=inject(FormBuilder);private notify=inject(NotificationService);
  tab=signal('reviews');reviews=signal<any[]>([]);findings=signal<any[]>([]);depScans=signal<any[]>([]);depFindings=signal<any[]>([]);expandedDepId=signal<string|null>(null);depFindingsLoading=signal(false);healthData=signal<any>(null);selected=signal<any>(null);launching=signal(false);
  reviewTypeFilter='';findingSevFilter='';findingTypeFilter='';

  launchForm=this.fb.group({
    name:['',Validators.required],
    reviewType:['full',Validators.required],
    targetType:['repository',Validators.required],
    repoUrl:[''],
    targetPath:[''],
  });

  ngOnInit(){this.loadReviews();}

  loadReviews(){
    let u=`${environment.apiUrl}/code-review/reviews?limit=50`;
    if(this.reviewTypeFilter)u+=`&reviewType=${this.reviewTypeFilter}`;
    this.http.get<{data:any[]}>(u).subscribe({next:(r)=>this.reviews.set(r.data||[])});
  }
  loadFindings(){
    let u=`${environment.apiUrl}/code-review/findings?limit=100`;
    if(this.findingSevFilter)u+=`&severity=${this.findingSevFilter}`;
    if(this.findingTypeFilter)u+=`&findingType=${this.findingTypeFilter}`;
    this.http.get<{data:any[]}>(u).subscribe({next:(r)=>this.findings.set(r.data||[])});
  }
  loadDepScans(){
    this.http.get<{data:any[]}>(`${environment.apiUrl}/code-review/dependency-scans?limit=50`).subscribe({
      next:(r)=>this.depScans.set(r.data||[]),
      error:()=>this.depScans.set([]),
    });
  }
  toggleDepScan(scanId:string){
    if(this.expandedDepId()===scanId){this.expandedDepId.set(null);this.depFindings.set([]);return;}
    this.expandedDepId.set(scanId);this.depFindingsLoading.set(true);this.depFindings.set([]);
    this.http.get<{data:any[]}>(`${environment.apiUrl}/code-review/dependency-scans/${scanId}/findings`).subscribe({
      next:(r)=>{this.depFindings.set(r.data||[]);this.depFindingsLoading.set(false);},
      error:()=>{this.depFindings.set([]);this.depFindingsLoading.set(false);},
    });
  }
  loadHealth(){
    const revs=this.reviews();
    const latest=revs.find(r=>r.status==='completed');
    if(latest){
      this.http.get<any>(`${environment.apiUrl}/code-review/repo-health/${latest.id}`).subscribe({
        next:(r)=>this.healthData.set(r),
        error:()=>this.healthData.set(null),
      });
    }
  }
  viewReview(id:string){
    this.findingSevFilter='';this.findingTypeFilter='';
    this.tab.set('findings');
    let u=`${environment.apiUrl}/code-review/findings?limit=100&reviewId=${id}`;
    this.http.get<{data:any[]}>(u).subscribe({next:(r)=>this.findings.set(r.data||[])});
  }
  onTargetTypeChange(){
    if(this.launchForm.get('targetType')?.value==='repository'){
      this.launchForm.patchValue({targetPath:''});
    } else {
      this.launchForm.patchValue({repoUrl:''});
    }
  }
  launchReview(){
    if(this.launchForm.invalid)return;
    this.launching.set(true);
    const v=this.launchForm.value;
    const body:any={name:v.name,reviewType:v.reviewType,targetType:v.targetType};
    if(v.targetType==='repository'&&v.repoUrl){
      body.repoUrl=v.repoUrl;
    } else if(v.targetPath){
      body.targetPath=v.targetPath;
    }
    this.http.post(`${environment.apiUrl}/code-review/reviews/launch`,body).subscribe({
      next:()=>{this.launching.set(false);this.notify.success('Review launched');this.tab.set('reviews');setTimeout(()=>this.loadReviews(),1500);},
      error:(e)=>{this.launching.set(false);this.notify.error(e?.error?.error||'Launch failed');},
    });
  }
  shortPath(p:string):string{
    if(!p)return'N/A';
    const parts=p.split('/');
    return parts.length>3?'.../' + parts.slice(-3).join('/'):p;
  }
}
