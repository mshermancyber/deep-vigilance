import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { NotificationService } from '../../core/services/notification.service';
import { environment } from '../../../environments/environment';

@Component({selector:'app-scheduler',standalone:true,imports:[CommonModule,FormsModule,MatButtonModule,MatIconModule,MatFormFieldModule,MatSelectModule,MatInputModule,MatSlideToggleModule],
  template:`<div class="page-container fade-in"><div class="page-header"><h1>Scan Scheduler</h1><button mat-flat-button color="primary" (click)="showForm=true"><mat-icon>add</mat-icon>New Schedule</button></div>
  @if(showForm){<div class="launch-panel"><mat-form-field appearance="outline"><mat-label>Name</mat-label><input matInput [(ngModel)]="form.name"></mat-form-field>
    <mat-form-field appearance="outline"><mat-label>Schedule</mat-label><mat-select [(ngModel)]="form.schedule"><mat-option value="hourly">Hourly</mat-option><mat-option value="daily">Daily</mat-option><mat-option value="weekly">Weekly</mat-option><mat-option value="monthly">Monthly</mat-option><mat-option value="cron">Cron</mat-option></mat-select></mat-form-field>
    <mat-form-field appearance="outline"><mat-label>Scan Type</mat-label><mat-select [(ngModel)]="form.scanType"><mat-option value="sast">SAST</mat-option><mat-option value="sca">SCA</mat-option><mat-option value="secret">Secrets</mat-option><mat-option value="dast">DAST</mat-option><mat-option value="api">API</mat-option><mat-option value="full">Full</mat-option></mat-select></mat-form-field>
    <button mat-flat-button color="primary" (click)="create()">Create</button><button mat-button (click)="showForm=false">Cancel</button></div>}
  @if(schedules().length){<table class="data-table"><thead><tr><th>Name</th><th>Project</th><th>Type</th><th>Schedule</th><th>Enabled</th><th>Last Run</th></tr></thead><tbody>
    @for(s of schedules();track s.id){<tr><td>{{s.name}}</td><td>{{s.project_name}}</td><td>{{s.scan_type}}</td><td>{{s.schedule}}{{s.cron_expression?' ('+s.cron_expression+')':''}}</td><td><mat-slide-toggle [checked]="s.enabled" (change)="toggle(s.id,$event.checked)"></mat-slide-toggle></td><td>{{s.last_run|date:'short'}}</td></tr>}
  </tbody></table>}@else{<div class="empty-state"><mat-icon>schedule</mat-icon><h3>No scheduled scans</h3><p>Create recurring scans to automate security testing.</p></div>}</div>`,
  styles:[`.launch-panel{display:flex;gap:12px;align-items:center;margin-bottom:20px;padding:16px;background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-lg);flex-wrap:wrap}`],
})
export class SchedulerComponent implements OnInit {
  private http=inject(HttpClient);private notify=inject(NotificationService);
  schedules=signal<any[]>([]);showForm=false;form={name:'',schedule:'daily',scanType:'full'};
  ngOnInit(){this.load();}
  load(){this.http.get<{data:any[]}>(`${environment.apiUrl}/scheduler`).subscribe({next:(r)=>this.schedules.set(r.data||[])});}
  create(){this.http.post(`${environment.apiUrl}/scheduler`,this.form).subscribe({next:()=>{this.notify.success('Schedule created');this.showForm=false;this.load();},error:(e)=>this.notify.error(e.error?.error||'Failed')});}
  toggle(id:string,enabled:boolean){this.http.patch(`${environment.apiUrl}/scheduler/${id}`,{enabled}).subscribe({next:()=>this.load()});}
}
