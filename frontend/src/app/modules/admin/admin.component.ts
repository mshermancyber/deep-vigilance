import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { MatTabsModule } from '@angular/material/tabs';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { environment } from '../../../environments/environment';

@Component({selector:'app-admin',standalone:true,imports:[CommonModule,MatTabsModule,MatButtonModule,MatIconModule],
  template:`<div class="page-container fade-in"><div class="page-header"><h1>Administration</h1></div>
  <mat-tab-group>
    <mat-tab label="Users"><div class="tab">
      @if(users().length){<table class="data-table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th></tr></thead><tbody>
        @for(u of users();track u.id){<tr><td>{{u.name}}</td><td>{{u.email}}</td><td><span class="severity-badge info">{{u.role}}</span></td><td>{{u.disabled?'Disabled':'Active'}}</td><td>{{u.last_login|date:'short'}}</td></tr>}
      </tbody></table>}@else{<div class="spinner"></div>}
    </div></mat-tab>
    <mat-tab label="Audit Log"><div class="tab">
      @if(audit().length){<table class="data-table"><thead><tr><th>User</th><th>Action</th><th>Resource</th><th>IP</th><th>Date</th></tr></thead><tbody>
        @for(a of audit();track a.id){<tr><td>{{a.user_name||'System'}}</td><td>{{a.action}}</td><td>{{a.resource}}</td><td>{{a.ip_address}}</td><td>{{a.created_at|date:'short'}}</td></tr>}
      </tbody></table>}@else{<div class="spinner"></div>}
    </div></mat-tab>
    <mat-tab label="System Health"><div class="tab">
      @if(health();as h){<div class="grid-3"><div class="stat-card"><div class="stat-value">{{h.uptime|number:'1.0-0'||'N/A'}}</div><div class="stat-label">Uptime (s)</div></div>
      <div class="stat-card"><div class="stat-value">{{h.database?.sizeMb||'N/A'}}</div><div class="stat-label">DB Size (MB)</div></div>
      <div class="stat-card"><div class="stat-value">{{h.users?.total||'N/A'}}</div><div class="stat-label">Total Users</div></div></div>}@else{<div class="spinner"></div>}
    </div></mat-tab>
  </mat-tab-group></div>`,
  styles:[`.tab{padding:20px}`],
})
export class AdminComponent implements OnInit {
  private http=inject(HttpClient);
  users=signal<any[]>([]);audit=signal<any[]>([]);health=signal<any>(null);
  ngOnInit(){
    this.http.get<{data:any[]}>(`${environment.apiUrl}/users`).subscribe({next:(r)=>this.users.set(r.data||[])});
    this.http.get<{data:any[]}>(`${environment.apiUrl}/admin/audit-log`).subscribe({next:(r)=>this.audit.set(r.data||[])});
    this.http.get<any>(`${environment.apiUrl}/admin/system-health`).subscribe({next:(d)=>this.health.set(d)});
  }
}
