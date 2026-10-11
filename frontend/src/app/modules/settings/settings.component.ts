import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTabsModule } from '@angular/material/tabs';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { AuthService } from '../../core/services/auth.service';
import { NotificationService } from '../../core/services/notification.service';
import { ThemeService } from '../../core/services/theme.service';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';

@Component({selector:'app-settings',standalone:true,imports:[CommonModule,FormsModule,MatButtonModule,MatIconModule,MatTabsModule,MatFormFieldModule,MatInputModule,MatSelectModule],
  template:`<div class="page-container fade-in"><div class="page-header"><h1>Settings</h1></div>
  <mat-tab-group>
    <mat-tab label="Profile"><div class="tab"><h3>User Profile</h3>
      <p><strong>Name:</strong> {{auth.user()?.name}}</p><p><strong>Email:</strong> {{auth.user()?.email}}</p><p><strong>Role:</strong> {{auth.user()?.role}}</p><p><strong>Organization:</strong> {{auth.user()?.orgName}}</p>
      <h3 style="margin-top:20px">Change Password</h3>
      <mat-form-field appearance="outline" style="width:100%;margin-bottom:12px"><mat-label>Current Password</mat-label><input matInput type="password" [(ngModel)]="pw.current"></mat-form-field>
      <mat-form-field appearance="outline" style="width:100%;margin-bottom:12px"><mat-label>New Password</mat-label><input matInput type="password" [(ngModel)]="pw.new"></mat-form-field>
      <button mat-flat-button color="primary" (click)="changePassword()">Change Password</button>
    </div></mat-tab>
    <mat-tab label="Appearance"><div class="tab"><h3>Theme</h3>
      <mat-form-field appearance="outline"><mat-label>Theme</mat-label><mat-select [ngModel]="theme.theme()" (ngModelChange)="theme.setTheme($event)"><mat-option value="dark">Dark</mat-option><mat-option value="light">Light</mat-option></mat-select></mat-form-field>
    </div></mat-tab>
    <mat-tab label="API Keys"><div class="tab"><h3>API Keys</h3><p style="color:var(--text-secondary)">Manage API keys for service accounts and automation.</p></div></mat-tab>
  </mat-tab-group></div>`,
  styles:[`.tab{padding:24px;max-width:600px}`],
})
export class SettingsComponent {
  auth=inject(AuthService);private http=inject(HttpClient);private notify=inject(NotificationService);theme=inject(ThemeService);
  pw={current:'',new:''};
  changePassword(){if(!this.pw.current||!this.pw.new)return;this.http.put(`${environment.apiUrl}/auth/change-password`,{currentPassword:this.pw.current,newPassword:this.pw.new}).subscribe({next:()=>{this.notify.success('Password changed');this.pw={current:'',new:''};},error:(e)=>this.notify.error(e.error?.error||'Failed')});}
}
