import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [
    CommonModule, FormsModule, ReactiveFormsModule, RouterModule,
    MatCardModule, MatFormFieldModule, MatInputModule, MatButtonModule,
    MatIconModule, MatProgressSpinnerModule,
  ],
  template: `
    <div class="register-container">
      <div class="register-card">
        <div class="register-header">
          <mat-icon class="logo-icon">visibility</mat-icon>
          <h1>Create Organization</h1>
          <p>Set up your DeepVigilance instance</p>
        </div>
        <form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Full Name</mat-label>
            <input matInput formControlName="name" placeholder="John Doe">
            <mat-icon matPrefix>person</mat-icon>
          </mat-form-field>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Organization Name</mat-label>
            <input matInput formControlName="organizationName" placeholder="Acme Corp">
            <mat-icon matPrefix>business</mat-icon>
          </mat-form-field>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Email</mat-label>
            <input matInput type="email" formControlName="email" placeholder="admin@company.com">
            <mat-icon matPrefix>email</mat-icon>
          </mat-form-field>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Password</mat-label>
            <input matInput [type]="hidePassword() ? 'password' : 'text'" formControlName="password">
            <mat-icon matPrefix>lock</mat-icon>
            <button mat-icon-button matSuffix type="button" (click)="hidePassword.set(!hidePassword())">
              <mat-icon>{{ hidePassword() ? 'visibility_off' : 'visibility' }}</mat-icon>
            </button>
            <mat-hint>Minimum 12 characters with uppercase, lowercase, number, and special character</mat-hint>
          </mat-form-field>
          <div class="error-message" *ngIf="errorMessage()">
            <mat-icon>error_outline</mat-icon> {{ errorMessage() }}
          </div>
          <button mat-flat-button color="primary" type="submit" class="full-width register-btn" [disabled]="registerForm.invalid || loading()">
            <mat-spinner diameter="20" *ngIf="loading()"></mat-spinner>
            <span *ngIf="!loading()">Create Account</span>
          </button>
        </form>
        <div class="register-footer">
          <span>Already have an account?</span>
          <a routerLink="/login">Sign in</a>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .register-container { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: linear-gradient(135deg, var(--bg-primary) 0%, #1e293b 100%); padding: 20px; }
    .register-card { width: 100%; max-width: 480px; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-xl); padding: 40px; box-shadow: var(--shadow-lg); }
    .register-header { text-align: center; margin-bottom: 32px; }
    .logo-icon { font-size: 52px; width: 52px; height: 52px; background: var(--brand-gradient); -webkit-background-clip: text; background-clip: text; color: transparent; margin-bottom: 12px; }
    .register-header h1 { font-size: 24px; margin-bottom: 4px; }
    .register-header p { color: var(--text-secondary); font-size: 14px; }
    .full-width { width: 100%; margin-bottom: 16px; }
    .register-btn { width: 100%; height: 48px; font-size: 16px; font-weight: 600; margin-top: 8px; }
    .register-footer { text-align: center; margin-top: 24px; color: var(--text-secondary); font-size: 13px; }
    .error-message { display: flex; align-items: center; gap: 8px; background: var(--severity-critical-bg); color: var(--severity-critical); padding: 10px 16px; border-radius: var(--radius-md); margin-bottom: 16px; font-size: 13px; }
    mat-spinner { display: inline-block; margin: 0 auto; }
  `],
})
export class RegisterComponent {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  hidePassword = signal(true);
  loading = signal(false);
  errorMessage = signal('');

  registerForm = this.fb.group({
    name: ['', Validators.required],
    organizationName: [''],
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(12), Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$/)]],
  });

  onSubmit(): void {
    if (this.registerForm.invalid) return;
    this.loading.set(true);
    this.errorMessage.set('');
    this.authService.register(this.registerForm.value as any).subscribe({
      error: (err) => {
        this.loading.set(false);
        this.errorMessage.set(err.error?.error || 'Registration failed.');
      },
    });
  }
}
