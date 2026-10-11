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
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule, FormsModule, ReactiveFormsModule, RouterModule,
    MatCardModule, MatFormFieldModule, MatInputModule, MatButtonModule,
    MatIconModule, MatProgressSpinnerModule,
  ],
  template: `
    <div class="login-container">
      <div class="login-card">
        <div class="login-header">
          <mat-icon class="logo-icon">visibility</mat-icon>
          <h1 class="brand-wordmark"><span class="brand-deep">DEEP</span><span class="brand-vigilance">VIGILANCE</span></h1>
          <p>From code to container: Deep Vigilance</p>
        </div>

        <form [formGroup]="loginForm" (ngSubmit)="onSubmit()">
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Email</mat-label>
            <input matInput type="email" formControlName="email" placeholder="admin@example.com" autocomplete="email">
            <mat-icon matPrefix>email</mat-icon>
            <mat-error *ngIf="loginForm.get('email')?.hasError('required')">Email is required</mat-error>
            <mat-error *ngIf="loginForm.get('email')?.hasError('email')">Invalid email format</mat-error>
          </mat-form-field>

          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Password</mat-label>
            <input matInput [type]="hidePassword() ? 'password' : 'text'" formControlName="password" autocomplete="current-password">
            <mat-icon matPrefix>lock</mat-icon>
            <button mat-icon-button matSuffix type="button" (click)="hidePassword.set(!hidePassword())">
              <mat-icon>{{ hidePassword() ? 'visibility_off' : 'visibility' }}</mat-icon>
            </button>
            <mat-error *ngIf="loginForm.get('password')?.hasError('required')">Password is required</mat-error>
          </mat-form-field>

          <div class="error-message" *ngIf="errorMessage()">
            <mat-icon>error_outline</mat-icon>
            {{ errorMessage() }}
          </div>

          <button mat-flat-button color="primary" type="submit" class="full-width login-btn" [disabled]="loginForm.invalid || loading()">
            <mat-spinner diameter="20" *ngIf="loading()"></mat-spinner>
            <span *ngIf="!loading()">Sign In</span>
          </button>
        </form>

        <div class="login-footer">
          <span>Don't have an account?</span>
          <a routerLink="/register">Create an organization</a>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .login-container {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      background: linear-gradient(135deg, var(--bg-primary) 0%, #1e293b 100%);
      padding: 20px;
    }
    .login-card {
      width: 100%;
      max-width: 440px;
      background: var(--bg-card);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-xl);
      padding: 40px;
      box-shadow: var(--shadow-lg);
    }
    .login-header {
      text-align: center;
      margin-bottom: 32px;
    }
    .logo-icon {
      font-size: 52px;
      width: 52px;
      height: 52px;
      margin-bottom: 12px;
      background: var(--brand-gradient);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }
    .brand-wordmark {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: 1px;
      margin-bottom: 4px;
    }
    .brand-wordmark .brand-deep { color: var(--brand-teal); }
    .brand-wordmark .brand-vigilance { color: var(--brand-cyan); }
    .login-header p { color: var(--text-secondary); font-size: 13px; letter-spacing: 0.3px; }
    .full-width { width: 100%; margin-bottom: 16px; }
    .login-btn {
      width: 100%;
      height: 48px;
      font-size: 16px;
      font-weight: 600;
      margin-top: 8px;
    }
    .login-footer {
      text-align: center;
      margin-top: 24px;
      color: var(--text-secondary);
      font-size: 13px;
    }
    .login-footer a { margin-left: 4px; }
    .error-message {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--severity-critical-bg);
      color: var(--severity-critical);
      padding: 10px 16px;
      border-radius: var(--radius-md);
      margin-bottom: 16px;
      font-size: 13px;
    }
    mat-spinner { display: inline-block; margin: 0 auto; }
  `],
})
export class LoginComponent {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);

  hidePassword = signal(true);
  loading = signal(false);
  errorMessage = signal('');

  loginForm = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required],
  });

  onSubmit(): void {
    if (this.loginForm.invalid) return;

    this.loading.set(true);
    this.errorMessage.set('');

    const { email, password } = this.loginForm.value;
    this.authService.login(email!, password!).subscribe({
      error: (err) => {
        this.loading.set(false);
        this.errorMessage.set(err.error?.error || 'Login failed. Please check your credentials.');
      },
    });
  }
}
