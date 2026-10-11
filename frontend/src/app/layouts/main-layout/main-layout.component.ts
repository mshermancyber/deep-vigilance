import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, RouterOutlet } from '@angular/router';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatMenuModule } from '@angular/material/menu';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';
import { AuthService } from '../../core/services/auth.service';
import { ThemeService } from '../../core/services/theme.service';
import { DeviceService } from '../../core/services/device.service';

interface NavItem {
  label: string;
  icon: string;
  route: string;
  permission?: string;
}

@Component({
  selector: 'app-main-layout',
  standalone: true,
  imports: [
    CommonModule, RouterOutlet, RouterModule,
    MatSidenavModule, MatToolbarModule, MatIconModule,
    MatButtonModule, MatMenuModule, MatDividerModule, MatTooltipModule,
  ],
  template: `
    <mat-sidenav-container class="layout-container">
      <mat-sidenav #snav [mode]="device.isMobile() ? 'over' : 'side'" [opened]="!device.isMobile()" class="sidebar">
        <div class="sidebar-header">
          <mat-icon class="sidebar-logo">visibility</mat-icon>
          <span class="sidebar-title"><span class="brand-deep">DEEP</span><span class="brand-vigilance">VIGILANCE</span></span>
        </div>

        <mat-divider></mat-divider>

        <nav class="sidebar-nav">
          @for (item of mainNav; track item.route) {
            <a [routerLink]="['/' + item.route]"
               routerLinkActive="active"
               class="nav-item"
               (click)="onNav(snav)"
               [matTooltip]="collapsed() ? item.label : ''"
               matTooltipPosition="right">
              <mat-icon>{{ item.icon }}</mat-icon>
              <span class="nav-label">{{ item.label }}</span>
            </a>
          }

          <mat-divider class="nav-divider"></mat-divider>

          @for (item of secondaryNav; track item.route) {
            <a [routerLink]="['/' + item.route]"
               routerLinkActive="active"
               class="nav-item"
               (click)="onNav(snav)">
              <mat-icon>{{ item.icon }}</mat-icon>
              <span class="nav-label">{{ item.label }}</span>
            </a>
          }
        </nav>
      </mat-sidenav>

      <mat-sidenav-content class="main-content">
        <header class="top-header">
          <div class="header-left">
            @if (device.isMobile()) {
              <button mat-icon-button class="menu-btn" (click)="snav.toggle()" aria-label="Menu"><mat-icon>menu</mat-icon></button>
            }
            <h2 class="page-title">{{ currentTitle() }}</h2>
          </div>
          <div class="header-right">
            <button mat-icon-button [matTooltip]="themeService.theme() === 'dark' ? 'Light mode' : 'Dark mode'"
                    (click)="themeService.toggleTheme()">
              <mat-icon>{{ themeService.theme() === 'dark' ? 'light_mode' : 'dark_mode' }}</mat-icon>
            </button>

            <button mat-icon-button matTooltip="Notifications">
              <mat-icon>notifications</mat-icon>
            </button>

            <button mat-icon-button [matMenuTriggerFor]="userMenu">
              <mat-icon>account_circle</mat-icon>
            </button>

            <mat-menu #userMenu="matMenu">
              <div class="user-menu-header">
                <strong>{{ authService.user()?.name }}</strong>
                <small>{{ authService.user()?.email }}</small>
              </div>
              <button mat-menu-item routerLink="/settings">
                <mat-icon>settings</mat-icon>Settings
              </button>
              <button mat-menu-item routerLink="/admin">
                <mat-icon>admin_panel_settings</mat-icon>Administration
              </button>
              <mat-divider></mat-divider>
              <button mat-menu-item (click)="authService.logout()">
                <mat-icon>logout</mat-icon>Sign Out
              </button>
            </mat-menu>
          </div>
        </header>

        <main class="page-content">
          <router-outlet />
        </main>
      </mat-sidenav-content>
    </mat-sidenav-container>
  `,
  styles: [`
    .layout-container { height: 100vh; }
    .sidebar {
      width: var(--sidebar-width);
      background: var(--bg-sidebar);
      border-right: 1px solid var(--border-primary);
    }
    .sidebar-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      height: var(--header-height);
    }
    .sidebar-logo { font-size: 28px; width: 28px; height: 28px; background: var(--brand-gradient); -webkit-background-clip: text; background-clip: text; color: transparent; }
    .sidebar-title { font-size: 18px; font-weight: 800; letter-spacing: 0.5px; }
    .sidebar-title .brand-deep { color: var(--brand-teal); }
    .sidebar-title .brand-vigilance { color: var(--brand-cyan); }
    .sidebar-nav { padding: 12px 8px; }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 16px;
      margin-bottom: 2px;
      border-radius: var(--radius-md);
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.15s ease;
    }
    .nav-item:hover { background: var(--bg-hover); color: var(--text-primary); }
    .nav-item.active { background: rgba(59, 130, 246, 0.15); color: var(--accent-primary); }
    .nav-item .mat-icon { font-size: 20px; width: 20px; height: 20px; }
    .nav-divider { margin: 8px 16px; }
    .main-content { display: flex; flex-direction: column; }
    .top-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      height: var(--header-height);
      padding: 0 24px;
      background: var(--bg-header);
      border-bottom: 1px solid var(--border-primary);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .header-right { display: flex; align-items: center; gap: 4px; }
    .page-title { font-size: 18px; font-weight: 600; margin: 0; }
    .page-content {
      flex: 1;
      overflow-y: auto;
      background: var(--bg-primary);
    }
    .user-menu-header {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-primary);
    }
    .user-menu-header strong { display: block; font-size: 14px; }
    .user-menu-header small { color: var(--text-secondary); font-size: 12px; }
    .menu-btn { margin-right: 4px; }
    .header-left { display: flex; align-items: center; gap: 4px; min-width: 0; }
    .page-title { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    /* ---- Mobile ---- */
    @media (max-width: 768px) {
      .sidebar { width: 82vw; max-width: 320px; }
      .top-header { padding: 0 12px; padding-top: env(safe-area-inset-top); }
      .nav-item { padding: 14px 16px; }            /* ≥48px touch target */
      .sidebar-nav { padding-bottom: calc(16px + env(safe-area-inset-bottom)); }
    }
    /* Don't leave hover styles "stuck" on touch devices */
    @media (hover: none) {
      .nav-item:hover { background: transparent; color: var(--text-secondary); }
      .nav-item.active { background: rgba(34,211,238,0.15); color: var(--accent-primary); }
    }
  `],
})
export class MainLayoutComponent {
  authService = inject(AuthService);
  themeService = inject(ThemeService);
  device = inject(DeviceService);
  collapsed = signal(false);
  currentTitle = signal('Dashboard');

  // On mobile the drawer is an overlay — close it after navigating.
  onNav(snav: { close: () => void }): void {
    if (this.device.isMobile()) snav.close();
  }

  mainNav: NavItem[] = [
    { label: 'Dashboard', icon: 'dashboard', route: 'dashboard' },
    { label: 'Projects', icon: 'folder', route: 'projects' },
    { label: 'Scans', icon: 'radar', route: 'scans' },
    { label: 'Findings', icon: 'bug_report', route: 'findings' },
  ];

  secondaryNav: NavItem[] = [
    { label: 'API Client', icon: 'api', route: 'api-client' },
    { label: 'API Security', icon: 'security', route: 'api-security' },
    { label: 'Code Review', icon: 'code_review', route: 'code-review' },
    { label: 'Binary / Mobile', icon: 'memory', route: 'binary-scan' },
    { label: 'Containers', icon: 'inventory_2', route: 'container-scan' },
    { label: 'SBOM', icon: 'verified', route: 'sbom' },
    { label: 'Reports', icon: 'description', route: 'reports' },
    { label: 'Scheduler', icon: 'schedule', route: 'scheduler' },
    { label: 'Settings', icon: 'settings', route: 'settings' },
    { label: 'Admin', icon: 'admin_panel_settings', route: 'admin' },
  ];
}
