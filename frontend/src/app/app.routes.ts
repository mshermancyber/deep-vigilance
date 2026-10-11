import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';

export const APP_ROUTES: Routes = [
  {
    path: '',
    loadComponent: () => import('./layouts/main-layout/main-layout.component')
      .then((m) => m.MainLayoutComponent),
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      {
        path: 'dashboard',
        loadComponent: () => import('./modules/dashboard/dashboard.component')
          .then((m) => m.DashboardComponent),
        data: { title: 'Dashboard' },
      },
      {
        path: 'projects',
        loadComponent: () => import('./modules/projects/projects.component')
          .then((m) => m.ProjectsComponent),
        data: { title: 'Projects' },
      },
      {
        path: 'scans',
        loadComponent: () => import('./modules/scans/scans.component')
          .then((m) => m.ScansComponent),
        data: { title: 'Scans' },
      },
      {
        path: 'findings',
        loadComponent: () => import('./modules/findings/findings.component')
          .then((m) => m.FindingsComponent),
        data: { title: 'Findings' },
      },
      {
        path: 'api-client',
        loadComponent: () => import('./modules/api-client/api-client.component')
          .then((m) => m.ApiClientComponent),
        data: { title: 'API Client' },
      },
      {
        path: 'reports',
        loadComponent: () => import('./modules/reports/reports.component')
          .then((m) => m.ReportsComponent),
        data: { title: 'Reports' },
      },
      {
        path: 'scheduler',
        loadComponent: () => import('./modules/scheduler/scheduler.component')
          .then((m) => m.SchedulerComponent),
        data: { title: 'Scheduler' },
      },
      {
        path: 'settings',
        loadComponent: () => import('./modules/settings/settings.component')
          .then((m) => m.SettingsComponent),
        data: { title: 'Settings' },
      },
      {
        path: 'code-review',
        loadComponent: () => import('./modules/code-review/code-review.component')
          .then((m) => m.CodeReviewComponent),
        data: { title: 'Code Review & Fuzz Analysis' },
      },
      {
        path: 'admin',
        loadComponent: () => import('./modules/admin/admin.component')
          .then((m) => m.AdminComponent),
        data: { title: 'Administration' },
      },
      {
        path: 'container-scan',
        loadComponent: () => import('./modules/container-scan/container-scan.component')
          .then((m) => m.ContainerScanComponent),
        data: { title: 'Container & Image Scanning' },
      },
      {
        path: 'api-security',
        loadComponent: () => import('./modules/api-security/api-security.component')
          .then((m) => m.ApiSecurityComponent),
        data: { title: 'API Security' },
      },
      {
        path: 'binary-scan',
        loadComponent: () => import('./modules/binary-scan/binary-scan.component')
          .then((m) => m.BinaryScanComponent),
        data: { title: 'Binary & Mobile Scan' },
      },
      {
        path: 'sbom',
        loadComponent: () => import('./modules/sbom/sbom.component')
          .then((m) => m.SBOMComponent),
        data: { title: 'SBOM & Supply Chain' },
      },
    ],
  },
  {
    path: 'login',
    loadComponent: () => import('./modules/auth/login/login.component')
      .then((m) => m.LoginComponent),
  },
  {
    path: 'register',
    loadComponent: () => import('./modules/auth/register/register.component')
      .then((m) => m.RegisterComponent),
  },
  { path: '**', redirectTo: '' },
];
