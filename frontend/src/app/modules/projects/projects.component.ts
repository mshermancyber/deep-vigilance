import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatChipsModule } from '@angular/material/chips';
import { MatDialogModule } from '@angular/material/dialog';
import { RouterModule } from '@angular/router';
import { environment } from '../../../environments/environment';
import { NotificationService } from '../../core/services/notification.service';

@Component({selector:'app-projects',standalone:true,imports:[CommonModule,RouterModule,FormsModule,MatCardModule,MatButtonModule,MatIconModule,MatFormFieldModule,MatInputModule,MatChipsModule,MatDialogModule],
  template:`<div class="page-container fade-in"><div class="page-header"><h1>Projects</h1><button mat-flat-button color="primary" (click)="showCreate=true"><mat-icon>add</mat-icon>New Project</button></div>
  @if(showCreate){<mat-card style="margin-bottom:20px;background:var(--bg-card);border:1px solid var(--border-primary);padding:20px"><h3>Create Project</h3>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0">
      <mat-form-field appearance="outline"><mat-label>Name</mat-label><input matInput [(ngModel)]="newProject.name"></mat-form-field>
      <mat-form-field appearance="outline"><mat-label>Target URL</mat-label><input matInput [(ngModel)]="newProject.targetUrl" placeholder="https://app.example.com"></mat-form-field>
      <mat-form-field appearance="outline"><mat-label>Repository</mat-label><input matInput [(ngModel)]="newProject.repository" placeholder="https://github.com/org/repo"></mat-form-field>
      <mat-form-field appearance="outline"><mat-label>Description</mat-label><input matInput [(ngModel)]="newProject.description"></mat-form-field>
    </div>
    <div style="display:flex;gap:8px"><button mat-flat-button color="primary" (click)="createProject()" [disabled]="!newProject.name">Create</button><button mat-button (click)="showCreate=false">Cancel</button></div>
  </mat-card>}
  @if(loading()){<div class="spinner"></div>}
  @else if(projects().length){<div class="project-grid">
    @for(p of projects();track p.id){<mat-card class="project-card"><mat-card-header><mat-card-title>{{p.name}}</mat-card-title><mat-card-subtitle>{{p.target_url||'No URL'}}<br>{{p.description||''}}</mat-card-subtitle></mat-card-header>
    <mat-card-content><div style="display:flex;gap:12px;margin:8px 0"><span class="severity-badge critical">{{p.critical_count||0}} Critical</span><span class="severity-badge high">{{p.high_count||0}} High</span><span style="color:var(--text-secondary)">{{p.scan_count||0}} scans</span></div>
    @if(p.tags?.length){<mat-chip-listbox>@for(t of p.tags;track t){<mat-chip>{{t}}</mat-chip>}</mat-chip-listbox>}</mat-card-content>
    <mat-card-actions><a mat-button [routerLink]="['/scans']" [queryParams]="{projectId:p.id}">Scans</a><a mat-button [routerLink]="['/findings']" [queryParams]="{projectId:p.id}">Findings</a><button mat-icon-button color="warn" (click)="deleteProject(p.id)"><mat-icon>delete</mat-icon></button></mat-card-actions></mat-card>}
  </div>}@else{<div class="empty-state"><mat-icon>folder_open</mat-icon><h3>No projects</h3><p>Create your first project to start security scanning.</p></div>}</div>`,
  styles:[`.project-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}.project-card{background:var(--bg-card);border:1px solid var(--border-primary)}`]
})
export class ProjectsComponent implements OnInit {
  private http=inject(HttpClient);private notify=inject(NotificationService);
  projects=signal<any[]>([]);loading=signal(true);showCreate=false;
  newProject={name:'',targetUrl:'',repository:'',description:''};
  ngOnInit(){this.loadProjects();}
  loadProjects(){this.loading.set(true);this.http.get<{data:any[]}>(`${environment.apiUrl}/projects`).subscribe({next:(r)=>{this.projects.set(r.data||[]);this.loading.set(false)},error:()=>this.loading.set(false)});}
  createProject(){this.http.post(`${environment.apiUrl}/projects`,this.newProject).subscribe({next:()=>{this.notify.success('Project created');this.showCreate=false;this.newProject={name:'',targetUrl:'',repository:'',description:''};this.loadProjects();},error:(e)=>this.notify.error(e.error?.error||'Failed')});}
  deleteProject(id:string){if(confirm('Delete this project?'))this.http.delete(`${environment.apiUrl}/projects/${id}`).subscribe({next:()=>{this.notify.success('Project deleted');this.loadProjects();}});}
}
