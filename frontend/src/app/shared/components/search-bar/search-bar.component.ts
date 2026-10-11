import { Component, inject, signal, output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSelectModule } from '@angular/material/select';
import { HttpClient } from '@angular/common/http';
import { debounceTime, distinctUntilChanged, Subject } from 'rxjs';
import { environment } from '../../../../environments/environment';

@Component({
  selector: 'app-search-bar',
  standalone: true,
  imports: [CommonModule, FormsModule, MatFormFieldModule, MatInputModule, MatIconModule, MatButtonModule, MatSelectModule],
  template: `
    <div class="search-container">
      <mat-form-field appearance="outline" class="search-field">
        <mat-label>Global Search</mat-label>
        <input matInput [(ngModel)]="query" (ngModelChange)="onSearch($event)" (keydown.enter)="executeSearch()" placeholder="Search projects, findings, CVEs, users...">
        <mat-icon matPrefix>search</mat-icon>
        <button mat-icon-button matSuffix *ngIf="query()" (click)="clear()"><mat-icon>close</mat-icon></button>
      </mat-form-field>
      <mat-form-field appearance="outline" class="type-field">
        <mat-select [(ngModel)]="searchType" (selectionChange)="executeSearch()">
          <mat-option value="all">All</mat-option>
          <mat-option value="projects">Projects</mat-option>
          <mat-option value="findings">Findings</mat-option>
          <mat-option value="scans">Scans</mat-option>
          <mat-option value="reports">Reports</mat-option>
          <mat-option value="users">Users</mat-option>
        </mat-select>
      </mat-form-field>
      @if (results()) {
        <div class="search-results">
          @for (group of resultGroups(); track group.key) {
            <div class="result-group">
              <h4>{{ group.key }} ({{ group.items.length }})</h4>
              @for (item of group.items; track item.id) {
                <div class="result-item" (click)="navigateTo(group.key, item.id)">
                  <span class="result-title">{{ item.name || item.title }}</span>
                  <span class="result-meta">{{ item.severity || item.type || item.email }}</span>
                </div>
              }
            </div>
          } @empty {
            <div class="no-results">No results found for "{{ query() }}"</div>
          }
        </div>
      }
    </div>
  `,
  styles: [`.search-container{position:relative}.search-field{width:400px}.type-field{width:130px;margin-left:8px}.search-results{position:absolute;top:100%;left:0;right:0;background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-lg);box-shadow:var(--shadow-lg);z-index:1000;max-height:500px;overflow:auto;margin-top:4px}.result-group{padding:8px 16px}.result-group h4{font-size:11px;text-transform:uppercase;color:var(--text-secondary);margin-bottom:4px}.result-item{padding:8px 12px;cursor:pointer;border-radius:var(--radius-sm);display:flex;justify-content:space-between}.result-item:hover{background:var(--bg-hover)}.no-results{padding:24px;text-align:center;color:var(--text-secondary)}`],
})
export class SearchBarComponent {
  private http = inject(HttpClient);
  query = signal('');
  searchType = 'all';
  results = signal<any>(null);
  private searchSubject = new Subject<string>();

  constructor() { this.searchSubject.pipe(debounceTime(300), distinctUntilChanged()).subscribe(() => this.executeSearch()); }

  resultGroups() {
    const r = this.results();
    if (!r?.results) return [];
    return Object.entries(r.results as Record<string, any[]>).filter(([,v]) => Array.isArray(v) && v.length > 0).map(([k, v]) => ({ key: k, items: v }));
  }

  onSearch(val: string): void { this.query.set(val); if (val.length >= 2) this.searchSubject.next(val); else this.results.set(null); }
  executeSearch(): void {
    const q = this.query();
    if (q.length < 2) return;
    this.http.get<any>(`${environment.apiUrl}/search?q=${encodeURIComponent(q)}&type=${this.searchType}&limit=10`).subscribe({ next: (res) => this.results.set(res) });
  }
  clear(): void { this.query.set(''); this.results.set(null); }
  navigateTo(type: string, id: string): void { this.results.set(null); this.query.set(''); }
}
