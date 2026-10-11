import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatTabsModule } from '@angular/material/tabs';
import { MatMenuModule } from '@angular/material/menu';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { environment } from '../../../environments/environment';
import { ApiService } from '../../core/services/api.service';
import { NotificationService } from '../../core/services/notification.service';

export interface WorkspaceMember {
  id: string;
  user_id: string;
  username: string;
  email: string;
  role: 'admin' | 'editor' | 'viewer';
  joined_at: string;
}

export interface Workspace {
  id: string;
  name: string;
  description: string;
  type: 'personal' | 'team' | 'public';
  owner_id: string;
  owner_name: string;
  created_at: string;
  updated_at: string;
  member_count: number;
  collection_count: number;
  members?: WorkspaceMember[];
}

@Component({
  selector: 'app-workspace-manager',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatButtonModule, MatIconModule, MatFormFieldModule,
    MatSelectModule, MatInputModule, MatCardModule,
    MatChipsModule, MatDividerModule, MatTooltipModule,
    MatTabsModule, MatMenuModule, MatDialogModule,
  ],
  template: `
    <div class="workspace-container">
      <!-- Header -->
      <div class="ws-header">
        <div style="display:flex;align-items:center;gap:12px">
          <mat-icon>workspaces</mat-icon>
          <h3>Workspaces</h3>
        </div>
        <div style="display:flex;gap:8px">
          <button mat-stroked-button (click)="loadWorkspaces()"><mat-icon>refresh</mat-icon></button>
          <button mat-flat-button color="primary" (click)="showCreateForm.set(true)"><mat-icon>add</mat-icon> New Workspace</button>
        </div>
      </div>

      <!-- Create / Edit Form -->
      @if (showCreateForm()) {
        <div class="ws-form-overlay" (click)="showCreateForm.set(false)">
          <div class="ws-form-panel" (click)="$event.stopPropagation()">
            <div class="form-header">
              <mat-icon>{{ editingWorkspace() ? 'edit' : 'add_circle' }}</mat-icon>
              <h4>{{ editingWorkspace() ? 'Edit Workspace' : 'Create Workspace' }}</h4>
              <button mat-icon-button (click)="showCreateForm.set(false)"><mat-icon>close</mat-icon></button>
            </div>
            <div class="form-body">
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>Name</mat-label>
                <input matInput [(ngModel)]="formName" placeholder="My Workspace" required>
              </mat-form-field>
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>Description</mat-label>
                <textarea matInput [(ngModel)]="formDescription" placeholder="Description of this workspace" rows="3"></textarea>
              </mat-form-field>
              <mat-form-field appearance="outline" class="full-width">
                <mat-label>Type</mat-label>
                <mat-select [(ngModel)]="formType">
                  <mat-option value="personal">Personal</mat-option>
                  <mat-option value="team">Team</mat-option>
                  <mat-option value="public">Public</mat-option>
                </mat-select>
              </mat-form-field>
            </div>
            <div class="form-actions">
              <button mat-button (click)="showCreateForm.set(false)">Cancel</button>
              <button mat-flat-button color="primary" (click)="saveWorkspace()" [disabled]="!formName.trim()">
                {{ editingWorkspace() ? 'Update' : 'Create' }}
              </button>
            </div>
          </div>
        </div>
      }

      <!-- Tabs: All / Personal / Team / Public -->
      <mat-tab-group (selectedTabChange)="filterByType($event.tab.textLabel)">
        <mat-tab label="All"></mat-tab>
        <mat-tab label="Personal"></mat-tab>
        <mat-tab label="Team"></mat-tab>
        <mat-tab label="Public"></mat-tab>
      </mat-tab-group>

      <!-- Workspace list -->
      @if (loading()) {
        <div class="spinner"></div>
      } @else if (filteredWorkspaces().length === 0) {
        <div class="empty-state" style="margin-top:32px">
          <mat-icon>workspaces</mat-icon>
          <h3>No workspaces found</h3>
          <p>Create a new workspace to organize your API collections.</p>
        </div>
      } @else {
        <div class="workspace-list">
          @for (ws of filteredWorkspaces(); track ws.id) {
            <div class="workspace-card" [class.expanded]="expandedWsId() === ws.id">
              <!-- Card header -->
              <div class="ws-card-header" (click)="toggleExpand(ws)">
                <div class="ws-type-badge" [class]="ws.type">
                  <mat-icon>{{ ws.type === 'personal' ? 'person' : ws.type === 'team' ? 'group' : 'public' }}</mat-icon>
                </div>
                <div class="ws-info">
                  <strong>{{ ws.name }}</strong>
                  <span class="ws-description">{{ ws.description || 'No description' }}</span>
                </div>
                <div class="ws-meta">
                  <span class="ws-type-label" [class]="ws.type">{{ ws.type }}</span>
                  <span class="ws-stat" matTooltip="Members"><mat-icon>people</mat-icon> {{ ws.member_count || 1 }}</span>
                  <span class="ws-stat" matTooltip="Collections"><mat-icon>folder</mat-icon> {{ ws.collection_count || 0 }}</span>
                  <span class="ws-owner" matTooltip="Owner">{{ ws.owner_name }}</span>
                </div>
                <button mat-icon-button class="ws-menu-btn" (click)="$event.stopPropagation()" [matMenuTriggerFor]="wsMenu">
                  <mat-icon>more_vert</mat-icon>
                </button>
                <mat-menu #wsMenu="matMenu">
                  <button mat-menu-item (click)="editWorkspace(ws); $event.stopPropagation()">
                    <mat-icon>edit</mat-icon> Edit
                  </button>
                  <button mat-menu-item (click)="loadMembers(ws); $event.stopPropagation()">
                    <mat-icon>people</mat-icon> Manage Members
                  </button>
                  <mat-divider></mat-divider>
                  <button mat-menu-item (click)="deleteWorkspace(ws); $event.stopPropagation()" style="color:var(--severity-critical)">
                    <mat-icon>delete</mat-icon> Delete
                  </button>
                </mat-menu>
              </div>

              <!-- Expanded member area -->
              @if (expandedWsId() === ws.id) {
                <div class="ws-expanded">
                  <mat-divider></mat-divider>
                  <!-- Members -->
                  <div class="members-section">
                    <div class="section-header">
                      <h5><mat-icon>people</mat-icon> Members ({{ ws.members?.length || 0 }})</h5>
                      <div style="display:flex;gap:8px;align-items:center">
                        <mat-form-field appearance="outline" style="width:220px">
                          <mat-label>Invite by email</mat-label>
                          <input matInput [(ngModel)]="inviteEmail" placeholder="user@example.com">
                        </mat-form-field>
                        <mat-form-field appearance="outline" style="width:120px">
                          <mat-label>Role</mat-label>
                          <mat-select [(ngModel)]="inviteRole">
                            <mat-option value="editor">Editor</mat-option>
                            <mat-option value="viewer">Viewer</mat-option>
                            <mat-option value="admin">Admin</mat-option>
                          </mat-select>
                        </mat-form-field>
                        <button mat-flat-button color="primary" (click)="inviteMember(ws)" [disabled]="!inviteEmail.trim()">
                          <mat-icon>person_add</mat-icon> Invite
                        </button>
                      </div>
                    </div>
                    @if (ws.members && ws.members.length > 0) {
                      <table class="data-table members-table">
                        <thead>
                          <tr>
                            <th>User</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Joined</th>
                            <th></th>
                          </tr>
                        </thead>
                        <tbody>
                          @for (m of ws.members; track m.id) {
                            <tr>
                              <td>
                                <div class="member-avatar">{{ m.username.charAt(0).toUpperCase() }}</div>
                                {{ m.username }}
                              </td>
                              <td style="color:var(--text-secondary)">{{ m.email }}</td>
                              <td>
                                <mat-form-field appearance="outline" style="width:120px" *ngIf="m.role !== 'admin'">
                                  <mat-select [value]="m.role" (selectionChange)="updateMemberRole(ws, m, $event.value)">
                                    <mat-option value="admin">Admin</mat-option>
                                    <mat-option value="editor">Editor</mat-option>
                                    <mat-option value="viewer">Viewer</mat-option>
                                  </mat-select>
                                </mat-form-field>
                                <span *ngIf="m.role === 'admin'" class="role-badge admin">Admin</span>
                              </td>
                              <td style="color:var(--text-tertiary);font-size:12px">{{ m.joined_at | date:'mediumDate' }}</td>
                              <td>
                                <button mat-icon-button (click)="removeMember(ws, m)" *ngIf="m.role !== 'admin'" matTooltip="Remove member">
                                  <mat-icon style="color:var(--severity-critical)">remove_circle</mat-icon>
                                </button>
                              </td>
                            </tr>
                          }
                        </tbody>
                      </table>
                    } @else {
                      <div class="no-members">
                        <mat-icon>people_outline</mat-icon>
                        <span>No members yet. Invite team members to collaborate.</span>
                      </div>
                    }

                    <!-- Invite Pending -->
                    @if (pendingInvites().length > 0) {
                      <div class="pending-section">
                        <h5><mat-icon>schedule_send</mat-icon> Pending Invitations</h5>
                        @for (inv of pendingInvites(); track inv.id) {
                          <div class="pending-row">
                            <span>{{ inv.email }}</span>
                            <span class="role-badge">{{ inv.role }}</span>
                            <span style="color:var(--text-tertiary);font-size:12px">{{ inv.created_at }}</span>
                            <button mat-icon-button (click)="cancelInvite(inv.id)" matTooltip="Cancel invitation">
                              <mat-icon>cancel</mat-icon>
                            </button>
                          </div>
                        }
                      </div>
                    }
                  </div>

                  <!-- Collections in workspace -->
                  <div class="coll-in-ws-section" *ngIf="wsCollections().length > 0">
                    <h5><mat-icon>folder</mat-icon> Collections ({{ wsCollections().length }})</h5>
                    <div class="ws-coll-list">
                      @for (c of wsCollections(); track c.id) {
                        <div class="ws-coll-item">
                          <mat-icon>folder_open</mat-icon>
                          <span>{{ c.name }}</span>
                          <span class="req-count">{{ c.request_count || 0 }} requests</span>
                        </div>
                      }
                    </div>
                  </div>
                </div>
              }
            </div>
          }
        </div>
      }
    </div>
  `,
  styles: [`
    .workspace-container { padding: 16px; }
    .ws-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
    .ws-header h3 { display: flex; align-items: center; gap: 8px; margin: 0; }
    .ws-form-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
    .ws-form-panel { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-lg); padding: 24px; width: 480px; max-width: 90vw; box-shadow: var(--shadow-lg); }
    .form-header { display: flex; align-items: center; gap: 8px; margin-bottom: 20px; }
    .form-header h4 { margin: 0; flex: 1; }
    .form-body { display: flex; flex-direction: column; gap: 12px; margin-bottom: 20px; }
    .full-width { width: 100%; }
    .form-actions { display: flex; gap: 8px; justify-content: flex-end; }
    .workspace-list { display: flex; flex-direction: column; gap: 8px; margin-top: 16px; }
    .workspace-card { background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md); overflow: hidden; transition: border-color 0.2s; }
    .workspace-card:hover { border-color: var(--border-accent); }
    .workspace-card.expanded { border-color: var(--border-accent); }
    .ws-card-header { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; }
    .ws-type-badge { display: flex; align-items: center; justify-content: center; width: 36px; height: 36px; border-radius: 8px; }
    .ws-type-badge mat-icon { font-size: 20px; width: 20px; height: 20px; }
    .ws-type-badge.personal { background: rgba(59, 130, 246, 0.15); color: var(--accent-primary); }
    .ws-type-badge.team { background: rgba(139, 92, 246, 0.15); color: var(--accent-info); }
    .ws-type-badge.public { background: rgba(34, 197, 94, 0.15); color: var(--accent-success); }
    .ws-info { flex: 1; min-width: 0; }
    .ws-info strong { display: block; font-size: 14px; }
    .ws-description { font-size: 12px; color: var(--text-tertiary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
    .ws-meta { display: flex; align-items: center; gap: 12px; font-size: 12px; }
    .ws-type-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; padding: 2px 8px; border-radius: 3px; }
    .ws-type-label.personal { background: rgba(59, 130, 246, 0.15); color: var(--accent-primary); }
    .ws-type-label.team { background: rgba(139, 92, 246, 0.15); color: var(--accent-info); }
    .ws-type-label.public { background: rgba(34, 197, 94, 0.15); color: var(--accent-success); }
    .ws-stat { display: inline-flex; align-items: center; gap: 4px; color: var(--text-secondary); cursor: help; }
    .ws-stat mat-icon { font-size: 14px; width: 14px; height: 14px; }
    .ws-owner { color: var(--text-tertiary); }
    .ws-menu-btn { margin-left: 4px; }
    .ws-expanded { padding: 0 16px 16px; }
    .section-header { display: flex; align-items: center; justify-content: space-between; margin: 12px 0; flex-wrap: wrap; gap: 8px; }
    .section-header h5 { display: flex; align-items: center; gap: 6px; margin: 0; font-size: 13px; color: var(--text-secondary); }
    .section-header h5 mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .members-section { margin-top: 12px; }
    .members-table { margin-top: 8px; }
    .members-table th { white-space: nowrap; }
    .members-table td { vertical-align: middle; }
    .member-avatar { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: var(--accent-primary); color: white; font-size: 12px; font-weight: 700; margin-right: 8px; vertical-align: middle; }
    .role-badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
    .role-badge.admin { background: rgba(239, 68, 68, 0.12); color: var(--severity-critical); }
    .role-badge.editor { background: rgba(59, 130, 246, 0.12); color: var(--accent-primary); }
    .role-badge.viewer { background: rgba(34, 197, 94, 0.12); color: var(--accent-success); }
    .no-members { display: flex; align-items: center; gap: 8px; padding: 16px; color: var(--text-tertiary); font-size: 13px; }
    .no-members mat-icon { color: var(--text-tertiary); }
    .pending-section { margin-top: 12px; padding: 12px; background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: var(--radius-md); }
    .pending-section h5 { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--accent-warning); margin-bottom: 8px; }
    .pending-section h5 mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .pending-row { display: flex; align-items: center; gap: 12px; font-size: 13px; padding: 4px 0; }
    .pending-row button { margin-left: auto; }
    .coll-in-ws-section { margin-top: 16px; }
    .coll-in-ws-section h5 { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; }
    .coll-in-ws-section h5 mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .ws-coll-list { display: flex; flex-direction: column; gap: 4px; }
    .ws-coll-item { display: flex; align-items: center; gap: 8px; padding: 6px 12px; background: var(--bg-secondary); border-radius: var(--radius-sm); font-size: 13px; }
    .ws-coll-item mat-icon { font-size: 18px; width: 18px; height: 18px; color: var(--accent-primary); }
    .req-count { margin-left: auto; font-size: 11px; color: var(--text-tertiary); }
  `],
})
export class WorkspaceManagerComponent {
  private api = inject(ApiService);
  private notify = inject(NotificationService);

  // State
  workspaces = signal<Workspace[]>([]);
  filteredWorkspaces = signal<Workspace[]>([]);
  expandedWsId = signal<string | null>(null);
  loading = signal(false);
  showCreateForm = signal(false);
  editingWorkspace = signal<Workspace | null>(null);
  pendingInvites = signal<any[]>([]);
  wsCollections = signal<any[]>([]);

  // Form fields
  formName = '';
  formDescription = '';
  formType: 'personal' | 'team' | 'public' = 'personal';

  // Invite fields
  inviteEmail = '';
  inviteRole: 'admin' | 'editor' | 'viewer' = 'editor';

  private currentTypeFilter = 'All';

  ngOnInit() {
    this.loadWorkspaces();
  }

  loadWorkspaces() {
    this.loading.set(true);
    this.api.get<{ data: Workspace[] }>('/api-client/workspaces').subscribe({
      next: (res) => {
        this.workspaces.set(res.data || []);
        this.applyFilter();
        this.loading.set(false);
      },
      error: (err) => {
        this.notify.error('Failed to load workspaces: ' + (err.message || 'Unknown error'));
        this.loading.set(false);
      },
    });
  }

  filterByType(label: string) {
    this.currentTypeFilter = label;
    this.applyFilter();
  }

  private applyFilter() {
    const all = this.workspaces();
    if (this.currentTypeFilter === 'All') {
      this.filteredWorkspaces.set(all);
    } else {
      const type = this.currentTypeFilter.toLowerCase() as 'personal' | 'team' | 'public';
      this.filteredWorkspaces.set(all.filter(w => w.type === type));
    }
  }

  toggleExpand(ws: Workspace) {
    if (this.expandedWsId() === ws.id) {
      this.expandedWsId.set(null);
    } else {
      this.expandedWsId.set(ws.id);
      this.loadMembers(ws);
      this.loadCollectionCount(ws);
    }
  }

  // --- Create / Edit ---

  saveWorkspace() {
    if (!this.formName.trim()) {
      this.notify.warning('Workspace name is required');
      return;
    }

    const body = {
      name: this.formName.trim(),
      description: this.formDescription.trim(),
      type: this.formType,
    };

    const edit = this.editingWorkspace();
    if (edit) {
      this.api.patch<Workspace>(`/api-client/workspaces/${edit.id}`, body).subscribe({
        next: () => {
          this.notify.success('Workspace updated');
          this.showCreateForm.set(false);
          this.editingWorkspace.set(null);
          this.resetForm();
          this.loadWorkspaces();
        },
        error: (err) => this.notify.error('Failed to update workspace: ' + (err.message || 'Unknown error')),
      });
    } else {
      this.api.post<Workspace>('/api-client/workspaces', body).subscribe({
        next: () => {
          this.notify.success('Workspace created');
          this.showCreateForm.set(false);
          this.resetForm();
          this.loadWorkspaces();
        },
        error: (err) => this.notify.error('Failed to create workspace: ' + (err.message || 'Unknown error')),
      });
    }
  }

  editWorkspace(ws: Workspace) {
    this.formName = ws.name;
    this.formDescription = ws.description || '';
    this.formType = ws.type;
    this.editingWorkspace.set(ws);
    this.showCreateForm.set(true);
  }

  deleteWorkspace(ws: Workspace) {
    if (!confirm(`Delete workspace "${ws.name}"? This cannot be undone.`)) return;
    this.api.delete(`/api-client/workspaces/${ws.id}`).subscribe({
      next: () => {
        this.notify.success('Workspace deleted');
        this.loadWorkspaces();
      },
      error: (err) => this.notify.error('Failed to delete workspace: ' + (err.message || 'Unknown error')),
    });
  }

  private resetForm() {
    this.formName = '';
    this.formDescription = '';
    this.formType = 'personal';
    this.editingWorkspace.set(null);
  }

  // --- Members ---

  loadMembers(ws: Workspace) {
    if (ws.id) {
      this.api.get<{ data: WorkspaceMember[] }>(`/api-client/workspaces/${ws.id}/members`).subscribe({
        next: (res) => {
          ws.members = res.data || [];
          this.workspaces.update(list => list.map(w => w.id === ws.id ? ws : w));
          this.applyFilter();
        },
        error: () => { /* silently fail, members remain empty */ },
      });

      // Also load pending invites
      this.api.get<{ data: any[] }>(`/api-client/workspaces/${ws.id}/invitations`).subscribe({
        next: (res) => this.pendingInvites.set(res.data || []),
        error: () => this.pendingInvites.set([]),
      });
    }
  }

  inviteMember(ws: Workspace) {
    if (!this.inviteEmail.trim()) return;
    const email = this.inviteEmail.trim();

    this.api.post(`/api-client/workspaces/${ws.id}/invitations`, {
      email,
      role: this.inviteRole,
    }).subscribe({
      next: () => {
        this.notify.success(`Invitation sent to ${email}`);
        this.inviteEmail = '';
        this.loadMembers(ws);
      },
      error: (err) => this.notify.error('Failed to invite member: ' + (err.message || 'Unknown error')),
    });
  }

  cancelInvite(inviteId: string) {
    this.api.delete(`/api-client/workspaces/invitations/${inviteId}`).subscribe({
      next: () => {
        this.notify.info('Invitation cancelled');
        this.pendingInvites.update(list => list.filter(i => i.id !== inviteId));
      },
      error: (err) => this.notify.error('Failed to cancel invitation'),
    });
  }

  updateMemberRole(ws: Workspace, member: WorkspaceMember, newRole: string) {
    this.api.patch(`/api-client/workspaces/${ws.id}/members/${member.id}`, { role: newRole }).subscribe({
      next: () => {
        this.notify.success(`Updated ${member.username}'s role to ${newRole}`);
        this.loadMembers(ws);
      },
      error: (err) => this.notify.error('Failed to update role: ' + (err.message || 'Unknown error')),
    });
  }

  removeMember(ws: Workspace, member: WorkspaceMember) {
    if (!confirm(`Remove ${member.username} from this workspace?`)) return;
    this.api.delete(`/api-client/workspaces/${ws.id}/members/${member.id}`).subscribe({
      next: () => {
        this.notify.success(`Removed ${member.username}`);
        this.loadMembers(ws);
      },
      error: (err) => this.notify.error('Failed to remove member: ' + (err.message || 'Unknown error')),
    });
  }

  // --- Collections in workspace ---

  private loadCollectionCount(ws: Workspace) {
    this.api.get<{ data: any[] }>(`/api-client/collections`, { workspace_id: ws.id }).subscribe({
      next: (res) => {
        if (res.data) {
          this.wsCollections.set(res.data);
        }
      },
      error: () => this.wsCollections.set([]),
    });
  }
}
