import { Component, OnInit, inject, signal, HostListener } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpHeaders, HttpParams, HttpResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';
import { MatTabsModule } from '@angular/material/tabs';
import { MatMenuModule } from '@angular/material/menu';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDividerModule } from '@angular/material/divider';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { environment } from '../../../environments/environment';
import { ApiService } from '../../core/services/api.service';
import { NotificationService } from '../../core/services/notification.service';
import { ScriptExecutorService } from './script-executor.service';
import { CollectionRunnerComponent } from './collection-runner.component';
import { WorkspaceManagerComponent } from './workspace-manager.component';

/* ------------------------------------------------------------------ */
/*  Internal interfaces                                                */
/* ------------------------------------------------------------------ */
interface Kvp {
  key: string;
  value: string;
  enabled: boolean;
}

interface AuthCfg {
  type: 'none' | 'bearer' | 'basic' | 'api-key' | 'oauth2';
  bearerToken: string;
  basicUsername: string;
  basicPassword: string;
  apiKeyKey: string;
  apiKeyValue: string;
  apiKeyAddTo: 'header' | 'query';
  oauth2Token: string;
  oauth2TokenType: string;
}

interface ApiResponseData {
  status: number;
  statusText: string;
  body: string;
  headers: Record<string, string>;
  timing: number;
  size: number;
  contentType: string;
}

interface TestResultItem {
  name: string;
  passed: boolean;
  error: string | null;
}

interface CollItem {
  id: string;
  name: string;
  request_count: number;
  requests?: CollRequest[];
}

interface CollRequest {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: string;
  body: string;
  body_language: string;
  query_params: string;
  auth: string;
  pre_script: string;
  post_script: string;
  sort_order: number;
}

interface ContextMenuState {
  visible: boolean;
  x: number;
  y: number;
  type: 'collection' | 'request';
  item: CollItem | CollRequest | null;
}

/**
 * Parsed cookie representation
 */
interface ParsedCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */
@Component({
  selector: 'app-api-client',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatButtonModule,
    MatIconModule,
    MatFormFieldModule,
    MatSelectModule,
    MatInputModule,
    MatTabsModule,
    MatMenuModule,
    MatTooltipModule,
    MatDividerModule,
    MatProgressBarModule,
    MatCheckboxModule,
    CollectionRunnerComponent,
    WorkspaceManagerComponent,
  ],
  template: `
    <mat-tab-group class="ac-outer-tabs" [(selectedIndex)]="outerTabIndex" animationDuration="200ms">

      <!-- ============================================================
           TAB 1: REQUEST BUILDER
           ============================================================ -->
      <mat-tab label="Request">
        <ng-template matTabContent>
    <div class="ac-root">
      <!-- ============================================================
           LEFT SIDEBAR — Collections
           ============================================================ -->
      <aside class="ac-sidebar">
        <div class="ac-sidebar-head">
          <h3>Collections</h3>
          <div class="ac-sidebar-actions">
            <button mat-icon-button (click)="loadCollections()" matTooltip="Refresh">
              <mat-icon>refresh</mat-icon>
            </button>
            <button mat-icon-button color="primary" (click)="startCreateCollection()" matTooltip="New Collection">
              <mat-icon>note_add</mat-icon>
            </button>
          </div>
        </div>

        <!-- Inline create-collection form -->
        @if (showCreateColl()) {
          <div class="ac-inline-form">
            <mat-form-field appearance="outline" dense>
              <mat-label>Name</mat-label>
              <input matInput [(ngModel)]="newCollName" (keydown.enter)="createCollection()" placeholder="Collection name">
            </mat-form-field>
            <div class="ac-inline-actions">
              <button mat-flat-button color="primary" (click)="createCollection()" [disabled]="!newCollName.trim()">
                Create
              </button>
              <button mat-button (click)="cancelCreateCollection()">Cancel</button>
            </div>
          </div>
        }

        <!-- Inline rename-collection form -->
        @if (showRenameColl()) {
          <div class="ac-inline-form">
            <mat-form-field appearance="outline" dense>
              <mat-label>Rename</mat-label>
              <input matInput [(ngModel)]="renameCollName" (keydown.enter)="confirmRenameCollection()" placeholder="New name">
            </mat-form-field>
            <div class="ac-inline-actions">
              <button mat-flat-button color="primary" (click)="confirmRenameCollection()" [disabled]="!renameCollName.trim()">
                Save
              </button>
              <button mat-button (click)="cancelRename()">Cancel</button>
            </div>
          </div>
        }

        <!-- Collection list -->
        <div class="ac-coll-list">
          @for (c of collections(); track c.id) {
            <div
              class="ac-coll-item"
              [class.active]="selectedCollection()?.id === c.id"
              (click)="selectCollection(c)"
              (contextmenu)="openContextMenu($event, 'collection', c)"
            >
              <mat-icon class="ac-coll-icon">folder</mat-icon>
              <span class="ac-coll-name">{{ c.name }}</span>
              <span class="ac-coll-count">{{ c.request_count ?? 0 }}</span>
            </div>
          } @empty {
            <div class="ac-empty-hint">No collections yet</div>
          }
        </div>

        <!-- Requests in selected collection -->
        @if (selectedCollection(); as selColl) {
          <mat-divider></mat-divider>
          <div class="ac-sidebar-head ac-sub-head">
            <h4>Requests</h4>
            <button mat-icon-button (click)="addRequest()" matTooltip="New Request">
              <mat-icon>add</mat-icon>
            </button>
          </div>
          <div class="ac-req-list">
            @for (r of requestsInColl(); track r.id) {
              <div
                class="ac-req-item"
                [class.active]="selectedRequest()?.id === r.id"
                (click)="loadRequest(r)"
                (contextmenu)="openContextMenu($event, 'request', r)"
              >
                <span class="ac-method-badge" [class]="r.method.toLowerCase()">{{ r.method }}</span>
                <span class="ac-req-name">{{ r.name || r.url || 'Untitled' }}</span>
              </div>
            } @empty {
              <div class="ac-empty-hint">No requests in this collection</div>
            }
          </div>
        }
      </aside>

      <!-- ============================================================
           MIDDLE — Request Builder
           ============================================================ -->
      <main class="ac-request-panel">
        <!-- URL bar -->
        <div class="ac-url-bar">
          <mat-form-field appearance="outline" class="ac-method-sel">
            <mat-select [(ngModel)]="method" (selectionChange)="onMethodChange()">
              @for (m of methods; track m) {
                <mat-option [value]="m">{{ m }}</mat-option>
              }
            </mat-select>
          </mat-form-field>
          <mat-form-field appearance="outline" class="ac-url-input">
            <mat-label>Request URL</mat-label>
            <input
              matInput
              [(ngModel)]="url"
              placeholder="https://api.example.com/endpoint"
              (keydown.enter)="sendRequest()"
            />
          </mat-form-field>
          <button
            mat-flat-button
            color="primary"
            class="ac-send-btn"
            (click)="sendRequest()"
            [disabled]="!url.trim() || loading()"
            matTooltip="Send (Ctrl+Enter)"
          >
            <mat-icon>send</mat-icon>
            <span>Send</span>
          </button>
          <button
            mat-stroked-button
            class="ac-save-btn"
            (click)="saveRequest()"
            [disabled]="!url.trim() || !selectedCollection()"
            matTooltip="Save to collection"
          >
            <mat-icon>save</mat-icon>
          </button>
        </div>

        <!-- Request tabs -->
        <mat-tab-group class="ac-req-tabs" [(selectedIndex)]="requestTabIndex">
          <!-- HEADERS -->
          <mat-tab label="Headers">
            <div class="ac-tab-body">
              <div class="ac-kv-editor">
                @for (h of headers(); track idx; let idx = $index) {
                  <div class="ac-kv-row">
                    <mat-checkbox [(ngModel)]="h.enabled"></mat-checkbox>
                    <input
                      class="ac-kv-key"
                      [(ngModel)]="h.key"
                      placeholder="Header name"
                    />
                    <input
                      class="ac-kv-val"
                      [(ngModel)]="h.value"
                      placeholder="Value"
                    />
                    <button class="ac-kv-del" (click)="removeHeader(idx)" mat-icon-button matTooltip="Remove">
                      <mat-icon>close</mat-icon>
                    </button>
                  </div>
                }
                <button mat-stroked-button (click)="addHeader()" class="ac-kv-add">
                  <mat-icon>add</mat-icon> Add Header
                </button>
              </div>
              @if (presetHeaderKeys.length) {
                <div class="ac-presets">
                  <span class="ac-preset-label">Quick add:</span>
                  @for (p of presetHeaderKeys; track p) {
                    <button mat-button dense (click)="addPresetHeader(p)">{{ p }}</button>
                  }
                </div>
              }
            </div>
          </mat-tab>

          <!-- BODY -->
          <mat-tab label="Body">
            <div class="ac-tab-body">
              <div class="ac-body-toolbar">
                <mat-form-field appearance="outline" class="ac-body-lang">
                  <mat-select [(ngModel)]="bodyLanguage">
                    <mat-option value="json">application/json</mat-option>
                    <mat-option value="xml">application/xml</mat-option>
                    <mat-option value="form">application/x-www-form-urlencoded</mat-option>
                    <mat-option value="text">text/plain</mat-option>
                    <mat-option value="graphql">application/graphql</mat-option>
                  </mat-select>
                </mat-form-field>
                <button mat-button (click)="formatBody()" matTooltip="Pretty-print">
                  <mat-icon>auto_fix_high</mat-icon>
                </button>
                <button mat-button (click)="clearBody()" matTooltip="Clear">
                  <mat-icon>delete</mat-icon>
                </button>
              </div>
              <textarea class="ac-code-editor" [(ngModel)]="body" placeholder="Request body..."></textarea>
            </div>
          </mat-tab>

          <!-- PARAMS -->
          <mat-tab label="Params">
            <div class="ac-tab-body">
              <div class="ac-kv-editor">
                @for (p of params(); track idx; let idx = $index) {
                  <div class="ac-kv-row">
                    <mat-checkbox [(ngModel)]="p.enabled"></mat-checkbox>
                    <input class="ac-kv-key" [(ngModel)]="p.key" placeholder="Parameter name" />
                    <input class="ac-kv-val" [(ngModel)]="p.value" placeholder="Value" />
                    <button class="ac-kv-del" (click)="removeParam(idx)" mat-icon-button matTooltip="Remove">
                      <mat-icon>close</mat-icon>
                    </button>
                  </div>
                }
                <button mat-stroked-button (click)="addParam()" class="ac-kv-add">
                  <mat-icon>add</mat-icon> Add Parameter
                </button>
              </div>
            </div>
          </mat-tab>

          <!-- AUTH -->
          <mat-tab label="Auth">
            <div class="ac-tab-body">
              <mat-form-field appearance="outline" class="ac-auth-type">
                <mat-label>Auth Type</mat-label>
                <mat-select [(ngModel)]="auth.type">
                  <mat-option value="none">No Auth</mat-option>
                  <mat-option value="bearer">Bearer Token</mat-option>
                  <mat-option value="basic">Basic Auth</mat-option>
                  <mat-option value="api-key">API Key</mat-option>
                  <mat-option value="oauth2">OAuth 2.0</mat-option>
                </mat-select>
              </mat-form-field>

              @switch (auth.type) {
                @case ('bearer') {
                  <div class="ac-auth-fields">
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Token</mat-label>
                      <input matInput [(ngModel)]="auth.bearerToken" placeholder="eyJhbGciOi..." />
                    </mat-form-field>
                    <div class="ac-auth-info">
                      <mat-icon>info</mat-icon>
                      <span>Sent as: <code>Authorization: Bearer &lt;token&gt;</code></span>
                    </div>
                  </div>
                }
                @case ('basic') {
                  <div class="ac-auth-fields">
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Username</mat-label>
                      <input matInput [(ngModel)]="auth.basicUsername" />
                    </mat-form-field>
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Password</mat-label>
                      <input matInput type="password" [(ngModel)]="auth.basicPassword" />
                    </mat-form-field>
                    <div class="ac-auth-info">
                      <mat-icon>info</mat-icon>
                      <span>Sent as: <code>Authorization: Basic &lt;base64&gt;</code></span>
                    </div>
                  </div>
                }
                @case ('api-key') {
                  <div class="ac-auth-fields">
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Key</mat-label>
                      <input matInput [(ngModel)]="auth.apiKeyKey" placeholder="X-API-Key" />
                    </mat-form-field>
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Value</mat-label>
                      <input matInput [(ngModel)]="auth.apiKeyValue" />
                    </mat-form-field>
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Add To</mat-label>
                      <mat-select [(ngModel)]="auth.apiKeyAddTo">
                        <mat-option value="header">Header</mat-option>
                        <mat-option value="query">Query Parameter</mat-option>
                      </mat-select>
                    </mat-form-field>
                  </div>
                }
                @case ('oauth2') {
                  <div class="ac-auth-fields">
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Access Token</mat-label>
                      <input matInput [(ngModel)]="auth.oauth2Token" placeholder="ya29..." />
                    </mat-form-field>
                    <mat-form-field appearance="outline" class="ac-auth-field-full">
                      <mat-label>Token Type</mat-label>
                      <mat-select [(ngModel)]="auth.oauth2TokenType">
                        <mat-option value="Bearer">Bearer</mat-option>
                        <mat-option value="Basic">Basic</mat-option>
                        <mat-option value="Digest">Digest</mat-option>
                      </mat-select>
                    </mat-form-field>
                  </div>
                }
              }
            </div>
          </mat-tab>

          <!-- PRE-REQUEST SCRIPT -->
          <mat-tab label="Pre-request Script">
            <div class="ac-tab-body">
              <div class="ac-script-bar">
                <span class="ac-script-hint">JavaScript &mdash; uses <code>pm.*</code> API (variables, request, environment)</span>
                <button mat-button (click)="clearPreScript()" matTooltip="Clear">
                  <mat-icon>delete</mat-icon>
                </button>
              </div>
              <textarea
                class="ac-code-editor"
                [(ngModel)]="preScript"
                placeholder="// pm.variables.set('token', pm.request.headers['Authorization']);"
              ></textarea>
            </div>
          </mat-tab>

          <!-- TESTS -->
          <mat-tab label="Tests">
            <div class="ac-tab-body">
              <div class="ac-script-bar">
                <span class="ac-script-hint">JavaScript &mdash; use <code>pm.test()</code> and <code>pm.expect()</code></span>
                <div class="ac-snippet-group">
                  <button mat-button dense (click)="insertSnippet('status200')">Status 200</button>
                  <button mat-button dense (click)="insertSnippet('statusCode')">Status Code</button>
                  <button mat-button dense (click)="insertSnippet('jsonBody')">JSON Body</button>
                  <button mat-button dense (click)="insertSnippet('responseTime')">Response Time</button>
                  <button mat-button dense (click)="insertSnippet('headerExists')">Header Exists</button>
                  <button mat-button dense (click)="insertSnippet('bodyContains')">Body Contains</button>
                </div>
              </div>
              <textarea
                class="ac-code-editor"
                [(ngModel)]="testScript"
                placeholder="// pm.test('Status is 200', () => {&#10;//   pm.expect(pm.response.status).to.equal(200);&#10;// });"
              ></textarea>
            </div>
          </mat-tab>
        </mat-tab-group>
      </main>

      <!-- ============================================================
           RIGHT — Response Viewer
           ============================================================ -->
      <aside class="ac-response-panel">
        @if (loading()) {
          <mat-progress-bar mode="indeterminate" class="ac-loading-bar"></mat-progress-bar>
        }

        @if (response(); as resp) {
          <!-- Status bar -->
          <div class="ac-resp-topbar">
            <div class="ac-resp-meta">
              <span
                class="ac-status-badge"
                [class.success]="resp.status < 400"
                [class.redirect]="resp.status >= 300 && resp.status < 400"
                [class.error]="resp.status >= 400"
                >{{ resp.status }} {{ resp.statusText }}</span
              >
              <span class="ac-resp-stat"><mat-icon>timer</mat-icon> {{ resp.timing }} ms</span>
              <span class="ac-resp-stat"><mat-icon>data_usage</mat-icon> {{ formatSize(resp.size) }}</span>
            </div>
            <div class="ac-resp-actions">
              <button mat-icon-button (click)="copyResponse()" matTooltip="Copy response body">
                <mat-icon>content_copy</mat-icon>
              </button>
              <button mat-icon-button (click)="downloadResponse()" matTooltip="Download response">
                <mat-icon>download</mat-icon>
              </button>
              <button mat-icon-button (click)="clearResponse()" matTooltip="Clear">
                <mat-icon>clear</mat-icon>
              </button>
            </div>
          </div>

          <mat-tab-group class="ac-resp-tabs" [(selectedIndex)]="responseTabIndex">
            <!-- Body -->
            <mat-tab label="Body">
              <div class="ac-resp-body-wrap">
                <div class="ac-body-format-bar">
                  <button
                    mat-button
                    dense
                    (click)="setViewMode('pretty')"
                    [class.active]="viewMode() === 'pretty'"
                    matTooltip="Pretty-print JSON/XML"
                  >
                    <mat-icon>auto_fix_high</mat-icon> Pretty
                  </button>
                  <button
                    mat-button
                    dense
                    (click)="setViewMode('raw')"
                    [class.active]="viewMode() === 'raw'"
                    matTooltip="Raw view"
                  >
                    <mat-icon>text_snippet</mat-icon> Raw
                  </button>
                  @if (resp.contentType.startsWith('text/html') || resp.contentType.startsWith('image/')) {
                    <button
                      mat-button
                      dense
                      (click)="setViewMode('preview')"
                      [class.active]="viewMode() === 'preview'"
                      matTooltip="Preview"
                    >
                      <mat-icon>preview</mat-icon> Preview
                    </button>
                  }
                </div>
                @switch (viewMode()) {
                  @case ('pretty') {
                    <pre class="ac-code-display">{{ prettyResponseBody() }}</pre>
                  }
                  @case ('raw') {
                    <pre class="ac-code-display ac-raw-body">{{ resp.body }}</pre>
                  }
                  @case ('preview') {
                    <iframe class="ac-preview-frame" [srcdoc]="resp.body" sandbox=""></iframe>
                  }
                }
              </div>
            </mat-tab>

            <!-- Headers -->
            <mat-tab label="Headers">
              <div class="ac-resp-table-wrap">
                <table class="ac-data-table">
                  <thead>
                    <tr><th>Name</th><th>Value</th></tr>
                  </thead>
                  <tbody>
                    @for (entry of respHeadersArr(); track entry.key) {
                      <tr>
                        <td class="ac-hdr-name">{{ entry.key }}</td>
                        <td class="ac-hdr-val">{{ entry.value }}</td>
                      </tr>
                    } @empty {
                      <tr><td colspan="2" class="ac-empty-cell">No response headers</td></tr>
                    }
                  </tbody>
                </table>
              </div>
            </mat-tab>

            <!-- Cookies -->
            <mat-tab label="Cookies">
              <div class="ac-resp-table-wrap">
                <table class="ac-data-table">
                  <thead>
                    <tr><th>Name</th><th>Value</th><th>Domain</th><th>Path</th><th>Secure</th><th>HttpOnly</th></tr>
                  </thead>
                  <tbody>
                    @for (ck of responseCookies(); track ck.name) {
                      <tr>
                        <td>{{ ck.name }}</td>
                        <td class="ac-cookie-val">{{ ck.value }}</td>
                        <td>{{ ck.domain || '—' }}</td>
                        <td>{{ ck.path || '—' }}</td>
                        <td>{{ ck.secure ? 'Yes' : 'No' }}</td>
                        <td>{{ ck.httpOnly ? 'Yes' : 'No' }}</td>
                      </tr>
                    } @empty {
                      <tr><td colspan="6" class="ac-empty-cell">No cookies in response</td></tr>
                    }
                  </tbody>
                </table>
              </div>
            </mat-tab>

            <!-- Test Results -->
            <mat-tab label="Test Results">
              <div class="ac-resp-table-wrap">
                @if (testResults().length === 0) {
                  <div class="ac-empty-state-small">
                    <mat-icon>fact_check</mat-icon>
                    <p>No tests executed. Add test scripts in the Tests tab.</p>
                  </div>
                } @else {
                  <div class="ac-test-summary">
                    <span class="ac-test-pass">Passed: {{ testPassCount() }}</span>
                    <span class="ac-test-fail">Failed: {{ testFailCount() }}</span>
                    <span class="ac-test-total">Total: {{ testResults().length }}</span>
                  </div>
                  <div class="ac-test-list">
                    @for (t of testResults(); track t.name) {
                      <div class="ac-test-row" [class.ac-test-pass]="t.passed" [class.ac-test-fail]="!t.passed">
                        <mat-icon>{{ t.passed ? 'check_circle' : 'cancel' }}</mat-icon>
                        <div class="ac-test-info">
                          <span class="ac-test-name">{{ t.name }}</span>
                          @if (t.error) {
                            <span class="ac-test-err">{{ t.error }}</span>
                          }
                        </div>
                      </div>
                    }
                  </div>
                }
              </div>
            </mat-tab>
          </mat-tab-group>
        } @else {
          <div class="ac-empty-state">
            <mat-icon>api</mat-icon>
            <h3>Send a Request</h3>
            <p>Enter a URL and click Send to see the response.</p>
          </div>
        }
      </aside>

      <!-- ============================================================
           Right-click context menu
           ============================================================ -->
      @if (ctxMenu().visible) {
        <div class="ac-ctx-overlay" (click)="closeContextMenu()" (contextmenu)="$event.preventDefault(); closeContextMenu()"></div>
        <div
          class="ac-ctx-menu"
          [style.left.px]="ctxMenu().x"
          [style.top.px]="ctxMenu().y"
        >
          @if (ctxMenu().type === 'collection') {
            <div class="ac-ctx-item" (click)="startRenameCollection(ctxCollection)">
              <mat-icon>edit</mat-icon> Rename
            </div>
            <div class="ac-ctx-item" (click)="startCreateCollection()">
              <mat-icon>add</mat-icon> New Collection
            </div>
            <mat-divider></mat-divider>
            <div class="ac-ctx-item ac-ctx-danger" (click)="deleteCollection(ctxCollection)">
              <mat-icon>delete</mat-icon> Delete
            </div>
          } @else if (ctxMenu().type === 'request') {
            <div class="ac-ctx-item" (click)="startRenameRequest(ctxRequest)">
              <mat-icon>edit</mat-icon> Rename
            </div>
            <div class="ac-ctx-item" (click)="duplicateRequest(ctxRequest)">
              <mat-icon>content_copy</mat-icon> Duplicate
            </div>
            <mat-divider></mat-divider>
            <div class="ac-ctx-item ac-ctx-danger" (click)="deleteRequest(ctxRequest)">
              <mat-icon>delete</mat-icon> Delete
            </div>
          }
        </div>
      }

      <!-- Rename request overlay dialog -->
      @if (showRenameReq()) {
        <div class="ac-overlay-form">
          <div class="ac-overlay-card">
            <h4>Rename Request</h4>
            <mat-form-field appearance="outline" class="ac-field-full">
              <mat-label>Request Name</mat-label>
              <input matInput [(ngModel)]="renameReqName" (keydown.enter)="confirmRenameRequest()" placeholder="New name" />
            </mat-form-field>
            <div class="ac-overlay-actions">
              <button mat-button (click)="cancelRename()">Cancel</button>
              <button mat-flat-button color="primary" (click)="confirmRenameRequest()" [disabled]="!renameReqName.trim()">
                Save
              </button>
            </div>
          </div>
        </div>
      }
    </div>
        </ng-template>
      </mat-tab>

      <!-- ============================================================
           TAB 2: COLLECTION RUNNER
           ============================================================ -->
      <mat-tab label="Runner">
        <ng-template matTabContent>
          <app-collection-runner />
        </ng-template>
      </mat-tab>

      <!-- ============================================================
           TAB 3: WORKSPACES
           ============================================================ -->
      <mat-tab label="Workspaces">
        <ng-template matTabContent>
          <app-workspace-manager />
        </ng-template>
      </mat-tab>

    </mat-tab-group>
  `,
  styles: [
    `
    /* ================================================================
       Outer tab group — full-height tabs for Request / Runner / Workspaces
       ================================================================ */
    .ac-outer-tabs {
      height: calc(100vh - var(--header-height, 56px) - 16px);
      display: flex;
      flex-direction: column;
    }
    .ac-outer-tabs ::ng-deep .mat-mdc-tab-body-wrapper {
      flex: 1;
      overflow: hidden;
    }
    .ac-outer-tabs ::ng-deep .mat-mdc-tab-body-content {
      overflow: hidden;
    }

    /* ================================================================
       Root grid layout — 3-panel
       ================================================================ */
    .ac-root {
      display: grid;
      grid-template-columns: 240px 1fr 1fr;
      height: calc(100vh - var(--header-height, 56px) - 16px);
      gap: 8px;
      padding: 8px;
      overflow: hidden;
    }
    @media (max-width: 1360px) {
      .ac-root { grid-template-columns: 220px 1fr 1fr; }
    }
    @media (max-width: 1100px) {
      .ac-root { grid-template-columns: 200px 1fr; }
    }
    @media (max-width: 768px) {
      .ac-root { grid-template-columns: 1fr; }
    }

    /* ================================================================
       Sidebar
       ================================================================ */
    .ac-sidebar {
      background: var(--bg-card);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-md);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .ac-sidebar-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border-secondary);
    }
    .ac-sidebar-head h3 {
      margin: 0;
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-secondary);
    }
    .ac-sidebar-head h4 {
      margin: 0;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-tertiary);
    }
    .ac-sidebar-actions { display: flex; gap: 2px; }
    .ac-sidebar-actions button mat-icon { font-size: 18px; width: 18px; height: 18px; }
    .ac-sub-head { border-top: none; padding: 6px 12px; }

    .ac-coll-list {
      flex: 1 1 auto;
      overflow-y: auto;
      padding: 4px;
    }
    .ac-coll-item {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px 8px;
      border-radius: var(--radius-sm);
      cursor: pointer;
      font-size: 13px;
      transition: background 0.15s;
    }
    .ac-coll-item:hover { background: var(--bg-hover); }
    .ac-coll-item.active { background: rgba(59, 130, 246, 0.12); color: var(--accent-primary); }
    .ac-coll-icon { font-size: 18px; width: 18px; height: 18px; color: var(--accent-warning); flex-shrink: 0; }
    .ac-coll-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .ac-coll-count {
      font-size: 11px;
      color: var(--text-tertiary);
      background: var(--bg-tertiary);
      padding: 0 6px;
      border-radius: 8px;
      line-height: 18px;
      flex-shrink: 0;
    }

    .ac-req-list {
      flex: 1;
      overflow-y: auto;
      padding: 2px 4px 4px;
    }
    .ac-req-item {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 5px 8px;
      border-radius: var(--radius-sm);
      cursor: pointer;
      font-size: 12px;
      transition: background 0.15s;
    }
    .ac-req-item:hover { background: var(--bg-hover); }
    .ac-req-item.active { background: rgba(59, 130, 246, 0.10); }
    .ac-req-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .ac-method-badge {
      font-family: var(--font-mono);
      font-size: 9px;
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 3px;
      text-transform: uppercase;
      min-width: 36px;
      text-align: center;
      flex-shrink: 0;
    }
    .ac-method-badge.get     { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
    .ac-method-badge.post    { background: rgba(34, 197, 94, 0.15);  color: #4ade80; }
    .ac-method-badge.put     { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
    .ac-method-badge.patch   { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
    .ac-method-badge.delete  { background: rgba(239, 68, 68, 0.15);  color: #f87171; }
    .ac-method-badge.options { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }
    .ac-method-badge.head    { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }

    .ac-empty-hint { padding: 12px; text-align: center; color: var(--text-tertiary); font-size: 12px; }

    /* Inline form */
    .ac-inline-form { padding: 8px; border-bottom: 1px solid var(--border-secondary); }
    .ac-inline-form mat-form-field { width: 100%; margin-bottom: 6px; }
    .ac-inline-actions { display: flex; gap: 6px; justify-content: flex-end; }

    /* ================================================================
       Request Panel
       ================================================================ */
    .ac-request-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-md);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      min-width: 0;
    }
    .ac-url-bar {
      display: flex;
      gap: 6px;
      align-items: center;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border-secondary);
      flex-wrap: wrap;
    }
    .ac-method-sel { width: 100px; flex-shrink: 0; }
    .ac-url-input { flex: 1; min-width: 120px; }
    .ac-send-btn { white-space: nowrap; flex-shrink: 0; }
    .ac-save-btn { flex-shrink: 0; }

    .ac-req-tabs {
      flex: 1;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .ac-req-tabs .mdc-tab-indicator { /* Material overrides inside component */ }
    .ac-tab-body {
      padding: 12px;
      overflow-y: auto;
      height: 100%;
      box-sizing: border-box;
    }

    /* Key-value editor */
    .ac-kv-editor { display: flex; flex-direction: column; gap: 4px; }
    .ac-kv-row { display: flex; align-items: center; gap: 6px; padding: 2px 0; }
    .ac-kv-row mat-checkbox { flex-shrink: 0; }
    .ac-kv-key {
      flex: 0 0 200px;
      background: var(--bg-input);
      color: var(--text-primary);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-sm);
      padding: 6px 8px;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .ac-kv-val {
      flex: 1;
      background: var(--bg-input);
      color: var(--text-primary);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-sm);
      padding: 6px 8px;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .ac-kv-del mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .ac-kv-add { width: 100%; margin-top: 6px; }
    .ac-presets { display: flex; align-items: center; gap: 4px; margin-top: 8px; flex-wrap: wrap; }
    .ac-preset-label { font-size: 11px; color: var(--text-tertiary); }
    .ac-presets button { font-size: 11px; min-width: auto; padding: 0 8px; height: 26px; line-height: 26px; }

    /* Body */
    .ac-body-toolbar { display: flex; align-items: center; gap: 6px; margin-bottom: 8px; }
    .ac-body-lang { width: 240px; }
    .ac-code-editor {
      width: 100%;
      min-height: 120px;
      background: var(--bg-input);
      color: var(--text-primary);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-md);
      padding: 10px;
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 1.5;
      resize: vertical;
      tab-size: 2;
      box-sizing: border-box;
    }
    .ac-code-editor:focus { outline: none; border-color: var(--accent-primary); }

    /* Auth */
    .ac-auth-type { width: 220px; margin-bottom: 12px; }
    .ac-auth-fields { display: flex; flex-direction: column; gap: 8px; }
    .ac-auth-field-full { width: 100%; }
    .ac-auth-info {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--text-tertiary);
      padding: 6px 0;
    }
    .ac-auth-info mat-icon { font-size: 16px; width: 16px; height: 16px; }
    .ac-auth-info code {
      background: var(--bg-tertiary);
      padding: 1px 5px;
      border-radius: 3px;
      font-family: var(--font-mono);
      font-size: 11px;
    }

    /* Script tab */
    .ac-script-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
      gap: 8px;
      flex-wrap: wrap;
    }
    .ac-script-hint { font-size: 11px; color: var(--text-tertiary); }
    .ac-script-hint code {
      background: var(--bg-tertiary);
      padding: 1px 4px;
      border-radius: 3px;
      font-size: 11px;
    }
    .ac-snippet-group { display: flex; gap: 4px; flex-wrap: wrap; }
    .ac-snippet-group button {
      font-size: 10px;
      min-width: auto;
      padding: 0 8px;
      height: 24px;
      line-height: 24px;
      background: var(--bg-tertiary);
      border-radius: 3px;
    }

    /* ================================================================
       Response Panel
       ================================================================ */
    .ac-response-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-md);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      min-width: 0;
      position: relative;
    }
    .ac-loading-bar { position: absolute; top: 0; left: 0; right: 0; border-radius: 0; z-index: 1; }

    .ac-resp-topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border-secondary);
      gap: 8px;
      flex-wrap: wrap;
      flex-shrink: 0;
    }
    .ac-resp-meta { display: flex; align-items: center; gap: 12px; }
    .ac-status-badge {
      font-family: var(--font-mono);
      font-weight: 700;
      font-size: 13px;
      padding: 2px 10px;
      border-radius: 4px;
    }
    .ac-status-badge.success  { color: var(--accent-success); background: rgba(34, 197, 94, 0.12); }
    .ac-status-badge.redirect { color: var(--accent-warning); background: rgba(245, 158, 11, 0.12); }
    .ac-status-badge.error    { color: var(--severity-critical); background: rgba(239, 68, 68, 0.12); }
    .ac-resp-stat {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: 12px;
      color: var(--text-secondary);
      font-family: var(--font-mono);
    }
    .ac-resp-stat mat-icon { font-size: 14px; width: 14px; height: 14px; }
    .ac-resp-actions { display: flex; gap: 2px; }

    .ac-resp-tabs {
      flex: 1;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }

    .ac-resp-body-wrap {
      height: 100%;
      display: flex;
      flex-direction: column;
    }
    .ac-body-format-bar {
      display: flex;
      gap: 2px;
      padding: 4px 8px;
      border-bottom: 1px solid var(--border-secondary);
      background: var(--bg-secondary);
      flex-shrink: 0;
    }
    .ac-body-format-bar button {
      font-size: 11px;
      min-width: auto;
      padding: 0 8px;
      height: 26px;
      line-height: 26px;
    }
    .ac-body-format-bar button.active { background: var(--accent-primary); color: white; }
    .ac-code-display {
      flex: 1;
      background: var(--bg-input);
      color: var(--text-primary);
      padding: 12px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-all;
      overflow: auto;
      margin: 0;
    }
    .ac-raw-body { color: var(--text-secondary); }
    .ac-preview-frame { width: 100%; flex: 1; border: none; background: white; }

    /* Response tables */
    .ac-resp-table-wrap { overflow: auto; height: 100%; }
    .ac-data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .ac-data-table thead th {
      position: sticky;
      top: 0;
      background: var(--bg-secondary);
      text-align: left;
      padding: 8px 10px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-tertiary);
      border-bottom: 1px solid var(--border-primary);
    }
    .ac-data-table tbody td { padding: 6px 10px; border-bottom: 1px solid var(--border-secondary); vertical-align: top; }
    .ac-hdr-name { font-family: var(--font-mono); font-weight: 600; color: var(--accent-primary); white-space: nowrap; }
    .ac-hdr-val { font-family: var(--font-mono); font-size: 11px; word-break: break-all; }
    .ac-cookie-val { font-family: var(--font-mono); font-size: 11px; color: var(--accent-success); }
    .ac-empty-cell { text-align: center; color: var(--text-tertiary); padding: 24px !important; }

    /* Test results */
    .ac-test-summary {
      display: flex;
      gap: 16px;
      padding: 10px 12px;
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border-primary);
      font-size: 13px;
      font-weight: 600;
    }
    .ac-test-pass { color: var(--accent-success); }
    .ac-test-fail { color: var(--severity-critical); }
    .ac-test-total { color: var(--text-tertiary); }
    .ac-test-list { padding: 4px 0; }
    .ac-test-row {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border-secondary);
    }
    .ac-test-row mat-icon { font-size: 18px; width: 18px; height: 18px; flex-shrink: 0; margin-top: 1px; }
    .ac-test-pass mat-icon { color: var(--accent-success); }
    .ac-test-fail mat-icon { color: var(--severity-critical); }
    .ac-test-name { font-size: 13px; font-weight: 500; }
    .ac-test-err { display: block; font-size: 11px; color: var(--text-tertiary); margin-top: 2px; font-family: var(--font-mono); }
    .ac-empty-state-small {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
      color: var(--text-tertiary);
      text-align: center;
    }
    .ac-empty-state-small mat-icon { font-size: 40px; width: 40px; height: 40px; margin-bottom: 8px; opacity: 0.5; }
    .ac-empty-state-small p { margin: 0; font-size: 13px; }

    /* Empty state */
    .ac-empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      padding: 40px;
      text-align: center;
      color: var(--text-tertiary);
    }
    .ac-empty-state mat-icon { font-size: 56px; width: 56px; height: 56px; margin-bottom: 12px; opacity: 0.4; }
    .ac-empty-state h3 { margin: 0 0 6px; color: var(--text-secondary); font-size: 16px; }
    .ac-empty-state p { margin: 0; font-size: 13px; }

    /* ================================================================
       Context menu (right-click)
       ================================================================ */
    .ac-ctx-overlay { position: fixed; inset: 0; z-index: 999; }
    .ac-ctx-menu {
      position: fixed;
      z-index: 1000;
      background: var(--bg-card);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-lg);
      min-width: 180px;
      padding: 4px;
    }
    .ac-ctx-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      font-size: 13px;
      cursor: pointer;
      border-radius: var(--radius-sm);
      transition: background 0.1s;
    }
    .ac-ctx-item:hover { background: var(--bg-hover); }
    .ac-ctx-item mat-icon { font-size: 18px; width: 18px; height: 18px; color: var(--text-secondary); }
    .ac-ctx-danger { color: var(--severity-critical); }
    .ac-ctx-danger mat-icon { color: var(--severity-critical); }

    /* ================================================================
       Overlay dialog (rename request)
       ================================================================ */
    .ac-overlay-form {
      position: fixed;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, 0.5);
      z-index: 1001;
    }
    .ac-overlay-card {
      background: var(--bg-card);
      border: 1px solid var(--border-primary);
      border-radius: var(--radius-lg);
      padding: 24px;
      width: 400px;
      max-width: 90vw;
      box-shadow: var(--shadow-lg);
    }
    .ac-overlay-card h4 { margin: 0 0 16px; font-size: 16px; }
    .ac-field-full { width: 100%; }
    .ac-overlay-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
    `,
  ],
})
export class ApiClientComponent implements OnInit {
  /* ------------------------------------------------------------------ */
  /*  Dependencies                                                       */
  /* ------------------------------------------------------------------ */
  private http = inject(HttpClient);
  private api = inject(ApiService);
  private notify = inject(NotificationService);
  private scriptExecutor = inject(ScriptExecutorService);

  /* ------------------------------------------------------------------ */
  /*  Constants                                                         */
  /* ------------------------------------------------------------------ */
  readonly methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
  readonly presetHeaderKeys = [
    'Content-Type',
    'Authorization',
    'Accept',
    'Cache-Control',
    'X-API-Key',
    'User-Agent',
  ];

  /* ------------------------------------------------------------------ */
  /*  Sidebar state                                                      */
  /* ------------------------------------------------------------------ */
  collections = signal<CollItem[]>([]);
  selectedCollection = signal<CollItem | null>(null);
  requestsInColl = signal<CollRequest[]>([]);
  selectedRequest = signal<CollRequest | null>(null);

  showCreateColl = signal(false);
  newCollName = '';

  showRenameColl = signal(false);
  renameCollName = '';
  renameTargetCollection: CollItem | null = null;

  showRenameReq = signal(false);
  renameReqName = '';
  renameTargetRequest: CollRequest | null = null;

  /* ------------------------------------------------------------------ */
  /*  Request builder state                                              */
  /* ------------------------------------------------------------------ */
  method = 'GET';
  url = '';
  headers = signal<Kvp[]>([]);
  body = '';
  bodyLanguage: string = 'json';
  params = signal<Kvp[]>([]);
  auth: AuthCfg = {
    type: 'none',
    bearerToken: '',
    basicUsername: '',
    basicPassword: '',
    apiKeyKey: '',
    apiKeyValue: '',
    apiKeyAddTo: 'header',
    oauth2Token: '',
    oauth2TokenType: 'Bearer',
  };
  preScript = '';
  testScript = '';
  requestTabIndex = 0;
  outerTabIndex = 0;

  /* ------------------------------------------------------------------ */
  /*  Response state                                                     */
  /* ------------------------------------------------------------------ */
  loading = signal(false);
  response = signal<ApiResponseData | null>(null);
  responseTabIndex = 0;
  viewMode = signal<'pretty' | 'raw' | 'preview'>('pretty');
  testResults = signal<TestResultItem[]>([]);

  /* ------------------------------------------------------------------ */
  /*  Context menu state                                                 */
  /* ------------------------------------------------------------------ */
  ctxMenu = signal<ContextMenuState>({
    visible: false,
    x: 0,
    y: 0,
    type: 'collection',
    item: null,
  });

  // Typed views of the context-menu target (Angular templates can't do `as` casts).
  get ctxCollection(): CollItem | null { return this.ctxMenu().item as CollItem | null; }
  get ctxRequest(): CollRequest | null { return this.ctxMenu().item as CollRequest | null; }

  /* ------------------------------------------------------------------ */
  /*  Lifecycle                                                          */
  /* ------------------------------------------------------------------ */
  ngOnInit() {
    this.loadCollections();
  }

  /* ================================================================ */
  /*  COLLECTIONS                                                       */
  /* ================================================================ */

  loadCollections() {
    this.api.get<{ data: CollItem[] }>('/api-client/collections').subscribe({
      next: (res) => this.collections.set(res.data || []),
      error: () => this.notify.error('Failed to load collections'),
    });
  }

  selectCollection(c: CollItem) {
    this.selectedCollection.set(c);
    this.selectedRequest.set(null);
    this.resetForm();
    this.api.get<any>(`/api-client/collections/${c.id}`).subscribe({
      next: (res) => {
        const reqs: CollRequest[] = (res.requests || []).sort(
          (a: CollRequest, b: CollRequest) => (a.sort_order ?? 0) - (b.sort_order ?? 0),
        );
        this.requestsInColl.set(reqs);
        this.selectedCollection.update((coll) => {
          if (coll) coll.request_count = reqs.length;
          return coll;
        });
      },
      error: () => this.notify.error('Failed to load collection requests'),
    });
  }

  /* -- Create -- */
  startCreateCollection() {
    this.showCreateColl.set(true);
    this.newCollName = '';
    this.showRenameColl.set(false);
  }

  cancelCreateCollection() {
    this.showCreateColl.set(false);
    this.newCollName = '';
  }

  createCollection() {
    const name = this.newCollName.trim();
    if (!name) return;
    this.api.post<{ data: CollItem }>('/api-client/collections', { name }).subscribe({
      next: () => {
        this.notify.success('Collection created');
        this.showCreateColl.set(false);
        this.newCollName = '';
        this.loadCollections();
      },
      error: (err) =>
        this.notify.error('Failed to create collection: ' + (err.message || 'Unknown error')),
    });
  }

  /* -- Rename -- */
  startRenameCollection(item: CollItem | null) {
    if (!item) return;
    this.closeContextMenu();
    this.renameTargetCollection = item;
    this.renameCollName = item.name;
    this.showRenameColl.set(true);
  }

  confirmRenameCollection() {
    const coll = this.renameTargetCollection;
    if (!coll || !this.renameCollName.trim()) return;
    this.api
      .patch(`/api-client/collections/${coll.id}`, { name: this.renameCollName.trim() })
      .subscribe({
        next: () => {
          this.notify.success('Collection renamed');
          this.showRenameColl.set(false);
          this.renameTargetCollection = null;
          this.renameCollName = '';
          this.loadCollections();
        },
        error: (err) =>
          this.notify.error('Failed to rename collection: ' + (err.message || 'Unknown error')),
      });
  }

  /* -- Delete -- */
  deleteCollection(item: CollItem | null) {
    if (!item) return;
    this.closeContextMenu();
    if (!confirm(`Delete collection "${item.name}"? All requests inside will be deleted.`)) return;
    this.api.delete(`/api-client/collections/${item.id}`).subscribe({
      next: () => {
        this.notify.success('Collection deleted');
        if (this.selectedCollection()?.id === item.id) {
          this.selectedCollection.set(null);
          this.requestsInColl.set([]);
          this.selectedRequest.set(null);
          this.resetForm();
        }
        this.loadCollections();
      },
      error: (err) =>
        this.notify.error('Failed to delete collection: ' + (err.message || 'Unknown error')),
    });
  }

  /* ================================================================ */
  /*  REQUESTS (inside a collection)                                    */
  /* ================================================================ */

  loadRequest(r: CollRequest) {
    this.selectedRequest.set(r);
    this.method = r.method || 'GET';
    this.url = r.url || '';
    this.headers.set(this.parseKvpJson(r.headers));
    this.body = r.body || '';
    this.bodyLanguage = r.body_language || 'json';
    this.params.set(this.parseKvpJson(r.query_params));

    if (r.auth) {
      try {
        this.auth = { ...this.auth, ...JSON.parse(r.auth) };
      } catch {
        /* keep defaults */
      }
    }

    this.preScript = r.pre_script || '';
    this.testScript = r.post_script || '';

    this.syncAuthToHeaders();
    this.clearResponse();
    this.requestTabIndex = 0;
  }

  saveRequest() {
    const coll = this.selectedCollection();
    if (!coll) {
      this.notify.warning('Select a collection first');
      return;
    }
    if (!this.url.trim()) {
      this.notify.warning('URL is required');
      return;
    }

    const payload = {
      name: this.selectedRequest()?.name || this.extractNameFromUrl(),
      method: this.method,
      url: this.url.trim(),
      headers: this.serializeKvp(this.headers().filter((h) => h.enabled)),
      body: this.body,
      body_language: this.bodyLanguage,
      query_params: this.serializeKvp(this.params().filter((p) => p.enabled)),
      auth: JSON.stringify(this.auth),
      pre_script: this.preScript,
      post_script: this.testScript,
    };

    const existing = this.selectedRequest();
    if (existing) {
      this.api
        .patch(`/api-client/collections/${coll.id}/requests/${existing.id}`, payload)
        .subscribe({
          next: () => {
            this.notify.success('Request updated');
            this.selectCollection(coll);
          },
          error: (err) =>
            this.notify.error('Failed to update request: ' + (err.message || 'Unknown error')),
        });
    } else {
      this.api.post(`/api-client/collections/${coll.id}/requests`, payload).subscribe({
        next: () => {
          this.notify.success('Request saved');
          this.selectCollection(coll);
        },
        error: (err) =>
          this.notify.error('Failed to save request: ' + (err.message || 'Unknown error')),
      });
    }
  }

  addRequest() {
    const coll = this.selectedCollection();
    if (!coll) {
      this.notify.warning('Select a collection first');
      return;
    }
    const payload = {
      name: 'Untitled Request',
      method: 'GET',
      url: '',
      headers: '{}',
      body: '',
      body_language: 'json',
      query_params: '{}',
      auth: '{}',
      pre_script: '',
      post_script: '',
    };
    this.api.post<{ data: CollRequest }>(`/api-client/collections/${coll.id}/requests`, payload).subscribe({
      next: (res) => {
        this.notify.success('New request created');
        this.selectCollection(coll);
        if (res.data) this.loadRequest(res.data);
      },
      error: (err) =>
        this.notify.error('Failed to create request: ' + (err.message || 'Unknown error')),
    });
  }

  duplicateRequest(r: CollRequest | null) {
    if (!r) return;
    this.closeContextMenu();
    const coll = this.selectedCollection();
    if (!coll) return;
    this.api
      .post(`/api-client/collections/${coll.id}/requests`, {
        name: (r.name || 'Request') + ' (copy)',
        method: r.method,
        url: r.url,
        headers: r.headers,
        body: r.body,
        body_language: r.body_language,
        query_params: r.query_params,
        auth: r.auth,
        pre_script: r.pre_script,
        post_script: r.post_script,
      })
      .subscribe({
        next: () => {
          this.notify.success('Request duplicated');
          this.selectCollection(coll);
        },
        error: (err) =>
          this.notify.error('Failed to duplicate request: ' + (err.message || 'Unknown error')),
      });
  }

  deleteRequest(r: CollRequest | null) {
    if (!r) return;
    this.closeContextMenu();
    const coll = this.selectedCollection();
    if (!coll) return;
    if (!confirm(`Delete request "${r.name || r.url}"?`)) return;
    this.api.delete(`/api-client/collections/${coll.id}/requests/${r.id}`).subscribe({
      next: () => {
        this.notify.success('Request deleted');
        if (this.selectedRequest()?.id === r.id) {
          this.selectedRequest.set(null);
          this.resetForm();
        }
        this.selectCollection(coll);
      },
      error: (err) =>
        this.notify.error('Failed to delete request: ' + (err.message || 'Unknown error')),
    });
  }

  startRenameRequest(r: CollRequest | null) {
    if (!r) return;
    this.closeContextMenu();
    this.renameTargetRequest = r;
    this.renameReqName = r.name || '';
    this.showRenameReq.set(true);
  }

  confirmRenameRequest() {
    const r = this.renameTargetRequest;
    const coll = this.selectedCollection();
    if (!r || !coll || !this.renameReqName.trim()) return;
    this.api
      .patch(`/api-client/collections/${coll.id}/requests/${r.id}`, { name: this.renameReqName.trim() })
      .subscribe({
        next: () => {
          this.notify.success('Request renamed');
          this.showRenameReq.set(false);
          this.renameTargetRequest = null;
          this.renameReqName = '';
          this.selectCollection(coll);
        },
        error: (err) =>
          this.notify.error('Failed to rename request: ' + (err.message || 'Unknown error')),
      });
  }

  cancelRename() {
    this.showRenameColl.set(false);
    this.showRenameReq.set(false);
    this.renameTargetCollection = null;
    this.renameTargetRequest = null;
    this.renameCollName = '';
    this.renameReqName = '';
  }

  /* ================================================================ */
  /*  KEY-VALUE HELPERS                                                */
  /* ================================================================ */

  addHeader() {
    this.headers.update((h) => [...h, { key: '', value: '', enabled: true }]);
  }

  removeHeader(index: number) {
    this.headers.update((h) => h.filter((_, i) => i !== index));
  }

  addPresetHeader(name: string) {
    const existing = this.headers().find(
      (h) => h.key.toLowerCase() === name.toLowerCase() && h.enabled,
    );
    if (existing) {
      this.notify.info(`Header "${name}" already exists`);
      return;
    }
    this.headers.update((h) => [...h, { key: name, value: '', enabled: true }]);
  }

  addParam() {
    this.params.update((p) => [...p, { key: '', value: '', enabled: true }]);
  }

  removeParam(index: number) {
    this.params.update((p) => p.filter((_, i) => i !== index));
  }

  /* ================================================================ */
  /*  AUTH                                                             */
  /* ================================================================ */

  private syncAuthToHeaders() {
    const authHeaderNames = ['authorization', 'x-api-key'];
    this.headers.update((h) => h.filter((kvp) => !authHeaderNames.includes(kvp.key.toLowerCase())));

    switch (this.auth.type) {
      case 'bearer':
        if (this.auth.bearerToken) {
          this.headers.update((h) => [
            ...h,
            { key: 'Authorization', value: `Bearer ${this.auth.bearerToken}`, enabled: true },
          ]);
        }
        break;
      case 'basic':
        if (this.auth.basicUsername && this.auth.basicPassword) {
          const encoded = btoa(`${this.auth.basicUsername}:${this.auth.basicPassword}`);
          this.headers.update((h) => [
            ...h,
            { key: 'Authorization', value: `Basic ${encoded}`, enabled: true },
          ]);
        }
        break;
      case 'api-key':
        if (this.auth.apiKeyKey && this.auth.apiKeyValue && this.auth.apiKeyAddTo === 'header') {
          this.headers.update((h) => [
            ...h,
            { key: this.auth.apiKeyKey, value: this.auth.apiKeyValue, enabled: true },
          ]);
        }
        break;
      case 'oauth2':
        if (this.auth.oauth2Token) {
          this.headers.update((h) => [
            ...h,
            {
              key: 'Authorization',
              value: `${this.auth.oauth2TokenType} ${this.auth.oauth2Token}`,
              enabled: true,
            },
          ]);
        }
        break;
    }
  }

  /* ================================================================ */
  /*  TEST SNIPPETS                                                    */
  /* ================================================================ */

  insertSnippet(type: string) {
    const snippets: Record<string, string> = {
      status200: `pm.test('Status is 200', () => {\n  pm.expect(pm.response.status).to.equal(200);\n});`,
      statusCode: `pm.test('Status code is successful', () => {\n  pm.expect(pm.response.status).to.be.below(400);\n});`,
      jsonBody: `pm.test('Response has JSON body', () => {\n  const body = pm.response.json();\n  pm.expect(body).to.exist;\n});`,
      responseTime: `pm.test('Response time is acceptable', () => {\n  pm.expect(pm.response.responseTime).to.be.below(200);\n});`,
      headerExists: `pm.test('Response has required header', () => {\n  pm.expect(pm.response.headers['content-type']).to.exist;\n});`,
      bodyContains: `pm.test('Body contains expected text', () => {\n  pm.expect(pm.response.text()).to.include('success');\n});`,
    };
    const snippet = snippets[type];
    if (!snippet) return;
    this.testScript = (this.testScript ? this.testScript + '\n\n' : '') + snippet;
  }

  /* ================================================================ */
  /*  BODY HELPERS                                                     */
  /* ================================================================ */

  formatBody() {
    if (!this.body.trim()) return;
    if (this.bodyLanguage === 'json') {
      try {
        this.body = JSON.stringify(JSON.parse(this.body), null, 2);
      } catch {
        this.notify.warning('Invalid JSON');
      }
    } else if (this.bodyLanguage === 'xml') {
      this.body = this.formatXml(this.body);
    }
  }

  private formatXml(xml: string): string {
    let out = '';
    let indent = 0;
    const lines = xml.replace(/>\s*</g, '>\n<').split('\n');
    for (const line of lines) {
      const t = line.trim();
      if (!t) continue;
      if (t.match(/^<\/\w/)) indent--;
      out += '  '.repeat(Math.max(0, indent)) + t + '\n';
      if (t.match(/^<\w[^>]*[^/]>$/) && !t.match(/^<\?/)) indent++;
    }
    return out;
  }

  clearBody() {
    this.body = '';
  }

  clearPreScript() {
    this.preScript = '';
  }

  onMethodChange() {
    /* no-op — users may switch methods without clearing everything */
  }

  /* ================================================================ */
  /*  SEND REQUEST                                                     */
  /* ================================================================ */

  sendRequest() {
    const url = this.url.trim();
    if (!url) {
      this.notify.warning('Enter a URL');
      return;
    }

    this.loading.set(true);
    this.response.set(null);
    this.testResults.set([]);

    const startTime = performance.now();

    // Sync auth into headers
    this.syncAuthToHeaders();

    // Build header map from KVP
    const resolvedHeaders: Record<string, string> = {};
    for (const h of this.headers()) {
      if (h.enabled && h.key.trim()) {
        resolvedHeaders[h.key.trim()] = h.value;
      }
    }

    // Build query params
    let finalUrl = url;
    const activeParams = this.params().filter((p) => p.enabled && p.key.trim());
    if (activeParams.length > 0) {
      const sp = new URLSearchParams();
      for (const p of activeParams) sp.append(p.key.trim(), p.value);
      const qs = sp.toString();
      if (qs) finalUrl += (finalUrl.includes('?') ? '&' : '?') + qs;
    }

    // API Key as query param
    if (this.auth.type === 'api-key' && this.auth.apiKeyAddTo === 'query' && this.auth.apiKeyKey && this.auth.apiKeyValue) {
      finalUrl +=
        (finalUrl.includes('?') ? '&' : '?') +
        `${encodeURIComponent(this.auth.apiKeyKey)}=${encodeURIComponent(this.auth.apiKeyValue)}`;
    }

    // Pre-request script
    if (this.preScript.trim()) {
      const preResult = this.scriptExecutor.execute(this.preScript, {
        request: { method: this.method, url: finalUrl, headers: resolvedHeaders, body: this.body },
      });
      if (preResult.logs.length) {
        console.debug('[pre-request script]', preResult.logs);
      }
    }

    // Build body for methods that support it
    const bodyMethods = ['POST', 'PUT', 'PATCH'];
    let requestBody: unknown = undefined;
    if (bodyMethods.includes(this.method.toUpperCase()) && this.body) {
      if (this.bodyLanguage === 'json') {
        try {
          requestBody = JSON.parse(this.body);
        } catch {
          requestBody = this.body;
        }
      } else {
        requestBody = this.body;
      }
    }

    const httpHeaders = new HttpHeaders(resolvedHeaders);

    this.http
      .request(this.method, finalUrl, {
        body: bodyMethods.includes(this.method.toUpperCase()) ? requestBody : undefined,
        headers: httpHeaders,
        observe: 'response',
        responseType: 'json',
      })
      .subscribe({
        next: (res: HttpResponse<unknown>) => {
          const timing = Math.round(performance.now() - startTime);
          const respHeaders: Record<string, string> = {};
          res.headers.keys().forEach((k) => {
            const v = res.headers.get(k);
            if (v) respHeaders[k] = v;
          });
          const bodyStr =
            typeof res.body === 'string' ? res.body : JSON.stringify(res.body, null, 2);
          const size = new TextEncoder().encode(bodyStr).length;
          const contentType = res.headers.get('content-type') || '';

          const resp: ApiResponseData = {
            status: res.status,
            statusText: res.statusText || '',
            body: bodyStr,
            headers: respHeaders,
            timing,
            size,
            contentType,
          };

          this.executeTestScript(finalUrl, resolvedHeaders, resp);
          this.response.set(resp);
          this.viewMode.set('pretty');
          this.responseTabIndex = 0;
          this.loading.set(false);
        },
        error: (err) => {
          const timing = Math.round(performance.now() - startTime);
          const errBody = err.error
            ? typeof err.error === 'string'
              ? err.error
              : JSON.stringify(err.error, null, 2)
            : err.message || 'Request failed';

          const respHeaders: Record<string, string> = {};
          if (err.headers) {
            err.headers.keys().forEach((k: string) => {
              const v = err.headers.get(k);
              if (v) respHeaders[k] = v;
            });
          }

          const size = new TextEncoder().encode(errBody).length;
          const resp: ApiResponseData = {
            status: err.status || 0,
            statusText: err.statusText || 'Error',
            body: errBody,
            headers: respHeaders,
            timing,
            size,
            contentType: err.headers?.get('content-type') || '',
          };

          this.executeTestScript(finalUrl, resolvedHeaders, resp);
          this.response.set(resp);
          this.viewMode.set('pretty');
          this.responseTabIndex = 0;
          this.loading.set(false);
        },
      });
  }

  private executeTestScript(
    requestUrl: string,
    requestHeaders: Record<string, string>,
    resp: ApiResponseData,
  ) {
    if (!this.testScript.trim()) return;
    const result = this.scriptExecutor.execute(this.testScript, {
      request: {
        method: this.method,
        url: requestUrl,
        headers: requestHeaders,
        body: this.body,
      },
      response: {
        status: resp.status,
        statusText: resp.statusText,
        body: resp.body,
        headers: resp.headers,
        responseTime: resp.timing,
      },
    });
    this.testResults.set(result.tests);
  }

  /* ================================================================ */
  /*  RESPONSE HELPERS                                                 */
  /* ================================================================ */

  clearResponse() {
    this.response.set(null);
    this.testResults.set([]);
    this.viewMode.set('pretty');
  }

  copyResponse() {
    const r = this.response();
    if (!r) return;
    navigator.clipboard.writeText(r.body).then(
      () => this.notify.success('Response body copied'),
      () => this.notify.error('Failed to copy'),
    );
  }

  downloadResponse() {
    const r = this.response();
    if (!r) return;
    const ext = r.contentType.includes('json')
      ? 'json'
      : r.contentType.includes('xml')
        ? 'xml'
        : r.contentType.includes('html')
          ? 'html'
          : 'txt';
    const blob = new Blob([r.body], { type: r.contentType || 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `response-${Date.now()}.${ext}`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  setViewMode(mode: 'pretty' | 'raw' | 'preview') {
    this.viewMode.set(mode);
  }

  prettyResponseBody(): string {
    const r = this.response();
    if (!r) return '';
    const ct = r.contentType.toLowerCase();
    if (ct.includes('json')) {
      try {
        return JSON.stringify(JSON.parse(r.body), null, 2);
      } catch {
        return r.body;
      }
    }
    if (ct.includes('xml') || ct.includes('html')) {
      return this.formatXml(r.body);
    }
    return r.body;
  }

  /* -- Response headers as array -- */
  respHeadersArr(): Array<{ key: string; value: string }> {
    const r = this.response();
    if (!r) return [];
    return Object.entries(r.headers).map(([key, value]) => ({ key, value }));
  }

  /* -- Response cookies -- */
  responseCookies(): ParsedCookie[] {
    const r = this.response();
    if (!r) return [];
    const setCookie = r.headers['set-cookie'] || r.headers['Set-Cookie'] || '';
    if (!setCookie) return [];
    return this.parseSetCookieHeader(setCookie);
  }

  private parseSetCookieHeader(header: string): ParsedCookie[] {
    const cookies: ParsedCookie[] = [];

    // Split on comma but be mindful of Expires dates that contain commas
    const parts: string[] = [];
    let buf = '';
    let inQuoted = false;
    for (let i = 0; i < header.length; i++) {
      const ch = header[i];
      if (ch === '"') {
        inQuoted = !inQuoted;
        buf += ch;
      } else if (ch === ',' && !inQuoted) {
        const next = header.slice(i + 1).trimStart();
        if (next && /^[a-zA-Z]/.test(next)) {
          parts.push(buf);
          buf = '';
        } else {
          buf += ch;
        }
      } else {
        buf += ch;
      }
    }
    if (buf.trim()) parts.push(buf);

    for (const part of parts) {
      const parsed = this.parseSingleCookie(part.trim());
      if (parsed) cookies.push(parsed);
    }
    return cookies;
  }

  private parseSingleCookie(str: string): ParsedCookie | null {
    const result: ParsedCookie = {
      name: '',
      value: '',
      domain: '',
      path: '',
      secure: false,
      httpOnly: false,
    };
    const semi = str.indexOf(';');
    const nv = semi >= 0 ? str.slice(0, semi) : str;
    const eq = nv.indexOf('=');
    if (eq < 0) return null;
    result.name = nv.slice(0, eq).trim();
    result.value = nv.slice(eq + 1).trim();

    if (semi >= 0) {
      const attrs = str.slice(semi + 1).split(';');
      for (const attr of attrs) {
        const a = attr.trim();
        const ae = a.indexOf('=');
        const key = ae >= 0 ? a.slice(0, ae).trim().toLowerCase() : a.trim().toLowerCase();
        const val = ae >= 0 ? a.slice(ae + 1).trim() : '';
        switch (key) {
          case 'domain':
            result.domain = val;
            break;
          case 'path':
            result.path = val;
            break;
          case 'secure':
            result.secure = true;
            break;
          case 'httponly':
            result.httpOnly = true;
            break;
        }
      }
    }
    return result;
  }

  /* -- Test result counts -- */
  testPassCount(): number {
    return this.testResults().filter((t) => t.passed).length;
  }

  testFailCount(): number {
    return this.testResults().filter((t) => !t.passed).length;
  }

  /* ================================================================ */
  /*  UTILITIES                                                        */
  /* ================================================================ */

  formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const size = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
    return `${size} ${units[i]}`;
  }

  private extractNameFromUrl(): string {
    try {
      const u = new URL(this.url);
      return u.pathname.split('/').filter(Boolean).pop() || u.hostname;
    } catch {
      return this.url.slice(0, 40);
    }
  }

  private parseKvpJson(jsonStr: string): Kvp[] {
    if (!jsonStr) return [];
    try {
      const obj = JSON.parse(jsonStr);
      if (typeof obj === 'object' && !Array.isArray(obj)) {
        return Object.entries(obj).map(([key, value]) => ({
          key,
          value: String(value ?? ''),
          enabled: true,
        }));
      }
      return [];
    } catch {
      return [];
    }
  }

  private serializeKvp(entries: Kvp[]): string {
    const obj: Record<string, string> = {};
    for (const e of entries) {
      if (e.key.trim()) obj[e.key.trim()] = e.value;
    }
    return JSON.stringify(obj);
  }

  private resetForm() {
    this.method = 'GET';
    this.url = '';
    this.headers.set([]);
    this.body = '';
    this.bodyLanguage = 'json';
    this.params.set([]);
    this.auth = {
      type: 'none',
      bearerToken: '',
      basicUsername: '',
      basicPassword: '',
      apiKeyKey: '',
      apiKeyValue: '',
      apiKeyAddTo: 'header',
      oauth2Token: '',
      oauth2TokenType: 'Bearer',
    };
    this.preScript = '';
    this.testScript = '';
    this.clearResponse();
    this.requestTabIndex = 0;
  }

  /* ================================================================ */
  /*  CONTEXT MENU                                                     */
  /* ================================================================ */

  openContextMenu(
    event: MouseEvent,
    type: 'collection' | 'request',
    item: CollItem | CollRequest,
  ) {
    event.preventDefault();
    this.ctxMenu.set({ visible: true, x: event.clientX, y: event.clientY, type, item });
  }

  closeContextMenu() {
    this.ctxMenu.set({ visible: false, x: 0, y: 0, type: 'collection', item: null });
  }

  @HostListener('document:keydown.escape')
  onEscape() {
    this.closeContextMenu();
  }
}
