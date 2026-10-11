import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, catchError, of, map, switchMap } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  orgId: string;
  orgName: string;
  permissions: string[];
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

// Auth is cookie-based: the backend sets HttpOnly access/refresh cookies that the
// browser sends automatically (the interceptor adds withCredentials + the CSRF
// header). No tokens are stored in JS-accessible storage, so an XSS bug cannot
// exfiltrate them.
@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);

  private state = signal<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
  });

  readonly user = computed(() => this.state().user);
  readonly isAuthenticated = computed(() => this.state().isAuthenticated);
  readonly isLoading = computed(() => this.state().isLoading);

  login(email: string, password: string): Observable<{ user: User }> {
    return this.http.post<{ user: User; csrfToken: string }>(
      `${environment.apiUrl}/auth/login`,
      { email, password },
    ).pipe(
      tap((response) => {
        this.state.set({ user: response.user, isAuthenticated: true, isLoading: false });
        this.router.navigate(['/dashboard']);
      }),
    );
  }

  register(data: { email: string; password: string; name: string; organizationName?: string }): Observable<{ user: User }> {
    return this.http.post<{ user: User; csrfToken: string }>(
      `${environment.apiUrl}/auth/register`,
      data,
    ).pipe(
      tap((response) => {
        this.state.set({ user: response.user, isAuthenticated: true, isLoading: false });
        this.router.navigate(['/dashboard']);
      }),
    );
  }

  logout(): void {
    // Cookies are cleared server-side; always attempt it, then reset local state.
    this.http.post(`${environment.apiUrl}/auth/logout`, {}).subscribe({
      error: () => {/* ignore — clear local state regardless */},
    });
    this.state.set({ user: null, isAuthenticated: false, isLoading: false });
    this.router.navigate(['/login']);
  }

  checkAuth(): void {
    this.verifySession().subscribe();
  }

  /**
   * Resolves the current session against the HttpOnly cookies: tries /me, and on
   * failure attempts a refresh then /me again. Emits true if authenticated.
   * Used by the route guard (the SPA can't read the HttpOnly token directly).
   */
  verifySession(): Observable<boolean> {
    return this.http.get<User>(`${environment.apiUrl}/auth/me`).pipe(
      map((user) => {
        this.state.set({ user, isAuthenticated: true, isLoading: false });
        return true;
      }),
      catchError(() =>
        this.http.post<{ csrfToken: string }>(`${environment.apiUrl}/auth/refresh`, {}).pipe(
          switchMap(() => this.http.get<User>(`${environment.apiUrl}/auth/me`)),
          map((user) => {
            this.state.set({ user, isAuthenticated: true, isLoading: false });
            return true;
          }),
          catchError(() => {
            this.state.set({ user: null, isAuthenticated: false, isLoading: false });
            return of(false);
          }),
        ),
      ),
    );
  }

  hasPermission(permission: string): boolean {
    const user = this.user();
    return user?.permissions?.includes(permission) ?? false;
  }

  hasRole(role: string): boolean {
    return this.user()?.role === role;
  }
}
