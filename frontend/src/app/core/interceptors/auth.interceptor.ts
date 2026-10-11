import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { environment } from '../../../environments/environment';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()[\]\\/+^]/g, '\\$&') + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

function isApiRequest(url: string): boolean {
  try {
    const apiOrigin = new URL(environment.apiUrl, window.location.origin).origin;
    return new URL(url, window.location.origin).origin === apiOrigin;
  } catch {
    return false;
  }
}

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);

  let authReq = req;
  // Only send credentials (HttpOnly auth cookies) and the CSRF token to our OWN
  // API. The API-client feature lets users target arbitrary hosts — those must
  // never receive our session cookies or CSRF token.
  if (isApiRequest(req.url)) {
    const mutating = !SAFE_METHODS.has(req.method.toUpperCase());
    const csrf = readCookie('csrf_token');
    authReq = req.clone({
      withCredentials: true,
      setHeaders: mutating && csrf ? { 'X-CSRF-Token': csrf } : {},
    });
  }

  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      // Don't auto-logout on auth-flow endpoints (login/refresh/me handle their
      // own 401s, e.g. the refresh retry), which would otherwise cause a loop.
      const isAuthFlow = /\/auth\/(login|refresh|me)\b/.test(req.url);
      if (error.status === 401 && !isAuthFlow) {
        authService.logout();
      }
      return throwError(() => error);
    }),
  );
};
