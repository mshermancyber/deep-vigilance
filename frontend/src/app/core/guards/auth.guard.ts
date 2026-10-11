import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { map } from 'rxjs';
import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  // Auth tokens are HttpOnly cookies the SPA can't read, so verify the session
  // against the backend (which falls back to a refresh) before deciding.
  return authService.verifySession().pipe(
    map((ok) => (ok ? true : router.createUrlTree(['/login']))),
  );
};
