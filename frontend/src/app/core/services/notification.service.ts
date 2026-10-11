import { Injectable, inject } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';

@Injectable({ providedIn: 'root' })
export class NotificationService {
  private snackBar = inject(MatSnackBar);
  private dialog = inject(MatDialog);

  success(message: string): void { this.snackBar.open(message, 'Close', { duration: 4000, panelClass: 'snackbar-success', horizontalPosition: 'right', verticalPosition: 'top' }); }
  error(message: string): void { this.snackBar.open(message, 'Close', { duration: 8000, panelClass: 'snackbar-error', horizontalPosition: 'right', verticalPosition: 'top' }); }
  warning(message: string): void { this.snackBar.open(message, 'Close', { duration: 6000, panelClass: 'snackbar-warning', horizontalPosition: 'right', verticalPosition: 'top' }); }
  info(message: string): void { this.snackBar.open(message, 'Close', { duration: 3000, panelClass: 'snackbar-info', horizontalPosition: 'right', verticalPosition: 'top' }); }
  confirm(title: string, message: string): Promise<boolean> { return Promise.resolve(window.confirm(`${title}\n\n${message}`)); }
}
