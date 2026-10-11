import { Injectable, signal } from '@angular/core';

export type Theme = 'dark' | 'light';

@Injectable({ providedIn: 'root' })
export class ThemeService {
  readonly theme = signal<Theme>('dark');

  loadTheme(): void {
    const saved = localStorage.getItem('appsec_theme') as Theme | null;
    this.setTheme(saved || 'dark');
  }

  toggleTheme(): void {
    this.setTheme(this.theme() === 'dark' ? 'light' : 'dark');
  }

  setTheme(theme: Theme): void {
    this.theme.set(theme);
    localStorage.setItem('appsec_theme', theme);
    document.documentElement.classList.remove('dark-theme', 'light-theme');
    document.documentElement.classList.add(`${theme}-theme`);
  }
}
