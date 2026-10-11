import { Injectable, signal, computed } from '@angular/core';

export type DeviceType = 'desktop' | 'android' | 'ios';

/**
 * Adaptive device detection for the SPA. Combines User-Agent sniffing (Android / iOS)
 * with a viewport-width breakpoint so a narrow desktop window also gets the mobile layout.
 */
@Injectable({ providedIn: 'root' })
export class DeviceService {
  private readonly narrow = signal(this.isNarrow());
  readonly deviceType = signal<DeviceType>(this.detect());
  readonly isMobile = computed(() => this.deviceType() !== 'desktop' || this.narrow());
  readonly isIOS = computed(() => this.deviceType() === 'ios');
  readonly isAndroid = computed(() => this.deviceType() === 'android');

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('resize', () => this.narrow.set(this.isNarrow()), { passive: true });
      // Reflect device class on <html> so global CSS (safe-area insets) can target it.
      const el = document.documentElement;
      el.classList.toggle('ios', this.deviceType() === 'ios');
      el.classList.toggle('android', this.deviceType() === 'android');
      el.classList.toggle('touch', this.deviceType() !== 'desktop');
    }
  }

  private isNarrow(): boolean {
    return typeof window !== 'undefined' && window.innerWidth <= 768;
  }

  private detect(): DeviceType {
    const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
    // iPadOS 13+ reports as desktop Safari; the touch-capable Mac check catches it.
    if (/iPhone|iPad|iPod/i.test(ua) || (/Macintosh/.test(ua) && typeof navigator !== 'undefined' && (navigator as Navigator & { maxTouchPoints: number }).maxTouchPoints > 1)) return 'ios';
    if (/Android/i.test(ua)) return 'android';
    return 'desktop';
  }
}
