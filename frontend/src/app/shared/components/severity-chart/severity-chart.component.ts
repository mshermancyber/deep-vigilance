import {
  Component,
  Input,
  OnChanges,
  AfterViewInit,
  OnDestroy,
  ViewChild,
  ElementRef,
  SimpleChanges,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { Chart } from 'chart.js/auto';

// ---------------------------------------------------------------------------
// Public interface for findings consumed by this component
// ---------------------------------------------------------------------------
export interface ChartFinding {
  severity: string;
  createdAt: string;
  /** Optional OWASP / vulnerability category used for the bar-chart grouping. */
  category?: string;
}

// ---------------------------------------------------------------------------
// Severity colour palette – mirrors the Angular Material dark-theme CSS
// custom properties defined in styles.scss so charts remain in sync.
// ---------------------------------------------------------------------------
const SEVERITY_PALETTE: Record<string, { background: string; border: string }> =
  {
    critical: { background: '#ef4444', border: '#dc2626' },
    high: { background: '#f97316', border: '#ea580c' },
    medium: { background: '#eab308', border: '#ca8a04' },
    low: { background: '#22c55e', border: '#16a34a' },
    info: { background: '#3b82f6', border: '#2563eb' },
  };

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// Additional palette for OWASP category bars when more than 5 categories exist.
const CATEGORY_COLORS = [
  '#8b5cf6',
  '#ec4899',
  '#14b8a6',
  '#f43f5e',
  '#0ea5e9',
  '#a855f7',
  '#84cc16',
  '#06b6d4',
  '#d946ef',
  '#10b981',
];

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function isValidDate(d: Date): boolean {
  return !isNaN(d.getTime());
}

/**
 * Returns the chart.js-friendly date-key (YYYY-MM-DD) for a Date, or `null`
 * when the value cannot be parsed.
 */
function toDateKey(raw: string): string | null {
  const d = new Date(raw);
  return isValidDate(d) ? d.toISOString().slice(0, 10) : null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
@Component({
  selector: 'app-severity-chart',
  standalone: true,
  imports: [CommonModule, MatButtonModule, MatIconModule, MatTooltipModule],
  template: `
    <div class="severity-chart" role="region" [attr.aria-label]="'Severity distribution ' + chartType + ' chart'">
      <!-- header row -->
      <div class="chart-header">
        <span class="chart-title">{{ chartLabel() }}</span>
        <button
          mat-icon-button
          class="export-btn"
          (click)="exportAsPng()"
          [matTooltip]="'Export chart as PNG'"
          [attr.aria-label]="'Export ' + chartType + ' chart as PNG image'"
          [disabled]="!hasData"
        >
          <mat-icon>download</mat-icon>
        </button>
      </div>

      <!-- chart canvas -->
      @if (hasData) {
        <div class="chart-body">
          <canvas
            #chartCanvas
            role="img"
            [attr.aria-label]="'Severity distribution ' + chartType + ' chart showing findings over ' + timeRange"
          ></canvas>

          <!-- accessible custom legend -->
          @if (legendItems().length > 0) {
            <ul class="chart-legend" role="list" aria-label="Chart legend">
              @for (item of legendItems(); track item.label; let i = $index) {
                <li
                  class="legend-item"
                  [class.hidden]="item.hidden"
                  role="listitem"
                  tabindex="0"
                  [attr.aria-label]="item.label + ': ' + item.value + ' findings' + (item.hidden ? ' (hidden)' : '')"
                  (click)="toggleDataset($event, i)"
                  (keydown.enter)="toggleDataset($event, i)"
                  (keydown.space)="toggleDataset($event, i)"
                >
                  <span
                    class="legend-marker"
                    [style.background]="item.color"
                  ></span>
                  <span class="legend-label">{{ item.label }}</span>
                  <span class="legend-value">{{ item.value }}</span>
                </li>
              }
            </ul>
          }
        </div>
      } @else {
        <div class="chart-empty">
          <mat-icon>bar_chart</mat-icon>
          <p>No findings data available for the selected time range.</p>
        </div>
      }
    </div>
  `,
  styles: [
    `
      .severity-chart {
        display: flex;
        flex-direction: column;
        background: var(--bg-card, #1e293b);
        border: 1px solid var(--border-primary, #334155);
        border-radius: var(--radius-lg, 12px);
        padding: 20px;
        width: 100%;
        min-height: 320px;
        box-sizing: border-box;
      }

      .chart-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 16px;
      }

      .chart-title {
        font-size: 14px;
        font-weight: 600;
        color: var(--text-primary, #f1f5f9);
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }

      .export-btn {
        color: var(--text-secondary, #94a3b8);
        transition: color 0.2s;
      }
      .export-btn:hover {
        color: var(--accent-primary, #3b82f6);
      }
      .export-btn:disabled {
        opacity: 0.4;
        cursor: not-allowed;
      }

      .chart-body {
        flex: 1;
        display: flex;
        flex-direction: column;
        position: relative;
        min-height: 0;
      }

      .chart-body canvas {
        max-height: 300px;
        width: 100% !important;
      }

      /* -- custom accessible legend -- */
      .chart-legend {
        display: flex;
        flex-wrap: wrap;
        gap: 12px 20px;
        list-style: none;
        margin: 16px 0 0;
        padding: 12px 0 0;
        border-top: 1px solid var(--border-secondary, #1e293b);
      }

      .legend-item {
        display: flex;
        align-items: center;
        gap: 6px;
        cursor: pointer;
        padding: 4px 8px;
        border-radius: var(--radius-sm, 4px);
        font-size: 12px;
        color: var(--text-secondary, #94a3b8);
        transition: background 0.15s, opacity 0.15s;
        user-select: none;
        outline: none;
      }
      .legend-item:hover,
      .legend-item:focus-visible {
        background: var(--bg-hover, #334155);
        color: var(--text-primary, #f1f5f9);
      }
      .legend-item:focus-visible {
        outline: 2px solid var(--accent-primary, #3b82f6);
        outline-offset: 2px;
      }
      .legend-item.hidden {
        opacity: 0.4;
        text-decoration: line-through;
      }

      .legend-marker {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        flex-shrink: 0;
      }

      .legend-label {
        font-weight: 500;
      }

      .legend-value {
        font-weight: 700;
        font-variant-numeric: tabular-nums;
        min-width: 24px;
        text-align: right;
      }

      /* -- empty state -- */
      .chart-empty {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 8px;
        color: var(--text-tertiary, #64748b);
        padding: 40px 20px;
      }
      .chart-empty mat-icon {
        font-size: 40px;
        width: 40px;
        height: 40px;
        opacity: 0.5;
      }
      .chart-empty p {
        font-size: 13px;
        text-align: center;
        max-width: 260px;
        margin: 0;
      }
    `,
  ],
})
export class SeverityChartComponent implements OnChanges, AfterViewInit, OnDestroy {
  // -----------------------------------------------------------------------
  // View children
  // -----------------------------------------------------------------------
  @ViewChild('chartCanvas') private chartCanvas!: ElementRef<HTMLCanvasElement>;

  // -----------------------------------------------------------------------
  // Inputs
  // -----------------------------------------------------------------------

  /** Array of findings to visualise. Re-computed whenever the reference changes. */
  @Input() findings: ChartFinding[] = [];

  /** Visualisation type. */
  @Input() chartType: 'doughnut' | 'bar' | 'line' = 'doughnut';

  /** Time window filter applied to `createdAt`. */
  @Input() timeRange: '7d' | '30d' | '90d' | 'all' = '30d';

  // -----------------------------------------------------------------------
  // Internal state
  // -----------------------------------------------------------------------
  private chart: Chart | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private canvasReady = false;

  /** Cached, filtered findings used by the currently rendered chart. */
  private filtered: ChartFinding[] = [];

  /** Indicates whether the chart canvas contains displayable data. */
  get hasData(): boolean {
    return this.filtered.length > 0;
  }

  // -----------------------------------------------------------------------
  // Signal-backed derived state (computed synchronously on each change)
  // -----------------------------------------------------------------------

  /** Human-readable title displayed in the chart header. */
  chartLabel(): string {
    const typeLabels: Record<string, string> = {
      doughnut: 'Severity Distribution',
      bar: 'Findings by Category',
      line: 'Trend Over Time',
    };
    return typeLabels[this.chartType] ?? 'Severity Distribution';
  }

  /** Items for the custom accessible legend. */
  legendItems(): Array<{
    label: string;
    value: number;
    color: string;
    hidden: boolean;
  }> {
    if (!this.chart || this.filtered.length === 0) return [];

    const datasets = this.chart.data.datasets;

    // Doughnut: single dataset where data corresponds to severity levels
    if (this.chartType === 'doughnut') {
      return (this.chart.data.labels ?? []).map((label, i) => {
        const sev = (label as string).toLowerCase();
        const palette = SEVERITY_PALETTE[sev];
        const meta = this.chart!.getDatasetMeta(0);
        return {
          label: label as string,
          value: (datasets[0]?.data[i] as number) ?? 0,
          color: palette?.background ?? '#64748b',
          hidden: !!(meta.data[i] as any)?.hidden,
        };
      });
    }

    // Bar & Line: one dataset per severity
    if (this.chartType === 'bar' || this.chartType === 'line') {
      return datasets.map((ds, i) => {
        const values = ds.data as number[];
        const total = values.reduce((a, b) => a + (b ?? 0), 0);
        const meta = this.chart!.getDatasetMeta(i);
        return {
          label: ds.label as string,
          value: total,
          color: (ds.backgroundColor as string) ?? '#64748b',
          hidden: meta.hidden ?? false,
        };
      });
    }

    return [];
  }

  // -----------------------------------------------------------------------
  // Lifecycle hooks
  // -----------------------------------------------------------------------

  ngAfterViewInit(): void {
    this.canvasReady = true;
    this.initResizeObserver();
    this.buildChart();
  }

  ngOnChanges(changes: SimpleChanges): void {
    // Re-filter & re-build whenever any input changes.
    // We skip the very first call if the canvas isn't ready yet because
    // ngAfterViewInit will pick it up.
    if (this.canvasReady) {
      this.buildChart();
    }
  }

  ngOnDestroy(): void {
    this.destroyChart();
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /** Export the current chart canvas as a PNG download. */
  exportAsPng(): void {
    const canvas = this.chartCanvas?.nativeElement;
    if (!canvas) return;

    canvas.toBlob((blob: Blob | null) => {
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `severity-${this.chartType}-${new Date().toISOString().slice(0, 10)}.png`;
      anchor.click();
      URL.revokeObjectURL(url);
    }, 'image/png');
  }

  /** Toggle visibility of a dataset (or doughnut segment) by index. */
  toggleDataset(event: Event | MouseEvent | KeyboardEvent, index?: number): void {
    // Support both (index) and (event, index) signatures
    const idx = typeof index === 'number' ? index : (event as any);
    if (typeof idx !== 'number' || !this.chart) return;

    // Prevent default for keyboard events
    if (event instanceof KeyboardEvent) {
      event.preventDefault();
    }

    const meta = this.chart.getDatasetMeta(
      this.chartType === 'doughnut' ? 0 : idx
    );

    if (this.chartType === 'doughnut') {
      // For doughnut, each segment is a data point in dataset 0
      const dataPoint = meta.data[idx] as any;
      if (dataPoint) {
        dataPoint.hidden = !dataPoint.hidden;
      }
    } else {
      // For bar/line, toggle the entire dataset
      meta.hidden = !meta.hidden;
    }

    this.chart.update();
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  /** Remove the old chart instance and build a fresh one from current inputs. */
  private buildChart(): void {
    this.destroyChart();

    // Filter by time range
    this.filtered = this.filterByTimeRange(this.findings);

    if (this.filtered.length === 0) return;

    const ctx = this.chartCanvas?.nativeElement?.getContext('2d');
    if (!ctx) return;

    const config = this.buildConfig();
    this.chart = new Chart(ctx, config);
  }

  /** Destroy the existing Chart.js instance. */
  private destroyChart(): void {
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }
  }

  /** Initialise the ResizeObserver on the canvas parent for responsive redraws. */
  private initResizeObserver(): void {
    if (
      typeof ResizeObserver === 'undefined' ||
      !this.chartCanvas?.nativeElement?.parentElement
    ) {
      return;
    }

    this.resizeObserver = new ResizeObserver(() => {
      if (this.chart) {
        this.chart.resize();
      }
    });

    this.resizeObserver.observe(this.chartCanvas.nativeElement.parentElement);
  }

  // -----------------------------------------------------------------------
  // Data filtering
  // -----------------------------------------------------------------------

  /**
   * Return only findings whose `createdAt` falls within the configured
   * `timeRange`, or all findings when `timeRange === 'all'`.
   */
  private filterByTimeRange(all: ChartFinding[]): ChartFinding[] {
    if (!all || all.length === 0) return [];
    if (this.timeRange === 'all') return all;

    const days = this.timeRangeDays();
    if (days <= 0) return all;

    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);

    return all.filter((f) => {
      const d = new Date(f.createdAt);
      return isValidDate(d) && d >= cutoff;
    });
  }

  /** Parse the timeRange string into a number of days. */
  private timeRangeDays(): number {
    switch (this.timeRange) {
      case '7d':
        return 7;
      case '30d':
        return 30;
      case '90d':
        return 90;
      default:
        return 0;
    }
  }

  // -----------------------------------------------------------------------
  // Chart config builders
  // -----------------------------------------------------------------------

  /** Return the appropriate Chart.js configuration based on `chartType`. */
  private buildConfig(): any {
    switch (this.chartType) {
      case 'doughnut':
        return this.doughnutConfig();
      case 'bar':
        return this.barConfig();
      case 'line':
        return this.lineConfig();
      default:
        return this.doughnutConfig();
    }
  }

  /** Common options shared by all chart types. */
  private baseOptions(): any {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: {
        duration: 600,
        easing: 'easeInOutQuart' as const,
      },
      plugins: {
        legend: {
          display: false, // we render a custom accessible legend
        },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.95)',
          titleColor: '#f1f5f9',
          bodyColor: '#94a3b8',
          borderColor: '#334155',
          borderWidth: 1,
          cornerRadius: 6,
          padding: 10,
          boxPadding: 4,
          usePointStyle: true,
        },
      },
      interaction: {
        intersect: false,
        mode: 'index' as const,
      },
    };
  }

  // -- Doughnut -----------------------------------------------------------

  private doughnutConfig(): any {
    const counts = this.severityCounts(this.filtered);

    return {
      type: 'doughnut' as const,
      data: {
        labels: SEVERITY_ORDER.map(capitalize),
        datasets: [
          {
            data: SEVERITY_ORDER.map((s) => counts[s] ?? 0),
            backgroundColor: SEVERITY_ORDER.map(
              (s) => SEVERITY_PALETTE[s]?.background ?? '#64748b'
            ),
            borderColor: SEVERITY_ORDER.map(
              (s) => SEVERITY_PALETTE[s]?.border ?? '#475569'
            ),
            borderWidth: 2,
            hoverOffset: 8,
          },
        ],
      },
      options: {
        ...this.baseOptions(),
        cutout: '55%',
        plugins: {
          ...this.baseOptions().plugins,
          tooltip: {
            ...this.baseOptions().plugins.tooltip,
            callbacks: {
              label: (ctx: any) => {
                const total = (ctx.dataset.data as number[]).reduce(
                  (a: number, b: number) => a + b,
                  0
                );
                const val = ctx.parsed as number;
                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0.0';
                return ` ${ctx.label}: ${val} (${pct}%)`;
              },
            },
          },
        },
      },
    };
  }

  // -- Bar ----------------------------------------------------------------

  private barConfig(): any {
    // Group findings by category (OWASP) then severity.
    const categoryMap = new Map<string, Record<string, number>>();

    for (const f of this.filtered) {
      const cat = f.category?.trim() || 'Uncategorized';
      if (!categoryMap.has(cat)) categoryMap.set(cat, {});
      const sevMap = categoryMap.get(cat)!;
      const sev = f.severity.toLowerCase();
      sevMap[sev] = (sevMap[sev] ?? 0) + 1;
    }

    const categories = [...categoryMap.keys()].sort();

    return {
      type: 'bar' as const,
      data: {
        labels: categories,
        datasets: SEVERITY_ORDER.map((sev, idx) => ({
          label: capitalize(sev),
          data: categories.map(
            (cat) => categoryMap.get(cat)![sev] ?? 0
          ),
          backgroundColor: SEVERITY_PALETTE[sev]?.background ?? '#64748b',
          borderColor: SEVERITY_PALETTE[sev]?.border ?? '#475569',
          borderWidth: 1,
          borderRadius: 2,
          // Stack all severity datasets together
          stack: 'severity',
        })),
      },
      options: {
        ...this.baseOptions(),
        scales: {
          x: {
            stacked: true,
            ticks: {
              color: '#94a3b8',
              maxRotation: 45,
              font: { size: 11 },
            },
            grid: { display: false },
          },
          y: {
            stacked: true,
            beginAtZero: true,
            ticks: {
              color: '#94a3b8',
              precision: 0,
              font: { size: 11 },
            },
            grid: {
              color: 'rgba(51, 65, 85, 0.5)',
            },
          },
        },
      },
    };
  }

  // -- Line ---------------------------------------------------------------

  private lineConfig(): any {
    const days = this.timeRangeDays();
    // For 'all' we need to derive the range from actual data.
    let startDate: Date;
    const endDate = new Date();

    if (this.timeRange === 'all') {
      // Find the earliest createdAt in the filtered set
      let earliest = Infinity;
      for (const f of this.filtered) {
        const ts = new Date(f.createdAt).getTime();
        if (!isNaN(ts) && ts < earliest) earliest = ts;
      }
      startDate = earliest < Infinity ? new Date(earliest) : new Date();
    } else {
      startDate = new Date(endDate);
      startDate.setDate(startDate.getDate() - days);
    }

    // Build a map of dateKey -> severity -> count
    const dateMap = new Map<string, Record<string, number>>();
    for (const f of this.filtered) {
      const key = toDateKey(f.createdAt);
      if (!key) continue;
      if (!dateMap.has(key)) dateMap.set(key, {});
      const sevMap = dateMap.get(key)!;
      const sev = f.severity.toLowerCase();
      sevMap[sev] = (sevMap[sev] ?? 0) + 1;
    }

    // Generate every date in the range (fill gaps with 0)
    const labels: string[] = [];
    const cursor = new Date(startDate);
    while (cursor <= endDate) {
      labels.push(cursor.toISOString().slice(0, 10));
      cursor.setDate(cursor.getDate() + 1);
    }

    return {
      type: 'line' as const,
      data: {
        labels,
        datasets: SEVERITY_ORDER.map((sev) => {
          const palette = SEVERITY_PALETTE[sev];
          return {
            label: capitalize(sev),
            data: labels.map((d) => dateMap.get(d)?.[sev] ?? 0),
            borderColor: palette?.background ?? '#64748b',
            backgroundColor: (palette?.background ?? '#64748b') + '20',
            borderWidth: 2,
            pointRadius: 2,
            pointHoverRadius: 5,
            pointBackgroundColor: palette?.background ?? '#64748b',
            tension: 0.3,
            fill: false,
          };
        }),
      },
      options: {
        ...this.baseOptions(),
        scales: {
          x: {
            type: 'category' as const,
            ticks: {
              color: '#94a3b8',
              maxTicksLimit: 20,
              maxRotation: 45,
              font: { size: 10 },
            },
            grid: { display: false },
          },
          y: {
            beginAtZero: true,
            ticks: {
              color: '#94a3b8',
              precision: 0,
              font: { size: 11 },
            },
            grid: {
              color: 'rgba(51, 65, 85, 0.5)',
            },
          },
        },
        elements: {
          line: {
            tension: 0.3,
          },
        },
      },
    };
  }

  // -----------------------------------------------------------------------
  // Data computation
  // -----------------------------------------------------------------------

  /**
   * Tally findings by severity, returning a map keyed by lower-case severity
   * string with integer counts.
   */
  private severityCounts(
    items: ChartFinding[]
  ): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const f of items) {
      const sev = f.severity?.toLowerCase() || 'info';
      counts[sev] = (counts[sev] ?? 0) + 1;
    }
    return counts;
  }
}
