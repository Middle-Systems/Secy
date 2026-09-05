import type { LucideIcon } from 'lucide-react';
import {
  Boxes,
  ChartLine,
  ClipboardCheck,
  Database,
  Flame,
  Percent,
  Server,
  ShieldCheck,
} from 'lucide-react';
import { Link } from '@tanstack/react-router';

import { cn } from '@/lib/utils';

interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

/**
 * Sidenav contents, ported from the Angular `sidenav.component.html`.
 *
 * "Threat Intelligence" and "Security Posture" both point at /dashboard until
 * those two views are split apart.
 */
const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Monitoring',
    items: [
      { label: 'Threat Intelligence', to: '/dashboard', icon: ChartLine },
      { label: 'Security Posture', to: '/dashboard', icon: ShieldCheck },
    ],
  },
  {
    label: 'Threat Intelligence',
    items: [
      { label: 'CVE Database', to: '/cve-database', icon: Database },
      { label: 'KEV Database', to: '/kev-database', icon: Flame },
      { label: 'EPSS Database', to: '/epss-database', icon: Percent },
    ],
  },
  {
    label: 'Asset Management',
    items: [
      { label: 'Product Catalog', to: '/product-catalog', icon: Boxes },
      { label: 'Infrastructure', to: '/infrastructure', icon: Server },
    ],
  },
  {
    label: 'Configuration',
    items: [{ label: 'Compliance', to: '/compliance', icon: ClipboardCheck }],
  },
];

/** Fixed 240px left navigation, sitting below the header. */
export function Sidenav() {
  return (
    <nav
      aria-label="Main"
      className="fixed bottom-0 left-0 top-header z-20 w-sidenav overflow-y-auto border-r border-border bg-card"
    >
      <div className="mx-3 mt-4 flex flex-col pb-4">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-2 mt-4 first:mt-0">
            <p className="mb-2 px-3 text-xs font-bold uppercase tracking-wide text-muted-foreground">
              {group.label}
            </p>
            {group.items.map((item) => (
              <Link
                key={`${group.label}-${item.label}`}
                to={item.to}
                className="flex items-center gap-3 border-l-4 border-transparent px-3 py-2 text-sm text-foreground transition-colors hover:bg-muted"
                activeProps={{
                  className: cn(
                    'border-l-4 border-primary bg-accent font-semibold text-primary hover:bg-accent',
                  ),
                }}
              >
                <item.icon className="h-[18px] w-5 shrink-0" aria-hidden="true" />
                <span>{item.label}</span>
              </Link>
            ))}
          </div>
        ))}
      </div>
    </nav>
  );
}
