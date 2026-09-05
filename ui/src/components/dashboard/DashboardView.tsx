import { useEffect, useMemo } from 'react';
import { Loader2, RefreshCw, ShieldAlert, Skull, TrendingUp, Unlock, Zap } from 'lucide-react';
import { toast } from 'sonner';

import { useDashboardStats, useKevPage } from '@/api/queries';
import { StatCard } from '@/components/common/StatCard';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

import { formatInteger } from '@/lib/format';

import { ExploitFeed } from './ExploitFeed';
import { RansomwareTargets } from './RansomwareTargets';
import { SeverityDonut } from './SeverityDonut';
import { VendorExposureChart } from './VendorExposureChart';
import {
  recentlyAddedKev,
  topRansomwareTargets,
  topVendorsByExposure,
} from './dashboard.helpers';

/** Everything past the KPI/severity numbers is derived from this KEV pull. */
const KEV_PULL_SIZE = 2000;

function PanelError({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center">
      <ShieldAlert className="h-6 w-6 text-destructive" aria-hidden="true" />
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}

function FeedSkeleton() {
  return (
    <div className="flex flex-col gap-3 px-6 py-3">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex flex-col gap-1.5">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-3 w-40" />
        </div>
      ))}
    </div>
  );
}

function LeaderboardSkeleton() {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: 5 }).map((_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  );
}

/**
 * Dashboard — threat intelligence and security posture at a glance.
 *
 * Structure and order match the Angular original: KPI row, global severity +
 * top-vendor exposure, then the exploit feed alongside the ransomware
 * leaderboard. The dead "Show Unanalyzed" toggle from the old severity card is
 * deliberately not ported.
 */
export function DashboardView() {
  const stats = useDashboardStats();
  const kev = useKevPage({ size: KEV_PULL_SIZE });

  useEffect(() => {
    if (stats.isError) toast.error('Failed to load dashboard statistics.');
  }, [stats.isError]);
  useEffect(() => {
    if (kev.isError) toast.error('Failed to load the KEV catalog for the dashboard panels.');
  }, [kev.isError]);

  const kevContent = useMemo(() => kev.data?.content ?? [], [kev.data]);
  const vendorExposure = useMemo(() => topVendorsByExposure(kevContent, 8), [kevContent]);
  const recentExploits = useMemo(() => recentlyAddedKev(kevContent, 10), [kevContent]);
  const ransomwareTargets = useMemo(() => topRansomwareTargets(kevContent, 5), [kevContent]);

  if (stats.isPending) {
    return (
      <div className="flex min-h-[70vh] flex-col items-center justify-center text-center">
        <Loader2 className="h-12 w-12 animate-spin text-primary" aria-hidden="true" />
        <p className="mt-4 font-bold text-foreground">
          Synchronizing Global Threat Intelligence…
        </p>
        <p className="mt-1 text-sm italic text-muted-foreground">
          Querying NVD, CISA KEV, and FIRST.org feeds
        </p>
      </div>
    );
  }

  if (stats.isError || !stats.data) {
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
        <ShieldAlert className="h-10 w-10 text-destructive" aria-hidden="true" />
        <p className="mt-3 font-semibold text-foreground">Unable to load the dashboard</p>
        <p className="mt-1 max-w-sm text-sm text-muted-foreground">
          The stats service did not respond. Check that the backend is running, then reload.
        </p>
      </div>
    );
  }

  const s = stats.data;
  const kevLoading = kev.isPending;
  const kevFailed = kev.isError;
  const panelError = 'Could not load KEV data.';

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Threat intelligence and security posture at a glance.
        </p>
      </div>

      {/* 1 — KPI row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Global Syncs (7d)"
          value={formatInteger(s.globalSyncs)}
          icon={RefreshCw}
          accent="blue"
        />
        <StatCard
          label="Active Exploits (KEV)"
          value={formatInteger(s.activeKevCount)}
          icon={Skull}
          accent="red"
        />
        <StatCard
          label="High Prob. EPSS (7d)"
          value={formatInteger(s.highEpssCount)}
          icon={TrendingUp}
          accent="amber"
        />
        <StatCard
          label="Accessible Threats"
          value={formatInteger(s.accessibleCount)}
          icon={Unlock}
          accent="cyan"
        />
      </div>

      {/* 2 + 3 — global severity & top-vendor exposure */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-base font-bold">Global Severity (NVD)</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityDonut
              critical={s.globalCrit}
              high={s.globalHigh}
              medium={s.globalMed}
              low={s.globalLow}
            />
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base font-bold">
              Global Product Exposure (Top Vendors)
            </CardTitle>
            <p className="text-xs text-muted-foreground">Known Exploited CVEs by vendor</p>
          </CardHeader>
          <CardContent>
            {kevLoading ? (
              <Skeleton className="h-[300px] w-full" />
            ) : kevFailed ? (
              <PanelError message={panelError} />
            ) : (
              <VendorExposureChart data={vendorExposure} />
            )}
          </CardContent>
        </Card>
      </div>

      {/* 4 + 5 — exploit feed & ransomware leaderboard */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="flex items-center gap-2 text-base font-bold">
              <Zap className="h-4 w-4 text-severity-high" aria-hidden="true" />
              Latest Exploit Intelligence
            </CardTitle>
            <span className="shrink-0 rounded-full border border-border px-2.5 py-0.5 text-xs font-medium text-primary">
              Direct CISA Sync
            </span>
          </CardHeader>
          <CardContent className="px-0">
            {kevLoading ? (
              <FeedSkeleton />
            ) : kevFailed ? (
              <PanelError message={panelError} />
            ) : (
              <ExploitFeed items={recentExploits} />
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-base font-bold">Top Ransomware Targets</CardTitle>
          </CardHeader>
          <CardContent>
            {kevLoading ? (
              <LeaderboardSkeleton />
            ) : kevFailed ? (
              <PanelError message={panelError} />
            ) : (
              <RansomwareTargets data={ransomwareTargets} />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
