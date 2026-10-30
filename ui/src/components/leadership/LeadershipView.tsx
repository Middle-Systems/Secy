import { Activity, AlertTriangle, Clock, Flame, Loader2 } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { useLeadershipMetrics } from '@/api/queries';
import { StatCard } from '@/components/common/StatCard';
import { SeverityDonut } from '@/components/dashboard/SeverityDonut';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EM_DASH, formatDate, formatInteger } from '@/lib/format';

/**
 * The leadership view's home screen (M1k) — read-only posture aggregates, no row-level
 * drill-down by default (only ids for links, which this screen doesn't follow yet — see
 * ROADMAP.md's M1k UI scope note on deferred detail pages).
 */
export function LeadershipView() {
  const { data, isPending, isError } = useLeadershipMetrics();

  if (isPending) {
    return (
      <div className="flex items-center justify-center py-24 text-muted-foreground">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" /> Loading leadership metrics…
      </div>
    );
  }

  if (isError || !data) {
    return (
      <p className="py-24 text-center text-sm text-muted-foreground">
        Could not load leadership metrics. Check the backend and try again.
      </p>
    );
  }

  const chartData = data.weeklyFlow.map((w) => ({
    week: formatDate(w.weekStart),
    'New findings': w.newFindings,
    'Items created': w.actionItemsCreated,
    'Items resolved': w.actionItemsResolved,
  }));

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Leadership</h1>
        <p className="text-sm text-muted-foreground">
          Read-only security-posture aggregates. Scoring model {data.scoringModelVersion}, as of{' '}
          {formatDate(data.generatedAt)}.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Actionable (vulnerabilities)"
          value={formatInteger(data.findingsBySeverity.total)}
          icon={Activity}
          accent="blue"
        />
        <StatCard
          label="KEV exposure"
          value={formatInteger(data.kevExposure.kevFindingCount)}
          icon={Flame}
          accent="red"
        />
        <StatCard
          label="KEV past due"
          value={formatInteger(data.kevExposure.kevPastDueCount)}
          icon={AlertTriangle}
          accent="amber"
        />
        <StatCard
          label="MTTR (mean, action items)"
          value={data.mttr.meanHours != null ? `${data.mttr.meanHours.toFixed(1)}h` : EM_DASH}
          icon={Clock}
          accent="cyan"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Severity distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityDonut
              critical={data.findingsBySeverity.critical}
              high={data.findingsBySeverity.high}
              medium={data.findingsBySeverity.medium}
              low={data.findingsBySeverity.low}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Weekly throughput (12 weeks)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[260px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="week" tick={{ fontSize: 11 }} />
                  <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="New findings" fill="hsl(var(--primary))" />
                  <Bar dataKey="Items created" fill="hsl(var(--severity-medium))" />
                  <Bar dataKey="Items resolved" fill="hsl(var(--severity-low))" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>SBOM lifecycle-stage coverage</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-sm text-muted-foreground">
            {data.sbomStageCoverage.summary.productsStaged} staged ·{' '}
            {data.sbomStageCoverage.summary.productsLegacyOnly} legacy-only ·{' '}
            {data.sbomStageCoverage.summary.productsWithNoSbom} with no SBOM, of{' '}
            {data.sbomStageCoverage.summary.productCount} products.
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Product</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Stages present</TableHead>
                <TableHead>Max risk score</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.sbomStageCoverage.products.map((p) => (
                <TableRow key={p.productId}>
                  <TableCell className="font-medium">{p.productName}</TableCell>
                  <TableCell>{p.mode}</TableCell>
                  <TableCell>{p.stagesPresent.join(', ') || EM_DASH}</TableCell>
                  <TableCell>{p.maxRiskScore?.toFixed(1) ?? EM_DASH}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Risk trend — not yet available</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{data.riskTrend.note}</p>
        </CardContent>
      </Card>
    </div>
  );
}

export default LeadershipView;
