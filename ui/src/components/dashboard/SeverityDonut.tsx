import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

import { formatInteger } from './dashboard.helpers';

interface SeverityDonutProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Slice order + severity colour tokens (never hex — see styles/index.css). */
const SLICES = [
  { key: 'critical', name: 'Critical', color: 'hsl(var(--severity-critical))' },
  { key: 'high', name: 'High', color: 'hsl(var(--severity-high))' },
  { key: 'medium', name: 'Medium', color: 'hsl(var(--severity-medium))' },
  { key: 'low', name: 'Low', color: 'hsl(var(--severity-low))' },
] as const;

/**
 * Global NVD severity distribution as a doughnut. Part-to-whole, four fixed
 * buckets, status colours — the reader compares slices at a glance and reads
 * exact values from the legend / tooltip / sr-only table.
 */
export function SeverityDonut({ critical, high, medium, low }: SeverityDonutProps) {
  const values: Record<string, number> = { critical, high, medium, low };
  const data = SLICES.map((slice) => ({
    name: slice.name,
    value: Math.max(0, values[slice.key] ?? 0),
    color: slice.color,
  }));
  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return (
      <p className="py-12 text-center text-sm text-muted-foreground">
        No severity data available.
      </p>
    );
  }

  return (
    <figure className="m-0">
      <div className="h-[260px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={62}
              outerRadius={96}
              paddingAngle={2}
              stroke="hsl(var(--card))"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
            <Tooltip
              formatter={(value) => {
                const n = Number(value);
                return `${formatInteger(n)}  ·  ${((n / total) * 100).toFixed(1)}%`;
              }}
              contentStyle={{
                borderRadius: 8,
                border: '1px solid hsl(var(--border))',
                fontSize: 12,
              }}
            />
            <Legend
              verticalAlign="bottom"
              height={32}
              iconType="circle"
              iconSize={9}
              formatter={(entryValue) => (
                <span className="text-xs text-muted-foreground">{entryValue}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="sr-only">
        <table>
          <caption>Global NVD severity distribution</caption>
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col">Count</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.name}>
                <th scope="row">{d.name}</th>
                <td>{formatInteger(d.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figcaption>
    </figure>
  );
}
