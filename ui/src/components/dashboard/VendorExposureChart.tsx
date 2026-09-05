import type { ReactNode } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { formatInteger } from '@/lib/format';

import type { VendorCount } from './dashboard.helpers';

const SERIES_LABEL = 'Known Exploited CVEs';

/**
 * Top vendors by KEV count — a horizontal bar chart. Magnitude comparison of a
 * single series, so one hue (primary), thin bars with a rounded data-end, a
 * hairline grid, and values direct-labelled at the tips.
 */
export function VendorExposureChart({ data }: { data: VendorCount[] }) {
  if (data.length === 0) {
    return (
      <p className="py-12 text-center text-sm text-muted-foreground">
        No vendor exposure data available.
      </p>
    );
  }

  return (
    <figure className="m-0">
      <div className="w-full" style={{ height: Math.max(220, data.length * 34 + 28) }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 4, right: 44, bottom: 4, left: 8 }}
            barCategoryGap={8}
          >
            <CartesianGrid horizontal={false} stroke="hsl(var(--border))" />
            <XAxis
              type="number"
              allowDecimals={false}
              tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
              tickLine={false}
              axisLine={{ stroke: 'hsl(var(--border))' }}
            />
            <YAxis
              type="category"
              dataKey="vendor"
              width={128}
              tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              cursor={{ fill: 'hsl(var(--muted))' }}
              formatter={(value) => [formatInteger(Number(value)), SERIES_LABEL]}
              contentStyle={{
                borderRadius: 8,
                border: '1px solid hsl(var(--border))',
                fontSize: 12,
              }}
            />
            <Bar
              dataKey="count"
              name={SERIES_LABEL}
              fill="hsl(var(--primary))"
              maxBarSize={22}
              radius={[0, 4, 4, 0]}
              isAnimationActive={false}
            >
              <LabelList
                dataKey="count"
                position="right"
                fill="hsl(var(--muted-foreground))"
                fontSize={12}
                formatter={(value: ReactNode) => formatInteger(Number(value))}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="sr-only">
        <table>
          <caption>Top {data.length} vendors by known exploited CVE count</caption>
          <thead>
            <tr>
              <th scope="col">Vendor</th>
              <th scope="col">{SERIES_LABEL}</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.vendor}>
                <th scope="row">{d.vendor}</th>
                <td>{formatInteger(d.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figcaption>
    </figure>
  );
}
