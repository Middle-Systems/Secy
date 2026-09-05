import { Component, OnInit } from '@angular/core';
import { ChartConfiguration, ChartData, Chart, registerables } from 'chart.js'
import {DashboardStats, StatsService} from "../../services/stats.service";
import {KevService} from "../../services/kev.service";

Chart.register(...registerables);

@Component({
  selector: 'app-dashboard',
  standalone: false,
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss'
})
export class DashboardComponent implements OnInit {

  public stats: DashboardStats | null = null;
  public showUnanalyzed = true; // Default to show
  private originalSeverityDistribution: { [key: string]: number } = {}

  recentExploits: any[] = [];
  topTargets: any[] = [];

  // Common Options
  public chartOptions: ChartConfiguration['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom' } }
  };

  public lineChartOptions: ChartConfiguration['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
        grid: { color: 'rgba(0, 0, 0, 0.05)' }
      },
      x: {
        grid: { display: false }
      }
    },
    plugins: {
      legend: { display: true, position: 'bottom' }
    },
    elements: {
      line: {
        tension: 0.4 // This makes the line curvy/smooth
      }
    }
  };

  // 1. Severity Doughnut
  public severityData: ChartData<'doughnut'> = {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: ['#bb2d3b', '#fd7e14', '#0dcaf0', '#14a44d']
    }]
  };

  // 2. Top Products (Horizontal Bar)
  public productData: ChartData<'bar'> = {
    labels: [],
    datasets: [{
      label: 'New CVEs',
      data: [],
      backgroundColor: '#3b71ca'
    }]
  };

  public horizontalBarOptions: ChartConfiguration['options'] = {
    indexAxis: 'y', // Makes it horizontal
    responsive: true,
    maintainAspectRatio: false
  };

  // 3. Trend Line
  public trendData: ChartData<'line'> = {
    labels: [],
    datasets: [
      {
        data: [],
        label: 'Daily Ingestion',
        borderColor: '#3b71ca',
        fill: true,
        backgroundColor: 'rgba(59, 113, 202, 0.1)'
      }
    ]
  };

  public severityColors: { [key: string]: string } = {
    'CRITICAL': '#bb2d3b',
    'HIGH': '#fd7e14',
    'MEDIUM': '#0dcaf0',
    'LOW': '#14a44d',
    'Awaiting NVD Analysis': '#adb5bd' // Sleek grey for pending items
  };

  constructor(private statsService: StatsService, private kevService: KevService) { }

  ngOnInit(): void {
    this.statsService.getStats().subscribe(res => {

      this.stats = res;

      this.initCharts(res)

    });

    this.loadKevStats();
  }

  private initCharts(data: DashboardStats) {
    // Severity Data from NVD
    this.severityData = {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [data.globalCrit, data.globalHigh, data.globalMed, data.globalLow],
        backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#0dcaf0']
      }]
    };
  }

  loadKevStats(): void {
    // 1. Get recent exploits (sorted by date, limit 10)
    this.kevService.getKevEntries(0, 10, '').subscribe((res: { content: any[]; }) => {
      this.recentExploits = res.content;
    });

    // 2. Logic for Top Targets Leaderboard
    // You can either add a custom backend endpoint for this or compute from full list
    this.kevService.getKevEntries(0, 1000, '').subscribe((res: { content: any; }) => {
      const allKev = res.content;
      const ransomwareOnly = allKev.filter((k: any) => k.knownRansomwareCampaignUse === 'Known');

      // Group by vendor and count
      const counts = ransomwareOnly.reduce((acc: any, val: any) => {
        acc[val.vendor] = (acc[val.vendor] || 0) + 1;
        return acc;
      }, {});

      this.topTargets = Object.keys(counts)
        .map(key => ({ vendor: key, count: counts[key] }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5); // Just top 5 for the dashboard
    });
  }

  onToggleUnanalyzed(): void {
    this.updateSeverityChart();
  }

  private updateSeverityChart(): void {
    // Filter the keys based on the toggle
    const filteredData = Object.entries(this.originalSeverityDistribution)
      .filter(([key]) => this.showUnanalyzed || key !== 'Awaiting NVD Analysis')
      .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});

    this.severityData = {
      labels: Object.keys(filteredData),
      datasets: [{
        ...this.severityData.datasets[0],
        data: Object.values(filteredData),
        backgroundColor: Object.keys(filteredData).map(label => this.severityColors[label] || '#dee2e6')
      }]
    };
  }

// Optional helper to make CPEs look pretty in the chart labels
  private simplifyCpe(cpe: string): string {
    const parts = cpe.split(':');
    return parts.length > 4 ? `${parts[3]} ${parts[4]}` : cpe;
  }
}
