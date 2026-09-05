import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";

export interface DashboardStats {
  globalSyncs: number;      // CVEs + KEVs + EPSS updated in last 7d
  activeKevCount: number;   // Total size of KEV table
  highEpssCount: number;    // EPSS > 0.36 updated in last 7d
  accessibleCount: number;
  globalCrit: number;
  globalHigh: number;
  globalMed: number;
  globalLow: number;
}

@Injectable({ providedIn: 'root' })
export class StatsService {
  private apiUrl = '/api/stats/dashboard';

  constructor(private http: HttpClient) {}

  getStats(): Observable<DashboardStats> {
    return this.http.get<DashboardStats>(this.apiUrl);
  }
}
