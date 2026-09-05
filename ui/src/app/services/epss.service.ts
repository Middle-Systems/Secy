import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface EPSS {
  cve: string;
  epss: number;       // Probability of exploitation (0.0 to 1.0)
  percentile: number; // Percentile rank relative to all other CVEs
  date: string;
}

@Injectable({ providedIn: 'root' })
export class EpssService {
  private apiUrl = '/api/epss';

  constructor(private http: HttpClient) {}

  getEpssData(page: number, size: number, search: string = ''): Observable<any> {
    return this.http.get(`${this.apiUrl}?page=${page}&size=${size}&search=${search}`);
  }

  ingestEpss(): Observable<any> {
    return this.http.get(`${this.apiUrl}/ingest`, {});
  }
}
