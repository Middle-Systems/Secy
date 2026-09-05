import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface KEV {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  added: Date;
  description: string;
  requiredActions: string;
  dueDate: Date;
  knownRansomwareCampaignUse: string;
  notes: string;
}

@Injectable({ providedIn: 'root' })
export class KevService {
  private apiUrl = '/api/kev';

  constructor(private http: HttpClient) {}

  getKevEntries(page: number, size: number, searchTerm: string = ''): Observable<any> {
    // If search exists, we hit a different or filtered endpoint
    const params = `?page=${page}&size=${size}&search=${searchTerm}`;
    return this.http.get(`${this.apiUrl}${params}`);
  }

  ingestKev(): Observable<any> {
    return this.http.get(`${this.apiUrl}/ingest`, {});
  }
}
