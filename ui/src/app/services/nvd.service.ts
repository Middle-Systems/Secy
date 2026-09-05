import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class NvdService {
  private apiUrl = '/api/nvd/search';

  constructor(private http: HttpClient) {}

  getVulnerabilities(search: string, page: number, size: number): Observable<any> {
    const params = new HttpParams()
      .set('search', search)
      .set('page', page.toString())
      .set('size', size.toString());

    return this.http.get<any>(this.apiUrl, { params });
  }

  ingestCveData(): Observable<any> {
    return this.http.get('api/nvd/ingest', {});
  }
}
