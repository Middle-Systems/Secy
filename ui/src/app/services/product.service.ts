import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Product {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  activeSbomStatus?: string;
  activeSbomId?: string;
  vulnerabilityCount?: number;
  sboms: SBOM[];
  lastScanned?: Date;
  actionableCount: number;
}

export interface SBOM {
  id: string;
  format: string;
  specVersion: string;
  version: number;
  active: boolean;
  status: string;
  lastScannedAt?: Date;
  uploadDate: Date;
  totalVulnerabilities: number;
  components: SBOMComponent[];
  tools: SBOMTool[];
}

export interface SBOMTool {
  group: string;
  name: string;
  version: string;
  type: string;
}

export interface VulnerabilityAlert {
  id: string; // UUID
  component: SBOMComponent;
  vulnerability: Vulnerability;
}

export interface Vulnerability {
  id: string; // The CVE ID (e.g., CVE-2024-1234)
  description: string;
  baseSeverity: string;
  cvssScore: number;
  exploitabilityScore: number;
  impactScore: number;
  published: string;
  lastModified: string;
  // Live Intelligence Links
  kev?: KEV;
  epss?: EPSS;
}

export interface KEV {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  added: string; // Date string
  description: string;
  requiredActions: string;
}

export interface EPSS {
  cve: string;
  epss: number; // The probability float
  percentile: number;
  date: string;
}

export interface SBOMComponent {
  id: string;
  name: string;
  version: string;
  purl: string;
  vulnerabilityAlerts: VulnerabilityAlert[];
}

@Injectable({
  providedIn: 'root'
})
export class ProductService {
  private http = inject(HttpClient);
  private apiUrl = '/api/products';

  getProducts(): Observable<Product[]> {
    return this.http.get<Product[]>(this.apiUrl);
  }

  createProduct(product: Product): Observable<Product> {
    return this.http.post<Product>(this.apiUrl, product);
  }

  deleteProduct(id: string): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }

  getVulnerabilityDetails(sbomId: string): Observable<VulnerabilityAlert[]> {
    return this.http.get<VulnerabilityAlert[]>(`/api/sbom/${sbomId}/vulnerabilities`);
  }

}
