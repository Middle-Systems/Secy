# Secy API
Vulnerability analytics and analysis.
---
Secy (sek-why) is a security tool written to be a single pane of glass for vulnerability management. 
The goal is to empower engineers to easily filter and find actionable issues within the vulnerability landscape. 


## Features
- NVD/EPSS/KEV Database Ingestion
- Ingestion of Software Bill of Materials (CycloneDX [JSON])
- CIS Docker Report Ingestion (Trivy [JSON])
- Docker Misconfiguration and Vulnerability Alerts
- SBOM Vulnerability Alerts
- Dismiss/Accept Risk with evidence

## Future Features:

- DeDupe vulnerabilities from multiple vulnerability sources
- Scan Cloud infrastructure for vulnerable services/implementations
- Filter SBOM and Create Vex Documents
- Generate ITSM tickets for Vulnerability alerts
- Add Pull Request Comments for vuln alerts
- SSL/TLS Scanning on endpoints
- Code Coverage Reports ingestion
- SAST/DAST Result ingestion
- Export Vex filtered sbom for product
- Export SBOM & Vex documents for product
