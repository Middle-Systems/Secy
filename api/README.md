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

## Lineage graph (Apache AGE): setup & manual verification

M1d (see `ROADMAP.md`) builds a lineage graph over Postgres data on top of the
[Apache AGE](https://age.apache.org/) extension: Product → SBOM/Asset → Component/AssetComponent →
VulnerabilityAlert/CompromiseFinding → Vulnerability. It is rebuilt from Postgres on demand, never
a second source of truth, and off by default (`secy.lineage.enabled=false`) — a Postgres without
AGE installed is completely unaffected. The planning/rendering/orchestration code is unit- and
H2-tested by `./gradlew test`; **the actual AGE JDBC execution can only be verified against a real
Postgres with AGE installed**, which this devcontainer cannot run (no Docker). This section is that
verification runbook, for whoever picks this up next with real Docker/Postgres access.

1. **Rebuild the Postgres image** (adds Apache AGE; your data volume is preserved):
   ```bash
   docker compose -f api/compose.yaml up -d --build
   ```
2. **Boot the app with lineage enabled** and confirm migration `022` applied:
   ```bash
   SECY_LINEAGE_ENABLED=true ./gradlew bootRun
   ```
   Then, against the same Postgres:
   ```sql
   select * from databasechangelog where id in ('022a-age-extension', '022b-lineage-graph');
   select * from ag_catalog.ag_graph where name = 'secy_lineage';
   ```
   Both should show one row each. If `022a`/`022b` are absent, AGE was not installed when Liquibase
   last ran `update` — rerun the app (or `liquibase update`) after step 1; the changesets are
   precondition-guarded to retry on every boot until they succeed (see the changelog README).
3. **Run the opt-in integration test**, `AgeLineageGraphWriterIT` (skipped by default — this is the
   one thing in the test suite this session could not exercise):
   ```bash
   SECY_AGE_IT_URL=jdbc:postgresql://localhost:5433/secy \
   SECY_AGE_IT_USER=secy \
   SECY_AGE_IT_PASSWORD=secy \
   ./gradlew test --tests net.jdesive.secy.lineage.AgeLineageGraphWriterIT
   ```
   It builds its own plain JDBC/transaction-manager stack (no Spring context), writes a snapshot for
   a random tenant id and cleans up after itself (an empty-snapshot write in `@AfterEach`), so it is
   safe to point at a real dev database.
4. **Trigger a real rebuild** through the API and poll it to completion:
   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8080/lineage/rebuild
   curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/jobs/<id>
   ```
5. **Spot-check counts** via `psql`, e.g. for the default tenant:
   ```sql
   select * from ag_catalog.cypher('secy_lineage', $$
       MATCH (n {tenant_id: '00000000-0000-0000-0000-000000000001'}) RETURN labels(n)[0], count(*)
   $$) as (label agtype, n agtype);
   ```
   Compare against `select count(*) from products where tenant_id = ...` and similar for
   `sbom`/`asset`/`sbom_component`/`vulnerability_alert`/`compromise_finding`, keeping the scope
   rules in mind (active SBOMs only, root component excluded, `present_in_last_scan = true` only).
6. **Re-run the rebuild** and confirm the counts are unchanged (idempotence) — a rebuild always
   deletes the tenant's whole prior subgraph first, so a second run should never produce duplicates
   or drift.
7. **Perf follow-up (not required for M1d):** once there is real data volume, `EXPLAIN` a
   representative `ag_catalog.cypher()` call against a warm graph to confirm the GIN
   properties-index and the edge start/end-id indexes `AgeSql.ensureSchemaBlock()` creates are
   actually being used, and revisit `secy.lineage.batch-size` if a rebuild's `UNWIND` batches show
   up as a bottleneck.
