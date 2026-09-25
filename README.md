<h1 align="center">Secy — Security Posture Management</h1>

<p align="center">
  <img src="ui/public/favicon.svg" alt="Secy logo" width="120px" height="120px"/>
  <br>
  <em>Cut through vulnerability-feed noise. Secy correlates NVD, FIRST EPSS and CISA KEV
    <br>against your SBOMs and infrastructure, and surfaces only what actually needs fixing.</em>
  <br>
</p>

<p align="center">
  <a href="#-quickstart"><strong>Quickstart</strong></a>
  ·
  <a href="#-how-it-works">How it works</a>
  ·
  <a href="ROADMAP.md">Roadmap</a>
  ·
  <a href="https://github.com/Middle-Systems/Secy/issues">Submit an Issue</a>
  <br>
  <br>
</p>

<p align="center">
  <a href="https://github.com/Middle-Systems/Secy/actions/workflows/ci.yml">
    <img src="https://github.com/Middle-Systems/Secy/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI status" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0" />
  </a>
  <img src="https://img.shields.io/badge/Java-17-orange.svg?logo=openjdk&logoColor=fff" alt="Java 17" />
  <img src="https://img.shields.io/badge/Spring%20Boot-3.3-6DB33F.svg?logo=springboot&logoColor=fff" alt="Spring Boot 3.3" />
  <img src="https://img.shields.io/badge/React-18-61DAFB.svg?logo=react&logoColor=000" alt="React 18" />
</p>

<hr>

**Secy** *(sek-wy)* is a security posture management platform engineered to filter the noise
inherent in modern vulnerability feeds. By aggregating data from diverse sources and applying
intelligent risk thresholds, Secy turns overwhelming lists of "findings" into a prioritized
stream of **actionable items** that truly require human intervention.

## ✨ Features

- **Threat-intel ingestion** — mirrors NVD, FIRST EPSS, CISA KEV, OSV and the CVE List into your own database.
- **SBOM & asset correlation** — maps CVEs onto components from CycloneDX / SPDX SBOMs and Trivy / Grype scans.
- **Actionable-item triage** — promotes an alert only when it is KEV-listed **or** its EPSS score clears a configurable threshold.
- **Compliance reports** — scan results and misconfigurations rolled up per report.
- **Agentless source connectors** — sync repositories straight from GitHub.
- **Dashboards** — at-a-glance stats on what's exposed, what's exploited and what's trending.
- **Self-hostable** — one `docker compose up` for the whole stack; JWT auth out of the box.

## 🚀 Quickstart

On any machine with Docker, the whole stack — PostgreSQL + API + UI behind nginx — comes up with:

```bash
cp .env.example .env       # fill in NVD_API_KEY, SECY_AUTH_JWT_SECRET, etc.
docker compose up --build  # http://localhost:4200
```

> [!IMPORTANT]
> **First run:** registration is open until an admin exists — the *first* account you register
> (UI register screen or `POST /auth/register`) becomes `ADMIN`. Register it right after startup,
> then set `SECY_AUTH_REGISTRATION_ENABLED=false` in `.env` and restart the `api` service to lock
> further self-registration. See [`.env.example`](.env.example) for every knob.

Get a free NVD API key at <https://nvd.nist.gov/developers/request-an-api-key>.

## 🧠 How it works

The goal of Secy is to separate *vulnerabilities that exist* from *vulnerabilities that matter*.
Every ingested finding passes through a three-stage intelligence funnel.

### 1. Ingestion & correlation

Secy ingests data from infrastructure scanners and SBOM sources (CycloneDX / SPDX), identifies
unique vulnerabilities by CVE identifier, and maps them to your specific assets and software
components.

### 2. The intelligence triple-check

| Pillar | Source | Answers |
|--------|--------|---------|
| **Context** | [NVD](https://nvd.nist.gov/) — National Vulnerability Database | How severe is it? (CVSS base score + description) |
| **Probability** | [FIRST EPSS](https://www.first.org/epss/) — Exploit Prediction Scoring System | How likely is it to be exploited in the wild? |
| **Evidence** | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities | Is it *already* being exploited by threat actors? |

### 3. Actionable item determination

An alert is promoted to an **Actionable Item** when it meets the criticality threshold:

1. **KEV-positive** — the CVE is listed in the CISA KEV catalog, **or**
2. **High-probability** — its EPSS score is $> 0.1$ (a $> 10\%$ chance of exploitation in the next 30 days).
   Tune it with `SECY_ACTIONABLE_EPSS_THRESHOLD`.

So if a component has 35 CVEs but only one is actively exploited, the engineer's dashboard
highlights the one that actually puts the organization at risk.

## 📦 Repository layout

This is a monorepo containing both halves of the platform:

| Path  | Stack | Description |
|-------|-------|-------------|
| [`ui/`](ui/README.md) | React 18 + Vite, TypeScript, TanStack Router/Query, Tailwind + shadcn/ui, Recharts | Web client — dashboards, threat-intel databases, product/SBOM catalog. |
| [`api/`](api/README.md) | Spring Boot 3.3 (Java 17), Gradle, JPA/PostgreSQL | REST backend — feed ingestion, SBOM parsing, correlation, stats. |

The backend was previously the standalone `secy-api` repository; its history is preserved here
under `api/` via a git subtree.

## 🛠 Development setup

### Prerequisites

- [Node.js](https://nodejs.org/) 20+
- [JDK](https://adoptium.net/) 17
- A PostgreSQL instance (Docker is the easiest way — see below)

Both services expect to run together. The frontend proxies `/api/*` to the backend
(`ui/vite.config.ts`).

### 1. PostgreSQL

The app **does not** start a database for you — run one and point the backend at it. It holds
the ingested NVD/EPSS/KEV feeds, so you want it persistent, not per-run.

```bash
docker compose -f api/compose.yaml up -d        # Postgres on :5433, named volume
```

Or use a native install / a hosted database and set `SECY_DB_URL` accordingly.

### 2. Backend

```bash
cd api
cp src/main/resources/application-local.properties.example src/main/resources/application-local.properties
#   ...then put your NVD API key in that (git-ignored) file
./gradlew bootRun                                # http://localhost:8080
```

It connects to `SECY_DB_URL` (default `jdbc:postgresql://localhost:5433/secy`). On first boot,
trigger the ingests (`POST /nvd/ingest`, `/kev/ingest`, `/epss/ingest`) once to populate the DB.

### 3. Frontend

```bash
cd ui && npm install && npm run dev              # http://localhost:4200
```

### Configuration

API config is env-var driven (`NVD_API_KEY`, `SECY_DB_URL`, `SECY_DB_USERNAME`,
`SECY_DB_PASSWORD`, `SECY_AUTH_JWT_SECRET`, …); `application-local.properties` is the local-only
override. See `api/src/main/resources/application.properties` for every setting and its default.

<details>
<summary><strong>Using the devcontainer</strong></summary>

The devcontainer image is Node 20 + JDK 17 and has **no Docker** of its own. Run Postgres on your
host (`docker compose -f api/compose.yaml up -d`); inside the container `SECY_DB_URL` is preset to
`host.docker.internal:5433`, so `./gradlew bootRun` reaches it with no extra config. Likewise,
when the frontend runs in the container and the backend on the host, the Vite proxy targets
`host.docker.internal:8080` automatically (`API_TARGET` overrides).

The root `docker-compose.yml` is the production-shaped stack (built images) — for day-to-day
work, stick with `api/compose.yaml` (Postgres only) plus the Gradle / Vite dev servers.

</details>

## 🤝 Contributing

Found a bug or have an idea? [Open an issue](https://github.com/Middle-Systems/Secy/issues).
Check the [roadmap](ROADMAP.md) to see where the project is heading, and the
[UI](ui/README.md) and [API](api/README.md) guides for conventions before sending a pull request.

## 📄 License

Secy is licensed under the **GNU Affero General Public License v3.0** ([`LICENSE`](LICENSE)). You
can run it, modify it, and self-host it freely; if you offer it as a network service, the AGPL
requires you to make your modified source available to its users.

The project is run on an **open-core** basis: the platform in this repository is and stays AGPL.
Some future enterprise-oriented add-ons (e.g. SSO, fine-grained RBAC, audit logging) will be
distributed under a separate commercial license. A hosted, managed version is offered as a paid
service — self-hosting the open-source platform is always free.
