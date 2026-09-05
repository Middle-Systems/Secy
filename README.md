# Secy | Security Posture Management Platform
**Secy** *(sek-wy)* is a Security Posture Management Platform engineered to filter the noise inherent in modern vulnerability feeds. By aggregating data from diverse sources and applying intelligent risk thresholds, Secy transforms overwhelming lists of "findings" into a prioritized stream of **actionable items** that truly require human intervention.

## 🛡 Overview
Traditional vulnerability management often leaves security teams buried under a mountain of low-context alerts. Secy streamlines this process by ingesting data from both Infrastructure and Software Bill of Materials (SBOM) sources, then enriching that data with live threat intelligence.

The platform correlates internal assets with three critical data pillars to provide a multidimensional view of risk:

 - NVD (National Vulnerability Database): Provides the foundational CVSS severity scores and vulnerability descriptions.

 - FIRST EPSS (Exploit Prediction Scoring System): Offers a data-driven estimate of the probability that a vulnerability will be exploited in the wild.

 - CISA KEV (Known Exploited Vulnerabilities): Leverages the CISA catalog to identify vulnerabilities with a proven track record of active exploitation.

By triangulating these sources, Secy isolates the signal from the noise, ensuring that your security resources are focused on the vulnerabilities that pose the greatest real-world threat to your environment.

## 🧠 How It Works: 
Noise Reduction LogicThe primary goal of Secy is to separate "vulnerabilities that exist" from "vulnerabilities that matter." To do this, the platform passes every ingested finding through a three-stage intelligence funnel.

### 1. Ingestion & Correlation
Secy ingests data from infrastructure scanners and SBOM sources (CycloneDX/SPDX). It identifies unique vulnerabilities using CVE identifiers and maps them to your specific assets and software components.

### 2. The Intelligence Triple-Check
Once a vulnerability is identified, Secy enriches it with the following data points:
- Context (NVD): Defines the base severity ($CVSS$).
- Probability (EPSS): Analyzes the likelihood of exploitation.
- Evidence (KEV): Confirms if the vulnerability is already being used by threat actors.


### 3. Actionable Item Determination
Secy promotes a standard "Alert" to an Actionable Item if it meets the Criticality Threshold. By default, an item requires immediate attention if:
1. It is KEV-Positive: The vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog.
2. It is High-Probability: The EPSS score is $> 0.1$ (indicating a $> 10\%$ probability of exploitation within the next 30 days).
 
This logic ensures that if a component has 35 CVEs, but only one is actively being exploited, the engineer's dashboard highlights the one that actually puts the organization at risk.
