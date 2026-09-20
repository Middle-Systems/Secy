package net.jdesive.secy.job;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.SourceConnectorRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SourceConnector;
import net.jdesive.secy.persistence.entity.SourceConnectorType;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withForbiddenRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code CONNECTOR_SYNC} job end to end, on the offline H2 profile: GitHub's API stubbed at the
 * transport (see {@code OsvIngestServiceTest} for the pattern this follows), a fixture "org" of a
 * few repos, one with a normal SPDX dependency graph, one 404ing (dependency graph not enabled) and
 * one 403ing (rate limit / scope-restricted token) — proving Phase 6b's contract: one repo → one
 * {@code Product} → the real {@code SbomParser}/{@code SBOMService.ingestDocument} path, correlation
 * actually runs, a bad repo does not take the sync down, and the repo allowlist filters what is
 * fetched at all.
 *
 * <p>Not {@code @Transactional}, for the same reason {@code SbomUploadJobFlowTest} isn't: the
 * connector's own placeholder writes, the job's ingest transactions and the async vulnerability scan
 * that follows each have to actually commit for {@link JobRunner} and {@code VulnerabilityScanner},
 * on their own threads, to see anything.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ConnectorSyncJobFlowTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);
    private static final String ORG_REPOS_URL = "https://api.github.com/orgs/demo-org/repos?per_page=100";

    /**
     * Not used to seed anything — cleared because a {@code compromise_finding} left behind by
     * another test class holds an FK into {@code sbom_component} and would block the deletes below
     * (Phase 6).
     */
    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private net.jdesive.secy.persistence.JobRepository jobRepository;

    @Autowired
    private SourceConnectorRepository sourceConnectorRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SBOMRepository sbomRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer github;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        sbomRepository.deleteAll();
        sourceConnectorRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();
        osvRepository.deleteAll();
        cveRepository.deleteAll();
        epssRepository.deleteAll();

        github = MockRestServiceServer.bindTo(restTemplate).build();
    }

    /* ------------------------------------------------------------------ */
    /* Happy path + per-repo skip                                         */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser(username = "alice@example.com")
    void syncIngestsAGoodRepoAndSkipsA404AndA403WithoutFailingTheWholeSync() throws Exception {
        // lodash 4.17.20 is vulnerable per this advisory; well above the EPSS funnel threshold.
        advisory("GHSA-connector-lodash", "npm", "lodash", "CVE-2099-9001", "4.0.0", "4.17.21");
        cve("CVE-2099-9001");

        github.expect(requestTo(ORG_REPOS_URL)).andRespond(withSuccess(reposJson(), MediaType.APPLICATION_JSON));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-a/dependency-graph/sbom"))
                .andRespond(withSuccess(sbomJson("service-a"), MediaType.APPLICATION_JSON));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-b/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"message\":\"Not Found\"}"));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-c/dependency-graph/sbom"))
                .andRespond(withForbiddenRequest());

        UUID connectorId = connector("demo-org", null);

        String response = mockMvc.perform(post("/connectors/{id}/sync", connectorId))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("CONNECTOR_SYNC"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"))
                .andReturn().getResponse().getContentAsString();

        SourceConnector queued = sourceConnectorRepository.findById(connectorId).orElseThrow();
        assertThat(queued.getStatus()).isEqualTo(SourceConnector.STATUS_QUEUED);

        UUID jobId = jobRepository.findAll().get(0).getId();
        assertThat(response).contains(jobId.toString());

        jobRunner.poll();
        Job finished = awaitJobTerminal(jobId);
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getItemsProcessed()).as("one of three repos actually ingested").isEqualTo(1);

        SourceConnector synced = sourceConnectorRepository.findById(connectorId).orElseThrow();
        assertThat(synced.getStatus())
                .as("partial success is still COMPLETED — the roadmap's 'degrades to stale, not empty'")
                .isEqualTo(SourceConnector.STATUS_COMPLETED);
        assertThat(synced.getLastSyncedAt()).isNotNull();

        // Exactly one product for the one repo that actually had a dependency graph.
        assertThat(productRepository.findAll()).hasSize(1);
        Product product = productRepository.findByName("demo-org/service-a").orElseThrow();

        SBOM sbom = sbomRepository.findByProductIdAndActiveTrue(product.getId()).orElseThrow();
        assertThat(sbom.getProductVersion()).isEqualTo("main");
        assertThat(sbom.getFormat()).isEqualTo("SPDX");

        // The async vulnerability scan (same VulnerabilityScanner hop SbomUploadJobFlowTest awaits)
        // must run and settle before the alert can be asserted on.
        awaitSbomStatus(sbom.getId());

        List<VulnerabilityAlert> alerts = alertRepository.findAllBySbomIdWithIntelligence(sbom.getId());
        assertThat(alerts)
                .as("correlation actually ran through the real OSV-primary path, not a shortcut")
                .extracting(a -> a.getVulnerability().getId())
                .containsExactly("CVE-2099-9001");
        assertThat(alerts.get(0).isActionable()).isTrue();

        github.verify();
    }

    /* ------------------------------------------------------------------ */
    /* Repo allowlist                                                     */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void repoAllowlistFiltersToOnlyTheNamedRepos() throws Exception {
        github.expect(requestTo(ORG_REPOS_URL)).andRespond(withSuccess(reposJson(), MediaType.APPLICATION_JSON));
        // Only service-a is allow-listed, so its dependency graph is the only one that may be
        // fetched — MockRestServiceServer fails the test on any unexpected request, which is exactly
        // what would happen if the allowlist were not honoured.
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-a/dependency-graph/sbom"))
                .andRespond(withSuccess(sbomJson("service-a"), MediaType.APPLICATION_JSON));

        UUID connectorId = connector("demo-org", Set.of("demo-org/service-a"));

        mockMvc.perform(post("/connectors/{id}/sync", connectorId)).andExpect(status().isAccepted());
        UUID jobId = jobRepository.findAll().get(0).getId();
        jobRunner.poll();
        assertThat(awaitJobTerminal(jobId).getStatus()).isEqualTo(JobStatus.SUCCEEDED);

        assertThat(productRepository.findAll()).hasSize(1);
        assertThat(productRepository.findByName("demo-org/service-a")).isPresent();

        github.verify();
    }

    /* ------------------------------------------------------------------ */
    /* Every repo failing                                                 */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void everyRepoFailingMarksTheConnectorAndTheJobFailed() throws Exception {
        github.expect(requestTo(ORG_REPOS_URL)).andRespond(withSuccess(reposJson(), MediaType.APPLICATION_JSON));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-a/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON).body("{\"message\":\"Not Found\"}"));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-b/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON).body("{\"message\":\"Not Found\"}"));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-c/dependency-graph/sbom"))
                .andRespond(withForbiddenRequest());

        UUID connectorId = connector("demo-org", null);

        mockMvc.perform(post("/connectors/{id}/sync", connectorId)).andExpect(status().isAccepted());
        UUID jobId = jobRepository.findAll().get(0).getId();
        jobRunner.poll();

        Job finished = awaitJobTerminal(jobId);
        assertThat(finished.getStatus()).isEqualTo(JobStatus.FAILED);

        SourceConnector failed = sourceConnectorRepository.findById(connectorId).orElseThrow();
        assertThat(failed.getStatus()).isEqualTo(SourceConnector.STATUS_FAILED);
        assertThat(productRepository.findAll()).isEmpty();
    }

    /**
     * The regression this test pins: every repo 404ing (no dependency graph — the ordinary state
     * for a personal account's repos, where Dependency graph is off by default for private repos)
     * is NOT the same as every repo being broken. Zero {@code forbidden}/{@code errored} means
     * there is no evidence anything is wrong with the connector or its token, so the sync completes
     * cleanly with zero components rather than failing the whole connector on a misleading
     * {@code IllegalStateException}.
     */
    @Test
    @WithMockUser
    void everyRepoHavingNoDependencyGraphCompletesCleanlyRatherThanFailing() throws Exception {
        github.expect(requestTo(ORG_REPOS_URL)).andRespond(withSuccess(reposJson(), MediaType.APPLICATION_JSON));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-a/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON).body("{\"message\":\"Not Found\"}"));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-b/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON).body("{\"message\":\"Not Found\"}"));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-c/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON).body("{\"message\":\"Not Found\"}"));

        UUID connectorId = connector("demo-org", null);

        mockMvc.perform(post("/connectors/{id}/sync", connectorId)).andExpect(status().isAccepted());
        UUID jobId = jobRepository.findAll().get(0).getId();
        jobRunner.poll();

        Job finished = awaitJobTerminal(jobId);
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);
        assertThat(finished.getMessage()).contains("0/3 repos ingested").contains("Dependency Graph data available");

        SourceConnector completed = sourceConnectorRepository.findById(connectorId).orElseThrow();
        assertThat(completed.getStatus()).isEqualTo(SourceConnector.STATUS_COMPLETED);
        assertThat(completed.getLastSyncedAt()).isNotNull();
        assertThat(productRepository.findAll()).isEmpty();
    }

    /* ------------------------------------------------------------------ */
    /* Per-invocation concurrency                                         */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void concurrentSyncsOfDifferentConnectorsEachGetTheirOwnJob() throws Exception {
        github.expect(requestTo(ORG_REPOS_URL)).andRespond(withSuccess(reposJson(), MediaType.APPLICATION_JSON));
        github.expect(requestTo(ORG_REPOS_URL)).andRespond(withSuccess(reposJson(), MediaType.APPLICATION_JSON));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-a/dependency-graph/sbom"))
                .andRespond(withSuccess(sbomJson("service-a"), MediaType.APPLICATION_JSON));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-a/dependency-graph/sbom"))
                .andRespond(withSuccess(sbomJson("service-a"), MediaType.APPLICATION_JSON));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-b/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON).body("{}"));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-b/dependency-graph/sbom"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.APPLICATION_JSON).body("{}"));
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-c/dependency-graph/sbom"))
                .andRespond(withForbiddenRequest());
        github.expect(requestTo("https://api.github.com/repos/demo-org/service-c/dependency-graph/sbom"))
                .andRespond(withForbiddenRequest());

        UUID first = connector("demo-org", null);
        UUID second = connector("demo-org", null);

        mockMvc.perform(post("/connectors/{id}/sync", first)).andExpect(status().isAccepted());
        mockMvc.perform(post("/connectors/{id}/sync", second)).andExpect(status().isAccepted());

        // CONNECTOR_SYNC is per-invocation like SBOM_UPLOAD/ASSET_SCAN/COMPLIANCE_SCAN, not a
        // singleton feed pull — both requests must get their own job rather than sharing one.
        assertThat(jobRepository.count()).isEqualTo(2);
        assertThat(jobRepository.findAll()).extracting(Job::getType)
                .containsExactly(net.jdesive.secy.persistence.entity.JobType.CONNECTOR_SYNC,
                        net.jdesive.secy.persistence.entity.JobType.CONNECTOR_SYNC);
    }

    /* ------------------------------------------------------------------ */
    /* Unknown connector                                                  */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void syncingAnUnknownConnectorIs404AndQueuesNoJob() throws Exception {
        mockMvc.perform(post("/connectors/{id}/sync", UUID.randomUUID()))
                .andExpect(status().isNotFound());
        assertThat(jobRepository.count()).as("no orphan job for an id that was never valid").isZero();
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private UUID connector(String scope, Set<String> allowlist) {
        SourceConnector connector = new SourceConnector();
        connector.setType(SourceConnectorType.GITHUB);
        connector.setName("Test connector " + UUID.randomUUID());
        connector.setScope(scope);
        if (allowlist != null) {
            connector.setRepoAllowlist(allowlist);
        }
        return sourceConnectorRepository.saveAndFlush(connector).getId();
    }

    private Job awaitJobTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> jobRepository.findById(id).orElseThrow().getStatus().isTerminal());
        return jobRepository.findById(id).orElseThrow();
    }

    private void awaitSbomStatus(UUID sbomId) {
        await().atMost(SETTLE).until(() -> {
            String status = sbomRepository.findById(sbomId).orElseThrow().getStatus();
            return "COMPLETED".equals(status) || "FAILED".equals(status);
        });
    }

    private void cve(String id) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for a connector-sync test");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cveRepository.save(cve);

        EPSS epss = new EPSS();
        epss.setCve(id);
        epss.setEpss(0.9f);
        epss.setPercentile(0.99f);
        epss.setDate(LocalDateTime.now());
        epssRepository.save(epss);
    }

    private void advisory(String osvId, String ecosystem, String packageName, String alias,
                          String introduced, String fixed) {
        OsvAdvisory advisory = new OsvAdvisory();
        advisory.setOsvId(osvId);
        advisory.setEcosystem(ecosystem);
        advisory.setPackageName(packageName);
        advisory.setModified(LocalDateTime.now());
        advisory.getAliases().add(alias);

        OsvAffectedRange range = new OsvAffectedRange();
        range.setAdvisory(advisory);
        range.setRangeType("SEMVER");
        range.setIntroduced(introduced);
        range.setFixed(fixed);
        advisory.getRanges().add(range);

        osvRepository.save(advisory);
    }

    /** {@code GET /orgs/demo-org/repos} — three repos, one page, no {@code Link} header needed. */
    private static String reposJson() {
        return """
                [
                  {"name":"service-a","full_name":"demo-org/service-a","default_branch":"main"},
                  {"name":"service-b","full_name":"demo-org/service-b","default_branch":"main"},
                  {"name":"service-c","full_name":"demo-org/service-c","default_branch":"main"}
                ]
                """;
    }

    /**
     * GitHub's dependency-graph SBOM response shape: the SPDX document nested under a top-level
     * {@code "sbom"} key (verified against the live API — see {@code GitHubApiClient}'s Javadoc).
     * Names one dependency, {@code lodash@4.17.20}, so the happy-path test can correlate it.
     */
    private static String sbomJson(String repoSlug) {
        return """
                {
                  "sbom": {
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": "demo-org/%s",
                    "creationInfo": {
                      "created": "2026-09-10T10:00:00Z",
                      "creators": [ "Tool: GitHub.com-Dependency-Graph" ]
                    },
                    "documentDescribes": [ "SPDXRef-Package-root" ],
                    "packages": [
                      {
                        "SPDXID": "SPDXRef-Package-root",
                        "name": "demo-org/%s",
                        "versionInfo": "main",
                        "downloadLocation": "NOASSERTION"
                      },
                      {
                        "SPDXID": "SPDXRef-Package-lodash",
                        "name": "lodash",
                        "versionInfo": "4.17.20",
                        "downloadLocation": "NOASSERTION",
                        "externalRefs": [
                          {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/lodash@4.17.20"
                          }
                        ]
                      }
                    ],
                    "relationships": [
                      {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-Package-root"
                      }
                    ]
                  }
                }
                """.formatted(repoSlug, repoSlug);
    }

}
