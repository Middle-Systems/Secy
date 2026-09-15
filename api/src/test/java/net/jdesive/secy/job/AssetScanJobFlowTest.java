package net.jdesive.secy.job;

import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.AssetComponentRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.AssetScanIngestJobService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code ASSET_SCAN} job end to end, on the offline H2 profile.
 *
 * <p>Proves the three things Phase 4 actually claims: a scanner-reported CVE becomes an alert
 * immediately with {@code fixSource = SCANNER} where the scanner supplied a fix; Grype's
 * {@code fix.state} vocabulary maps onto {@code FixState} correctly; and Secy's own correlation runs
 * alongside the scanner, so an OSV fix version is picked up for a finding the scanner had no fix for.
 *
 * <p>Deliberately not {@code @Transactional}: the upload's placeholder transaction and the job's
 * ingest transaction each have to commit for {@link JobRunner}'s worker thread to observe anything.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AssetScanJobFlowTest {

    private static final Duration SETTLE = Duration.ofSeconds(15);

    /**
     * Not used to seed anything — cleared because a {@code compromise_finding} left behind by
     * another test class holds an FK into {@code sbom_component} / {@code asset_component} and
     * would block the deletes below (Phase 6).
     */
    @Autowired
    private CompromiseFindingRepository findingRepository;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private JobRunner jobRunner;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private AssetComponentRepository assetComponentRepository;

    @Autowired
    private VulnerabilityAlertRepository alertRepository;

    @Autowired
    private VulnerabilityRepository cveRepository;

    @Autowired
    private OsvAdvisoryRepository osvRepository;

    @Autowired
    private EPSSRepository epssRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private AssetScanIngestJobService assetScanIngestJobService;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        findingRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();
        osvRepository.deleteAll();
        cveRepository.deleteAll();
        epssRepository.deleteAll();
    }

    /* ------------------------------------------------------------------ */
    /* Trivy                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser(username = "alice@example.com")
    void aTrivyScanCreatesTheAssetItsComponentsAndScannerSourcedAlerts() throws Exception {
        // Every CVE the fixture names, so nothing is dropped for want of an NVD row. All are
        // EPSS-high, so all clear the funnel.
        cve("CVE-2099-4001");
        cve("CVE-2099-4002");
        cve("CVE-2099-4003");

        String response = scan("trivy", "trivy-image.json")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("ASSET_SCAN"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"))
                .andReturn().getResponse().getContentAsString();

        // The controller's synchronous half: an asset row exists immediately, nothing ingested.
        Asset placeholder = onlyAsset();
        assertThat(placeholder.getName()).as("taken from the report's own ArtifactName")
                .isEqualTo("acme/api:1.4.2");
        assertThat(placeholder.getType()).isEqualTo(AssetType.CONTAINER_IMAGE);
        assertThat(placeholder.getStatus()).isEqualTo(Asset.STATUS_QUEUED);
        assertThat(placeholder.getScanner()).isEqualTo("Trivy");
        assertThat(assetComponentRepository.findAllByAssetId(placeholder.getId())).isEmpty();

        UUID jobId = jobRepository.findAll().get(0).getId();
        assertThat(response).contains(jobId.toString());

        jobRunner.poll();
        Job finished = awaitJobTerminal(jobId);
        assertThat(finished.getStatus()).isEqualTo(JobStatus.SUCCEEDED);

        Asset ingested = assetRepository.findById(placeholder.getId()).orElseThrow();
        assertThat(ingested.getStatus()).isEqualTo(Asset.STATUS_COMPLETED);
        assertThat(ingested.getLastScannedAt()).isNotNull();
        assertThat(ingested.getPendingRawBody()).as("consumed once ingested").isNull();

        // Three vulnerable packages: openssl + busybox (os-pkgs) and lodash (lang-pkgs). The
        // DLA-9999-1 finding on musl names no CVE, so neither it nor its package is ingested.
        Map<String, AssetComponent> components = componentsOf(ingested.getId());
        assertThat(components.keySet()).containsExactlyInAnyOrder("openssl", "busybox", "lodash");
        assertThat(components).doesNotContainKey("musl");

        // os-pkgs get no PURL by design — see ScannerPurls — so their identity is name-based and
        // they correlate through the CPE fallback.
        assertThat(components.get("openssl").getPurl()).isNull();
        assertThat(components.get("openssl").getIdentityKey()).isEqualTo("name/openssl");
        assertThat(components.get("openssl").getSource()).isEqualTo(AssetComponentSource.TRIVY);
        assertThat(components.get("openssl").getLayer()).startsWith("sha256:1111aaaa");

        // lang-pkgs get a synthesized PURL, so they take the same OSV-primary path an SBOM
        // component would.
        assertThat(components.get("lodash").getPurl()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(components.get("lodash").getIdentityKey()).isEqualTo("npm/lodash");
        assertThat(components.get("lodash").getEcosystem()).isEqualTo("npm");
        assertThat(components.get("lodash").getPackagePath()).isEqualTo("app/package-lock.json");

        Map<String, VulnerabilityAlert> alerts = alertsOf(ingested.getId());
        assertThat(alerts.keySet())
                .as("a scanner-reported CVE becomes an alert immediately, without waiting for OSV/NVD")
                .containsExactlyInAnyOrder("CVE-2099-4001", "CVE-2099-4002", "CVE-2099-4003");

        // Trivy supplied a FixedVersion for openssl and none for the other two.
        VulnerabilityAlert openssl = alerts.get("CVE-2099-4001");
        assertThat(openssl.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(openssl.getFixedVersions()).isEqualTo("3.1.4-r0");
        assertThat(openssl.getFixSource()).isEqualTo(FixSource.SCANNER);
        assertThat(openssl.getMatchConfidence())
                .as("the scanner read the image's own package database — the strongest component "
                        + "identification Secy gets")
                .isEqualTo(MatchConfidence.EXACT);
        assertThat(openssl.isActionable()).isTrue();
        assertThat(openssl.getAssetComponent()).isNotNull();
        assertThat(openssl.getComponent()).as("XOR: an asset alert cites no SBOM component").isNull();

        assertThat(alerts.get("CVE-2099-4002").getFixState()).isEqualTo(FixState.UNKNOWN);
        assertThat(alerts.get("CVE-2099-4002").getFixedVersions()).isNull();
    }

    @Test
    @WithMockUser
    void reCorrelationPicksUpAnOsvFixVersionTheScannerDidNotSupply() throws Exception {
        cve("CVE-2099-4001");
        cve("CVE-2099-4002");
        cve("CVE-2099-4003");

        // Trivy reported lodash 4.17.20 / CVE-2099-4003 with NO FixedVersion. OSV knows the fix.
        // The ingest job correlates the asset's components in the same pass, so the alert should
        // come out FIXED at OSV's version — this is the roadmap's "picks up an OSV fix version when
        // the scanner didn't supply one".
        advisory("GHSA-lodash-fixture", "npm", "lodash", "CVE-2099-4003", "4.0.0", "4.17.21");

        scan("trivy", "trivy-image.json").andExpect(status().isAccepted());
        UUID jobId = jobRepository.findAll().get(0).getId();
        jobRunner.poll();
        assertThat(awaitJobTerminal(jobId).getStatus()).isEqualTo(JobStatus.SUCCEEDED);

        VulnerabilityAlert lodash = alertsOf(onlyAsset().getId()).get("CVE-2099-4003");
        assertThat(lodash.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(lodash.getFixedVersions()).isEqualTo("4.17.21");
        assertThat(lodash.getFixSource()).isEqualTo(FixSource.OSV);

        // And the scanner's own fix is not clobbered by correlation having nothing to say about it.
        VulnerabilityAlert openssl = alertsOf(onlyAsset().getId()).get("CVE-2099-4001");
        assertThat(openssl.getFixedVersions()).isEqualTo("3.1.4-r0");
        assertThat(openssl.getFixSource()).isEqualTo(FixSource.SCANNER);
    }

    @Test
    @WithMockUser
    void reScanningTheSameAssetUpdatesItInPlaceAndAutoResolvesWhatIsGone() throws Exception {
        cve("CVE-2099-4001");
        cve("CVE-2099-4002");
        cve("CVE-2099-4003");

        runScan("trivy", "trivy-image.json");
        UUID assetId = onlyAsset().getId();
        assertThat(alertsOf(assetId)).hasSize(3);

        // A second scan of the same image:tag reporting only openssl. Same asset row (keyed on
        // (type, name)), so the other two findings must auto-resolve rather than linger ACTIVE.
        runScanWithBody("trivy", """
                {"SchemaVersion":2,"ArtifactName":"acme/api:1.4.2","ArtifactType":"container_image",
                 "Results":[{"Target":"acme/api:1.4.2 (alpine 3.18.4)","Class":"os-pkgs","Type":"alpine",
                   "Vulnerabilities":[{"VulnerabilityID":"CVE-2099-4001","PkgName":"openssl",
                     "InstalledVersion":"3.1.3-r0","FixedVersion":"3.1.4-r0"}]}]}
                """);

        assertThat(assetRepository.count()).as("re-scan updates in place; no second asset row").isEqualTo(1);
        assertThat(assetRepository.findById(assetId)).isPresent();

        Map<String, VulnerabilityAlert> alerts = alertsOf(assetId);
        assertThat(alerts).as("alerts are auto-resolved, never deleted").hasSize(3);
        assertThat(alerts.get("CVE-2099-4001").getLifecycleState())
                .isEqualTo(net.jdesive.secy.persistence.entity.AlertLifecycleState.ACTIVE);
        assertThat(alerts.get("CVE-2099-4002").getLifecycleState())
                .isEqualTo(net.jdesive.secy.persistence.entity.AlertLifecycleState.AUTO_RESOLVED);
        assertThat(alerts.get("CVE-2099-4003").getLifecycleState())
                .isEqualTo(net.jdesive.secy.persistence.entity.AlertLifecycleState.AUTO_RESOLVED);

        // The vanished components are kept as evidence, flagged absent — deleting them would take
        // the alerts citing them with it.
        Map<String, AssetComponent> components = componentsOf(assetId);
        assertThat(components.get("openssl").isPresentInLastScan()).isTrue();
        assertThat(components.get("lodash").isPresentInLastScan()).isFalse();
        assertThat(components.get("lodash").getLastSeenAt()).isNotNull();
    }

    /* ------------------------------------------------------------------ */
    /* Grype                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void aGrypeScanMapsPurlsAndTheFixStateVocabulary() throws Exception {
        cve("CVE-2099-5001");
        cve("CVE-2099-5002");
        cve("CVE-2099-5003");

        runScan("grype", "grype-image.json");

        Asset asset = onlyAsset();
        assertThat(asset.getName()).as("taken from source.target.userInput").isEqualTo("acme/worker:2.0.0");
        assertThat(asset.getScanner()).isEqualTo("Grype");

        Map<String, AssetComponent> components = componentsOf(asset.getId());
        // The fourth match (orphan-pkg) is a GHSA with no CVE anywhere — dropped, package and all.
        assertThat(components.keySet())
                .containsExactlyInAnyOrder("org.apache.logging.log4j:log4j-core", "minimist", "zlib");

        // Grype's own PURL is preferred over anything synthesized.
        assertThat(components.get("minimist").getPurl()).isEqualTo("pkg:npm/minimist@1.2.0");
        assertThat(components.get("org.apache.logging.log4j:log4j-core").getIdentityKey())
                .isEqualTo("maven/org.apache.logging.log4j:log4j-core");
        // …except for an OS package, whose apk PURL is dropped so the identity survives a scanner
        // upgrade. See ScannerPurls.
        assertThat(components.get("zlib").getPurl()).isNull();
        assertThat(components.get("zlib").getIdentityKey()).isEqualTo("name/zlib");

        Map<String, VulnerabilityAlert> alerts = alertsOf(asset.getId());
        assertThat(alerts.keySet()).containsExactlyInAnyOrder(
                "CVE-2099-5001",
                // resolved through relatedVulnerabilities[], since Grype indexed it under a GHSA
                "CVE-2099-5002",
                "CVE-2099-5003");

        // fix.state "fixed" + versions
        assertThat(alerts.get("CVE-2099-5001").getFixState()).isEqualTo(FixState.FIXED);
        assertThat(alerts.get("CVE-2099-5001").getFixedVersions()).isEqualTo("2.17.1");
        assertThat(alerts.get("CVE-2099-5001").getFixSource()).isEqualTo(FixSource.SCANNER);

        // fix.state "wont-fix" — a positive claim that no fixed release is coming
        assertThat(alerts.get("CVE-2099-5002").getFixState()).isEqualTo(FixState.NO_FIX);
        assertThat(alerts.get("CVE-2099-5002").getFixedVersions()).isNull();
        assertThat(alerts.get("CVE-2099-5002").getFixSource()).isEqualTo(FixSource.SCANNER);

        // fix.state "unknown" — nothing said, and nothing else knows either
        assertThat(alerts.get("CVE-2099-5003").getFixState()).isEqualTo(FixState.UNKNOWN);
    }

    /* ------------------------------------------------------------------ */
    /* Failure path                                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void aJobThatFailsMidIngestLeavesTheAssetRowFailedNotStuck() {
        // Bypasses the controller (which would have rejected an unparseable body with 400) to
        // exercise the job-side failure path directly.
        UUID jobId = UUID.randomUUID();
        Asset placeholder = new Asset();
        placeholder.setType(AssetType.HOST);
        placeholder.setName("broken-host-" + UUID.randomUUID());
        placeholder.setStatus(Asset.STATUS_QUEUED);
        placeholder.setScanner("Trivy");
        placeholder.setPendingScanFormat("TRIVY");
        placeholder.setPendingRawBody("{ this is not valid json");
        placeholder.setJobId(jobId);
        UUID assetId = assetRepository.saveAndFlush(placeholder).getId();

        Assertions.assertThrows(RuntimeException.class,
                () -> assetScanIngestJobService.ingest(jobId, JobProgress.NOOP));

        Asset reloaded = assetRepository.findById(assetId).orElseThrow();
        assertThat(reloaded.getStatus())
                .as("the UI must never show a permanently-stuck PROCESSING/QUEUED row")
                .isEqualTo(Asset.STATUS_FAILED);
        assertThat(reloaded.getPendingRawBody()).isNull();
    }

    @Test
    @WithMockUser
    void concurrentScansOfDifferentAssetsEachGetTheirOwnJob() throws Exception {
        scan("trivy", "trivy-image.json").andExpect(status().isAccepted());
        scan("grype", "grype-image.json").andExpect(status().isAccepted());

        // ASSET_SCAN is per-invocation like SBOM_UPLOAD, not a singleton feed pull.
        assertThat(jobRepository.count()).isEqualTo(2);
        assertThat(assetRepository.count()).isEqualTo(2);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private ResultActions scan(String scanner, String fixture) throws Exception {
        return mockMvc.perform(post("/assets/scan/{scanner}", scanner)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(fixture)));
    }

    /** Upload, run the job, and wait for it to settle. */
    private void runScan(String scanner, String fixture) throws Exception {
        runScanWithBody(scanner, body(fixture));
    }

    private void runScanWithBody(String scanner, String content) throws Exception {
        mockMvc.perform(post("/assets/scan/{scanner}", scanner)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(content))
                .andExpect(status().isAccepted());
        UUID jobId = jobRepository.findAll().stream()
                .filter(job -> !job.getStatus().isTerminal())
                .findFirst().orElseThrow().getId();
        jobRunner.poll();
        assertThat(awaitJobTerminal(jobId).getStatus()).isEqualTo(JobStatus.SUCCEEDED);
    }

    private Asset onlyAsset() {
        List<Asset> all = assetRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    private Map<String, AssetComponent> componentsOf(UUID assetId) {
        return index(assetComponentRepository.findAllByAssetId(assetId), AssetComponent::getName);
    }

    private Map<String, VulnerabilityAlert> alertsOf(UUID assetId) {
        return index(alertRepository.findAllByAssetId(assetId), a -> a.getVulnerability().getId());
    }

    private static <T> Map<String, T> index(List<T> rows, Function<T, String> key) {
        return rows.stream().collect(java.util.stream.Collectors.toMap(key, Function.identity()));
    }

    private Job awaitJobTerminal(UUID id) {
        await().atMost(SETTLE).until(() -> jobRepository.findById(id).orElseThrow().getStatus().isTerminal());
        return jobRepository.findById(id).orElseThrow();
    }

    private void cve(String id) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for an asset-scan test");
        cve.setBaseSeverity("HIGH");
        cve.setCvssScore(7.5d);
        cveRepository.save(cve);

        // Well above the 0.1 funnel threshold, so every seeded alert is actionable.
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

    private static String body(String fixture) throws IOException {
        try (InputStream in = new ClassPathResource("asset/" + fixture).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
