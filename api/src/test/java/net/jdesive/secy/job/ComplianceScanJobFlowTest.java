package net.jdesive.secy.job;

import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.AssetComponentRepository;
import net.jdesive.secy.persistence.AssetRepository;
import net.jdesive.secy.persistence.CveExploitRepository;
import net.jdesive.secy.persistence.DockerComplianceControlRepository;
import net.jdesive.secy.persistence.DockerComplianceReportMisconfigRepository;
import net.jdesive.secy.persistence.DockerComplianceReportRepository;
import net.jdesive.secy.persistence.DockerComplianceReportVulnerabilityRepository;
import net.jdesive.secy.persistence.EPSSRepository;
import net.jdesive.secy.persistence.JobRepository;
import net.jdesive.secy.persistence.KEVRepository;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.VulnerabilityRepository;
import net.jdesive.secy.model.compliance.ComplianceMisconfigurationResponse;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetComponent;
import net.jdesive.secy.persistence.entity.AssetType;
import net.jdesive.secy.persistence.entity.ComplianceStatus;
import net.jdesive.secy.persistence.entity.CveExploit;
import net.jdesive.secy.persistence.entity.DockerComplianceControl;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.KEV;
import net.jdesive.secy.persistence.entity.MatchConfidence;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.persistence.entity.OsvAffectedRange;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
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
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The {@code COMPLIANCE_SCAN} job end to end, on the offline H2 profile.
 *
 * <p>Proves the claim Phase 5 exists to make: a CIS/Docker compliance report's <b>vulnerability</b>
 * half goes through the very same pipeline a {@code trivy image} scan does — asset, asset components,
 * {@code VulnerabilityAlert}, enrichment, funnel, {@code GET /actionable} — while its
 * <b>misconfiguration</b> half stays a compliance concept with a pass/fail/skip verdict and
 * remediation text.
 *
 * <p>Deliberately not {@code @Transactional}: the upload's placeholder transaction and the job's
 * ingest transaction each have to commit for {@link JobRunner}'s worker thread to observe anything.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ComplianceScanJobFlowTest {

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
    private DockerComplianceReportRepository reportRepository;

    @Autowired
    private DockerComplianceControlRepository controlRepository;

    @Autowired
    private DockerComplianceReportMisconfigRepository misconfigRepository;

    @Autowired
    private DockerComplianceReportVulnerabilityRepository reportVulnerabilityRepository;

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
    private KEVRepository kevRepository;

    @Autowired
    private CveExploitRepository exploitRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private net.jdesive.secy.service.ComplianceService complianceService;

    @BeforeEach
    void seed() {
        // The H2 database is shared by every @SpringBootTest context in the run.
        findingRepository.deleteAll();
        reportRepository.deleteAll();
        alertRepository.deleteAll();
        assetRepository.deleteAll();
        jobRepository.deleteAll();
        productRepository.deleteAll();
        osvRepository.deleteAll();
        kevRepository.deleteAll();
        exploitRepository.deleteAll();
        cveRepository.deleteAll();
        epssRepository.deleteAll();

        cve("CVE-2099-7001");
        cve("CVE-2099-7002");
        cve("CVE-2099-7003");
    }

    /* ------------------------------------------------------------------ */
    /* The whole point of the phase                                       */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser(username = "alice@example.com")
    void aComplianceUploadPersistsTheBenchmarkAndPutsItsVulnerabilitiesThroughTheFunnel() throws Exception {
        // KEV-listed and weaponized, so the enrichment denormalization is observable rather than
        // inferred from the EPSS default every seeded CVE gets.
        kev("CVE-2099-7001", "Known");
        exploit("CVE-2099-7001", ExploitMaturity.WEAPONIZED);

        upload("acme/api:1.4.2")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("COMPLIANCE_SCAN"))
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.triggeredBy").value("alice@example.com"));

        // The controller's synchronous half: report and asset rows exist immediately, nothing parsed.
        DockerComplianceReport placeholder = onlyReport();
        assertThat(placeholder.getStatus()).isEqualTo(DockerComplianceReport.STATUS_QUEUED);
        assertThat(placeholder.getReportId()).isEqualTo("docker-cis-1.6.0");
        assertThat(controlRepository.findAllByReportIdOrderByControlIdAsc(placeholder.getId())).isEmpty();

        runQueuedJob();

        DockerComplianceReport report = onlyReport();
        assertThat(report.getStatus()).isEqualTo(DockerComplianceReport.STATUS_COMPLETED);
        assertThat(report.getScannedAt()).isNotNull();
        assertThat(report.getPendingRawBody()).as("consumed once ingested").isNull();

        /* --- the benchmark half ------------------------------------- */

        Map<String, DockerComplianceControl> controls = controlsOf(report.getId());
        assertThat(controls.keySet()).containsExactlyInAnyOrder("4.1", "4.6", "5.7", "1.1.1", "4.3");
        assertThat(controls.get("4.1").getStatus()).as("a reported FAIL check").isEqualTo(ComplianceStatus.FAIL);
        assertThat(controls.get("4.1").getFailedChecks()).isEqualTo(1);
        assertThat(controls.get("4.6").getStatus()).as("a reported PASS check").isEqualTo(ComplianceStatus.PASS);
        assertThat(controls.get("5.7").getStatus()).as("EXCEPTION is not a pass").isEqualTo(ComplianceStatus.SKIP);
        assertThat(controls.get("1.1.1").getStatus())
                .as("a control with no automated check at all is not evidence of compliance")
                .isEqualTo(ComplianceStatus.SKIP);
        assertThat(controls.get("4.3").getStatus())
                .as("a control that reported only vulnerabilities made no configuration claim")
                .isEqualTo(ComplianceStatus.SKIP);

        assertThat(report.getFailedControls()).isEqualTo(1);
        assertThat(report.getPassedControls()).isEqualTo(1);
        assertThat(report.getSkippedControls()).isEqualTo(3);
        assertThat(report.getTotalControls()).isEqualTo(5);

        Map<String, ComplianceMisconfigurationResponse> checks = checksOf(report.getId());
        assertThat(checks.keySet()).containsExactlyInAnyOrder("DS002", "DS026", "DS009");
        ComplianceMisconfigurationResponse rootUser = checks.get("DS002");
        assertThat(rootUser.status()).isEqualTo(ComplianceStatus.FAIL);
        assertThat(rootUser.resolution())
                .as("remediation text is the reason the screen is worth building")
                .isEqualTo("Add 'USER <non root user name>' line to the Dockerfile");
        assertThat(rootUser.avdId()).isEqualTo("AVD-DS-0002");
        assertThat(rootUser.severity()).isEqualTo("HIGH");
        assertThat(rootUser.controlId()).as("the control layer the old model threw away").isEqualTo("4.1");
        assertThat(rootUser.target()).isEqualTo("acme/api:1.4.2 (alpine 3.18.4)");
        assertThat(rootUser.references()).hasSize(1);

        /* --- the vulnerability half --------------------------------- */

        Asset asset = onlyAsset();
        assertThat(asset.getName()).isEqualTo("acme/api:1.4.2");
        assertThat(asset.getType()).isEqualTo(AssetType.CONTAINER_IMAGE);
        assertThat(asset.getStatus()).isEqualTo(Asset.STATUS_COMPLETED);
        assertThat(asset.getLastScannedAt()).isNotNull();
        assertThat(asset.getScanner()).isEqualTo("Trivy CIS");

        Map<String, AssetComponent> components = componentsOf(asset.getId());
        // The DLA-9999-1 finding on musl names no CVE, so neither it nor its package is ingested.
        assertThat(components.keySet()).containsExactlyInAnyOrder("openssl", "busybox", "lodash");
        assertThat(components).doesNotContainKey("musl");

        // Exactly the coordinate rules the asset path applies: os-pkgs carry no PURL and correlate
        // through the CPE fallback; lang-pkgs get one and take the OSV-primary path.
        assertThat(components.get("openssl").getPurl()).isNull();
        assertThat(components.get("openssl").getIdentityKey()).isEqualTo("name/openssl");
        assertThat(components.get("openssl").getLayer()).isEqualTo("sha256:2222bbbbcccc");
        assertThat(components.get("lodash").getPurl()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(components.get("lodash").getIdentityKey()).isEqualTo("npm/lodash");
        assertThat(components.get("lodash").getEcosystem()).isEqualTo("npm");
        assertThat(components.get("lodash").getPackagePath()).isEqualTo("app/package-lock.json");

        Map<String, VulnerabilityAlert> alerts = alertsOf(asset.getId());
        assertThat(alerts.keySet())
                .as("compliance-report vulnerabilities are ordinary VulnerabilityAlerts, not a "
                        + "parallel entity outside the funnel")
                .containsExactlyInAnyOrder("CVE-2099-7001", "CVE-2099-7002", "CVE-2099-7003");

        VulnerabilityAlert openssl = alerts.get("CVE-2099-7001");
        assertThat(openssl.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(openssl.getFixedVersions()).isEqualTo("3.1.4-r0");
        assertThat(openssl.getFixSource()).isEqualTo(FixSource.SCANNER);
        assertThat(openssl.getMatchConfidence()).isEqualTo(MatchConfidence.EXACT);
        assertThat(openssl.getAssetComponent()).isNotNull();
        assertThat(openssl.getComponent()).as("XOR: an asset alert cites no SBOM component").isNull();

        // The enrichment that DockerVulnerabilityAlert could never have: KEV membership, EPSS,
        // exploit maturity, and a funnel verdict with a reason.
        assertThat(openssl.isActionable()).isTrue();
        assertThat(openssl.getActionableReason()).isEqualTo(ActionableReason.KEV_AND_EPSS_HIGH);
        assertThat(openssl.getExploitMaturity()).isEqualTo(ExploitMaturity.IN_THE_WILD);
        assertThat(openssl.getKnownRansomwareUse()).isEqualTo("Known");
        assertThat(openssl.getEpssScore()).isEqualTo(0.9d, org.assertj.core.data.Offset.offset(1e-6));

        // Trivy supplied no FixedVersion for busybox, and nothing else knows one either.
        assertThat(alerts.get("CVE-2099-7002").getFixState()).isEqualTo(FixState.UNKNOWN);
        assertThat(alerts.get("CVE-2099-7002").getFixedVersions()).isNull();
        assertThat(alerts.get("CVE-2099-7002").getActionableReason()).isEqualTo(ActionableReason.EPSS_HIGH);

        // The report keeps its own record of what it said, for the audit document and for a re-scan.
        assertThat(reportVulnerabilityRepository.findAllByReportId(report.getId())).hasSize(3);
    }

    @Test
    @WithMockUser
    void complianceSourcedAlertsAppearInGetActionable() throws Exception {
        upload("acme/api:1.4.2").andExpect(status().isAccepted());
        runQueuedJob();

        UUID assetId = onlyAsset().getId();

        // The test that proves Docker/CIS vulnerabilities finally reach the primary screen. Nothing
        // about the query knows they came from a compliance report — which is the whole design.
        mockMvc.perform(get("/actionable").param("size", "50"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.content[?(@.cveId == 'CVE-2099-7001')]").exists())
                .andExpect(jsonPath("$.content[?(@.cveId == 'CVE-2099-7001')].assetId")
                        .value(assetId.toString()))
                .andExpect(jsonPath("$.content[?(@.cveId == 'CVE-2099-7001')].assetName")
                        .value("acme/api:1.4.2"))
                .andExpect(jsonPath("$.content[?(@.cveId == 'CVE-2099-7001')].productId").value((Object) null));

        // And the same rows through the asset filter, which is what the Infrastructure drill-down uses.
        mockMvc.perform(get("/actionable").param("assetId", assetId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(3));
    }

    @Test
    @WithMockUser
    void reCorrelationPicksUpAnOsvFixVersionTheReportDidNotSupply() throws Exception {
        // The compliance report named no FixedVersion for lodash. OSV knows one — and because the
        // findings take the ordinary correlation pass, the alert comes out FIXED at OSV's version.
        advisory("GHSA-lodash-compliance", "npm", "lodash", "CVE-2099-7003", "4.0.0", "4.17.21");

        upload("acme/api:1.4.2").andExpect(status().isAccepted());
        runQueuedJob();

        VulnerabilityAlert lodash = alertsOf(onlyAsset().getId()).get("CVE-2099-7003");
        assertThat(lodash.getFixState()).isEqualTo(FixState.FIXED);
        assertThat(lodash.getFixedVersions()).isEqualTo("4.17.21");
        assertThat(lodash.getFixSource()).isEqualTo(FixSource.OSV);
    }

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                          */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void aSecondReportForTheSameAssetKeepsBothAuditsButReconcilesOneSetOfAlerts() throws Exception {
        upload("acme/api:1.4.2").andExpect(status().isAccepted());
        runQueuedJob();
        UUID assetId = onlyAsset().getId();
        assertThat(alertsOf(assetId)).hasSize(3);

        // A later audit of the same image that still fails 4.1 but now reports only openssl.
        uploadBody("acme/api:1.4.2", """
                {"ID":"docker-cis-1.6.0","Title":"CIS Docker Community Edition Benchmark","Version":"1.6.0",
                 "Results":[
                   {"ID":"4.1","Name":"Ensure that a user for the container has been created","Severity":"HIGH",
                    "Results":[{"Target":"acme/api:1.4.2","Class":"config","Type":"dockerfile",
                      "Misconfigurations":[{"ID":"DS002","AVDID":"AVD-DS-0002","Title":"Image user should not be 'root'",
                        "Resolution":"Add 'USER <non root user name>' line to the Dockerfile","Severity":"HIGH","Status":"FAIL"}]}]},
                   {"ID":"4.3","Name":"Ensure that unnecessary packages are not installed","Severity":"HIGH",
                    "Results":[{"Target":"acme/api:1.4.2 (alpine 3.18.4)","Class":"os-pkgs","Type":"alpine",
                      "Vulnerabilities":[{"VulnerabilityID":"CVE-2099-7001","PkgName":"openssl",
                        "InstalledVersion":"3.1.3-r0","FixedVersion":"3.1.4-r0"}]}]}]}
                """).andExpect(status().isAccepted());
        runQueuedJob();

        // Two audits kept — a compliance report is a dated artefact and the trend is the point.
        assertThat(reportRepository.count()).as("reports are snapshots, never upserted").isEqualTo(2);
        // One asset, one set of alerts — the running thing is upserted, so nothing duplicates.
        assertThat(assetRepository.count()).isEqualTo(1);
        assertThat(assetRepository.findById(assetId)).isPresent();

        Map<String, VulnerabilityAlert> alerts = alertsOf(assetId);
        assertThat(alerts).as("alerts are auto-resolved, never deleted or duplicated").hasSize(3);
        assertThat(alerts.get("CVE-2099-7001").getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE);
        assertThat(alerts.get("CVE-2099-7002").getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);
        assertThat(alerts.get("CVE-2099-7003").getLifecycleState()).isEqualTo(AlertLifecycleState.AUTO_RESOLVED);

        Map<String, AssetComponent> components = componentsOf(assetId);
        assertThat(components.get("openssl").isPresentInLastScan()).isTrue();
        assertThat(components.get("lodash").isPresentInLastScan()).isFalse();
    }

    @Test
    @WithMockUser
    void reScanningAReportReplaysItsFindingsWithoutDuplicatingAnything() throws Exception {
        upload("acme/api:1.4.2").andExpect(status().isAccepted());
        runQueuedJob();

        String reportId = onlyReport().getId();
        UUID assetId = onlyAsset().getId();
        List<UUID> alertIdsBefore = alertRepository.findAllByAssetId(assetId).stream()
                .map(VulnerabilityAlert::getId).sorted().toList();

        // POST /compliance/reports/{id}/scan — what replaced GET /cis/docker/scan/{id}. The raw body
        // is gone by now, so this exercises the replay path off the persisted vulnerability rows.
        mockMvc.perform(post("/compliance/reports/{id}/scan", reportId))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.type").value("COMPLIANCE_SCAN"));
        runQueuedJob();

        assertThat(reportRepository.count()).as("a re-scan is not a new audit").isEqualTo(1);
        assertThat(controlRepository.findAllByReportIdOrderByControlIdAsc(reportId))
                .as("the benchmark half is not re-persisted").hasSize(5);
        assertThat(misconfigRepository.findForReport(reportId, null,
                org.springframework.data.domain.PageRequest.of(0, 50)).getTotalElements()).isEqualTo(3);

        // The identity keys the replay rebuilds must be the ones the upload wrote, or every alert
        // would look new and the old ones would auto-resolve.
        assertThat(alertRepository.findAllByAssetId(assetId).stream()
                .map(VulnerabilityAlert::getId).sorted().toList())
                .as("same alert rows, updated in place")
                .isEqualTo(alertIdsBefore);
        assertThat(alertsOf(assetId).values())
                .allSatisfy(alert -> assertThat(alert.getLifecycleState()).isEqualTo(AlertLifecycleState.ACTIVE));

        assertThat(onlyReport().getStatus()).isEqualTo(DockerComplianceReport.STATUS_COMPLETED);
    }

    /* ------------------------------------------------------------------ */
    /* Reads                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void theDetailEndpointReturnsBothHalvesCorrectlyShaped() throws Exception {
        upload("acme/api:1.4.2").andExpect(status().isAccepted());
        runQueuedJob();
        String reportId = onlyReport().getId();

        mockMvc.perform(get("/compliance/reports/{id}", reportId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.benchmarkId").value("docker-cis-1.6.0"))
                .andExpect(jsonPath("$.assetName").value("acme/api:1.4.2"))
                .andExpect(jsonPath("$.passedControls").value(1))
                .andExpect(jsonPath("$.failedControls").value(1))
                .andExpect(jsonPath("$.skippedControls").value(3))
                .andExpect(jsonPath("$.totalControls").value(5))
                .andExpect(jsonPath("$.relatedResources[0]").value("https://www.cisecurity.org/benchmark/docker"))
                .andExpect(jsonPath("$.controls.length()").value(5))
                // Failures sort first: the list exists to be worked through.
                .andExpect(jsonPath("$.misconfigurations.totalElements").value(3))
                .andExpect(jsonPath("$.misconfigurations.content[0].checkId").value("DS002"))
                .andExpect(jsonPath("$.misconfigurations.content[0].status").value("FAIL"))
                .andExpect(jsonPath("$.misconfigurations.content[0].controlId").value("4.1"))
                .andExpect(jsonPath("$.misconfigurations.content[0].resolution")
                        .value("Add 'USER <non root user name>' line to the Dockerfile"))
                // …and the vulnerability half is the ordinary actionable page, not a bespoke shape.
                .andExpect(jsonPath("$.actionableItems.totalElements").value(3))
                .andExpect(jsonPath("$.actionableItems.content[0].epssScore").exists());

        mockMvc.perform(get("/compliance/reports/{id}", reportId).param("misconfigStatus", "PASS"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.misconfigurations.totalElements").value(1))
                .andExpect(jsonPath("$.misconfigurations.content[0].checkId").value("DS026"));

        mockMvc.perform(get("/compliance/reports"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].failedControls").value(1))
                .andExpect(jsonPath("$.content[0].actionableItems").value(3))
                .andExpect(jsonPath("$.content[0].status").value("COMPLETED"));

        mockMvc.perform(get("/compliance/reports/{id}/misconfigurations", reportId)
                        .param("status", "SKIP"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].checkId").value("DS009"));

        mockMvc.perform(get("/compliance/reports/{id}", UUID.randomUUID().toString()))
                .andExpect(status().isNotFound());
    }

    /* ------------------------------------------------------------------ */
    /* Upload validation                                                  */
    /* ------------------------------------------------------------------ */

    @Test
    @WithMockUser
    void theAssetNameFallsBackToTheDocumentAndIsOtherwiseRequired() throws Exception {
        // No `name` param: the compliance format carries no ArtifactName, so the first scanned
        // Target names the asset.
        mockMvc.perform(post("/compliance/reports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body()))
                .andExpect(status().isAccepted());
        assertThat(onlyAsset().getName()).isEqualTo("acme/api:1.4.2 (alpine 3.18.4)");

        // …and a document that names nothing at all is a 400, not a 202 for work that could never
        // produce a readable report.
        mockMvc.perform(post("/compliance/reports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"ID":"docker-cis-1.6.0","Title":"CIS Docker Benchmark","Results":[]}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("`name` request parameter is required")));
    }

    @Test
    @WithMockUser
    void anImageScanPostedToTheComplianceEndpointIsRejected() throws Exception {
        String trivyImage;
        try (InputStream in = new ClassPathResource("asset/trivy-image.json").getInputStream()) {
            trivyImage = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        mockMvc.perform(post("/compliance/reports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(trivyImage))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message")
                        .value(org.hamcrest.Matchers.containsString("/assets/scan/trivy")));

        assertThat(reportRepository.count()).as("nothing stored").isZero();
        assertThat(jobRepository.count()).as("nothing queued").isZero();
    }

    @Test
    @WithMockUser
    void concurrentComplianceUploadsEachGetTheirOwnJob() throws Exception {
        upload("acme/api:1.4.2").andExpect(status().isAccepted());
        upload("acme/worker:2.0.0").andExpect(status().isAccepted());

        // COMPLIANCE_SCAN is per-invocation like SBOM_UPLOAD/ASSET_SCAN, not a singleton feed pull.
        assertThat(jobRepository.count()).isEqualTo(2);
        assertThat(reportRepository.count()).isEqualTo(2);
        assertThat(assetRepository.count()).isEqualTo(2);
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private ResultActions upload(String name) throws Exception {
        return uploadBody(name, body());
    }

    private ResultActions uploadBody(String name, String content) throws Exception {
        return mockMvc.perform(post("/compliance/reports")
                .param("name", name)
                .contentType(MediaType.APPLICATION_JSON)
                .content(content));
    }

    private void runQueuedJob() {
        UUID jobId = jobRepository.findAll().stream()
                .filter(job -> !job.getStatus().isTerminal())
                .findFirst().orElseThrow().getId();
        jobRunner.poll();
        await().atMost(SETTLE).until(() -> jobRepository.findById(jobId).orElseThrow().getStatus().isTerminal());
        Job finished = jobRepository.findById(jobId).orElseThrow();
        assertThat(finished.getStatus()).as(finished.getMessage()).isEqualTo(JobStatus.SUCCEEDED);
    }

    private DockerComplianceReport onlyReport() {
        List<DockerComplianceReport> all = reportRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    private Asset onlyAsset() {
        List<Asset> all = assetRepository.findAll();
        assertThat(all).hasSize(1);
        return all.get(0);
    }

    private Map<String, DockerComplianceControl> controlsOf(String reportId) {
        return index(controlRepository.findAllByReportIdOrderByControlIdAsc(reportId),
                DockerComplianceControl::getControlId);
    }

    private Map<String, ComplianceMisconfigurationResponse> checksOf(String reportId) {
        return index(complianceService.findMisconfigurations(reportId, 0, 100, null).getContent(),
                ComplianceMisconfigurationResponse::checkId);
    }

    private Map<String, AssetComponent> componentsOf(UUID assetId) {
        return index(assetComponentRepository.findAllByAssetId(assetId), AssetComponent::getName);
    }

    private Map<String, VulnerabilityAlert> alertsOf(UUID assetId) {
        return index(alertRepository.findAllByAssetId(assetId), a -> a.getVulnerability().getId());
    }

    private static <T> Map<String, T> index(List<T> rows, Function<T, String> key) {
        return rows.stream().collect(Collectors.toMap(key, Function.identity()));
    }

    private void cve(String id) {
        Vulnerability cve = new Vulnerability();
        cve.setId(id);
        cve.setDescription("Seeded for a compliance-scan test");
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

    private void kev(String cveId, String ransomware) {
        KEV kev = new KEV();
        kev.setCveId(cveId);
        kev.setVendor("acme");
        kev.setProduct("api");
        kev.setName("Seeded KEV entry");
        kev.setAdded(LocalDateTime.now());
        kev.setDueDate(new Date());
        kev.setKnownRansomwareCampaignUse(ransomware);
        kevRepository.save(kev);
    }

    private void exploit(String cveId, ExploitMaturity maturity) {
        CveExploit exploit = new CveExploit();
        exploit.setCveId(cveId);
        exploit.setMaturity(maturity);
        exploit.setMetasploit(true);
        exploit.setLastIngestedAt(LocalDateTime.now());
        exploitRepository.save(exploit);
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

    private static String body() throws IOException {
        try (InputStream in = new ClassPathResource("compliance/docker-cis.json").getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

}
